"""Multi-credential parallel validation."""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.colors import Colors, c
from ..core.constants import MAX_CREDENTIAL_VALIDATION_WORKERS
from ..core.output import output, print_section, status
from ..core.runner import run_nxc
from ..models.credential import Credential


def validate_credentials_multi(
    target: str, creds: list[Credential], timeout: int
) -> list[Credential]:
    """Validate multiple credentials in parallel, return list of valid ones."""
    print_section("Credential Validation", target)
    status(f"Testing {len(creds)} credential(s)...")

    def test_cred(cred: Credential) -> tuple[Credential, bool, bool, str]:
        auth = cred.auth_args()
        rc, stdout, stderr = run_nxc(["smb", target] + auth, timeout)
        # Combine stdout and stderr for checking (verbose output may go to either)
        combined_output = stdout + stderr
        # Check for successful auth (no STATUS_ error)
        success = "[+]" in combined_output and "STATUS_" not in combined_output
        cred.valid = success
        # Check for local admin (Pwn3d!)
        is_admin = "Pwn3d!" in combined_output
        cred.is_admin = is_admin
        # Extract error message if failed
        error_msg = ""
        if not success:
            for line in stdout.split("\n"):
                if "STATUS_" in line:
                    # Extract the STATUS code
                    match = re.search(r"(STATUS_\w+)", line)
                    if match:
                        error_msg = match.group(1)
                        break
        return cred, success, is_admin, error_msg

    valid_creds = []
    invalid_creds = []

    with ThreadPoolExecutor(
        max_workers=min(len(creds), MAX_CREDENTIAL_VALIDATION_WORKERS)
    ) as executor:
        futures = [executor.submit(test_cred, cred) for cred in creds]
        for future in as_completed(futures):
            try:
                cred, success, is_admin, error_msg = future.result()
                if success:
                    admin_tag = c(" (ADMIN)", Colors.RED) if is_admin else ""
                    status(f"{cred.display_name()}: valid{admin_tag}", "success")
                    valid_creds.append(cred)
                else:
                    err_detail = f" ({error_msg})" if error_msg else ""
                    status(f"{cred.display_name()}: invalid{err_detail}", "error")
                    invalid_creds.append(cred)
            except Exception as e:
                status(f"Error validating credential: {e}", "error")

    output("")
    # Count admin credentials (use 'cred' to avoid shadowing imported 'c' color function)
    admin_count = sum(1 for cred in valid_creds if cred.is_admin)
    if valid_creds:
        admin_info = f" ({admin_count} with local admin)" if admin_count > 0 else ""
        status(
            f"{len(valid_creds)}/{len(creds)} credentials validated successfully{admin_info}",
            "success",
        )
    else:
        status(f"No valid credentials found!", "error")

    # Sort so admin credentials come first - ensures creds[0] is admin if one exists
    # This is important because creds[0] is used for all one-time cached operations
    # Use 'cred' to avoid shadowing imported 'c' color function
    valid_creds.sort(key=lambda cred: (not cred.is_admin, cred.display_name()))

    return valid_creds
