"""Multi-credential parallel validation."""

import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.colors import Colors, c
from ..core.constants import MAX_CREDENTIAL_VALIDATION_WORKERS
from ..core.output import output, print_section, status
from ..core.runner import run_nxc
from ..models.credential import Credential


def _test_single_cred(
    target: str, cred: Credential, timeout: int
) -> tuple[Credential, bool, bool, str]:
    """Test a single credential against target.

    Returns:
        Tuple of (cred, success, is_admin, error_msg)
    """
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


def validate_credentials_multi(
    target: str, creds: list[Credential], timeout: int, args=None
) -> list[Credential]:
    """Validate multiple credentials, return list of valid ones.

    Args:
        target: Target host to validate against
        creds: List of credentials to test
        timeout: Timeout for each validation attempt
        args: Optional parsed arguments with spray control options:
            - continue_on_success: Keep testing after finding valid creds
            - jitter: Random delay between attempts (forces sequential)
            - fail_limit: Stop after N total failures
            - ufail_limit: Stop testing user after N failures for that user
            - gfail_limit: Stop after N consecutive failures
    """
    print_section("Credential Validation", target)
    status(f"Testing {len(creds)} credential(s)...")

    # Extract spray control options
    continue_on_success = getattr(args, "continue_on_success", False) if args else False
    jitter = getattr(args, "jitter", None) if args else None
    fail_limit = getattr(args, "fail_limit", None) if args else None
    ufail_limit = getattr(args, "ufail_limit", None) if args else None
    gfail_limit = getattr(args, "gfail_limit", None) if args else None

    valid_creds = []
    invalid_creds = []

    # Use sequential mode if any spray control options are set
    use_sequential = jitter is not None or fail_limit or ufail_limit or gfail_limit

    if use_sequential:
        # Sequential mode for spray control
        total_failures = 0
        consecutive_failures = 0
        user_failures: dict[str, int] = {}
        stopped_early = False
        stop_reason = ""

        for cred in creds:
            # Check fail limits before testing
            if fail_limit and total_failures >= fail_limit:
                stopped_early = True
                stop_reason = f"total fail limit ({fail_limit})"
                break
            if gfail_limit and consecutive_failures >= gfail_limit:
                stopped_early = True
                stop_reason = f"consecutive fail limit ({gfail_limit})"
                break
            if ufail_limit:
                user_key = cred.user.lower()
                if user_failures.get(user_key, 0) >= ufail_limit:
                    status(f"{cred.display_name()}: skipped (user fail limit)", "warning")
                    continue

            # Apply jitter delay
            if jitter and jitter > 0:
                delay = random.uniform(0, jitter)
                time.sleep(delay)

            try:
                cred, success, is_admin, error_msg = _test_single_cred(target, cred, timeout)
                if success:
                    consecutive_failures = 0
                    admin_tag = c(" (ADMIN)", Colors.RED) if is_admin else ""
                    status(f"{cred.display_name()}: valid{admin_tag}", "success")
                    valid_creds.append(cred)
                    # Stop on first success if not continuing
                    if not continue_on_success:
                        stopped_early = True
                        stop_reason = "found valid credential"
                        break
                else:
                    total_failures += 1
                    consecutive_failures += 1
                    user_key = cred.user.lower()
                    user_failures[user_key] = user_failures.get(user_key, 0) + 1
                    err_detail = f" ({error_msg})" if error_msg else ""
                    status(f"{cred.display_name()}: invalid{err_detail}", "error")
                    invalid_creds.append(cred)
            except Exception as e:
                total_failures += 1
                consecutive_failures += 1
                status(f"Error validating {cred.display_name()}: {e}", "error")

        if stopped_early and stop_reason:
            status(f"Stopped early: {stop_reason}", "warning")
    else:
        # Parallel mode (default)
        with ThreadPoolExecutor(
            max_workers=min(len(creds), MAX_CREDENTIAL_VALIDATION_WORKERS)
        ) as executor:
            futures = [executor.submit(_test_single_cred, target, cred, timeout) for cred in creds]
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
        status("No valid credentials found!", "error")

    # Sort so admin credentials come first - ensures creds[0] is admin if one exists
    # This is important because creds[0] is used for all one-time cached operations
    # Use 'cred' to avoid shadowing imported 'c' color function
    valid_creds.sort(key=lambda cred: (not cred.is_admin, cred.display_name()))

    return valid_creds
