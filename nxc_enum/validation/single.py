"""Single credential validation."""

from ..core.output import status


def validate_credentials(target: str, auth: list, cache) -> tuple[bool, bool]:
    """Validate credentials using cache to avoid redundant calls.
    Returns (success, is_admin) tuple."""
    # Use cache to avoid duplicate SMB call
    rc, stdout, stderr = cache.get_smb_basic(target, auth)

    if "not found" in stderr.lower():
        status("netexec (nxc) not found in PATH", "error")
        return False, False

    # Combine stdout and stderr for checking (verbose output may go to either)
    combined_output = stdout + stderr

    # Check for local admin - NetExec outputs "Pwn3d!" or "(Pwn3d!)" when you have local admin
    is_admin = "Pwn3d!" in combined_output or "(Pwn3d!)" in combined_output

    if "[+]" in combined_output and "STATUS_" not in combined_output:
        return True, is_admin
    elif "[-]" in combined_output and "STATUS_LOGON_FAILURE" in combined_output.upper():
        status("Authentication failed - invalid credentials", "error")
        return False, False
    elif "[-]" in combined_output:
        status("Connection failed - check target accessibility", "error")
        return False, False
    elif "STATUS_" in combined_output:
        status("Authentication failed - status error in response", "error")
        return False, False

    # Default to failure if no explicit success marker
    status("Could not confirm authentication success", "warning")
    return False, False
