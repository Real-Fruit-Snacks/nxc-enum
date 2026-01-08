"""FTP enumeration module.

This module checks FTP access:
1. First tries anonymous access
2. If anonymous fails and credentials are provided, tests with credentials
3. Lists accessible files on successful login

This is pure enumeration - read-only directory listing.
"""

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line


def _check_ftp_login(target, username, password, timeout, label="FTP"):
    """Attempt FTP login and return success status.

    Args:
        target: Target IP/hostname
        username: FTP username
        password: FTP password (can be empty string)
        timeout: Connection timeout
        label: Debug label for logging

    Returns:
        Tuple of (success, is_accessible, stdout, stderr)
        - success: True if login succeeded
        - is_accessible: True if FTP port is open
        - stdout: Raw stdout from nxc
        - stderr: Raw stderr from nxc
    """
    ftp_args = ["ftp", target, "-u", username, "-p", password]
    rc, stdout, stderr = run_nxc(ftp_args, timeout)
    debug_nxc(ftp_args, stdout, stderr, label)

    combined = stdout + stderr

    # Check if FTP is available
    if (
        "Connection refused" in combined
        or "port" in combined.lower()
        and "closed" in combined.lower()
    ):
        return False, False, stdout, stderr

    if "timed out" in combined.lower():
        return False, False, stdout, stderr

    # FTP is accessible
    is_accessible = "FTP" in stdout

    # Check for successful login
    if "[+]" in stdout:
        return True, is_accessible, stdout, stderr

    # Check for failed login
    if "Login failed" in combined or "530" in combined or "[-]" in stdout:
        return False, True, stdout, stderr

    return False, is_accessible, stdout, stderr


def _list_ftp_files(target, username, password, timeout, label="FTP List"):
    """List files via FTP after successful login.

    Args:
        target: Target IP/hostname
        username: FTP username
        password: FTP password
        timeout: Connection timeout
        label: Debug label for logging

    Returns:
        List of filenames found
    """
    ls_args = ["ftp", target, "-u", username, "-p", password, "--ls"]
    rc, stdout, stderr = run_nxc(ls_args, timeout)
    debug_nxc(ls_args, stdout, stderr, label)

    files = []
    for line in stdout.split("\n"):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue

        # Parse directory listing
        if line.startswith("FTP"):
            parts = line.split()
            if len(parts) >= 5:
                filename = parts[-1]
                if filename not in ("[*]", "[+]", "[-]", "Directory", "listing"):
                    files.append(filename)
        elif not line.startswith(("[", "FTP")):
            # Raw file entry (e.g., "drwxr-xr-x  2 root root 4096 Dec 25 file.txt")
            parts = line.split()
            if parts:
                filename = parts[-1]
                if filename and not filename.startswith("."):
                    files.append(filename)

    return files


def enum_ftp(args, cache):
    """Check FTP access with anonymous and provided credentials.

    Attempts:
    1. Anonymous FTP login first
    2. If anonymous fails and credentials provided, tests with credentials
    3. Directory listing on successful login
    """
    target = cache.target if cache else args.target
    print_section("FTP Enumeration", target)

    ftp_info = {
        "accessible": False,
        "anonymous": False,
        "authenticated": False,
        "auth_user": None,
        "files": [],
    }

    # Skip if port pre-scan determined FTP is unavailable
    if cache.ftp_available is False:
        status("FTP port (21) not open - skipping", "info")
        if args.json_output:
            JSON_DATA["ftp"] = ftp_info
        return

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 1: Try anonymous access
    # ─────────────────────────────────────────────────────────────────────────
    status("Checking FTP anonymous access...", "info")

    anon_success, is_accessible, stdout, stderr = _check_ftp_login(
        target, "anonymous", "", args.timeout, "FTP Anonymous"
    )

    combined = stdout + stderr

    # Check if FTP port is not open
    if not is_accessible and "Connection refused" in combined:
        status("FTP port (21) not open", "info")
        if args.json_output:
            JSON_DATA["ftp"] = ftp_info
        return

    if not is_accessible and "timed out" in combined.lower():
        status("FTP connection timed out", "error")
        if args.json_output:
            JSON_DATA["ftp"] = ftp_info
        return

    ftp_info["accessible"] = is_accessible or "FTP" in stdout

    if anon_success:
        ftp_info["anonymous"] = True
        status("Anonymous FTP access allowed!", "warning")
        output("")
        output(c("[!] ANONYMOUS FTP ACCESS ENABLED", Colors.RED + Colors.BOLD))
        output("-" * 50)

        # List files
        files = _list_ftp_files(target, "anonymous", "", args.timeout, "FTP Anonymous List")
        ftp_info["files"] = files

        if files:
            output(f"  {c('[*]', Colors.CYAN)} Found {len(files)} file(s)/folder(s):")
            output("")
            for f in sorted(files)[:20]:
                output(f"    - {f}")
            if len(files) > 20:
                output(f"    ... and {len(files) - 20} more")
            output("")
            cache.copy_paste_data["ftp_files"].update(files)
        else:
            output(f"  {c('[*]', Colors.CYAN)} Directory listing empty or not available")
            output("")

        cache.add_next_step(
            finding="Anonymous FTP access",
            command=f"ftp {target}  # Login: anonymous, Password: (empty)",
            description="Browse and download files via anonymous FTP",
            priority="high",
        )

        cache.ftp_info = ftp_info
        cache.ftp_anonymous = True
        if args.json_output:
            JSON_DATA["ftp"] = ftp_info
        return

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 2: Anonymous failed - try with credentials if provided
    # ─────────────────────────────────────────────────────────────────────────
    status("Anonymous FTP login denied", "info")

    # Get credentials from args or cache
    username = None
    password = None

    if hasattr(args, "user") and args.user:
        username = args.user
        password = args.password if hasattr(args, "password") and args.password else ""
    elif cache.primary_credential:
        cred = cache.primary_credential
        username = cred.user
        password = cred.password if cred.password else ""

    if not username:
        output(c("    FTP requires authentication (no credentials to test)", Colors.CYAN))
        cache.ftp_info = ftp_info
        if args.json_output:
            JSON_DATA["ftp"] = ftp_info
        return

    status(f"Testing FTP with credentials ({username})...", "info")

    auth_success, _, stdout, stderr = _check_ftp_login(
        target, username, password, args.timeout, "FTP Authenticated"
    )

    if auth_success:
        ftp_info["authenticated"] = True
        ftp_info["auth_user"] = username
        status(f"FTP authentication successful as '{username}'!", "success")
        output("")
        output(c(f"[+] FTP ACCESS WITH CREDENTIALS: {username}", Colors.GREEN + Colors.BOLD))
        output("-" * 50)

        # List files
        files = _list_ftp_files(target, username, password, args.timeout, "FTP Auth List")
        ftp_info["files"] = files

        if files:
            output(f"  {c('[*]', Colors.CYAN)} Found {len(files)} file(s)/folder(s):")
            output("")
            for f in sorted(files)[:20]:
                output(f"    - {f}")
            if len(files) > 20:
                output(f"    ... and {len(files) - 20} more")
            output("")
            cache.copy_paste_data["ftp_files"].update(files)
        else:
            output(f"  {c('[*]', Colors.CYAN)} Directory listing empty or not available")
            output("")

        cache.add_next_step(
            finding=f"FTP access with credentials ({username})",
            command=f"ftp {target}  # Login: {username}",
            description="Browse and download files via authenticated FTP",
            priority="medium",
        )
    else:
        status(f"FTP authentication failed for '{username}'", "info")
        output(c("    FTP credentials do not work for this service", Colors.CYAN))

    cache.ftp_info = ftp_info
    cache.ftp_anonymous = False
    if args.json_output:
        JSON_DATA["ftp"] = ftp_info
