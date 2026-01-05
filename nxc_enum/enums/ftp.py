"""FTP anonymous access check.

This module checks if FTP allows anonymous access and lists accessible files.

This is pure enumeration - read-only directory listing.
"""

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line


def enum_ftp(args, cache):
    """Check FTP anonymous access and list files.

    Attempts anonymous FTP login and directory listing.
    """
    print_section("FTP Anonymous Access", args.target)

    status("Checking FTP anonymous access...")

    # Try anonymous login
    ftp_args = ["ftp", args.target, "-u", "anonymous", "-p", ""]
    rc, stdout, stderr = run_nxc(ftp_args, args.timeout)
    debug_nxc(ftp_args, stdout, stderr, "FTP Anonymous")

    ftp_info = {
        "accessible": False,
        "anonymous": False,
        "files": [],
        "banner": None,
    }

    combined = stdout + stderr

    # Check if FTP is available
    if (
        "Connection refused" in combined
        or "port" in combined.lower()
        and "closed" in combined.lower()
    ):
        status("FTP port (21) not open", "info")
        if args.json_output:
            JSON_DATA["ftp"] = ftp_info
        return

    if "timed out" in combined.lower():
        status("FTP connection timed out", "error")
        if args.json_output:
            JSON_DATA["ftp"] = ftp_info
        return

    # Check if we have FTP output
    if "FTP" in stdout:
        ftp_info["accessible"] = True

    # Check for successful anonymous login
    if "[+]" in stdout or "anonymous" in stdout.lower() and "success" in stdout.lower():
        ftp_info["anonymous"] = True

    # Check for failed login
    if "Login failed" in combined or "530" in combined or "Authentication failed" in combined:
        ftp_info["anonymous"] = False
        status("Anonymous FTP login denied", "success")
        output(c("    FTP requires authentication", Colors.GREEN))
        if args.json_output:
            JSON_DATA["ftp"] = ftp_info
        return

    # If anonymous works, try to list files
    if ftp_info["anonymous"]:
        status("Anonymous FTP access allowed!", "warning")
        output("")

        # Try directory listing
        ls_args = ["ftp", args.target, "-u", "anonymous", "-p", "", "--ls"]
        rc_ls, stdout_ls, stderr_ls = run_nxc(ls_args, args.timeout)
        debug_nxc(ls_args, stdout_ls, stderr_ls, "FTP List")

        files = []
        for line in stdout_ls.split("\n"):
            line = line.strip()
            if not line or is_nxc_noise_line(line):
                continue

            # Parse directory listing
            # Format varies, but typically includes file/dir names
            if line.startswith("FTP"):
                parts = line.split()
                if len(parts) >= 5:
                    # Last part is usually the filename
                    filename = parts[-1]
                    if filename not in (
                        "[*]",
                        "[+]",
                        "[-]",
                        "Directory",
                        "listing",
                    ):
                        files.append(filename)
            elif not line.startswith(("[", "FTP")):
                # Raw file entry
                # Could be "drwxr-xr-x  2 root root 4096 Dec 25 file.txt"
                parts = line.split()
                if parts:
                    filename = parts[-1]
                    if filename and not filename.startswith("."):
                        files.append(filename)

        ftp_info["files"] = files

        # Display results
        output(c("[!] ANONYMOUS FTP ACCESS ENABLED", Colors.RED + Colors.BOLD))
        output(f"{'-'*50}")

        if files:
            output(f"  {c('[*]', Colors.CYAN)} Found {len(files)} file(s)/folder(s):")
            output("")
            for f in sorted(files)[:20]:  # Limit display
                output(f"    - {f}")
            if len(files) > 20:
                output(f"    ... and {len(files) - 20} more")
            output("")

            # Store copy-paste data
            cache.copy_paste_data["ftp_files"] = set(files)
        else:
            output(f"  {c('[*]', Colors.CYAN)} Directory listing empty or not available")
            output("")

        # Add next step
        cache.add_next_step(
            finding="Anonymous FTP access",
            command=f"ftp {args.target}  # Login: anonymous, Password: (empty)",
            description="Browse and download files via anonymous FTP",
            priority="high",
        )

    else:
        # Check if FTP exists but needs auth
        if ftp_info["accessible"]:
            status("FTP available but requires authentication", "info")

    # Store results
    cache.ftp_info = ftp_info
    cache.ftp_anonymous = ftp_info["anonymous"]

    if args.json_output:
        JSON_DATA["ftp"] = ftp_info
