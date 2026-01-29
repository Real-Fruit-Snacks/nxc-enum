"""BitLocker encryption status enumeration.

This module checks BitLocker encryption status on target systems.
Identifies encrypted vs unencrypted drives.

This is pure enumeration - queries WMI for BitLocker status via SMB.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line


def enum_bitlocker(args, cache, is_admin: bool = False):
    """Check BitLocker encryption status on the target.

    Uses the bitlocker SMB module to query encryption status.
    Requires local admin privileges.
    """
    target = cache.target if cache else args.target
    print_section("BitLocker Status", target, cache=cache)

    if not is_admin:
        status("Skipping: requires local admin (current user is not admin)", "info")
        return

    auth = cache.auth_args
    status("Checking BitLocker encryption status...")

    # Use bitlocker module
    bitlocker_args = ["smb", target] + auth + ["-M", "bitlocker"]
    rc, stdout, stderr = run_nxc(bitlocker_args, args.timeout)
    debug_nxc(bitlocker_args, stdout, stderr, "BitLocker")

    bitlocker_status = {}
    encrypted_drives = []
    unencrypted_drives = []

    # Parse output
    # Format varies, but typically shows drive letters and status
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        if is_nxc_noise_line(line):
            continue

        line_lower = line.lower()

        # Look for drive status
        # Pattern: "C: Encrypted" or "C: Not Encrypted" or "C: FullyEncrypted"
        drive_match = re.search(r"([A-Z]:)\s*(.*)", line, re.IGNORECASE)
        if drive_match:
            drive = drive_match.group(1).upper()
            status_text = drive_match.group(2).strip()

            # Determine encryption status
            if "encrypt" in status_text.lower():
                if "not" in status_text.lower() or "un" in status_text.lower():
                    bitlocker_status[drive] = "Not Encrypted"
                    unencrypted_drives.append(drive)
                else:
                    bitlocker_status[drive] = "Encrypted"
                    encrypted_drives.append(drive)
            elif "protection" in status_text.lower():
                if "on" in status_text.lower():
                    bitlocker_status[drive] = "Encrypted"
                    encrypted_drives.append(drive)
                else:
                    bitlocker_status[drive] = "Not Encrypted"
                    unencrypted_drives.append(drive)

        # Alternative format: "BitLocker: Enabled/Disabled"
        elif "bitlocker" in line_lower:
            if "enabled" in line_lower or "encrypted" in line_lower:
                # Mark as encrypted (drive letter may not be specified)
                if "C:" not in bitlocker_status:
                    bitlocker_status["C:"] = "Encrypted"
                    encrypted_drives.append("C:")
            elif "disabled" in line_lower or "not" in line_lower:
                if "C:" not in bitlocker_status:
                    bitlocker_status["C:"] = "Not Encrypted"
                    unencrypted_drives.append("C:")

    # Store results
    cache.bitlocker_status = bitlocker_status
    cache.encrypted_drives = encrypted_drives
    cache.unencrypted_drives = unencrypted_drives

    # Display results
    if bitlocker_status:
        total_drives = len(bitlocker_status)
        encrypted_count = len(encrypted_drives)

        if encrypted_count == total_drives:
            status(f"All {total_drives} drive(s) encrypted", "success")
        elif encrypted_count == 0:
            status(
                f"No drives encrypted ({total_drives} drive(s) checked)",
                "warning",
            )
        else:
            status(f"{encrypted_count}/{total_drives} drive(s) encrypted", "info")

        output("")
        output(c("BITLOCKER STATUS", Colors.CYAN))
        output(f"{'Drive':<10} {'Status'}")
        output(f"{'-'*10} {'-'*20}")

        for drive, drive_status in sorted(bitlocker_status.items()):
            if drive_status == "Encrypted":
                icon = c("[+]", Colors.GREEN)
                status_color = Colors.GREEN
            else:
                icon = c("[!]", Colors.YELLOW)
                status_color = Colors.YELLOW

            output(f"{icon} {drive:<6} {c(drive_status, status_color)}")

        output("")

        # Security note for unencrypted drives
        if unencrypted_drives:
            output(
                c(
                    "[*] Unencrypted drives may expose data if physical access is obtained",
                    Colors.YELLOW,
                )
            )
            output("")

    else:
        # Check for common errors
        combined = stdout + stderr
        if "STATUS_ACCESS_DENIED" in combined.upper():
            status("Access denied - cannot check BitLocker status", "error")
            output(c("    Requires local admin privileges", Colors.YELLOW))
        elif (
            "Module not found" in combined
            or "module" in combined.lower()
            and "error" in combined.lower()
        ):
            status("Bitlocker module not available", "error")
        elif rc != 0:
            status("Could not query BitLocker status", "error")
        else:
            status("No BitLocker information available", "info")

    if args.json_output:
        JSON_DATA["bitlocker"] = {
            "status": bitlocker_status,
            "encrypted_drives": encrypted_drives,
            "unencrypted_drives": unencrypted_drives,
        }
