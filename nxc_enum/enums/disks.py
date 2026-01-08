"""Disk/volume enumeration.

This module enumerates available disk drives and volumes on the target
system using SMB SRVSVC RPC queries.

This is pure RPC enumeration - queries disk info via SRVSVC.
No command execution on the target.

Pentest value: Maps storage for potential data exfiltration targets.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

# Regex patterns for parsing disk info
RE_DISK = re.compile(r"([A-Z]:)(?:\s+|$)", re.IGNORECASE)
RE_DISK_TYPE = re.compile(r"Type:\s*(\S+)", re.IGNORECASE)
RE_DISK_SIZE = re.compile(r"Size:\s*(\S+)", re.IGNORECASE)


def enum_disks(args, cache, is_admin: bool = False):
    """Enumerate disk drives and volumes on the target.

    Uses nxc --disks flag which queries via SRVSVC RPC
    (NetServerDiskEnum) to list available drives.

    Identifies storage locations for data enumeration and exfiltration.
    Requires local admin privileges.
    """
    target = cache.target if cache else args.target
    print_section("Disk Enumeration", target)

    if not is_admin:
        status("Skipping: requires local admin (current user is not admin)", "info")
        return

    auth = cache.auth_args
    status("Enumerating disk drives...")

    # Query disks using nxc --disks
    disk_args = ["smb", target] + auth + ["--disks"]
    rc, stdout, stderr = run_nxc(disk_args, args.timeout)
    debug_nxc(disk_args, stdout, stderr, "Disk Enumeration")

    disks = []

    # Check for access/error conditions FIRST (before parsing)
    combined = stdout + stderr
    combined_upper = combined.upper()
    access_denied = (
        "STATUS_ACCESS_DENIED" in combined_upper
        or "RPC_S_ACCESS_DENIED" in combined_upper
        or "ACCESS_DENIED" in combined_upper
    )
    requires_admin = "requires admin" in combined.lower()
    enum_failed = "failed to enumerate disks" in combined.lower()

    # Only parse output if enumeration didn't fail
    if not access_denied and not enum_failed:
        for line in stdout.split("\n"):
            line = line.strip()
            if not line:
                continue

            if is_nxc_noise_line(line):
                continue

            # Skip error/info lines that might contain false matches
            if "failed" in line.lower() or "error" in line.lower():
                continue

            # Look for drive letters (must be standalone, not part of error msg)
            # Only match if line looks like disk output (not error messages)
            disk_match = RE_DISK.search(line)
            if disk_match:
                drive = disk_match.group(1).upper()
                # Sanity check: don't match drives from error strings
                if "_" + drive[0].lower() + ":" in line.lower():
                    continue  # Skip false matches like "rpc_s_access_denied"
                disk_info = {"drive": drive}

                # Try to parse additional info
                type_match = RE_DISK_TYPE.search(line)
                if type_match:
                    disk_info["type"] = type_match.group(1)

                size_match = RE_DISK_SIZE.search(line)
                if size_match:
                    disk_info["size"] = size_match.group(1)

                # Avoid duplicates
                if not any(d["drive"] == drive for d in disks):
                    disks.append(disk_info)

            # Alternative format: "DISK: C:"
            if "disk" in line.lower() and "failed" not in line.lower():
                parts = line.split()
                for part in parts:
                    if re.match(r"^[A-Z]:$", part, re.IGNORECASE):
                        drive = part.upper()
                        if not any(d["drive"] == drive for d in disks):
                            disks.append({"drive": drive})

    # Store in cache
    cache.disk_drives = disks

    if disks:
        status(f"Found {len(disks)} disk drive(s)", "success")
        output("")

        output(c("DISK DRIVES", Colors.CYAN))
        output(f"{'Drive':<10} {'Type':<15} {'Size'}")
        output(f"{'-'*10} {'-'*15} {'-'*20}")

        for disk in sorted(disks, key=lambda x: x["drive"]):
            drive = disk["drive"]
            disk_type = disk.get("type", "Unknown")
            size = disk.get("size", "Unknown")

            # Highlight non-system drives
            if drive != "C:":
                output(f"{c(drive, Colors.GREEN + Colors.BOLD):<10} " f"{disk_type:<15} {size}")
            else:
                output(f"{drive:<10} {disk_type:<15} {size}")

        output("")

        # Note about additional drives
        non_system = [d["drive"] for d in disks if d["drive"] != "C:"]
        if non_system:
            output(
                c(
                    f"[*] Non-system drives detected: {', '.join(non_system)}",
                    Colors.YELLOW,
                )
            )
            output(
                c(
                    "    May contain backups, databases, or sensitive files",
                    Colors.YELLOW,
                )
            )
            output("")

        # Store for copy-paste
        cache.copy_paste_data["disk_drives"] = {d["drive"] for d in disks}

    elif access_denied or requires_admin or enum_failed:
        status("Requires admin privileges to enumerate disks", "warning")
    else:
        if not stdout.strip() or rc != 0:
            status("Could not enumerate disk drives", "error")
        else:
            status("No disk drives enumerated (or only system drive)", "info")

    if args.json_output:
        JSON_DATA["disks"] = {
            "drives": disks,
            "count": len(disks),
        }
