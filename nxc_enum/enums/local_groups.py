"""Local group enumeration.

This module enumerates local groups on the target system.
Useful for identifying available local groups on the target.

This is pure enumeration - reads local group list via SMB SAMRPC.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

# Regex to match group line: "SMB IP PORT HOST RID - GroupName"
# The format after hostname is: "RID - GroupName" where RID is a number
RE_GROUP_LINE = re.compile(r"(\d+)\s+-\s+(.+)$")


def enum_local_groups(args, cache):
    """Enumerate local groups on the target.

    Uses SMB --local-groups to list local groups via SAMRPC.
    Note: This lists groups only - members require additional enumeration.
    """
    print_section("Local Groups", args.target)

    auth = cache.auth_args
    status("Enumerating local groups...")

    # Query local groups
    group_args = ["smb", args.target] + auth + ["--local-groups"]
    rc, stdout, stderr = run_nxc(group_args, args.timeout)
    debug_nxc(group_args, stdout, stderr, "Local Groups")

    local_groups = {}
    high_value_groups = []

    # High-value groups for privilege escalation
    HIGH_VALUE_GROUP_NAMES = [
        "administrators",
        "server operators",
        "backup operators",
        "account operators",
        "print operators",
        "dnsadmins",
        "remote desktop users",
        "remote management users",
        "hyper-v administrators",
    ]

    # Parse output
    # Actual nxc format:
    # SMB  10.1.174.149  445  DC01  [+] Enumerated local groups
    # SMB  10.1.174.149  445  DC01  549 - Server Operators
    # SMB  10.1.174.149  445  DC01  548 - Account Operators
    for line in stdout.split("\n"):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        if is_nxc_noise_line(line_stripped):
            continue

        # Skip info/success messages
        if "[*]" in line_stripped or "[+]" in line_stripped:
            if "Enumerated" in line_stripped or "Local Groups" in line_stripped:
                continue
            if "SAMRPC" in line_stripped:
                continue

        # Parse group line: find "RID - GroupName" pattern
        # Line format: "SMB IP PORT HOST RID - GroupName"
        match = RE_GROUP_LINE.search(line_stripped)
        if match:
            rid = int(match.group(1))
            group_name = match.group(2).strip()
            local_groups[group_name] = {"rid": rid, "members": []}

            # Track high-value groups
            if group_name.lower() in HIGH_VALUE_GROUP_NAMES:
                high_value_groups.append(group_name)

    # Store results
    cache.local_groups = local_groups
    cache.high_value_local_groups = high_value_groups

    # Display results
    if local_groups:
        total_groups = len(local_groups)
        status(f"Found {total_groups} local group(s)", "success")
        output("")

        # Show high-value groups first (privilege escalation targets)
        if high_value_groups:
            output(c("HIGH-VALUE GROUPS (Privilege Escalation)", Colors.RED + Colors.BOLD))
            output(f"{'-'*50}")
            for group_name in sorted(high_value_groups):
                group_info = local_groups[group_name]
                rid = group_info["rid"]
                output(f"  {c('[!]', Colors.YELLOW)} {c(group_name, Colors.YELLOW)} (RID: {rid})")
            output("")

        # Show all groups with RIDs
        output(c("ALL LOCAL GROUPS", Colors.CYAN))
        output(f"{'Group Name':<40} {'RID':<8}")
        output(f"{'-'*40} {'-'*8}")

        for group_name in sorted(local_groups.keys()):
            group_info = local_groups[group_name]
            rid = group_info["rid"]
            # Highlight high-value groups
            if group_name.lower() in [g.lower() for g in high_value_groups]:
                output(f"{c(group_name, Colors.YELLOW):<40} {rid:<8}")
            else:
                output(f"{group_name:<40} {rid:<8}")
        output("")

        # Store copy-paste data for group names
        cache.copy_paste_data["local_group_names"] = set(local_groups.keys())

    else:
        # Check for common errors
        combined = stdout + stderr
        if "STATUS_ACCESS_DENIED" in combined.upper():
            status("Access denied - cannot enumerate local groups", "error")
            output(
                c(
                    "    Requires local admin or specific permissions",
                    Colors.YELLOW,
                )
            )
        elif "STATUS_LOGON_FAILURE" in combined.upper():
            status(
                "Authentication failed - cannot enumerate local groups",
                "error",
            )
        else:
            status("No local groups enumerated", "info")

    if args.json_output:
        JSON_DATA["local_groups"] = {
            "groups": {name: {"rid": info["rid"]} for name, info in local_groups.items()},
            "high_value_groups": high_value_groups,
            "total_groups": len(local_groups),
        }
