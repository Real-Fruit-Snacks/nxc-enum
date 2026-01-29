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


def enum_local_groups(args, cache, is_admin: bool = False):
    """Enumerate local groups on the target.

    Uses SMB --local-groups to list local groups via SAMRPC.
    Note: This lists groups only - members require additional enumeration.
    Requires local admin privileges.
    """
    target = cache.target if cache else args.target
    print_section("Local Groups", target, cache=cache)

    if not is_admin:
        status("Skipping: requires local admin (current user is not admin)", "info")
        return

    auth = cache.auth_args

    # Check for group filter
    group_filter = getattr(args, "local_groups_filter", None)
    if group_filter:
        status(f"Filtering to group: {group_filter}", "info")

    status("Enumerating local groups...")

    # Query local groups
    group_args = ["smb", target] + auth + ["--local-groups"]
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

    # Store results (all groups, before filtering)
    cache.local_groups = local_groups
    cache.high_value_local_groups = high_value_groups

    # Apply filter if specified
    display_groups = local_groups
    display_high_value = high_value_groups
    if group_filter:
        # Case-insensitive matching
        filter_lower = group_filter.lower()
        matched_groups = {
            name: info for name, info in local_groups.items() if name.lower() == filter_lower
        }
        if not matched_groups:
            status(f"Group '{group_filter}' not found", "error")
            # JSON export with empty filtered result
            if args.json_output:
                JSON_DATA["local_groups"] = {
                    "groups": {name: {"rid": info["rid"]} for name, info in local_groups.items()},
                    "high_value_groups": high_value_groups,
                    "total_groups": len(local_groups),
                    "filter": group_filter,
                    "filtered_groups": {},
                }
            return
        display_groups = matched_groups
        display_high_value = [g for g in high_value_groups if g.lower() == filter_lower]

    # Display results
    if display_groups:
        total_groups = len(display_groups)
        if group_filter:
            status(f"Found {total_groups} matching group(s)", "success")
        else:
            status(f"Found {total_groups} local group(s)", "success")
        output("")

        # Show high-value groups first (privilege escalation targets)
        if display_high_value:
            output(c("HIGH-VALUE GROUPS (Privilege Escalation)", Colors.RED + Colors.BOLD))
            output(f"{'-'*50}")
            for group_name in sorted(display_high_value):
                group_info = display_groups[group_name]
                rid = group_info["rid"]
                output(f"  {c('[!]', Colors.YELLOW)} {c(group_name, Colors.YELLOW)} (RID: {rid})")
            output("")

        # Show all groups with RIDs
        if group_filter:
            output(c("FILTERED LOCAL GROUPS", Colors.CYAN))
        else:
            output(c("ALL LOCAL GROUPS", Colors.CYAN))
        output(f"{'Group Name':<40} {'RID':<8}")
        output(f"{'-'*40} {'-'*8}")

        for group_name in sorted(display_groups.keys()):
            group_info = display_groups[group_name]
            rid = group_info["rid"]
            # Highlight high-value groups
            if group_name.lower() in [g.lower() for g in display_high_value]:
                output(f"{c(group_name, Colors.YELLOW):<40} {rid:<8}")
            else:
                output(f"{group_name:<40} {rid:<8}")
        output("")

        # Store copy-paste data for group names (filtered)
        cache.copy_paste_data["local_group_names"] = set(display_groups.keys())

    else:
        # Check for common errors
        combined = stdout + stderr
        combined_lower = combined.lower()
        if (
            "status_access_denied" in combined_lower
            or "rpc_s_access_denied" in combined_lower
            or "access_denied" in combined_lower
        ):
            status("Access denied - cannot enumerate local groups", "warning")
            output(
                c(
                    "    Requires local admin or specific permissions",
                    Colors.YELLOW,
                )
            )
        elif "status_logon_failure" in combined_lower:
            status(
                "Authentication failed - cannot enumerate local groups",
                "error",
            )
        else:
            status("No local groups enumerated", "info")

    if args.json_output:
        json_data = {
            "groups": {name: {"rid": info["rid"]} for name, info in local_groups.items()},
            "high_value_groups": high_value_groups,
            "total_groups": len(local_groups),
        }
        if group_filter:
            json_data["filter"] = group_filter
            json_data["filtered_groups"] = {
                name: {"rid": info["rid"]} for name, info in display_groups.items()
            }
        JSON_DATA["local_groups"] = json_data
