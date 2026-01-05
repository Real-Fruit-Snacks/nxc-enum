"""LAPS deployment enumeration.

This module identifies computers with LAPS (Local Administrator Password
Solution) deployed by querying for the ms-Mcs-AdmPwd attribute in AD.

This is pure enumeration - it does NOT retrieve LAPS passwords.
To actually retrieve passwords, use the command shown in Next Steps.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

# LDAP filter for computers with LAPS configured (has ms-Mcs-AdmPwd attribute)
LAPS_FILTER = "(ms-Mcs-AdmPwd=*)"

# Regex patterns for parsing
RE_CN = re.compile(r"CN=([^,]+)", re.IGNORECASE)


def enum_laps(args, cache):
    """Enumerate LAPS deployment in the domain.

    Queries LDAP for computers with ms-Mcs-AdmPwd attribute.
    This is enumeration only - does not retrieve actual passwords.
    """
    print_section("LAPS Deployment Check", args.target)

    auth = cache.auth_args
    status("Checking for LAPS deployment...")

    # Query for computers with LAPS attribute
    # If we can see results, we may have read access
    query_args = (
        ["ldap", args.target] + auth + ["--query", LAPS_FILTER, "cn,ms-Mcs-AdmPwdExpirationTime"]
    )
    rc, stdout, stderr = run_nxc(query_args, args.timeout)
    debug_nxc(query_args, stdout, stderr, "LAPS Query")

    laps_computers = []
    can_read_passwords = False
    current_computer = None

    # Parse output
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        if is_nxc_noise_line(line):
            continue

        # Look for "Response for object: CN=computername,..."
        if "Response for object:" in line and "CN=" in line:
            cn_match = RE_CN.search(line)
            if cn_match:
                computer_name = cn_match.group(1)
                current_computer = computer_name
            continue

        # If we see ms-Mcs-AdmPwdExpirationTime, we can at least see LAPS is configured
        if current_computer and "ms-Mcs-AdmPwdExpirationTime" in line:
            if current_computer not in laps_computers:
                laps_computers.append(current_computer)
            # If the line has actual data (not just attribute name), we might have read access
            parts = re.split(r"[:\s]+", line, maxsplit=1)
            if len(parts) >= 2 and parts[1].strip():
                can_read_passwords = True
            current_computer = None
            continue

        # Alternative: LDAP response line format
        if line.startswith("LDAP") and "ms-Mcs-AdmPwd" not in line:
            # Check for computer names in response
            parts = line.split()
            for part in parts:
                if part.endswith("$") and part not in laps_computers:
                    laps_computers.append(part.rstrip("$"))

    # Check if we got access denied (means LAPS is deployed but we can't read)
    combined = stdout + stderr
    access_denied = "STATUS_ACCESS_DENIED" in combined.upper()
    no_entries = "No entries found" in combined or "0 entries" in combined

    # Store results in cache
    cache.laps_computers = laps_computers
    cache.laps_readable = can_read_passwords

    if laps_computers:
        status(
            f"Found {len(laps_computers)} computer(s) with LAPS configured",
            "success",
        )
        output("")

        # Display computers with LAPS
        output(c("LAPS-ENABLED COMPUTERS", Colors.CYAN))
        output(f"{'Computer Name':<30} {'Status'}")
        output(f"{'-'*30} {'-'*20}")

        for computer in sorted(laps_computers):
            output(f"{computer:<30} LAPS Configured")

        output("")

        # Check read access status
        if can_read_passwords:
            output(
                c(
                    "[!] Current user CAN read LAPS passwords!",
                    Colors.RED + Colors.BOLD,
                )
            )
            output(
                c(
                    "    This indicates high privileges (Domain Admin, LAPS readers, etc.)",
                    Colors.RED,
                )
            )
            output("")

            # Build auth hint for command
            if args.user:
                auth_hint = f"-u '{args.user}'"
                if args.password:
                    auth_hint += f" -p '{args.password}'"
                elif args.hash:
                    auth_hint += f" -H '{args.hash}'"
                else:
                    auth_hint += " -p '<password>'"
            else:
                auth_hint = "-u <user> -p <pass>"

            # Add high-priority next step for password retrieval
            cache.add_next_step(
                finding=f"LAPS readable on {len(laps_computers)} computers",
                command=f"nxc ldap {args.target} {auth_hint} -M laps",
                description="Retrieve LAPS passwords for local admin access",
                priority="high",
            )
        else:
            output(
                c(
                    "[*] LAPS is deployed but current user cannot read passwords",
                    Colors.YELLOW,
                )
            )
            output(
                c(
                    "    Try with Domain Admin or LAPS-delegated account",
                    Colors.YELLOW,
                )
            )
            output("")

        # Store for copy-paste
        cache.copy_paste_data["laps_computers"] = set(laps_computers)

    elif access_denied:
        status("LAPS may be deployed but access denied to query", "warning")
        output(
            c(
                "    Try with higher privileges to enumerate LAPS",
                Colors.YELLOW,
            )
        )
    elif no_entries:
        status("No LAPS deployment detected in domain", "info")
    else:
        # Check if query returned any data at all
        if not stdout.strip() or rc != 0:
            status("Could not query LAPS status (LDAP query failed)", "error")
        else:
            status("No LAPS deployment detected in domain", "info")

    if args.json_output:
        JSON_DATA["laps"] = {
            "computers": laps_computers,
            "readable": can_read_passwords,
            "count": len(laps_computers),
        }
