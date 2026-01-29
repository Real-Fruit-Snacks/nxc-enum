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
from ..reporting.next_steps import get_external_tool_auth

# LDAP filter for computers with LAPS configured (has ms-Mcs-AdmPwd attribute)
LAPS_FILTER = "(ms-Mcs-AdmPwd=*)"

# Regex patterns for parsing
RE_CN = re.compile(r"CN=([^,]+)", re.IGNORECASE)


def enum_laps(args, cache):
    """Enumerate LAPS deployment in the domain.

    Queries LDAP for computers with ms-Mcs-AdmPwd attribute.
    This is enumeration only - does not retrieve actual passwords.

    CLI Options:
        --laps-computer: Filter to computer names matching pattern (e.g., 'SRV*')
    """
    target = cache.target if cache else args.target
    print_section("LAPS Deployment Check", target, cache=cache)

    # Skip if LDAP is unavailable (determined during cache priming)
    if not cache.ldap_available:
        status("LDAP unavailable - skipping LAPS enumeration", "error")
        return

    auth = cache.auth_args

    # Check for computer filter option
    computer_filter = getattr(args, "laps_computer", None)

    # Try to use batch data first (if no filter specified)
    if not computer_filter:
        batch_data = cache.get_laps_computers_from_batch()
        if batch_data is not None:
            # Use pre-fetched batch data - much faster
            laps_computers = batch_data
            can_read_passwords = False  # Need separate check for read access
            rc, stdout, stderr = 0, "", ""
            status("Checking for LAPS deployment...")
        else:
            batch_data = None  # Fall through to query

    if computer_filter or (not computer_filter and batch_data is None):
        # Fall back to individual query
        if computer_filter:
            # Build filter with computer name pattern
            ldap_pattern = computer_filter.replace("*", "*")
            combined_filter = f"(&(ms-Mcs-AdmPwd=*)(cn={ldap_pattern}))"
            status(f"Checking for LAPS deployment (computers matching: {computer_filter})...")
        else:
            combined_filter = LAPS_FILTER
            status("Checking for LAPS deployment...")

        # Query for computers with LAPS attribute
        query_args = (
            ["ldap", target] + auth + ["--query", combined_filter, "cn,ms-Mcs-AdmPwdExpirationTime"]
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

            # If we see ms-Mcs-AdmPwdExpirationTime, LAPS is configured
            if current_computer and "ms-Mcs-AdmPwdExpirationTime" in line:
                if current_computer not in laps_computers:
                    laps_computers.append(current_computer)
                # If line has actual data, we might have read access
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
    # (only relevant for individual query path)
    combined = stdout + stderr
    access_denied = "STATUS_ACCESS_DENIED" in combined.upper()
    no_entries = "No entries found" in combined or "0 entries" in combined
    ldap_failed = (
        "Failed to create connection" in combined
        or "Failed to connect" in combined.lower()
        or "ldap connection failed" in combined.lower()
    )

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

            # Build auth hint for command using auth helper
            auth_info = get_external_tool_auth(args, cache, tool="nxc")
            auth_hint = auth_info["auth_string"]

            # Add high-priority next step for password retrieval
            cache.add_next_step(
                finding=f"LAPS readable on {len(laps_computers)} computers",
                command=f"nxc ldap {target} {auth_hint} -M laps",
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

    elif ldap_failed:
        status("LDAP unavailable - cannot check LAPS deployment", "error")
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
            status("Could not query LAPS status", "error")
        else:
            status("No LAPS deployment detected in domain", "info")

    if args.json_output:
        JSON_DATA["laps"] = {
            "computers": laps_computers,
            "readable": can_read_passwords,
            "count": len(laps_computers),
        }
