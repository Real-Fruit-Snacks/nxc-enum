"""Kerberoastable account enumeration."""

import re

from ..core.colors import Colors, c
from ..core.constants import RE_LDAP_CN
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..reporting.next_steps import get_external_tool_auth

# Regex to extract SPN values from verbose output
# nxc --query uses space-padded format: "servicePrincipalName   HTTP/server.domain.local"
# Also handle colon format for compatibility: "servicePrincipalName: HTTP/server.domain.local"
RE_SPN_VALUE = re.compile(r"servicePrincipalName[:\s]+(\S+)", re.IGNORECASE)

# Regex to match continuation lines for multi-valued SPNs
# Format: "LDAP   IP   PORT   HOST   <lots of spaces>   SPN_VALUE"
# The continuation line has the attribute value column aligned but no attribute name
# We look for: LDAP prefix, then mostly spaces in the attribute name column, then the SPN
RE_SPN_CONTINUATION = re.compile(r"^LDAP\s+\S+\s+\d+\s+\S+\s{10,}(\S+)$")


def enum_kerberoastable(args, cache):
    """Identify Kerberoastable accounts (users with SPNs) without requesting tickets."""
    target = cache.target if cache else args.target
    print_section("Kerberoastable Accounts", target)

    # Skip if LDAP is unavailable (determined during cache priming)
    if not cache.ldap_available:
        status("LDAP unavailable - skipping Kerberoastable enumeration", "error")
        return

    auth = cache.auth_args
    status("Querying accounts with SPNs...")

    # Try to use batch data first (populated during cache priming)
    batch_data = cache.get_kerberoastable_from_batch()
    if batch_data is not None:
        # Use pre-fetched batch data - much faster
        kerberoastable = batch_data
        rc, stdout, stderr = 0, "", ""  # No individual query needed
    else:
        # Fall back to individual query
        # Note: nxc --query requires space-separated attributes, not comma-separated
        query_args = (
            ["ldap", target]
            + auth
            + ["--query", "(servicePrincipalName=*)", "sAMAccountName servicePrincipalName"]
        )
        rc, stdout, stderr = run_nxc(query_args, args.timeout)
        debug_nxc(query_args, stdout, stderr, "Kerberoastable Query")

        kerberoastable = []
        filtered_machine_accounts = 0
        filtered_dc_accounts = 0
        filtered_krbtgt = 0
        lines = stdout.split("\n")
        current_user = None
        current_spns = []
        in_spn_attribute = False  # Track if we're parsing multi-valued SPN lines

        for i, line in enumerate(lines):
            # Don't strip the line yet - we need to check for continuation patterns
            raw_line = line
            line = line.strip()
            if not line:
                continue

            # nxc --query verbose shows "Response for object: CN=username,..."
            # Followed by attribute values on subsequent lines
            if "Response for object:" in line and "CN=" in line:
                # Save previous user if exists
                if current_user:
                    kerberoastable.append({"username": current_user, "spns": current_spns or None})

                # Skip Domain Controllers
                if "OU=Domain Controllers" in line:
                    filtered_dc_accounts += 1
                    current_user = None
                    current_spns = []
                    in_spn_attribute = False
                    continue

                cn_match = RE_LDAP_CN.search(line)
                if cn_match:
                    username = cn_match.group(1)
                    # Skip computer accounts and krbtgt
                    if username.endswith("$"):
                        filtered_machine_accounts += 1
                        current_user = None
                        current_spns = []
                        in_spn_attribute = False
                    elif username.lower() == "krbtgt":
                        filtered_krbtgt += 1
                        current_user = None
                        current_spns = []
                        in_spn_attribute = False
                    else:
                        current_user = username
                        current_spns = []
                        in_spn_attribute = False
                else:
                    current_user = None
                    current_spns = []
                    in_spn_attribute = False

            # Parse SPN values from verbose output lines
            elif current_user:
                # Check for servicePrincipalName line (first SPN value)
                spn_match = RE_SPN_VALUE.search(line)
                if spn_match:
                    spn_value = spn_match.group(1).strip()
                    if spn_value and spn_value not in current_spns:
                        current_spns.append(spn_value)
                    in_spn_attribute = True  # Now look for continuation lines
                elif in_spn_attribute:
                    # Check for continuation line (multi-valued SPN)
                    cont_match = RE_SPN_CONTINUATION.match(raw_line)
                    if cont_match:
                        spn_value = cont_match.group(1).strip()
                        if spn_value and spn_value not in current_spns:
                            current_spns.append(spn_value)
                    elif "LDAP" in line and not RE_SPN_CONTINUATION.match(raw_line):
                        # Hit a different attribute line
                        in_spn_attribute = False

        # Don't forget to add the last user
        if current_user:
            # Check if user already exists (avoid duplicates)
            existing_users = [k["username"] for k in kerberoastable]
            if current_user not in existing_users:
                kerberoastable.append(
                    {"username": current_user, "spns": current_spns if current_spns else None}
                )

    cache.kerberoastable = kerberoastable

    if kerberoastable:
        status(f"Found {len(kerberoastable)} Kerberoastable account(s):", "warning")
        output("")
        output(c("KERBEROASTABLE ACCOUNTS (have SPNs)", Colors.RED))
        output("")
        for account in kerberoastable:
            user = account["username"]
            spns = account["spns"]
            output(f"  {c(user, Colors.RED)}")
            if spns:
                for spn in spns:
                    output(f"    SPN: {c(spn, Colors.YELLOW)}")

        # Build auth hint for command using auth helper
        auth_info = get_external_tool_auth(args, cache, tool="nxc")
        auth_hint = auth_info["auth_string"]

        # Add next step recommendation
        usernames = [k["username"] for k in kerberoastable]
        users_list = ", ".join(usernames[:3])
        if len(kerberoastable) > 3:
            users_list += f" (+{len(kerberoastable) - 3} more)"
        cache.add_next_step(
            finding=f"Kerberoastable accounts: {users_list}",
            command=f"nxc ldap {target} {auth_hint} --kerberoasting hashes.txt",
            description="Request TGS tickets for offline cracking with hashcat",
            priority="high",
        )

        # Store for aggregated copy-paste section
        cache.copy_paste_data["kerberoastable_users"].update(
            account["username"] for account in kerberoastable
        )
        for account in kerberoastable:
            if account.get("spns"):
                cache.copy_paste_data["spns"].update(account["spns"])
    else:
        # Check if LDAP actually failed before claiming "no accounts found"
        combined = (stdout + stderr).lower()
        ldap_failure_indicators = [
            "failed to connect",
            "connection refused",
            "timed out",
            "ldap ping failed",
            "status_logon_failure",
            "status_access_denied",
            "failed to create connection",
            "kerberos sessionerror",
        ]
        if any(ind in combined for ind in ldap_failure_indicators) or rc != 0:
            status("LDAP unavailable - cannot enumerate Kerberoastable accounts", "error")
        else:
            status("No Kerberoastable accounts found", "success")
            # Show filtered account summary if any were filtered
            total_filtered = filtered_machine_accounts + filtered_dc_accounts + filtered_krbtgt
            if total_filtered > 0:
                filter_parts = []
                if filtered_machine_accounts:
                    filter_parts.append(f"{filtered_machine_accounts} machine account(s)")
                if filtered_dc_accounts:
                    filter_parts.append(f"{filtered_dc_accounts} DC account(s)")
                if filtered_krbtgt:
                    filter_parts.append("krbtgt")
                output(f"  (Filtered: {', '.join(filter_parts)})")

    if args.json_output:
        JSON_DATA["kerberoastable"] = kerberoastable
