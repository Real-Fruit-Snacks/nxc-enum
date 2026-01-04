"""Kerberoastable account enumeration."""

import re
from ..core.runner import run_nxc
from ..core.output import output, status, print_section, debug_nxc, JSON_DATA
from ..core.colors import Colors, c
from ..core.constants import RE_LDAP_CN

# Regex to extract SPN values from verbose output
# nxc --query uses space-padded format: "servicePrincipalName   HTTP/server.domain.local"
# Also handle colon format for compatibility: "servicePrincipalName: HTTP/server.domain.local"
RE_SPN_VALUE = re.compile(r'servicePrincipalName[:\s]+(\S+)', re.IGNORECASE)

# Regex to match continuation lines for multi-valued SPNs
# Format: "LDAP   IP   PORT   HOST   <lots of spaces>   SPN_VALUE"
# The continuation line has the attribute value column aligned but no attribute name
# We look for: LDAP prefix, then mostly spaces in the attribute name column, then the SPN
RE_SPN_CONTINUATION = re.compile(r'^LDAP\s+\S+\s+\d+\s+\S+\s{10,}(\S+)$')


def enum_kerberoastable(args, cache):
    """Identify Kerberoastable accounts (users with SPNs) without requesting tickets."""
    print_section("Kerberoastable Accounts", args.target)

    auth = cache.auth_args
    status("Querying accounts with SPNs...")

    # Note: nxc --query requires space-separated attributes, not comma-separated
    query_args = ["ldap", args.target] + auth + ["--query", "(servicePrincipalName=*)", "sAMAccountName servicePrincipalName"]
    rc, stdout, stderr = run_nxc(query_args, args.timeout)
    debug_nxc(query_args, stdout, stderr, "Kerberoastable Query")

    kerberoastable = []
    lines = stdout.split('\n')
    current_user = None
    current_spns = []
    in_spn_attribute = False  # Track if we're parsing multi-valued SPN lines

    for i, line in enumerate(lines):
        # Don't strip the line yet - we need to check for continuation patterns on raw line
        raw_line = line
        line = line.strip()
        if not line:
            continue

        # nxc --query verbose output shows "Response for object: CN=username,..." for each result
        # Followed by attribute values on subsequent lines
        if 'Response for object:' in line and 'CN=' in line:
            # Save previous user if exists
            if current_user:
                kerberoastable.append({
                    'username': current_user,
                    'spns': current_spns if current_spns else None
                })

            # Skip Domain Controllers
            if 'OU=Domain Controllers' in line:
                current_user = None
                current_spns = []
                in_spn_attribute = False
                continue

            cn_match = RE_LDAP_CN.search(line)
            if cn_match:
                username = cn_match.group(1)
                # Skip computer accounts and krbtgt
                if not username.endswith('$') and username.lower() != 'krbtgt':
                    current_user = username
                    current_spns = []
                    in_spn_attribute = False
                else:
                    current_user = None
                    current_spns = []
                    in_spn_attribute = False
            else:
                current_user = None
                current_spns = []
                in_spn_attribute = False

        # Parse SPN values from verbose output lines following the object response
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
                # These lines have LDAP prefix but no attribute name, just the value
                cont_match = RE_SPN_CONTINUATION.match(raw_line)
                if cont_match:
                    spn_value = cont_match.group(1).strip()
                    if spn_value and spn_value not in current_spns:
                        current_spns.append(spn_value)
                elif 'LDAP' in line and not RE_SPN_CONTINUATION.match(raw_line):
                    # Hit a different attribute line, stop looking for SPN continuations
                    in_spn_attribute = False

    # Don't forget to add the last user
    if current_user:
        # Check if user already exists (avoid duplicates)
        existing_users = [k['username'] for k in kerberoastable]
        if current_user not in existing_users:
            kerberoastable.append({
                'username': current_user,
                'spns': current_spns if current_spns else None
            })

    cache.kerberoastable = kerberoastable

    if kerberoastable:
        status(f"Found {len(kerberoastable)} Kerberoastable account(s):", "warning")
        output("")
        for account in kerberoastable:
            user = account['username']
            spns = account['spns']
            output(f"  {c(user, Colors.YELLOW)}")
            if spns:
                for spn in spns:
                    output(f"    SPN: {c(spn, Colors.CYAN)}")

        # Build auth hint for command
        auth_hint = f"-u '{args.user}'" if args.user else "-u <user>"
        if args.password:
            auth_hint += f" -p '{args.password}'"
        elif args.hash:
            auth_hint += f" -H '{args.hash}'"
        else:
            auth_hint += " -p '<password>'"

        # Add next step recommendation
        usernames = [k['username'] for k in kerberoastable]
        users_list = ', '.join(usernames[:3])
        if len(kerberoastable) > 3:
            users_list += f" (+{len(kerberoastable) - 3} more)"
        cache.add_next_step(
            finding=f"Kerberoastable accounts: {users_list}",
            command=f"nxc ldap {args.target} {auth_hint} --kerberoasting hashes.txt",
            description="Request TGS tickets for offline cracking with hashcat",
            priority="high"
        )
    else:
        status("No Kerberoastable accounts found", "success")

    if args.json_output:
        JSON_DATA['kerberoastable'] = kerberoastable
