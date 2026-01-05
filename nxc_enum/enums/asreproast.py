"""AS-REP Roastable account enumeration.

This module identifies accounts vulnerable to AS-REP roasting by querying
for accounts with the DONT_REQUIRE_PREAUTH flag set (UAC bit 0x400000).

This is pure enumeration - it does NOT request AS-REP tickets or obtain hashes.
To actually perform AS-REP roasting, use the command shown in Next Steps.
"""

import re

from ..core.colors import Colors, c
from ..core.constants import RE_LDAP_CN
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

# UAC flag for DONT_REQUIRE_PREAUTH = 0x400000 = 4194304
# LDAP filter uses bitwise AND to check if this flag is set
DONT_REQUIRE_PREAUTH_FILTER = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"

# Regex to match "No entries found" or similar
RE_NO_ENTRIES = re.compile(r"No entries found|0 entries", re.IGNORECASE)


def enum_asreproast(args, cache):
    """Identify accounts vulnerable to AS-REP roasting.

    Queries LDAP for accounts with DONT_REQUIRE_PREAUTH flag set.
    This is enumeration only - does not request tickets or obtain hashes.
    """
    print_section("AS-REP Roastable Accounts", args.target)

    auth = cache.auth_args
    status("Querying accounts without Kerberos pre-authentication...")

    # Use LDAP query to find accounts with DONT_REQUIRE_PREAUTH flag
    # This is pure enumeration - no AS-REP tickets are requested
    query_args = (
        ["ldap", args.target] + auth + ["--query", DONT_REQUIRE_PREAUTH_FILTER, "sAMAccountName"]
    )
    rc, stdout, stderr = run_nxc(query_args, args.timeout)
    debug_nxc(query_args, stdout, stderr, "AS-REP Roastable Query")

    asreproastable = []

    # Parse output for vulnerable accounts
    # nxc --query output format: "Response for object: CN=username,..."
    # followed by "sAMAccountName    username"
    current_user = None

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Skip noise lines
        if is_nxc_noise_line(line):
            continue

        # Look for "Response for object: CN=username,..." lines
        if "Response for object:" in line and "CN=" in line:
            cn_match = RE_LDAP_CN.search(line)
            if cn_match:
                username = cn_match.group(1)
                # Skip computer accounts
                if not username.endswith("$"):
                    current_user = username
                else:
                    current_user = None
            continue

        # Look for sAMAccountName attribute line
        if current_user and "sAMAccountName" in line:
            # Format: "sAMAccountName    username" or "sAMAccountName: username"
            parts = re.split(r"[:\s]+", line, maxsplit=1)
            if len(parts) >= 2:
                sam_name = parts[1].strip()
                if sam_name and sam_name not in [a["username"] for a in asreproastable]:
                    asreproastable.append(
                        {
                            "username": sam_name,
                            "domain": (
                                args.domain if hasattr(args, "domain") and args.domain else None
                            ),
                        }
                    )
            current_user = None
            continue

        # Alternative: direct username in LDAP response line (older nxc versions)
        # Format: "LDAP  IP  PORT  HOST  username"
        if line.startswith("LDAP") and "sAMAccountName" not in line:
            parts = line.split()
            if len(parts) >= 5:
                try:
                    port_idx = -1
                    for i, p in enumerate(parts):
                        if p in ("389", "636"):
                            port_idx = i
                            break
                    if port_idx >= 0 and port_idx + 2 < len(parts):
                        username = parts[port_idx + 2]
                        # Skip if it looks like a status indicator
                        if username not in ("[*]", "[+]", "[-]", "[!]"):
                            if not username.endswith("$"):
                                if username not in [a["username"] for a in asreproastable]:
                                    asreproastable.append(
                                        {
                                            "username": username,
                                            "domain": (
                                                args.domain
                                                if hasattr(args, "domain") and args.domain
                                                else None
                                            ),
                                        }
                                    )
                except (ValueError, IndexError):
                    pass

    # Store results in cache
    cache.asreproastable = asreproastable

    if asreproastable:
        status(f"Found {len(asreproastable)} account(s) vulnerable to AS-REP roasting:", "warning")
        output("")

        # Display accounts
        output(c("VULNERABLE ACCOUNTS (DONT_REQUIRE_PREAUTH)", Colors.YELLOW))
        output(f"{'Username':<30} {'Notes'}")
        output(f"{'-'*30} {'-'*40}")

        for account in asreproastable:
            username = account["username"]
            output(f"{c(username, Colors.YELLOW):<40} Pre-auth disabled")

        output("")
        output(c("ATTACK INFORMATION:", Colors.RED))
        output(c("  [!] These accounts can be attacked WITHOUT valid credentials!", Colors.RED))
        output(c("  [!] AS-REP roasting obtains hashes for offline password cracking.", Colors.RED))
        output("")

        # Build auth hint for command - can use any valid creds or even anonymous in some cases
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

        # Add next step recommendation - this is the actual attack command
        usernames = [a["username"] for a in asreproastable]
        users_list = ", ".join(usernames[:3])
        if len(asreproastable) > 3:
            users_list += f" (+{len(asreproastable) - 3} more)"

        cache.add_next_step(
            finding=f"AS-REP roastable accounts: {users_list}",
            command=f"nxc ldap {args.target} {auth_hint} --asreproast hashes.txt",
            description="Request AS-REP tickets and export hashes (hashcat -m 18200)",
            priority="high",
        )

        # Store for aggregated copy-paste section
        cache.copy_paste_data["asreproastable_users"].update(
            account["username"] for account in asreproastable
        )
    else:
        # Check for explicit "no entries" message or access denied
        combined = stdout + stderr
        if RE_NO_ENTRIES.search(combined):
            status("No AS-REP roastable accounts found", "success")
        elif "STATUS_ACCESS_DENIED" in combined.upper():
            status("Access denied - cannot query AS-REP roastable accounts", "error")
        elif "STATUS_LOGON_FAILURE" in combined.upper():
            status("Authentication failed - cannot query AS-REP roastable accounts", "error")
        else:
            status("No AS-REP roastable accounts found", "success")

    if args.json_output:
        JSON_DATA["asreproastable"] = asreproastable
