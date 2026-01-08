"""gMSA (Group Managed Service Account) enumeration.

This module enumerates gMSA accounts and checks if the current user can
read the msDS-ManagedPassword attribute to retrieve passwords.

This is pure LDAP enumeration - queries the msDS-GroupMSAMembership and
msDS-ManagedPassword attributes from Active Directory.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

# LDAP filter for gMSA accounts
GMSA_FILTER = "(objectClass=msDS-GroupManagedServiceAccount)"

# Regex patterns
RE_CN = re.compile(r"CN=([^,]+)", re.IGNORECASE)
RE_SAM = re.compile(r"sAMAccountName:\s*(\S+)", re.IGNORECASE)


def enum_gmsa(args, cache):
    """Enumerate gMSA accounts and check password readability.

    gMSA accounts use automatically rotated passwords managed by AD.
    If we can read msDS-ManagedPassword, we can extract the password.
    """
    target = cache.target if cache else args.target
    print_section("gMSA Account Enumeration", target)

    # Skip if LDAP is unavailable (determined during cache priming)
    if not cache.ldap_available:
        status("LDAP unavailable - skipping gMSA enumeration", "error")
        return

    auth = cache.auth_args
    status("Querying for gMSA accounts...")

    # Try to use batch data first (populated during cache priming)
    batch_data = cache.get_gmsa_accounts_from_batch()
    if batch_data is not None:
        # Use pre-fetched batch data - much faster
        gmsa_accounts = batch_data
        rc, stdout, stderr = 0, "", ""  # No individual query needed
    else:
        # Fall back to individual query
        # Query for gMSA accounts
        query_args = (
            ["ldap", target]
            + auth
            + [
                "--query",
                GMSA_FILTER,
                "cn,sAMAccountName,msDS-ManagedPasswordId,msDS-GroupMSAMembership",
            ]
        )
        rc, stdout, stderr = run_nxc(query_args, args.timeout)
        debug_nxc(query_args, stdout, stderr, "gMSA Query")

        gmsa_accounts = []
        current_account = None

        # Parse output for gMSA accounts
        for line in stdout.split("\n"):
            line = line.strip()
            if not line:
                continue

            if is_nxc_noise_line(line):
                continue

            # Look for "Response for object: CN=accountname,..."
            if "Response for object:" in line and "CN=" in line:
                cn_match = RE_CN.search(line)
                if cn_match:
                    current_account = {
                        "name": cn_match.group(1),
                        "sam": None,
                        "has_password_id": False,
                    }
                continue

            # Get sAMAccountName
            sam_match = RE_SAM.search(line)
            if sam_match and current_account:
                current_account["sam"] = sam_match.group(1)

            # Check for msDS-ManagedPasswordId (indicates gMSA is configured)
            if current_account and "msDS-ManagedPasswordId" in line:
                current_account["has_password_id"] = True
                # Save account when we've parsed enough
                if current_account not in gmsa_accounts:
                    gmsa_accounts.append(current_account)
                current_account = None

        # Also check LDAP line format
        for line in stdout.split("\n"):
            if "msDS-GroupManagedServiceAccount" in line:
                # Parse account name from line
                parts = line.split()
                for part in parts:
                    if part.endswith("$"):
                        account_name = part.rstrip("$")
                        if not any(a["name"] == account_name for a in gmsa_accounts):
                            gmsa_accounts.append(
                                {
                                    "name": account_name,
                                    "sam": part,
                                    "has_password_id": True,
                                }
                            )

    # Check if we got access denied or LDAP failed (only for individual query path)
    combined = stdout + stderr
    access_denied = "STATUS_ACCESS_DENIED" in combined.upper()
    no_entries = "No entries found" in combined or "0 entries" in combined
    ldap_failed = (
        "Failed to create connection" in combined
        or "Failed to connect" in combined.lower()
        or "ldap connection failed" in combined.lower()
    )

    # Store in cache
    cache.gmsa_accounts = gmsa_accounts
    cache.gmsa_readable = False  # Will check below

    if gmsa_accounts:
        status(f"Found {len(gmsa_accounts)} gMSA account(s)", "success")
        output("")

        output(c("gMSA ACCOUNTS", Colors.CYAN))
        output(f"{'Account Name':<30} {'sAMAccountName':<35} {'Status'}")
        output(f"{'-'*30} {'-'*35} {'-'*20}")

        for account in sorted(gmsa_accounts, key=lambda x: x["name"]):
            sam = account.get("sam") or f"{account['name']}$"
            output(f"{account['name']:<30} {sam:<35} gMSA Configured")

        output("")

        # Try to read actual password (nxc ldap --gmsa)
        status("Checking if passwords are readable...")
        gmsa_args = ["ldap", target] + auth + ["-M", "laps"]  # --gmsa in newer versions
        rc_pwd, stdout_pwd, stderr_pwd = run_nxc(gmsa_args, args.timeout)
        debug_nxc(gmsa_args, stdout_pwd, stderr_pwd, "gMSA Password Read")

        # Check if we could read passwords
        if "msDS-ManagedPassword" in stdout_pwd or "GMSA" in stdout_pwd.upper():
            if "ACCESS_DENIED" not in stdout_pwd.upper():
                cache.gmsa_readable = True
                output(
                    c(
                        "[!] Current user CAN read gMSA passwords!",
                        Colors.RED + Colors.BOLD,
                    )
                )
                output(
                    c(
                        "    gMSA passwords can be used for authentication",
                        Colors.RED,
                    )
                )
                output("")

                # Build auth hint
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

                cache.add_next_step(
                    finding=f"gMSA readable ({len(gmsa_accounts)} accounts)",
                    command=f"nxc ldap {target} {auth_hint} --gmsa",
                    description="Retrieve gMSA passwords for service account access",
                    priority="high",
                )
        else:
            output(
                c(
                    "[*] gMSA accounts found but passwords not readable",
                    Colors.YELLOW,
                )
            )
            output(
                c(
                    "    Need to be in msDS-GroupMSAMembership to read",
                    Colors.YELLOW,
                )
            )
            output("")

        # Store for copy-paste
        cache.copy_paste_data["gmsa_accounts"] = {
            a.get("sam") or f"{a['name']}$" for a in gmsa_accounts
        }

    elif ldap_failed:
        status("LDAP unavailable - cannot check gMSA accounts", "error")
    elif access_denied:
        status("Access denied querying gMSA accounts", "warning")
    elif no_entries:
        status("No gMSA accounts found in domain", "info")
    else:
        if not stdout.strip() or rc != 0:
            status("Could not query gMSA accounts", "error")
        else:
            status("No gMSA accounts found in domain", "info")

    if args.json_output:
        JSON_DATA["gmsa"] = {
            "accounts": [
                {"name": a["name"], "sam": a.get("sam")} for a in gmsa_accounts
            ],
            "readable": cache.gmsa_readable,
            "count": len(gmsa_accounts),
        }
