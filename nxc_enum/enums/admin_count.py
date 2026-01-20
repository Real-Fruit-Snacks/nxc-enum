"""AdminCount enumeration."""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

# Regex patterns for parsing verbose --admin-count output
# Format: INFO ... Account: <name> ... MemberOf: <group1>, <group2>, ...
RE_INFO_MEMBEROF = re.compile(
    r"INFO.*?(?:Account|User|Principal):\s*(\S+).*?(?:MemberOf|Groups?):\s*(.+)", re.IGNORECASE
)

# Format: INFO ... <account> ... adminCount set: <timestamp/date>
RE_INFO_ADMINCOUNT_SET = re.compile(
    r"INFO.*?(\S+).*?adminCount\s+(?:set|modified|changed)(?:\s+(?:on|at|:))?\s*(.+)", re.IGNORECASE
)

# Format: INFO ... Account: <name> Type: <user|computer|group>
RE_INFO_ACCOUNT_TYPE = re.compile(
    r"INFO.*?(?:Account|Object):\s*(\S+).*?(?:Type|ObjectClass|Class):\s*(\w+)", re.IGNORECASE
)

# Format for extracting group names from memberOf attribute
# Matches CN=GroupName,... patterns
RE_CN_GROUP = re.compile(r"CN=([^,]+)", re.IGNORECASE)

# Format: INFO ... <account> ... protected by: <group> or inherited from: <group>
RE_INFO_PROTECTED_BY = re.compile(
    r"INFO.*?(\S+).*?(?:protected\s+by|inherited\s+from|via):\s*(.+)", re.IGNORECASE
)

# Format: INFO ... <account> ... Status: <enabled|disabled>
RE_INFO_STATUS = re.compile(r"INFO.*?(\S+).*?Status:\s*(\w+)", re.IGNORECASE)


def _parse_verbose_admin_info(stdout: str) -> dict:
    """Parse verbose INFO lines for additional adminCount details.

    Returns a dict mapping account names to their verbose info:
    - groups: list of group memberships
    - admin_count_set: when adminCount was set
    - account_type: user, computer, or group
    - protected_by: what group caused the adminCount flag
    - status: enabled/disabled
    """
    verbose_info = {}

    for line in stdout.split("\n"):
        line = line.strip()
        if not line or "INFO" not in line:
            continue

        # Parse group membership from INFO lines
        memberof_match = RE_INFO_MEMBEROF.search(line)
        if memberof_match:
            account = memberof_match.group(1).strip()
            groups_raw = memberof_match.group(2).strip()

            if account not in verbose_info:
                verbose_info[account] = {
                    "groups": [],
                    "account_type": None,
                    "admin_count_set": None,
                    "protected_by": None,
                    "status": None,
                }

            # Extract CN values from group DN strings
            cn_matches = RE_CN_GROUP.findall(groups_raw)
            if cn_matches:
                for grp in cn_matches:
                    if grp not in verbose_info[account]["groups"]:
                        verbose_info[account]["groups"].append(grp)
            else:
                # Groups might be comma-separated simple names
                for grp in groups_raw.split(","):
                    grp = grp.strip()
                    if grp and grp not in verbose_info[account]["groups"]:
                        verbose_info[account]["groups"].append(grp)

        # Parse when adminCount was set
        admincount_set_match = RE_INFO_ADMINCOUNT_SET.search(line)
        if admincount_set_match:
            account = admincount_set_match.group(1).strip()
            timestamp = admincount_set_match.group(2).strip()

            if account not in verbose_info:
                verbose_info[account] = {
                    "groups": [],
                    "account_type": None,
                    "admin_count_set": None,
                    "protected_by": None,
                    "status": None,
                }
            verbose_info[account]["admin_count_set"] = timestamp

        # Parse account type (user, computer, group)
        account_type_match = RE_INFO_ACCOUNT_TYPE.search(line)
        if account_type_match:
            account = account_type_match.group(1).strip()
            acct_type = account_type_match.group(2).strip().lower()

            if account not in verbose_info:
                verbose_info[account] = {
                    "groups": [],
                    "account_type": None,
                    "admin_count_set": None,
                    "protected_by": None,
                    "status": None,
                }
            verbose_info[account]["account_type"] = acct_type

        # Parse protected by / inherited from
        protected_match = RE_INFO_PROTECTED_BY.search(line)
        if protected_match:
            account = protected_match.group(1).strip()
            protected_by = protected_match.group(2).strip()

            if account not in verbose_info:
                verbose_info[account] = {
                    "groups": [],
                    "account_type": None,
                    "admin_count_set": None,
                    "protected_by": None,
                    "status": None,
                }
            verbose_info[account]["protected_by"] = protected_by

        # Parse account status
        status_match = RE_INFO_STATUS.search(line)
        if status_match:
            account = status_match.group(1).strip()
            acct_status = status_match.group(2).strip().lower()

            if account not in verbose_info:
                verbose_info[account] = {
                    "groups": [],
                    "account_type": None,
                    "admin_count_set": None,
                    "protected_by": None,
                    "status": None,
                }
            verbose_info[account]["status"] = acct_status

    return verbose_info


def _classify_admin_accounts(accounts: list) -> dict:
    """Classify adminCount accounts by type based on naming conventions.

    Returns dict with 'users', 'computers', 'groups', 'service_accounts'.
    """
    classified = {"users": [], "computers": [], "groups": [], "service_accounts": []}

    for acct in accounts:
        name = acct["name"] if isinstance(acct, dict) else acct
        name_lower = name.lower()

        if name.endswith("$"):
            classified["computers"].append(acct)
        elif any(kw in name_lower for kw in ["svc", "service", "sql", "iis", "app", "backup"]):
            classified["service_accounts"].append(acct)
        elif any(kw in name_lower for kw in ["admin", "operator", "group", "users", "managers"]):
            # Could be group names (often pluralized or contain 'group')
            if any(
                kw in name_lower for kw in ["group", "users", "operators", "admins", "managers"]
            ):
                classified["groups"].append(acct)
            else:
                classified["users"].append(acct)
        else:
            classified["users"].append(acct)

    return classified


def enum_admin_count(args, cache):
    """Find accounts with adminCount attribute."""
    target = cache.target if cache else args.target
    print_section("AdminCount Accounts", target)

    # Skip if LDAP is unavailable (determined during cache priming)
    if not cache.ldap_available:
        status("LDAP unavailable - skipping adminCount enumeration", "error")
        return

    # Try to use batch data first (avoids extra LDAP query if cache was primed)
    batch_accounts = cache.get_admin_count_from_batch()
    if batch_accounts:
        status("Using cached batch data for adminCount accounts...")
        accounts = batch_accounts
        account_details = [
            {
                "name": a,
                "groups": [],
                "account_type": None,
                "admin_count_set": None,
                "protected_by": None,
                "status": None,
            }
            for a in accounts
        ]

        # Store in cache
        cache.admin_count_accounts = accounts
        cache.admin_count_details = account_details

        if accounts:
            status(f"Found {len(accounts)} account(s) with adminCount=1:", "warning")
            output("")

            # Classify and display accounts
            classified = _classify_admin_accounts(account_details)
            has_categories = sum(1 for v in classified.values() if v) > 1

            if has_categories:
                if classified["users"]:
                    output(c(f"  User Accounts ({len(classified['users'])})", Colors.CYAN))
                    for acct in classified["users"]:
                        _print_account_detail(acct)
                if classified["service_accounts"]:
                    svc_count = len(classified["service_accounts"])
                    output(c(f"  Service Accounts ({svc_count})", Colors.YELLOW))
                    for acct in classified["service_accounts"]:
                        _print_account_detail(acct)
                if classified["computers"]:
                    output(c(f"  Computer Accounts ({len(classified['computers'])})", Colors.CYAN))
                    for acct in classified["computers"]:
                        _print_account_detail(acct)
                if classified["groups"]:
                    output(c(f"  Groups ({len(classified['groups'])})", Colors.CYAN))
                    for acct in classified["groups"]:
                        _print_account_detail(acct)
            else:
                for acct in account_details:
                    _print_account_detail(acct)

            output("")
            status(
                "adminCount=1 indicates accounts protected by SDProp. "
                "These have or had Domain Admin-level privileges.",
                "info",
            )
            cache.copy_paste_data["admincount_accounts"].update(a.lower() for a in accounts)
        else:
            status("No accounts with adminCount attribute found", "info")

        if args.json_output:
            JSON_DATA["admin_count"] = {
                "accounts": accounts,
                "details": account_details,
                "summary": {"total": len(accounts)},
            }
        return

    # Fall back to LDAP query if batch data unavailable
    auth = cache.auth_args
    status("Querying accounts with adminCount=1...")

    admin_args = ["ldap", target] + auth + ["--admin-count"]
    rc, stdout, stderr = run_nxc(admin_args, args.timeout)
    debug_nxc(admin_args, stdout, stderr, "AdminCount")

    # Parse verbose INFO lines first to get additional details
    verbose_info = _parse_verbose_admin_info(stdout)

    accounts = []
    account_details = []  # Structured list with verbose data

    for line in stdout.split("\n"):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue

        if "[*]" in line or "[+]" in line or "[!]" in line or "[-]" in line:
            continue
        if "Windows Server" in line:
            continue

        parts = line.split()
        if len(parts) >= 5:
            if parts[0] in ["LDAP", "SMB", "ldap", "smb"]:
                username = parts[-1]
                if username and username not in accounts:
                    if not any(x in username for x in ["[", "]", "(", ")", "="]):
                        if not re.match(r"^\d+\.\d+\.\d+\.\d+", username):
                            accounts.append(username)

                            # Build structured account info
                            acct_info = {
                                "name": username,
                                "groups": [],
                                "account_type": None,
                                "admin_count_set": None,
                                "protected_by": None,
                                "status": None,
                            }

                            # Merge verbose info if available for this account
                            if username in verbose_info:
                                vinfo = verbose_info[username]
                                acct_info["groups"] = vinfo.get("groups", [])
                                acct_info["account_type"] = vinfo.get("account_type")
                                acct_info["admin_count_set"] = vinfo.get("admin_count_set")
                                acct_info["protected_by"] = vinfo.get("protected_by")
                                acct_info["status"] = vinfo.get("status")

                            # Also check for partial matches (domain prefix stripped)
                            for vname, vinfo in verbose_info.items():
                                if vname.lower().endswith("\\" + username.lower()):
                                    if not acct_info["groups"]:
                                        acct_info["groups"] = vinfo.get("groups", [])
                                    if not acct_info["account_type"]:
                                        acct_info["account_type"] = vinfo.get("account_type")
                                    if not acct_info["admin_count_set"]:
                                        acct_info["admin_count_set"] = vinfo.get("admin_count_set")
                                    if not acct_info["protected_by"]:
                                        acct_info["protected_by"] = vinfo.get("protected_by")
                                    if not acct_info["status"]:
                                        acct_info["status"] = vinfo.get("status")
                                    break

                            # Infer account type from name if not in verbose data
                            if not acct_info["account_type"]:
                                if username.endswith("$"):
                                    acct_info["account_type"] = "computer"

                            account_details.append(acct_info)

    # Store both simple list and detailed list in cache
    cache.admin_count_accounts = accounts
    cache.admin_count_details = account_details

    if accounts:
        status(f"Found {len(accounts)} account(s) with adminCount=1:", "warning")
        output("")

        # Classify accounts for organized display
        classified = _classify_admin_accounts(account_details)

        # Print by category if we have multiple types
        has_categories = sum(1 for v in classified.values() if v) > 1

        if has_categories:
            if classified["users"]:
                output(c(f"  User Accounts ({len(classified['users'])})", Colors.CYAN))
                for acct in classified["users"]:
                    _print_account_detail(acct)

            if classified["service_accounts"]:
                output(
                    c(f"  Service Accounts ({len(classified['service_accounts'])})", Colors.YELLOW)
                )
                for acct in classified["service_accounts"]:
                    _print_account_detail(acct)

            if classified["computers"]:
                output(c(f"  Computer Accounts ({len(classified['computers'])})", Colors.CYAN))
                for acct in classified["computers"]:
                    _print_account_detail(acct)

            if classified["groups"]:
                output(c(f"  Groups ({len(classified['groups'])})", Colors.CYAN))
                for acct in classified["groups"]:
                    _print_account_detail(acct)
        else:
            # Simple list if only one category or no classification
            for acct in account_details:
                _print_account_detail(acct)

        output("")
        status(
            "adminCount=1 indicates accounts protected by SDProp. "
            "These have or had Domain Admin-level privileges.",
            "info",
        )

        # Print summary of verbose data if available
        _print_verbose_summary(account_details)

        # Store for aggregated copy-paste section (lowercase for deduplication)
        cache.copy_paste_data["admincount_accounts"].update(a.lower() for a in accounts)
    else:
        status("No accounts with adminCount attribute found", "info")

    if args.json_output:
        JSON_DATA["admin_count"] = {
            "accounts": accounts,
            "details": account_details,
            "summary": {
                "total": len(accounts),
                "users": len(
                    [
                        a
                        for a in account_details
                        if a.get("account_type") == "user"
                        or (not a.get("account_type") and not a["name"].endswith("$"))
                    ]
                ),
                "computers": len(
                    [
                        a
                        for a in account_details
                        if a.get("account_type") == "computer" or a["name"].endswith("$")
                    ]
                ),
                "with_group_info": len([a for a in account_details if a.get("groups")]),
                "disabled": len([a for a in account_details if a.get("status") == "disabled"]),
            },
        }


def _print_account_detail(acct: dict):
    """Print a single account with its verbose details."""
    name = acct["name"]
    status_indicator = ""
    if acct.get("status") == "disabled":
        status_indicator = c(" [DISABLED]", Colors.RED)
    elif acct.get("status") == "enabled":
        status_indicator = c(" [enabled]", Colors.GREEN)

    output(f"    {c(name, Colors.YELLOW)}{status_indicator}")

    # Show protected by / inherited from if available
    if acct.get("protected_by"):
        output(f"      Protected by: {c(acct['protected_by'], Colors.CYAN)}")

    # Show group memberships if available (limit to first few)
    if acct.get("groups"):
        groups_display = acct["groups"][:5]
        groups_str = ", ".join(groups_display)
        if len(acct["groups"]) > 5:
            groups_str += f" (+{len(acct['groups']) - 5} more)"
        output(f"      Member of: {c(groups_str, Colors.CYAN)}")

    # Show when adminCount was set if available
    if acct.get("admin_count_set"):
        output(f"      adminCount set: {acct['admin_count_set']}")


def _print_verbose_summary(account_details: list):
    """Print a summary of notable findings from verbose data."""
    disabled_accounts = [a["name"] for a in account_details if a.get("status") == "disabled"]
    accounts_with_groups = [a for a in account_details if a.get("groups")]

    if not disabled_accounts and not accounts_with_groups:
        return

    output("")
    output(c("Verbose Data Summary:", Colors.CYAN))

    if disabled_accounts:
        disabled_str = ", ".join(disabled_accounts[:5])
        if len(disabled_accounts) > 5:
            disabled_str += f" (+{len(disabled_accounts) - 5} more)"
        output(f"  Disabled accounts with adminCount: {c(disabled_str, Colors.RED)}")
        output(c("  (May indicate orphaned privileged accounts)", Colors.CYAN))

    # Find accounts in notable privileged groups
    privileged_groups = [
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "Schema Admins",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
    ]

    for acct in accounts_with_groups:
        notable_groups = [
            g
            for g in acct.get("groups", [])
            if any(pg.lower() in g.lower() for pg in privileged_groups)
        ]
        if notable_groups:
            groups_str = ", ".join(notable_groups)
            output(f"  {c(acct['name'], Colors.YELLOW)}: {c(groups_str, Colors.RED)}")
