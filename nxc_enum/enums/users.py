"""User enumeration."""

import re

from ..core.colors import Colors, c
from ..core.constants import HIGH_BADPWD_THRESHOLD, RE_RID_USER
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.classify import classify_users, safe_int

# Regex patterns for verbose --users output parsing
# Format: DOMAIN\username badpwdcount: N baddpwdtime: TIMESTAMP pwdlast: TIMESTAMP lastlogon: TIMESTAMP
RE_BADPWDCOUNT = re.compile(r"badpwdcount:\s*(\d+)", re.IGNORECASE)
RE_BADDPWDTIME = re.compile(r"baddpwdtime:\s*(\S+)", re.IGNORECASE)
RE_PWDLAST = re.compile(r"pwdlast:\s*(\S+)", re.IGNORECASE)
RE_LASTLOGON = re.compile(r"lastlogon:\s*(\S+)", re.IGNORECASE)

# Regex patterns for INFO lines with user attributes (verbose mode)
# Format: INFO <IP> User: <username> Attributes: <attr1>, <attr2>, ...
RE_INFO_USER_ATTRS = re.compile(r"INFO.*User:\s*(\S+)\s+Attributes?:\s*(.+)", re.IGNORECASE)
# Format: INFO <IP> <username> - Status: <status>
RE_INFO_USER_STATUS = re.compile(r"INFO.*?(\S+\\)?(\S+)\s+-\s+Status:\s*(.+)", re.IGNORECASE)
# Format: INFO <IP> Account <username>: <details>
RE_INFO_ACCOUNT = re.compile(r"INFO.*Account\s+(\S+):\s*(.+)", re.IGNORECASE)


def parse_verbose_user_line(line: str) -> dict:
    """Parse verbose user data from a line containing extended attributes.

    Returns dict with any of: badpwdcount, baddpwdtime, pwdlast, lastlogon
    """
    attrs = {}

    badpwd_match = RE_BADPWDCOUNT.search(line)
    if badpwd_match:
        attrs["badpwdcount"] = int(badpwd_match.group(1))

    baddtime_match = RE_BADDPWDTIME.search(line)
    if baddtime_match:
        attrs["baddpwdtime"] = baddtime_match.group(1)

    pwdlast_match = RE_PWDLAST.search(line)
    if pwdlast_match:
        attrs["pwdlast"] = pwdlast_match.group(1)

    lastlogon_match = RE_LASTLOGON.search(line)
    if lastlogon_match:
        attrs["lastlogon"] = lastlogon_match.group(1)

    return attrs


def parse_info_lines(stdout: str, users: dict) -> dict:
    """Parse INFO lines from verbose output for additional user attributes.

    Updates users dict in place with attributes, status info.
    Returns dict of accounts with notable status (disabled, locked, etc.)
    """
    notable_accounts = {
        "disabled": [],
        "locked": [],
        "pwd_never_expires": [],
        "pwd_not_required": [],
        "never_logged_on": [],
    }

    for line in stdout.split("\n"):
        line = line.strip()
        if not line or "INFO" not in line:
            continue

        # Parse user attributes from INFO lines
        attrs_match = RE_INFO_USER_ATTRS.search(line)
        if attrs_match:
            username = attrs_match.group(1)
            attributes = attrs_match.group(2).lower()

            # Find matching user (may have domain prefix stripped)
            for uname in users:
                if uname.lower() == username.lower() or username.lower().endswith(
                    "\\" + uname.lower()
                ):
                    if "attributes" not in users[uname]:
                        users[uname]["attributes"] = []
                    users[uname]["attributes"].extend([a.strip() for a in attributes.split(",")])
                    break

        # Parse user status from INFO lines
        status_match = RE_INFO_USER_STATUS.search(line)
        if status_match:
            username = status_match.group(2)
            status_info = status_match.group(3).lower()

            for uname in users:
                if uname.lower() == username.lower():
                    users[uname]["status"] = status_info

                    # Categorize notable status
                    if "disabled" in status_info:
                        notable_accounts["disabled"].append(uname)
                    if "locked" in status_info:
                        notable_accounts["locked"].append(uname)
                    if "never expires" in status_info or "dont_expire" in status_info:
                        notable_accounts["pwd_never_expires"].append(uname)
                    if "not required" in status_info or "passwd_notreqd" in status_info:
                        notable_accounts["pwd_not_required"].append(uname)
                    break

        # Parse account info from INFO lines
        account_match = RE_INFO_ACCOUNT.search(line)
        if account_match:
            username = account_match.group(1)
            details = account_match.group(2).lower()

            for uname in users:
                if uname.lower() == username.lower():
                    if "account_info" not in users[uname]:
                        users[uname]["account_info"] = details
                    break

    return notable_accounts


def enum_users(args, cache):
    """Enumerate domain users."""
    print_section("Users via RPC", args.target)

    auth = cache.auth_args

    # First try --users for basic enumeration
    status("Enumerating users via 'querydispinfo'")
    users_args = ["smb", args.target] + auth + ["--users"]
    rc, stdout, stderr = run_nxc(users_args, args.timeout)
    debug_nxc(users_args, stdout, stderr, "Users (querydispinfo)")

    users = {}
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue
        if "-Username-" in line or "[*]" in line or "[+]" in line or "[-]" in line:
            continue
        if "Windows Server" in line:
            continue

        # Parse lines that start with SMB or LDAP (protocol indicator)
        if line.startswith("SMB") or line.startswith("LDAP"):
            parts = line.split()
            # Find port index (445, 139, 389, 636)
            port_idx = -1
            for i, p in enumerate(parts):
                if p in ("445", "139", "389", "636"):
                    port_idx = i
                    break
            if port_idx >= 0 and port_idx + 2 < len(parts):
                # After port is hostname, then the user data
                user_data = parts[port_idx + 2 :]
                if len(user_data) >= 3:
                    username = user_data[0]
                    if username.startswith("[") or username.startswith("-"):
                        continue
                    desc = ""
                    if len(user_data) >= 5:
                        desc = " ".join(user_data[4:])
                    elif len(user_data) == 4:
                        desc = user_data[3] if not user_data[3].isdigit() else ""

                    if username and not username.startswith("["):
                        users[username] = {
                            "name": "(null)",
                            "description": desc.strip() if desc else "(null)",
                        }

                        # Parse verbose attributes from the same line
                        verbose_attrs = parse_verbose_user_line(line)
                        if verbose_attrs:
                            users[username].update(verbose_attrs)

    # Use cached RID brute results
    status("Enumerating users via 'enumdomusers'")
    rc2, stdout2, stderr2 = cache.get_rid_brute(args.target, auth)

    # Parse RID output using pre-compiled regex
    for line in stdout2.split("\n"):
        rid_match = RE_RID_USER.search(line)
        if rid_match:
            rid = rid_match.group(1)
            username = rid_match.group(2)
            if username not in users:
                users[username] = {"name": "(null)", "description": "(null)"}
            users[username]["rid"] = rid

    # Parse verbose INFO lines for additional user attributes
    notable_accounts = parse_info_lines(stdout, users)

    # Also check RID brute output for verbose data
    notable_from_rid = parse_info_lines(stdout2, users)
    for key in notable_accounts:
        notable_accounts[key].extend(notable_from_rid.get(key, []))

    if users:
        status(f"Found {len(users)} user(s) total", "success")
        cache.user_count = len(users)

        # Store notable accounts in cache for reporting
        cache.disabled_accounts = list(set(notable_accounts.get("disabled", [])))
        cache.locked_accounts = list(set(notable_accounts.get("locked", [])))
        cache.pwd_never_expires_accounts = list(set(notable_accounts.get("pwd_never_expires", [])))

        # Track users with high bad password counts (possible attack targets or spray victims)
        high_badpwd = [
            (u, info.get("badpwdcount", 0))
            for u, info in users.items()
            if info.get("badpwdcount", 0) > 0
        ]
        if high_badpwd:
            cache.high_badpwd_users = sorted(high_badpwd, key=lambda x: x[1], reverse=True)

        # Track users who have never logged on (potential honeypots or unused accounts)
        never_logged = [
            u
            for u, info in users.items()
            if info.get("lastlogon") in ("0", "never", "Never", None)
            or "never" in str(info.get("lastlogon", "")).lower()
        ]
        if never_logged:
            cache.never_logged_users = never_logged

        categories = classify_users(users)
        cache.service_accounts = [u for u, _ in categories["service"]]

        def print_user_table(title: str, user_list: list, highlight_color=None):
            if not user_list:
                return
            output("")
            title_text = f"{title} ({len(user_list)})"
            if highlight_color:
                output(c(title_text, highlight_color))
            else:
                output(c(title_text, Colors.CYAN))
            output(f"{'RID':<6}  {'Username':<22}  {'Description'}")
            output(f"{'-'*6}  {'-'*22}  {'-'*40}")
            for username, info in user_list:
                rid = info.get("rid", "???")
                desc = info.get("description", "(null)")
                if desc == "(null)":
                    desc = ""
                if len(desc) > 40:
                    desc = desc[:37] + "..."
                padded_username = username[:22].ljust(22)
                if highlight_color:
                    output(f"{rid:<6}  {c(padded_username, highlight_color)}  {desc}")
                else:
                    output(f"{rid:<6}  {padded_username}  {desc}")

        # Print each category
        print_user_table("Built-in Accounts", categories["builtin"])
        print_user_table("Service Accounts", categories["service"], Colors.YELLOW)
        print_user_table("Computer Accounts", categories["computer"])
        print_user_table("Domain Users", categories["domain"])

        # Print notable account status from verbose output
        _print_notable_accounts(notable_accounts, users)

        if args.json_output:
            sorted_users = sorted(users.items(), key=lambda x: safe_int(x[1].get("rid", "9999")))
            JSON_DATA["users"] = {u: v for u, v in sorted_users}
            # Add verbose data to JSON
            JSON_DATA["user_status"] = {
                "disabled": notable_accounts.get("disabled", []),
                "locked": notable_accounts.get("locked", []),
                "pwd_never_expires": notable_accounts.get("pwd_never_expires", []),
                "pwd_not_required": notable_accounts.get("pwd_not_required", []),
            }
    else:
        status("No users found or unable to parse output", "warning")
        for line in stdout.split("\n"):
            if line.strip() and "\\" in line:
                output(f"  {line.strip()}")


def _print_notable_accounts(notable_accounts: dict, users: dict):
    """Print notable account status information from verbose output."""
    has_notable = any(notable_accounts.values())
    if not has_notable:
        return

    output("")
    output(c("Account Status (from verbose output)", Colors.CYAN))
    output(f"{'-'*50}")

    if notable_accounts.get("disabled"):
        disabled_list = ", ".join(notable_accounts["disabled"][:10])
        if len(notable_accounts["disabled"]) > 10:
            disabled_list += f" (+{len(notable_accounts['disabled']) - 10} more)"
        output(f"  Disabled accounts: {disabled_list}")

    if notable_accounts.get("locked"):
        locked_list = ", ".join(notable_accounts["locked"])
        status(f"Locked accounts: {c(locked_list, Colors.YELLOW)}", "warning")

    if notable_accounts.get("pwd_never_expires"):
        pne_list = ", ".join(notable_accounts["pwd_never_expires"][:10])
        if len(notable_accounts["pwd_never_expires"]) > 10:
            pne_list += f" (+{len(notable_accounts['pwd_never_expires']) - 10} more)"
        output(f"  Password never expires: {c(pne_list, Colors.YELLOW)}")

    if notable_accounts.get("pwd_not_required"):
        pnr_list = ", ".join(notable_accounts["pwd_not_required"])
        status(f"Password not required: {c(pnr_list, Colors.RED)}", "warning")

    # Show users with high bad password count
    high_badpwd = [
        (u, info.get("badpwdcount", 0))
        for u, info in users.items()
        if info.get("badpwdcount", 0) >= HIGH_BADPWD_THRESHOLD
    ]
    if high_badpwd:
        high_badpwd.sort(key=lambda x: x[1], reverse=True)
        badpwd_info = ", ".join([f"{u}({cnt})" for u, cnt in high_badpwd[:5]])
        if len(high_badpwd) > 5:
            badpwd_info += f" (+{len(high_badpwd) - 5} more)"
        output(f"  High bad password count: {c(badpwd_info, Colors.YELLOW)}")
