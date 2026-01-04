"""Password not required enumeration."""

import re
from ..core.runner import run_nxc
from ..core.output import output, status, print_section, debug_nxc, JSON_DATA
from ..core.colors import Colors, c
from ..parsing.nxc_output import is_nxc_noise_line

# Regex patterns for parsing verbose --password-not-required output
# User and status from main output line
RE_USER_STATUS = re.compile(r'User:\s*(\S+)(?:\s+Status:\s*(.+))?', re.IGNORECASE)

# UAC flags from verbose INFO lines
# Format: INFO <IP> User <username>: userAccountControl=<value>
RE_UAC_INFO = re.compile(r'INFO.*(?:User|Account)\s+(\S+):\s*userAccountControl[=:]\s*(\d+)', re.IGNORECASE)
# Format: INFO <IP> <username> UAC: <flags> or UAC flags: <flags>
RE_UAC_FLAGS = re.compile(r'INFO.*?(\S+)\s+(?:UAC|userAccountControl)(?:\s+flags)?[=:]?\s*(.+)', re.IGNORECASE)

# Account status from INFO lines
# Format: INFO <IP> <username> - Status: enabled/disabled
RE_INFO_STATUS = re.compile(r'INFO.*?(\S+)\s+-\s+Status:\s*(\S+)', re.IGNORECASE)
# Format: INFO <IP> Account <username> is disabled/enabled
RE_ACCOUNT_STATE = re.compile(r'INFO.*Account\s+(\S+)\s+is\s+(disabled|enabled)', re.IGNORECASE)

# Timestamp fields from verbose output
# Format: pwdLastSet: <timestamp> or whenChanged: <timestamp>
RE_PWD_LAST_SET = re.compile(r'pwdLastSet[=:]\s*(\S+)', re.IGNORECASE)
RE_WHEN_CHANGED = re.compile(r'whenChanged[=:]\s*(\S+)', re.IGNORECASE)
RE_WHEN_CREATED = re.compile(r'whenCreated[=:]\s*(\S+)', re.IGNORECASE)
RE_LAST_LOGON = re.compile(r'lastLogon[=:]\s*(\S+)', re.IGNORECASE)

# Additional account attributes
RE_SAM_ACCOUNT = re.compile(r'sAMAccountName[=:]\s*(\S+)', re.IGNORECASE)
RE_DESCRIPTION = re.compile(r'description[=:]\s*(.+?)(?:\s+\w+[=:]|$)', re.IGNORECASE)

# Known UAC flag values for PASSWD_NOTREQD context
UAC_FLAGS = {
    0x0001: 'SCRIPT',
    0x0002: 'ACCOUNTDISABLE',
    0x0008: 'HOMEDIR_REQUIRED',
    0x0010: 'LOCKOUT',
    0x0020: 'PASSWD_NOTREQD',  # Primary flag we're looking for
    0x0040: 'PASSWD_CANT_CHANGE',
    0x0080: 'ENCRYPTED_TEXT_PWD_ALLOWED',
    0x0100: 'TEMP_DUPLICATE_ACCOUNT',
    0x0200: 'NORMAL_ACCOUNT',
    0x0800: 'INTERDOMAIN_TRUST_ACCOUNT',
    0x1000: 'WORKSTATION_TRUST_ACCOUNT',
    0x2000: 'SERVER_TRUST_ACCOUNT',
    0x10000: 'DONT_EXPIRE_PASSWORD',
    0x20000: 'MNS_LOGON_ACCOUNT',
    0x40000: 'SMARTCARD_REQUIRED',
    0x80000: 'TRUSTED_FOR_DELEGATION',
    0x100000: 'NOT_DELEGATED',
    0x200000: 'USE_DES_KEY_ONLY',
    0x400000: 'DONT_REQ_PREAUTH',
    0x800000: 'PASSWORD_EXPIRED',
    0x1000000: 'TRUSTED_TO_AUTH_FOR_DELEGATION',
    0x4000000: 'PARTIAL_SECRETS_ACCOUNT',
}


def decode_uac_flags(uac_value: int) -> list:
    """Decode UAC integer value into list of flag names."""
    flags = []
    for flag_val, flag_name in UAC_FLAGS.items():
        if uac_value & flag_val:
            flags.append(flag_name)
    return flags


def parse_verbose_info(stdout: str) -> dict:
    """Parse verbose INFO lines for additional account details.

    Returns dict mapping usernames to their verbose attributes:
    - uac_value: raw UAC integer
    - uac_flags: decoded flag names
    - is_disabled: boolean
    - pwd_last_set: timestamp
    - when_changed: timestamp
    - when_created: timestamp
    - last_logon: timestamp
    - description: account description
    """
    accounts_info = {}

    for line in stdout.split('\n'):
        line = line.strip()
        if not line:
            continue

        current_user = None

        # Parse UAC value from INFO lines
        uac_match = RE_UAC_INFO.search(line)
        if uac_match:
            username = uac_match.group(1)
            try:
                uac_value = int(uac_match.group(2))
                if username not in accounts_info:
                    accounts_info[username] = {}
                accounts_info[username]['uac_value'] = uac_value
                accounts_info[username]['uac_flags'] = decode_uac_flags(uac_value)
                accounts_info[username]['is_disabled'] = bool(uac_value & 0x0002)
                current_user = username
            except ValueError:
                pass

        # Parse UAC flags string from INFO lines
        uac_flags_match = RE_UAC_FLAGS.search(line)
        if uac_flags_match and 'INFO' in line:
            username = uac_flags_match.group(1)
            flags_str = uac_flags_match.group(2).strip()
            # Only process if it looks like flags (not a number we already handled)
            if not flags_str.isdigit() and username:
                if username not in accounts_info:
                    accounts_info[username] = {}
                # Parse comma or space separated flags
                flags = [f.strip() for f in re.split(r'[,\s]+', flags_str) if f.strip()]
                if 'uac_flags' not in accounts_info[username]:
                    accounts_info[username]['uac_flags'] = []
                accounts_info[username]['uac_flags'].extend(flags)
                current_user = username

        # Parse account enabled/disabled status
        status_match = RE_INFO_STATUS.search(line)
        if status_match:
            username = status_match.group(1)
            status_val = status_match.group(2).lower()
            if username not in accounts_info:
                accounts_info[username] = {}
            accounts_info[username]['is_disabled'] = 'disabled' in status_val
            accounts_info[username]['status_text'] = status_val

        state_match = RE_ACCOUNT_STATE.search(line)
        if state_match:
            username = state_match.group(1)
            state = state_match.group(2).lower()
            if username not in accounts_info:
                accounts_info[username] = {}
            accounts_info[username]['is_disabled'] = state == 'disabled'

        # Parse timestamps - these may appear on main output or INFO lines
        # Try to associate with current user context or last seen user
        pwd_set_match = RE_PWD_LAST_SET.search(line)
        if pwd_set_match:
            timestamp = pwd_set_match.group(1)
            # Find associated user in this line
            user_match = RE_USER_STATUS.search(line) or RE_SAM_ACCOUNT.search(line)
            if user_match:
                username = user_match.group(1)
                if username not in accounts_info:
                    accounts_info[username] = {}
                accounts_info[username]['pwd_last_set'] = timestamp

        when_changed_match = RE_WHEN_CHANGED.search(line)
        if when_changed_match:
            timestamp = when_changed_match.group(1)
            user_match = RE_USER_STATUS.search(line) or RE_SAM_ACCOUNT.search(line)
            if user_match:
                username = user_match.group(1)
                if username not in accounts_info:
                    accounts_info[username] = {}
                accounts_info[username]['when_changed'] = timestamp

        when_created_match = RE_WHEN_CREATED.search(line)
        if when_created_match:
            timestamp = when_created_match.group(1)
            user_match = RE_USER_STATUS.search(line) or RE_SAM_ACCOUNT.search(line)
            if user_match:
                username = user_match.group(1)
                if username not in accounts_info:
                    accounts_info[username] = {}
                accounts_info[username]['when_created'] = timestamp

        last_logon_match = RE_LAST_LOGON.search(line)
        if last_logon_match:
            timestamp = last_logon_match.group(1)
            user_match = RE_USER_STATUS.search(line) or RE_SAM_ACCOUNT.search(line)
            if user_match:
                username = user_match.group(1)
                if username not in accounts_info:
                    accounts_info[username] = {}
                accounts_info[username]['last_logon'] = timestamp

        # Parse description
        desc_match = RE_DESCRIPTION.search(line)
        if desc_match:
            description = desc_match.group(1).strip()
            user_match = RE_USER_STATUS.search(line) or RE_SAM_ACCOUNT.search(line)
            if user_match:
                username = user_match.group(1)
                if username not in accounts_info:
                    accounts_info[username] = {}
                accounts_info[username]['description'] = description

    return accounts_info


def enum_pwd_not_required(args, cache):
    """Find accounts without password requirement."""
    print_section("Password Not Required", args.target)

    auth = cache.auth_args
    status("Querying accounts with PASSWD_NOTREQD flag...")

    pwd_args = ["ldap", args.target] + auth + ["--password-not-required"]
    rc, stdout, stderr = run_nxc(pwd_args, args.timeout)
    debug_nxc(pwd_args, stdout, stderr, "Password Not Required")

    # Parse verbose INFO lines for additional account details
    verbose_info = parse_verbose_info(stdout)

    # Parse main output for accounts
    accounts = []
    accounts_detailed = []  # Structured account data for cache/JSON

    for line in stdout.split('\n'):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue

        if '[*]' in line or '[+]' in line or '[-]' in line:
            continue

        if 'User:' in line:
            user_match = RE_USER_STATUS.search(line)
            if user_match:
                username = user_match.group(1)
                status_val = user_match.group(2).strip() if user_match.group(2) else None

                # Check if already processed
                existing_names = [a['username'] for a in accounts_detailed]
                if username and username not in existing_names:
                    # Build account entry with verbose data
                    account_data = {
                        'username': username,
                        'status': status_val,
                        # Set is_disabled from status field (e.g., "disabled")
                        'is_disabled': status_val and 'disabled' in status_val.lower() if status_val else False,
                    }

                    # Merge verbose info if available (may override is_disabled)
                    if username in verbose_info:
                        account_data.update(verbose_info[username])

                    accounts_detailed.append(account_data)

                    # Build display string
                    display = username
                    if status_val:
                        display += f" ({status_val})"
                    accounts.append(display)

    # Store both simple list and detailed data in cache
    cache.pwd_not_required = accounts
    cache.pwd_not_required_details = accounts_detailed

    if accounts_detailed:
        # Separate enabled and disabled accounts for reporting
        enabled_accounts = [a for a in accounts_detailed if not a.get('is_disabled', False)]
        disabled_accounts = [a for a in accounts_detailed if a.get('is_disabled', False)]

        status(f"Found {len(accounts_detailed)} account(s) with PASSWD_NOTREQD flag:", "warning")
        output("")

        # Show enabled accounts first (higher risk)
        if enabled_accounts:
            output(c("  Enabled Accounts (HIGH RISK):", Colors.RED))
            for account in enabled_accounts:
                username = account['username']
                output(f"    {c(username, Colors.RED)}")

                # Show UAC flags if available
                if account.get('uac_flags'):
                    flags_str = ', '.join(account['uac_flags'][:5])
                    if len(account['uac_flags']) > 5:
                        flags_str += f" (+{len(account['uac_flags']) - 5} more)"
                    output(f"      UAC Flags: {c(flags_str, Colors.CYAN)}")

                # Show timestamps if available
                if account.get('pwd_last_set'):
                    output(f"      Password Last Set: {account['pwd_last_set']}")
                if account.get('when_changed'):
                    output(f"      When Changed: {account['when_changed']}")
                if account.get('last_logon'):
                    output(f"      Last Logon: {account['last_logon']}")

                # Show description if available
                if account.get('description'):
                    output(f"      Description: {account['description']}")

            output("")

        # Show disabled accounts (lower risk but still notable)
        if disabled_accounts:
            output(c("  Disabled Accounts:", Colors.YELLOW))
            for account in disabled_accounts:
                username = account['username']
                output(f"    {c(username, Colors.YELLOW)} (disabled)")

                # Show UAC flags if available
                if account.get('uac_flags'):
                    flags_str = ', '.join(account['uac_flags'][:5])
                    if len(account['uac_flags']) > 5:
                        flags_str += f" (+{len(account['uac_flags']) - 5} more)"
                    output(f"      UAC Flags: {c(flags_str, Colors.CYAN)}")

            output("")

        # Add next step recommendation for enabled accounts
        if enabled_accounts:
            enabled_names = [a['username'] for a in enabled_accounts[:3]]
            names_str = ', '.join(enabled_names)
            if len(enabled_accounts) > 3:
                names_str += f" (+{len(enabled_accounts) - 3} more)"

            # Build auth hint for command
            auth_hint = f"-u '{args.user}'" if args.user else "-u <user>"
            if args.password:
                auth_hint += f" -p '{args.password}'"
            elif args.hash:
                auth_hint += f" -H '{args.hash}'"
            else:
                auth_hint += " -p '<password>'"

            cache.add_next_step(
                finding=f"PASSWD_NOTREQD accounts: {names_str}",
                command=f"nxc smb {args.target} -u '{enabled_names[0]}' -p ''",
                description="Try empty password authentication for accounts with PASSWD_NOTREQD",
                priority="high"
            )

        # Summary of UAC flags found
        all_flags = set()
        for account in accounts_detailed:
            all_flags.update(account.get('uac_flags', []))

        if all_flags:
            notable_flags = all_flags - {'PASSWD_NOTREQD', 'NORMAL_ACCOUNT'}
            if notable_flags:
                output(c("  Notable UAC Flags Found:", Colors.CYAN))
                for flag in sorted(notable_flags):
                    output(f"    - {flag}")

    else:
        status("No accounts with PASSWD_NOTREQD flag found", "success")

    if args.json_output:
        JSON_DATA['password_not_required'] = {
            'accounts': accounts_detailed,
            'summary': {
                'total': len(accounts_detailed),
                'enabled': len([a for a in accounts_detailed if not a.get('is_disabled', False)]),
                'disabled': len([a for a in accounts_detailed if a.get('is_disabled', False)]),
            }
        }
