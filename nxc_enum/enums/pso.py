"""Fine-Grained Password Policy (PSO) enumeration.

This module enumerates Password Settings Objects (PSOs) which define
fine-grained password policies that can override the domain default.

This is pure LDAP enumeration - queries the Password Settings Container.
No command execution on the target.

Pentest value: Identifies groups with weaker password requirements.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

# LDAP filter for PSO objects
PSO_FILTER = "(objectClass=msDS-PasswordSettings)"

# Regex patterns for PSO attributes
RE_CN = re.compile(r"CN=([^,]+)", re.IGNORECASE)
RE_PRECEDENCE = re.compile(r"msDS-PasswordSettingsPrecedence:\s*(\d+)", re.IGNORECASE)
RE_MIN_LENGTH = re.compile(r"msDS-MinimumPasswordLength:\s*(\d+)", re.IGNORECASE)
RE_MIN_AGE = re.compile(r"msDS-MinimumPasswordAge:\s*([^\n]+)", re.IGNORECASE)
RE_MAX_AGE = re.compile(r"msDS-MaximumPasswordAge:\s*([^\n]+)", re.IGNORECASE)
RE_HISTORY = re.compile(r"msDS-PasswordHistoryLength:\s*(\d+)", re.IGNORECASE)
RE_COMPLEXITY = re.compile(r"msDS-PasswordComplexityEnabled:\s*(\w+)", re.IGNORECASE)
RE_REVERSIBLE = re.compile(r"msDS-PasswordReversibleEncryptionEnabled:\s*(\w+)", re.IGNORECASE)
RE_LOCKOUT_THRESHOLD = re.compile(r"msDS-LockoutThreshold:\s*(\d+)", re.IGNORECASE)
RE_LOCKOUT_DURATION = re.compile(r"msDS-LockoutDuration:\s*([^\n]+)", re.IGNORECASE)
RE_APPLIES_TO = re.compile(r"msDS-PSOAppliesTo:\s*(.+)", re.IGNORECASE)


def parse_ad_timespan(value: str) -> str:
    """Parse AD timespan format to human-readable string."""
    # AD stores timespan as negative 100-nanosecond intervals
    # e.g., -864000000000 = 1 day
    try:
        value = value.strip()
        if value.startswith("-"):
            ticks = abs(int(value))
            seconds = ticks / 10000000
            if seconds >= 86400:
                days = seconds / 86400
                return f"{days:.0f} days"
            elif seconds >= 3600:
                hours = seconds / 3600
                return f"{hours:.0f} hours"
            elif seconds >= 60:
                minutes = seconds / 60
                return f"{minutes:.0f} minutes"
            else:
                return f"{seconds:.0f} seconds"
        return value
    except (ValueError, TypeError):
        return value


def enum_pso(args, cache):
    """Enumerate Fine-Grained Password Policies (PSOs).

    Queries LDAP for Password Settings Objects which define password
    policies that override the domain default for specific users/groups.

    Weak PSOs = easier password attacks on affected accounts.
    """
    target = cache.target if cache else args.target
    print_section("Fine-Grained Password Policies (PSO)", target)

    # Skip if LDAP is unavailable (determined during cache priming)
    if not cache.ldap_available:
        status("LDAP unavailable - skipping PSO enumeration", "error")
        return

    auth = cache.auth_args
    status("Querying for Password Settings Objects...")

    # Query PSO objects using LDAP filter
    # PSOs are stored in CN=Password Settings Container,CN=System,DC=...
    pso_attrs = (
        "cn,msDS-PasswordSettingsPrecedence,msDS-MinimumPasswordLength,"
        "msDS-MaximumPasswordAge,msDS-PasswordComplexityEnabled,"
        "msDS-LockoutThreshold,msDS-PSOAppliesTo"
    )
    pso_args = ["ldap", target] + auth + ["--query", PSO_FILTER, pso_attrs]
    rc, stdout, stderr = run_nxc(pso_args, args.timeout)
    debug_nxc(pso_args, stdout, stderr, "PSO Query")

    pso_list = []
    current_pso = {}

    # Parse output
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            # Save current PSO if we have data
            if current_pso.get("name"):
                pso_list.append(current_pso.copy())
                current_pso = {}
            continue

        if is_nxc_noise_line(line):
            continue

        # Look for PSO object markers
        if "Response for object:" in line and "CN=" in line:
            # Save previous PSO
            if current_pso.get("name"):
                pso_list.append(current_pso.copy())
            cn_match = RE_CN.search(line)
            current_pso = {"name": cn_match.group(1) if cn_match else "Unknown"}
            continue

        # Parse PSO attributes
        precedence_match = RE_PRECEDENCE.search(line)
        if precedence_match:
            current_pso["precedence"] = int(precedence_match.group(1))

        min_length_match = RE_MIN_LENGTH.search(line)
        if min_length_match:
            current_pso["min_length"] = int(min_length_match.group(1))

        min_age_match = RE_MIN_AGE.search(line)
        if min_age_match:
            current_pso["min_age"] = parse_ad_timespan(min_age_match.group(1))

        max_age_match = RE_MAX_AGE.search(line)
        if max_age_match:
            current_pso["max_age"] = parse_ad_timespan(max_age_match.group(1))

        history_match = RE_HISTORY.search(line)
        if history_match:
            current_pso["history"] = int(history_match.group(1))

        complexity_match = RE_COMPLEXITY.search(line)
        if complexity_match:
            current_pso["complexity"] = complexity_match.group(1).upper() == "TRUE"

        reversible_match = RE_REVERSIBLE.search(line)
        if reversible_match:
            current_pso["reversible_encryption"] = (
                reversible_match.group(1).upper() == "TRUE"
            )

        lockout_match = RE_LOCKOUT_THRESHOLD.search(line)
        if lockout_match:
            current_pso["lockout_threshold"] = int(lockout_match.group(1))

        lockout_dur_match = RE_LOCKOUT_DURATION.search(line)
        if lockout_dur_match:
            current_pso["lockout_duration"] = parse_ad_timespan(lockout_dur_match.group(1))

        applies_match = RE_APPLIES_TO.search(line)
        if applies_match:
            if "applies_to" not in current_pso:
                current_pso["applies_to"] = []
            # Extract CN from DN
            cn_match = RE_CN.search(applies_match.group(1))
            if cn_match:
                current_pso["applies_to"].append(cn_match.group(1))

    # Don't forget last PSO
    if current_pso.get("name"):
        pso_list.append(current_pso.copy())

    # Check for access/error conditions
    combined = stdout + stderr
    access_denied = "STATUS_ACCESS_DENIED" in combined.upper()
    no_pso = "No entries" in combined or "0 entries" in combined
    ldap_failed = (
        "Failed to create connection" in combined
        or "Failed to connect" in combined.lower()
        or "ldap connection failed" in combined.lower()
    )

    # Store in cache
    cache.pso_policies = pso_list

    if pso_list:
        status(f"Found {len(pso_list)} Fine-Grained Password Policy(ies)", "success")
        output("")

        # Sort by precedence (lower = higher priority)
        pso_list.sort(key=lambda x: x.get("precedence", 999))

        output(c("PASSWORD SETTINGS OBJECTS (PSOs)", Colors.CYAN))
        output(f"{'-'*70}")

        for pso in pso_list:
            name = pso.get("name", "Unknown")
            precedence = pso.get("precedence", "?")
            min_len = pso.get("min_length", "?")
            complexity = pso.get("complexity")
            lockout = pso.get("lockout_threshold", "?")
            applies_to = pso.get("applies_to", [])
            max_age = pso.get("max_age", "?")
            reversible = pso.get("reversible_encryption", False)

            # Determine if this PSO is weak
            is_weak = False
            weak_reasons = []

            if isinstance(min_len, int) and min_len < 8:
                is_weak = True
                weak_reasons.append(f"short min length ({min_len})")

            if complexity is False:
                is_weak = True
                weak_reasons.append("no complexity")

            if isinstance(lockout, int) and lockout == 0:
                is_weak = True
                weak_reasons.append("no lockout")

            if reversible:
                is_weak = True
                weak_reasons.append("reversible encryption!")

            # Display PSO
            if is_weak:
                output(f"  {c('[!] ' + name, Colors.RED + Colors.BOLD)}")
            else:
                output(f"  {c('[*] ' + name, Colors.CYAN)}")

            output(f"      Precedence: {precedence}")
            output(f"      Min Length: {min_len}")
            output(f"      Complexity: {'Yes' if complexity else c('No', Colors.YELLOW)}")
            output(f"      Max Age: {max_age}")
            output(f"      Lockout: {lockout if lockout != 0 else c('Disabled', Colors.YELLOW)}")

            if reversible:
                output(f"      {c('Reversible Encryption: ENABLED!', Colors.RED + Colors.BOLD)}")

            if applies_to:
                output(f"      Applies To: {', '.join(applies_to[:5])}")
                if len(applies_to) > 5:
                    output(f"                 ... and {len(applies_to) - 5} more")

            if is_weak:
                output(f"      {c('WEAK: ' + ', '.join(weak_reasons), Colors.RED)}")

            output("")

        # Summarize weak PSOs
        weak_psos = [
            p for p in pso_list
            if p.get("min_length", 99) < 8 or not p.get("complexity", True)
        ]
        if weak_psos:
            output(
                c(
                    f"[!] {len(weak_psos)} PSO(s) with weak requirements!",
                    Colors.YELLOW + Colors.BOLD,
                )
            )
            output(
                c(
                    "    Users in affected groups may have weaker passwords",
                    Colors.YELLOW,
                )
            )
            output("")

        # Store weak PSO targets for copy-paste
        weak_targets = []
        for pso in weak_psos:
            weak_targets.extend(pso.get("applies_to", []))
        if weak_targets:
            cache.copy_paste_data["weak_pso_groups"] = set(weak_targets)

    elif ldap_failed:
        status("LDAP unavailable - cannot check PSO policies", "error")
    elif access_denied:
        status("Access denied querying PSO objects", "warning")
    elif no_pso:
        status("No Fine-Grained Password Policies found", "info")
        output(c("    Domain uses default password policy only", Colors.BLUE))
    else:
        if not stdout.strip() or rc != 0:
            status("Could not query PSO objects", "error")
        else:
            status("No Fine-Grained Password Policies found", "info")

    if args.json_output:
        JSON_DATA["pso"] = {
            "policies": pso_list,
            "count": len(pso_list),
        }
