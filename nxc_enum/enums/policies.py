"""Password policy enumeration."""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc

# Regex patterns for verbose --pass-pol output parsing
# Fine-grained password policies (FGPP)
RE_FGPP_NAME = re.compile(
    r"(?:Fine-?grained|FGPP|PSO).*?(?:Name|Policy)[:\s]+([^\n\r]+)", re.IGNORECASE
)
RE_FGPP_PRECEDENCE = re.compile(r"Precedence[:\s]+(\d+)", re.IGNORECASE)
RE_FGPP_APPLIES = re.compile(r"(?:Applies\s+to|msDS-PSOAppliesTo)[:\s]+([^\n\r]+)", re.IGNORECASE)

# Domain functional level
RE_DOMAIN_LEVEL = re.compile(
    r"(?:Domain\s+)?(?:Functional\s+)?Level[:\s]+([^\n\r]+)", re.IGNORECASE
)
RE_DOMAIN_MODE = re.compile(r"(?:Domain\s+Mode|domainFunctionality)[:\s]+([^\n\r]+)", re.IGNORECASE)
RE_FOREST_LEVEL = re.compile(
    r"(?:Forest\s+)?(?:Functional\s+)?Level[:\s]+([^\n\r]+)", re.IGNORECASE
)

# Policy enforcement details
RE_POLICY_ENFORCED = re.compile(
    r"(?:Policy\s+)?(?:Enforcement|Enforced)[:\s]+([^\n\r]+)", re.IGNORECASE
)
RE_CLEAR_TEXT = re.compile(
    r"(?:Store\s+)?(?:Clear\s*text|Reversible\s+Encryption)[:\s]+([^\n\r]+)", re.IGNORECASE
)
RE_KERBEROS_POLICY = re.compile(r"Kerberos[:\s]+([^\n\r]+)", re.IGNORECASE)
RE_FORCE_LOGOFF = re.compile(r"(?:Force\s+)?Logoff[:\s]+([^\n\r]+)", re.IGNORECASE)

# Additional policy attributes
RE_PASSWORD_PROPERTIES = re.compile(r"Password\s+Properties[:\s]+(\S+)", re.IGNORECASE)
RE_DOMAIN_SID = re.compile(r"(?:Domain\s+)?SID[:\s]+(S-\d+-\d+(?:-\d+)+)", re.IGNORECASE)
RE_INFO_LINE = re.compile(r"\[INFO\].*?(policy|password|lockout|domain|level)", re.IGNORECASE)


def parse_verbose_policy_info(stdout: str) -> dict:
    """Parse verbose --pass-pol output for additional policy metadata.

    Returns dict with:
        - fine_grained_policies: list of FGPP dicts
        - domain_functional_level: string
        - forest_functional_level: string
        - policy_enforcement: dict of enforcement details
        - password_properties: raw properties value
        - domain_sid: domain SID if found
        - kerberos_policy: kerberos policy details
        - info_messages: list of relevant INFO lines
    """
    verbose_data = {
        "fine_grained_policies": [],
        "domain_functional_level": None,
        "forest_functional_level": None,
        "policy_enforcement": {},
        "password_properties": None,
        "domain_sid": None,
        "kerberos_policy": None,
        "force_logoff": None,
        "clear_text_passwords": None,
        "info_messages": [],
    }

    current_fgpp = None

    for line in stdout.split("\n"):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Check for fine-grained password policy names
        fgpp_match = RE_FGPP_NAME.search(line_stripped)
        if fgpp_match:
            # Save previous FGPP if exists
            if current_fgpp and current_fgpp.get("name"):
                verbose_data["fine_grained_policies"].append(current_fgpp)
            current_fgpp = {"name": fgpp_match.group(1).strip()}
            continue

        # FGPP precedence
        if current_fgpp:
            prec_match = RE_FGPP_PRECEDENCE.search(line_stripped)
            if prec_match:
                current_fgpp["precedence"] = int(prec_match.group(1))
                continue

            applies_match = RE_FGPP_APPLIES.search(line_stripped)
            if applies_match:
                applies_to = applies_match.group(1).strip()
                if "applies_to" not in current_fgpp:
                    current_fgpp["applies_to"] = []
                current_fgpp["applies_to"].append(applies_to)
                continue

        # Domain functional level
        level_match = RE_DOMAIN_LEVEL.search(line_stripped)
        if level_match and not verbose_data["domain_functional_level"]:
            verbose_data["domain_functional_level"] = level_match.group(1).strip()
            continue

        mode_match = RE_DOMAIN_MODE.search(line_stripped)
        if mode_match and not verbose_data["domain_functional_level"]:
            verbose_data["domain_functional_level"] = mode_match.group(1).strip()
            continue

        # Forest functional level
        forest_match = RE_FOREST_LEVEL.search(line_stripped)
        if forest_match and not verbose_data["forest_functional_level"]:
            verbose_data["forest_functional_level"] = forest_match.group(1).strip()
            continue

        # Policy enforcement details
        enforced_match = RE_POLICY_ENFORCED.search(line_stripped)
        if enforced_match:
            verbose_data["policy_enforcement"]["enforced"] = enforced_match.group(1).strip()
            continue

        # Clear text / reversible encryption
        clear_match = RE_CLEAR_TEXT.search(line_stripped)
        if clear_match:
            value = clear_match.group(1).strip().lower()
            verbose_data["clear_text_passwords"] = value in ("true", "yes", "enabled", "1")
            continue

        # Kerberos policy
        kerb_match = RE_KERBEROS_POLICY.search(line_stripped)
        if kerb_match:
            verbose_data["kerberos_policy"] = kerb_match.group(1).strip()
            continue

        # Force logoff
        logoff_match = RE_FORCE_LOGOFF.search(line_stripped)
        if logoff_match:
            verbose_data["force_logoff"] = logoff_match.group(1).strip()
            continue

        # Password properties raw value
        props_match = RE_PASSWORD_PROPERTIES.search(line_stripped)
        if props_match:
            verbose_data["password_properties"] = props_match.group(1).strip()
            continue

        # Domain SID
        sid_match = RE_DOMAIN_SID.search(line_stripped)
        if sid_match:
            verbose_data["domain_sid"] = sid_match.group(1).strip()
            continue

        # Capture relevant INFO messages
        if RE_INFO_LINE.search(line_stripped) or "[INFO]" in line_stripped.upper():
            if any(
                kw in line_stripped.lower()
                for kw in [
                    "policy",
                    "password",
                    "lockout",
                    "domain",
                    "level",
                    "functional",
                    "fgpp",
                    "pso",
                ]
            ):
                verbose_data["info_messages"].append(line_stripped)

    # Save last FGPP if exists
    if current_fgpp and current_fgpp.get("name"):
        verbose_data["fine_grained_policies"].append(current_fgpp)

    return verbose_data


def enum_policies(args, cache):
    """Enumerate password policies."""
    target = cache.target if cache else args.target
    print_section("Policies via RPC", target)

    auth = cache.auth_args
    policies_args = ["smb", target] + auth + ["--pass-pol"]
    rc, stdout, stderr = run_nxc(policies_args, args.timeout)
    debug_nxc(policies_args, stdout, stderr, "Password Policies")

    if rc != 0 and not stdout:
        status("Could not enumerate policies", "error")
        return

    status("Trying port 445/tcp")

    policies = {
        "Minimum password length": None,
        "Password history length": None,
        "Maximum password age": None,
        "Minimum password age": None,
        "Lockout threshold": None,
        "Lockout duration": None,
        "Lockout observation window": None,
        "Password Complexity": None,
    }

    field_aliases = {
        "account lockout threshold": "Lockout threshold",
        "locked account duration": "Lockout duration",
        "reset account lockout counter": "Lockout observation window",
        "password complexity flags": "Password Complexity",
    }

    for line in stdout.split("\n"):
        line_lower = line.lower()
        if ":" not in line:
            continue
        for alias, key in field_aliases.items():
            if alias in line_lower:
                value = line.split(":", 1)[1].strip()
                policies[key] = value
                break
        else:
            for key in policies:
                if key.lower() in line_lower:
                    value = line.split(":", 1)[1].strip()
                    policies[key] = value
                    break

    # Check if we got any real policy values (not all Unknown/None)
    has_real_values = any(v is not None for v in policies.values())

    if has_real_values:
        status("Found policy:", "success")
    else:
        status("Policy retrieved (limited information):", "info")

    output("Domain password information:")
    output(f"  Password history length: {policies.get('Password history length') or 'Unknown'}")

    min_len = policies.get("Minimum password length") or "Unknown"
    try:
        min_len_int = int(min_len)
        if min_len_int < 8:
            msg = f"  Minimum password length: {c(min_len, Colors.YELLOW)}"
            msg += f" {c('← Weak!', Colors.YELLOW)}"
            output(msg)
        else:
            output(f"  Minimum password length: {c(min_len, Colors.GREEN)}")
    except ValueError:
        output(f"  Minimum password length: {min_len}")

    output(f"  Minimum password age: {policies.get('Minimum password age') or 'Unknown'}")
    output(f"  Maximum password age: {policies.get('Maximum password age') or 'Unknown'}")
    output("  Password properties:")
    complexity = policies.get("Password Complexity")
    output(f"  - DOMAIN_PASSWORD_COMPLEX: {complexity.lower() if complexity else 'unknown'}")

    output("Domain lockout information:")
    output(
        f"  Lockout observation window: {policies.get('Lockout observation window') or 'Unknown'}"
    )
    output(f"  Lockout duration: {policies.get('Lockout duration') or 'Unknown'}")

    lockout = policies.get("Lockout threshold")
    # Only claim "password spraying safe" if we actually retrieved policy data
    # (not when all values are Unknown due to failed retrieval)
    if lockout == "0" or (lockout is None and has_real_values):
        # We have policy data and lockout is explicitly 0 or None
        msg = f"  Lockout threshold: {c('None', Colors.RED)}"
        msg += f" {c('← Password spraying safe!', Colors.RED)}"
        output(msg)

        # Add password spraying recommendation
        cache.add_next_step(
            finding="No account lockout policy",
            command=f"nxc smb {target} -u users.txt -p passwords.txt --continue-on-success",
            description="Password spraying is safe - no lockout threshold configured",
            priority="medium",
        )
    elif lockout is None and not has_real_values:
        # Policy retrieval failed - we don't know the actual lockout threshold
        msg = f"  Lockout threshold: {c('Unknown', Colors.YELLOW)}"
        msg += f" {c('← Caution: policy data unavailable', Colors.YELLOW)}"
        output(msg)
    elif lockout:
        output(f"  Lockout threshold: {c(lockout, Colors.GREEN)}")

    # Parse verbose output for additional policy metadata
    verbose_info = parse_verbose_policy_info(stdout)

    # Display verbose policy information if found
    _print_verbose_policy_info(verbose_info, cache)

    # Store policy info in cache (merge verbose data)
    cache.policy_info = policies
    cache.policy_verbose_info = verbose_info

    # Store domain SID if found
    if verbose_info.get("domain_sid") and not cache.domain_info.get("domain_sid"):
        cache.domain_info["domain_sid"] = verbose_info["domain_sid"]

    # Store domain functional level if found
    if verbose_info.get("domain_functional_level") and not cache.domain_info.get(
        "functional_level"
    ):
        cache.domain_info["functional_level"] = verbose_info["domain_functional_level"]

    # Add next steps for security findings from verbose data
    if verbose_info.get("clear_text_passwords"):
        cache.add_next_step(
            finding="Reversible encryption enabled",
            command=f"nxc ldap {target} -u <user> -p <pass> --asreproast output.txt",
            description="Clear text passwords may be stored - check for AS-REP roastable accounts",
            priority="high",
        )

    if verbose_info.get("fine_grained_policies"):
        for fgpp in verbose_info["fine_grained_policies"]:
            if fgpp.get("applies_to"):
                cache.add_next_step(
                    finding=f"Fine-grained password policy: {fgpp.get('name', 'Unknown')}",
                    command=f"nxc ldap {target} -u <user> -p <pass> -M get-desc-users",
                    description=f"FGPP applies to: {', '.join(fgpp.get('applies_to', []))}",
                    priority="low",
                )

    if args.json_output:
        JSON_DATA["policies"] = policies
        # Add verbose data to JSON output
        if verbose_info["fine_grained_policies"]:
            JSON_DATA["fine_grained_policies"] = verbose_info["fine_grained_policies"]
        if verbose_info["domain_functional_level"]:
            JSON_DATA["domain_functional_level"] = verbose_info["domain_functional_level"]
        if verbose_info["forest_functional_level"]:
            JSON_DATA["forest_functional_level"] = verbose_info["forest_functional_level"]
        if verbose_info["domain_sid"]:
            JSON_DATA["domain_sid"] = verbose_info["domain_sid"]
        if verbose_info["clear_text_passwords"] is not None:
            JSON_DATA["clear_text_passwords"] = verbose_info["clear_text_passwords"]
        if verbose_info["kerberos_policy"]:
            JSON_DATA["kerberos_policy"] = verbose_info["kerberos_policy"]
        if verbose_info["policy_enforcement"]:
            JSON_DATA["policy_enforcement"] = verbose_info["policy_enforcement"]


def _print_verbose_policy_info(verbose_info: dict, cache):
    """Print verbose policy information if available."""
    has_verbose_data = (
        verbose_info.get("fine_grained_policies")
        or verbose_info.get("domain_functional_level")
        or verbose_info.get("forest_functional_level")
        or verbose_info.get("domain_sid")
        or verbose_info.get("clear_text_passwords") is not None
        or verbose_info.get("kerberos_policy")
        or verbose_info.get("force_logoff")
    )

    if not has_verbose_data:
        return

    output("")
    output(c("Extended Policy Information (from verbose output):", Colors.CYAN))

    # Domain functional level
    if verbose_info.get("domain_functional_level"):
        level = verbose_info["domain_functional_level"]
        # Highlight old functional levels as potential security concern
        old_levels = ["2003", "2008", "2008 R2", "2000"]
        if any(old in level for old in old_levels):
            output(f"  Domain Functional Level: {c(level, Colors.YELLOW)}")
        else:
            output(f"  Domain Functional Level: {level}")

    if verbose_info.get("forest_functional_level"):
        output(f"  Forest Functional Level: {verbose_info['forest_functional_level']}")

    # Domain SID
    if verbose_info.get("domain_sid"):
        output(f"  Domain SID: {verbose_info['domain_sid']}")

    # Clear text passwords (security concern)
    if verbose_info.get("clear_text_passwords"):
        enabled_str = c("ENABLED", Colors.RED)
        risk_str = c("← Security Risk!", Colors.RED)
        output(f"  Reversible Encryption: {enabled_str} {risk_str}")
    elif verbose_info.get("clear_text_passwords") is False:
        output(f"  Reversible Encryption: {c('Disabled', Colors.GREEN)}")

    # Kerberos policy
    if verbose_info.get("kerberos_policy"):
        output(f"  Kerberos Policy: {verbose_info['kerberos_policy']}")

    # Force logoff
    if verbose_info.get("force_logoff"):
        output(f"  Force Logoff: {verbose_info['force_logoff']}")

    # Password properties flags (decode hex value if available)
    if verbose_info.get("password_properties"):
        props_raw = verbose_info["password_properties"]
        output(f"  Password Properties: {props_raw}")
        # Try to decode common flag values
        try:
            props_val = int(props_raw, 16) if props_raw.startswith("0x") else int(props_raw)
            flags = []
            # Common password property flags from MS docs
            if props_val & 0x01:
                flags.append("DOMAIN_PASSWORD_COMPLEX")
            if props_val & 0x02:
                flags.append("DOMAIN_PASSWORD_NO_ANON_CHANGE")
            if props_val & 0x04:
                flags.append("DOMAIN_PASSWORD_NO_CLEAR_CHANGE")
            if props_val & 0x08:
                flags.append("DOMAIN_LOCKOUT_ADMINS")
            if props_val & 0x10:
                flags.append("DOMAIN_PASSWORD_STORE_CLEARTEXT")
            if props_val & 0x20:
                flags.append("DOMAIN_REFUSE_PASSWORD_CHANGE")
            if flags:
                output(f"    Decoded flags: {', '.join(flags)}")
                # Highlight security concerns
                if props_val & 0x10:  # Store cleartext
                    output(c("    WARNING: DOMAIN_PASSWORD_STORE_CLEARTEXT enabled!", Colors.RED))
                if props_val & 0x08:  # Lockout admins
                    lockout_msg = "NOTE: DOMAIN_LOCKOUT_ADMINS - Admins can be locked out"
                    output(c(f"    {lockout_msg}", Colors.YELLOW))
        except (ValueError, TypeError):
            pass

    # Fine-grained password policies
    if verbose_info.get("fine_grained_policies"):
        output("")
        output(c("Fine-Grained Password Policies (FGPP):", Colors.CYAN))
        for fgpp in verbose_info["fine_grained_policies"]:
            name = fgpp.get("name", "Unknown")
            precedence = fgpp.get("precedence", "N/A")
            output(f"  Policy: {c(name, Colors.BOLD)}")
            output(f"    Precedence: {precedence}")
            if fgpp.get("applies_to"):
                for target in fgpp["applies_to"]:
                    output(f"    Applies to: {target}")

    # Display relevant INFO messages if any
    if verbose_info.get("info_messages"):
        # Filter to unique, relevant messages
        seen = set()
        unique_msgs = []
        for msg in verbose_info["info_messages"]:
            clean_msg = msg.replace("[INFO]", "").strip()
            if clean_msg and clean_msg not in seen:
                seen.add(clean_msg)
                unique_msgs.append(clean_msg)

        if unique_msgs:
            output("")
            output(c("Additional Policy INFO:", Colors.CYAN))
            for msg in unique_msgs[:5]:  # Limit to first 5
                output(f"  {msg}")
