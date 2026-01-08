"""Delegation enumeration."""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

# Regex patterns for parsing delegation output
# Matches delegation type keywords with optional modifiers
RE_DELEGATION_TYPE = re.compile(
    r"(Unconstrained|Constrained(?:\s+w/\s+Protocol\s+Transition)?|Resource-Based\s+Constrained)",
    re.IGNORECASE,
)

# Matches verbose INFO lines with additional delegation details
# Format: "INFO ... Account: <name> ... Type: <type> ... Target: <services>"
RE_DELEGATION_INFO = re.compile(r"(?:Account|Principal):\s*([^\s,]+)", re.IGNORECASE)
RE_TARGET_SERVICES = re.compile(r"(?:Target|DelegationRightsTo|Services?):\s*(.+)", re.IGNORECASE)


def _normalize_delegation_type(deleg_type: str) -> str:
    """Normalize delegation type string for consistent storage."""
    deleg_lower = deleg_type.lower().strip()
    if "resource-based" in deleg_lower or "rbcd" in deleg_lower:
        return "RBCD"
    elif "protocol transition" in deleg_lower:
        return "Constrained (Protocol Transition)"
    elif "constrained" in deleg_lower:
        return "Constrained"
    elif "unconstrained" in deleg_lower:
        return "Unconstrained"
    return deleg_type.strip()


def _parse_delegation_line(line: str) -> dict | None:
    """Parse a single delegation output line.

    nxc --find-delegation output format (tabular):
    AccountName  AccountType  DelegationType  DelegationRightsTo

    Example lines:
    sansa.stark  Person  Unconstrained  N/A
    jon.snow  Person  Constrained w/ Protocol Transition  CIFS/winterfell, ...
    CASTELBLACK$  Computer  Constrained  HTTP/winterfell, HTTP/winterfell.north.sevenkingdoms.local
    """
    # Skip header/separator lines
    if "AccountName" in line and "AccountType" in line:
        return None
    if "---" in line:
        return None

    # Find delegation type in the line
    deleg_match = RE_DELEGATION_TYPE.search(line)
    if not deleg_match:
        return None

    deleg_type_raw = deleg_match.group(1)
    deleg_type = _normalize_delegation_type(deleg_type_raw)

    # Split line at the delegation type to get account info and rights
    before_deleg = line[: deleg_match.start()].strip()
    after_deleg = line[deleg_match.end() :].strip()

    # Parse account name and type from before the delegation keyword
    # Format typically: "IP PORT HOSTNAME ... AccountName AccountType"
    before_parts = before_deleg.split()
    if len(before_parts) >= 2:
        # Last two parts before delegation type are usually AccountType and AccountName
        # But we need to handle the nxc prefix (IP, port, hostname)
        # Look for Person/Computer as account type marker
        account_type = "Unknown"
        account_name = "Unknown"

        for i, part in enumerate(before_parts):
            if part.lower() in ("person", "computer", "user"):
                account_type = part.capitalize()
                if i > 0:
                    account_name = before_parts[i - 1]
                break

        # If we didn't find Person/Computer, take the last two parts
        if account_name == "Unknown" and len(before_parts) >= 2:
            account_name = before_parts[-2]
            account_type = before_parts[-1]
    else:
        return None

    # Parse target services/rights from after the delegation keyword
    rights_to = after_deleg.strip() if after_deleg else ""

    # Clean up N/A or empty values
    if rights_to.upper() == "N/A" or not rights_to:
        rights_to = ""

    # Parse target services into a list if present
    target_services = []
    if rights_to:
        # Services are typically comma-separated: "CIFS/server, HTTP/server"
        for svc in rights_to.split(","):
            svc = svc.strip()
            if svc:
                target_services.append(svc)

    return {
        "account": account_name,
        "type": account_type,
        "delegation": deleg_type,
        "rights_to": rights_to,
        "target_services": target_services,
    }


def _parse_verbose_info(lines: list) -> dict:
    """Parse verbose INFO lines for additional delegation details.

    Returns a dict mapping account names to additional info from verbose output.
    """
    verbose_info = {}

    for line in lines:
        if "INFO" not in line:
            continue

        # Try to extract account name from INFO line
        account_match = RE_DELEGATION_INFO.search(line)
        if account_match:
            account = account_match.group(1).strip()
            if account not in verbose_info:
                verbose_info[account] = {"extra_services": [], "notes": []}

            # Extract additional target services
            target_match = RE_TARGET_SERVICES.search(line)
            if target_match:
                services = target_match.group(1).strip()
                for svc in services.split(","):
                    svc = svc.strip()
                    if svc and svc not in verbose_info[account]["extra_services"]:
                        verbose_info[account]["extra_services"].append(svc)

            # Capture any additional notes/context from the INFO line
            if "sensitive" in line.lower() or "protected" in line.lower():
                verbose_info[account]["notes"].append("Sensitive/protected account")
            if "disabled" in line.lower():
                verbose_info[account]["notes"].append("Account disabled")

    return verbose_info


def enum_delegation(args, cache):
    """Find accounts with delegation misconfigurations."""
    target = cache.target if cache else args.target
    print_section("Delegation Enumeration", target)

    # Skip if LDAP is unavailable (determined during cache priming)
    if not cache.ldap_available:
        status("LDAP unavailable - skipping delegation enumeration", "error")
        return

    auth = cache.auth_args
    status("Querying delegation configurations...")

    delegation_args = ["ldap", target] + auth + ["--find-delegation"]
    rc, stdout, stderr = run_nxc(delegation_args, args.timeout)
    debug_nxc(delegation_args, stdout, stderr, "Find Delegation")

    lines = stdout.split("\n")
    delegations = []

    # First pass: parse verbose INFO lines for additional context
    verbose_info = _parse_verbose_info(lines)

    # Second pass: parse main delegation output
    for line in lines:
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue

        # Parse the delegation line
        parsed = _parse_delegation_line(line)
        if parsed:
            # Merge any verbose info for this account
            account = parsed["account"]
            if account in verbose_info:
                extra = verbose_info[account]
                # Add extra services not already captured
                for svc in extra.get("extra_services", []):
                    if svc not in parsed["target_services"]:
                        parsed["target_services"].append(svc)
                # Add notes
                parsed["notes"] = extra.get("notes", [])
            else:
                parsed["notes"] = []

            delegations.append(parsed)

    cache.delegation_accounts = delegations

    if delegations:
        # Count by delegation type for summary
        unconstrained = [d for d in delegations if d["delegation"] == "Unconstrained"]
        constrained = [
            d for d in delegations if "Constrained" in d["delegation"] and d["delegation"] != "RBCD"
        ]
        rbcd = [d for d in delegations if d["delegation"] == "RBCD"]

        status(f"Found {len(delegations)} delegation configuration(s):", "warning")
        output("")

        # Display grouped by delegation type for clarity
        if unconstrained:
            output(
                f"  {c('Unconstrained Delegation', Colors.RED)} ({len(unconstrained)} account(s)):"
            )
            for d in unconstrained:
                output(f"    {c(d['account'], Colors.RED)} ({d['type']})")
                if d.get("notes"):
                    for note in d["notes"]:
                        output(f"      Note: {c(note, Colors.CYAN)}")
            output("")

        if constrained:
            output(
                f"  {c('Constrained Delegation', Colors.YELLOW)} ({len(constrained)} account(s)):"
            )
            for d in constrained:
                deleg_label = d["delegation"]
                output(f"    {c(d['account'], Colors.YELLOW)} ({d['type']}) - {deleg_label}")
                # Show target services
                if d.get("target_services"):
                    for svc in d["target_services"]:
                        output(f"      -> {c(svc, Colors.CYAN)}")
                elif d.get("rights_to"):
                    output(f"      -> {d['rights_to']}")
                if d.get("notes"):
                    for note in d["notes"]:
                        output(f"      Note: {c(note, Colors.CYAN)}")
            output("")

        if rbcd:
            rbcd_label = c("Resource-Based Constrained Delegation (RBCD)", Colors.YELLOW)
            output(f"  {rbcd_label} ({len(rbcd)} account(s)):")
            for d in rbcd:
                output(f"    {c(d['account'], Colors.YELLOW)} ({d['type']})")
                # RBCD shows which accounts can delegate TO this account
                if d.get("target_services"):
                    for svc in d["target_services"]:
                        output(f"      <- can be impersonated by: {c(svc, Colors.CYAN)}")
                elif d.get("rights_to"):
                    output(f"      <- can be impersonated by: {d['rights_to']}")
                if d.get("notes"):
                    for note in d["notes"]:
                        output(f"      Note: {c(note, Colors.CYAN)}")
            output("")

        # Add delegation exploitation recommendations
        if unconstrained:
            # List all unconstrained accounts
            accounts_list = ", ".join([d["account"] for d in unconstrained[:3]])
            if len(unconstrained) > 3:
                accounts_list += f" (+{len(unconstrained) - 3} more)"
            cache.add_next_step(
                finding=f"Unconstrained delegation: {accounts_list}",
                command="krbrelayx.py -aesKey <key> -victim <dc_hostname>",
                description="Capture TGTs from machines authenticating to these hosts",
                priority="high",
            )

        if constrained:
            domain = cache.domain_info.get("dns_domain", "<domain>")
            # Use first constrained account with target services
            target_acct = constrained[0]
            target_spn = (
                target_acct["target_services"][0]
                if target_acct.get("target_services")
                else "<target_spn>"
            )
            # Format: getST.py -spn 'SPN' -impersonate USER 'domain/user:pass'
            cmd = f"getST.py -spn '{target_spn}' -impersonate Administrator"
            cmd += f" '{domain}/{target_acct['account']}:<pass>' -dc-ip {target}"
            cache.add_next_step(
                finding=f"Constrained delegation on {target_acct['account']}",
                command=cmd,
                description="Request service ticket as any user to delegated service",
                priority="high",
            )

        if rbcd:
            domain = cache.domain_info.get("dns_domain", "<domain>")
            target_acct = rbcd[0]
            # Format: getST.py -spn 'SPN' -impersonate USER 'domain/user:pass'
            cmd = f"getST.py -spn 'cifs/{target_acct['account']}'"
            cmd += f" -impersonate Administrator '<domain>/<user>:<pass>' -dc-ip {target}"
            cache.add_next_step(
                finding=f"RBCD on {target_acct['account']}",
                command=cmd,
                description="Impersonate users to this account via RBCD",
                priority="high",
            )

        # Store for aggregated copy-paste section
        cache.copy_paste_data["delegation_accounts"].update(d["account"] for d in delegations)
        for d in delegations:
            if d.get("target_services"):
                cache.copy_paste_data["target_services"].update(d["target_services"])
    else:
        # Check if LDAP actually failed before claiming "no configurations found"
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
            status("LDAP unavailable - cannot enumerate delegation configurations", "error")
        else:
            status("No delegation configurations found", "success")

    if args.json_output:
        JSON_DATA["delegation"] = {
            "accounts": delegations,
            "summary": {
                "total": len(delegations),
                "unconstrained": len(
                    [d for d in delegations if d["delegation"] == "Unconstrained"]
                ),
                "constrained": len(
                    [
                        d
                        for d in delegations
                        if "Constrained" in d["delegation"] and d["delegation"] != "RBCD"
                    ]
                ),
                "rbcd": len([d for d in delegations if d["delegation"] == "RBCD"]),
            },
        }
