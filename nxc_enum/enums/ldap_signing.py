"""LDAP signing requirements check.

This module checks whether LDAP signing is required on the domain controller.
When LDAP signing is not required, LDAP relay attacks may be possible.

This is pure enumeration - it checks the DC configuration via LDAP connection.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc

# Patterns to detect LDAP signing status from nxc output
RE_SIGNING_NOT_REQUIRED = re.compile(
    r"LDAP signing.*not.*enforced|signing.*not.*required|channel binding.*not.*enforced",
    re.IGNORECASE,
)
RE_SIGNING_REQUIRED = re.compile(
    r"LDAP signing.*enforced|signing.*required|channel binding.*enforced",
    re.IGNORECASE,
)


def enum_ldap_signing(args, cache):
    """Check LDAP signing requirements on the domain controller.

    Analyzes LDAP connection output to determine if signing is enforced.
    """
    target = cache.target if cache else args.target
    print_section("LDAP Signing Check", target)

    auth = cache.auth_args
    status("Checking LDAP signing requirements...")

    # Run basic LDAP connection - signing status shown in banner
    ldap_args = ["ldap", target] + auth
    rc, stdout, stderr = run_nxc(ldap_args, args.timeout)
    debug_nxc(ldap_args, stdout, stderr, "LDAP Signing Check")

    signing_required = None
    channel_binding = None
    ldap_info = {}

    combined = stdout + stderr

    # Parse output for signing status
    for line in combined.split("\n"):
        line = line.strip()
        if not line:
            continue

        line_lower = line.lower()

        # Check for signing status
        if "signing" in line_lower and "ldap" in line_lower:
            if RE_SIGNING_NOT_REQUIRED.search(line):
                signing_required = False
            elif RE_SIGNING_REQUIRED.search(line):
                signing_required = True
            ldap_info["signing_line"] = line

        # Check for channel binding
        if "channel binding" in line_lower or "channel_binding" in line_lower:
            if "not" in line_lower and ("enforced" in line_lower or "required" in line_lower):
                channel_binding = False
            elif "enforced" in line_lower or "required" in line_lower:
                channel_binding = True
            ldap_info["channel_binding_line"] = line

    # If we couldn't determine from banner, try a more explicit check
    # Some nxc versions may not show this in the banner
    if signing_required is None:
        # Try verbose LDAP connection to get more info
        verbose_args = ["ldap", target] + auth + ["--verbose"]
        rc_v, stdout_v, stderr_v = run_nxc(verbose_args, args.timeout)

        combined_v = stdout_v + stderr_v
        for line in combined_v.split("\n"):
            line_lower = line.lower()
            if "signing" in line_lower:
                if "not" in line_lower and ("required" in line_lower or "enforced" in line_lower):
                    signing_required = False
                    break
                elif "required" in line_lower or "enforced" in line_lower:
                    signing_required = True
                    break

    # Store results
    cache.ldap_signing_required = signing_required
    cache.ldap_channel_binding = channel_binding
    cache.ldap_signing_info = ldap_info

    # Display results
    output("")
    output(c("LDAP SECURITY CONFIGURATION", Colors.CYAN))
    output(f"{'-'*50}")

    if signing_required is False:
        output(
            f"  {c('[!]', Colors.RED)} {c('LDAP Signing: NOT REQUIRED', Colors.RED + Colors.BOLD)}"
        )
        output(c("      Vulnerable to LDAP relay attacks", Colors.RED))

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
            finding="LDAP signing not required",
            command=f"ntlmrelayx.py -t ldap://{target} --delegate-access",
            description="LDAP relay to create machine account for RBCD attack",
            priority="high",
        )
    elif signing_required is True:
        output(f"  {c('[+]', Colors.GREEN)} {c('LDAP Signing: REQUIRED', Colors.GREEN)}")
        output(c("      Protected against LDAP relay attacks", Colors.GREEN))
    else:
        output(f"  {c('[!]', Colors.YELLOW)} {c('LDAP Signing: UNKNOWN', Colors.YELLOW)}")
        output(c("      Could not determine signing requirements", Colors.YELLOW))

    output("")

    if channel_binding is False:
        cb_label = c("Channel Binding: NOT ENFORCED", Colors.RED + Colors.BOLD)
        output(f"  {c('[!]', Colors.RED)} {cb_label}")
        output(c("      May be vulnerable to certain relay attacks", Colors.RED))
    elif channel_binding is True:
        output(f"  {c('[+]', Colors.GREEN)} {c('Channel Binding: ENFORCED', Colors.GREEN)}")
    # If unknown, don't show (not all DCs report this)

    output("")

    # Summary status
    if signing_required is False:
        status("LDAP signing NOT required - relay attacks possible!", "warning")
    elif signing_required is True:
        status("LDAP signing required - relay attacks mitigated", "success")
    else:
        status("Could not determine LDAP signing status", "info")

    if args.json_output:
        JSON_DATA["ldap_signing"] = {
            "signing_required": signing_required,
            "channel_binding": channel_binding,
            "info": ldap_info,
        }
