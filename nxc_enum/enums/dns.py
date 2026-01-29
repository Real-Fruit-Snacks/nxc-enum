"""DNS enumeration detection and recommendations.

This module detects if DNS enumeration is possible and recommends
commands for the user to run manually.

It does NOT execute WMI queries on the target.
"""

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, output, print_section, status
from ..reporting.next_steps import get_external_tool_auth


def enum_dns(args, cache):
    """Recommend DNS enumeration commands.

    This module only:
    - Checks if LDAP is available for DNS enumeration
    - Recommends adidnsdump and other DNS tools

    NO WMI queries are executed on the target.
    The nxc enum_dns module uses WMI which executes on the target,
    so we recommend LDAP-based tools instead.
    """
    target = cache.target if cache else args.target
    print_section("DNS Enumeration", target, cache=cache)

    # Check if LDAP is available
    listener_results = getattr(cache, "listener_results", {})
    ldap_available = listener_results.get("LDAP", {}).get("open", False)
    ldaps_available = listener_results.get("LDAPS", {}).get("open", False)
    dns_available = listener_results.get("DNS", {}).get("open", False)

    # Get domain info
    domain_info = getattr(cache, "domain_info", {})
    dns_domain = domain_info.get("dns_domain", "<domain>")

    # Build auth strings for recommendations using the helper
    adidns_auth = get_external_tool_auth(args, cache, tool="adidnsdump")
    impacket_auth = get_external_tool_auth(args, cache, tool="impacket")
    nxc_auth_info = get_external_tool_auth(args, cache, tool="nxc")

    status("Checking DNS enumeration options...")
    output("")

    output(c("DNS ENUMERATION OPTIONS", Colors.CYAN))
    output(f"{'-'*60}")
    output("")

    if ldap_available or ldaps_available:
        output(c("[+] LDAP available - DNS zone transfer via LDAP possible", Colors.GREEN))
        output("")

        output(c("RECOMMENDED COMMANDS:", Colors.YELLOW))
        output(f"{'-'*60}")
        output("")

        # adidnsdump - best option for LDAP-based DNS enum
        output(c("[*] Dump all DNS records via LDAP (adidnsdump):", Colors.CYAN))
        output(f"    adidnsdump {adidns_auth['auth_string']} --dns-tcp {target}")
        if adidns_auth["kerberos_hint"]:
            output(f"    {adidns_auth['kerberos_hint']}")
        elif adidns_auth["alt_auth_hint"]:
            output(f"    {adidns_auth['alt_auth_hint']}")
        output("")

        output(c("[*] Dump specific zone:", Colors.CYAN))
        output(f"    adidnsdump {adidns_auth['auth_string']} --dns-tcp -z {dns_domain} {target}")
        output("")

        output(c("[*] Include tombstoned (deleted) records:", Colors.CYAN))
        auth_str = adidns_auth["auth_string"]
        output(f"    adidnsdump {auth_str} --dns-tcp --include-tombstoned {target}")
        output("")

        # dnstool.py from krbrelayx (impacket-style auth)
        output(c("[*] Query specific record (dnstool.py):", Colors.CYAN))
        dnstool_cred = impacket_auth["credential_format"]
        dnstool_flags = impacket_auth["auth_string"]
        if dnstool_flags:
            output(f"    dnstool.py {dnstool_flags} {dnstool_cred} {target} -r '<record>'")
        else:
            output(f"    dnstool.py {dnstool_cred} {target} -r '<record>'")
        output("")

        # Add to next steps
        dns_desc = "Dump AD-integrated DNS records via LDAP"
        if adidns_auth["alt_auth_hint"]:
            dns_desc += adidns_auth["alt_auth_hint"]
        cache.add_next_step(
            finding="LDAP available for DNS enumeration",
            command=f"adidnsdump {adidns_auth['auth_string']} --dns-tcp {target}",
            description=dns_desc,
            priority="medium",
        )

    elif dns_available:
        output(c("[*] DNS port (53) open but LDAP not available", Colors.YELLOW))
        output("")

        output(c("RECOMMENDED COMMANDS:", Colors.YELLOW))
        output(f"{'-'*60}")
        output("")

        # Standard DNS tools
        output(c("[*] Attempt zone transfer (usually blocked):", Colors.CYAN))
        output(f"    dig axfr @{target} {dns_domain}")
        output("")

        output(c("[*] Query specific records:", Colors.CYAN))
        output(f"    dig @{target} {dns_domain} ANY")
        output(f"    dig @{target} _ldap._tcp.{dns_domain} SRV")
        output(f"    dig @{target} _kerberos._tcp.{dns_domain} SRV")
        output("")

        output(c("[*] Enumerate subdomains (dnsrecon):", Colors.CYAN))
        output(f"    dnsrecon -d {dns_domain} -n {target} -t std")
        output("")

        cache.add_next_step(
            finding="DNS port open",
            command=f"dig axfr @{target} {dns_domain}",
            description="Attempt DNS zone transfer",
            priority="low",
        )

    else:
        output(c("[*] No LDAP or DNS ports detected", Colors.YELLOW))
        output("")
        output("    DNS enumeration requires either:")
        output("    - LDAP (389/636) for adidnsdump")
        output("    - DNS (53) for zone transfers/queries")
        output("")

    # Always show nxc enum_dns as an option (uses WMI)
    output(c("ALTERNATIVE (uses WMI - executes on target):", Colors.YELLOW))
    output(f"{'-'*60}")
    output("")
    output(c("[*] NetExec enum_dns module (requires admin, uses WMI):", Colors.YELLOW))
    output(f"    nxc smb {target} {nxc_auth_info['auth_string']} -M enum_dns")
    if nxc_auth_info["kerberos_hint"]:
        output(f"    {nxc_auth_info['kerberos_hint']}")
    elif nxc_auth_info["alt_auth_hint"]:
        output(f"    {nxc_auth_info['alt_auth_hint']}")
    output("")

    # Store empty results since we don't execute anything
    cache.dns_records = []

    if args.json_output:
        JSON_DATA["dns"] = {
            "ldap_available": ldap_available or ldaps_available,
            "dns_available": dns_available,
            "recommended_tool": "adidnsdump" if (ldap_available or ldaps_available) else "dig",
        }
