"""DNS enumeration."""

from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line


def enum_dns(args, cache):
    """Enumerate DNS records from AD-integrated DNS."""
    print_section("DNS Enumeration", args.target)

    auth = cache.auth_args
    status("Querying AD-integrated DNS records...")

    dns_args = ["smb", args.target] + auth + ["-M", "enum_dns"]
    rc, stdout, stderr = run_nxc(dns_args, args.timeout)
    debug_nxc(dns_args, stdout, stderr, "DNS Enumeration")

    records = []
    for line in stdout.split("\n"):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue

        # Primary: Parse "Name => zone.domain.local" format (cleaner)
        if "Name =>" in line:
            zone = line.split("=>", 1)[-1].strip()
            if zone and zone not in records:
                records.append(zone)
            continue

        # Fallback: Parse Python list format from ENUM_DNS summary line
        if "ENUM_DNS" in line or "Domains retrieved" in line:
            if ":" in line:
                record_info = line.split(":", 1)[-1].strip()
                if record_info:
                    # Parse Python list representation like "['domain1', 'domain2']"
                    if record_info.startswith("[") and record_info.endswith("]"):
                        inner = record_info[1:-1]
                        for item in inner.split(","):
                            item = item.strip().strip("'").strip('"')
                            if item and item not in records:
                                records.append(item)

    cache.dns_records = records

    if records:
        status(f"Found {len(records)} DNS record(s):", "info")
        output("")
        for record in records[:20]:
            output(f"  {record}")
        if len(records) > 20:
            output(f"  ... and {len(records) - 20} more")
    else:
        status(
            "No DNS records returned (module uses WMI - try adidnsdump for LDAP-based enumeration)",
            "info",
        )

        # Add recommendation for LDAP-based DNS enumeration (works for any domain user)
        domain = cache.domain_info.get("dns_domain", "<domain>")
        cache.add_next_step(
            finding="DNS enumeration via WMI returned no results",
            command=f"adidnsdump -u '{domain}\\<user>' -p '<pass>' --dns-tcp {args.target}",
            description="LDAP-based DNS zone dump - works for any authenticated domain user",
            priority="low",
        )

    if args.json_output:
        JSON_DATA["dns_records"] = records
