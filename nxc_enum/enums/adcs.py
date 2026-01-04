"""ADCS enumeration."""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line


def enum_adcs(args, cache):
    """Enumerate ADCS certificate templates and PKI infrastructure."""
    print_section("ADCS Enumeration", args.target)

    auth = cache.auth_args
    status("Querying ADCS certificate templates...")

    adcs_args = ["ldap", args.target] + auth + ["-M", "adcs"]
    rc, stdout, stderr = run_nxc(adcs_args, args.timeout)
    debug_nxc(adcs_args, stdout, stderr, "ADCS Enumeration")

    templates = []
    enrollment_servers = []
    ca_names = []
    web_services = []

    for line in stdout.split("\n"):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue

        # Parse PKI Enrollment Server hostname
        if "PKI Enrollment Server:" in line:
            server = line.split("PKI Enrollment Server:", 1)[-1].strip()
            if server and server not in enrollment_servers:
                enrollment_servers.append(server)

        # Parse Certificate Authority CN
        if "Found CN:" in line:
            ca_name = line.split("Found CN:", 1)[-1].strip()
            if ca_name and ca_name not in ca_names:
                ca_names.append(ca_name)

        # Parse PKI Enrollment WebService URLs (ESC8 indicator)
        if "PKI Enrollment WebService:" in line or "Enrollment WebService:" in line:
            match = re.search(r"https?://[^\s]+", line)
            if match:
                url = match.group(0)
                if url and url not in web_services:
                    web_services.append(url)

        # Parse Certificate Template names
        if "Certificate Template:" in line:
            template = line.split("Certificate Template:", 1)[-1].strip()
            if template and template not in templates:
                templates.append(template)
        elif "Found Template:" in line:
            template = line.split("Found Template:", 1)[-1].strip()
            if template and template not in templates:
                templates.append(template)

    # Store in cache for other modules
    cache.adcs_templates = templates
    cache.adcs_info = {
        "enrollment_servers": enrollment_servers,
        "ca_names": ca_names,
        "web_services": web_services,
        "templates": templates,
    }

    # Display results
    if enrollment_servers or ca_names:
        if enrollment_servers:
            status(f"Found {len(enrollment_servers)} PKI Enrollment Server(s):", "info")
            for server in enrollment_servers:
                output(f"  {c(server, Colors.CYAN)}")
        if ca_names:
            status(f"Found {len(ca_names)} Certificate Authority(s):", "warning")
            for ca in ca_names:
                output(f"  {c(ca, Colors.YELLOW)}")

        # Display web enrollment endpoints (ESC8 vulnerability indicator)
        if web_services:
            status(f"Found {len(web_services)} Web Enrollment Endpoint(s):", "warning")
            for url in web_services:
                output(f"  {c(url, Colors.RED)}")
            output("")
            output(
                f"  {c('[!] Web enrollment endpoints may be vulnerable to ESC8 (NTLM relay)', Colors.RED)}"
            )

        # Add next step recommendation for certipy
        domain = cache.domain_info.get("dns_domain", "<domain>")
        user = args.user if args.user else "<user>"
        cache.add_next_step(
            finding=f"ADCS infrastructure found ({len(ca_names)} CA)",
            command=f"certipy find -u '{user}@{domain}' -p '<pass>' -dc-ip {args.target}",
            description="Check for ESC1-ESC8 certificate template vulnerabilities",
            priority="high",
        )

        # Add ESC8 specific recommendation if web services found
        if web_services:
            cache.add_next_step(
                finding="Web enrollment endpoint found (potential ESC8)",
                command=f"certipy relay -ca {ca_names[0] if ca_names else '<ca>'} -template DomainController",
                description="Relay NTLM auth to web enrollment for domain admin certificate",
                priority="high",
            )
    else:
        status("No ADCS infrastructure found", "info")

    if templates:
        status(f"Found {len(templates)} Certificate Template(s):", "warning")
        for template in templates:
            # Highlight potentially dangerous templates
            if template.lower() in [
                "user",
                "machine",
                "domaincontroller",
                "webserver",
                "kerberoasting",
            ]:
                output(f"  {c(template, Colors.YELLOW)}")
            else:
                output(f"  {c(template, Colors.CYAN)}")

    if args.json_output:
        JSON_DATA["adcs"] = {
            "enrollment_servers": enrollment_servers,
            "ca_names": ca_names,
            "web_services": web_services,
            "templates": templates,
        }
