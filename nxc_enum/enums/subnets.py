"""AD Sites and Subnets enumeration.

This module enumerates Active Directory sites and their associated subnets.
Useful for understanding network topology and identifying additional targets.

This is pure enumeration - reads AD configuration via LDAP.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line


def enum_subnets(args, cache):
    """Enumerate AD sites and subnets.

    Uses the get-network LDAP module to enumerate AD site/subnet configuration.
    """
    target = cache.target if cache else args.target
    print_section("AD Sites and Subnets", target, cache=cache)

    # Skip if LDAP is unavailable (determined during cache priming)
    if not cache.ldap_available:
        status("LDAP unavailable - skipping AD subnet enumeration", "error")
        return

    auth = cache.auth_args
    status("Enumerating AD sites and subnets...")

    # Use get-network module
    subnet_args = ["ldap", target] + auth + ["-M", "get-network"]
    rc, stdout, stderr = run_nxc(subnet_args, args.timeout)
    debug_nxc(subnet_args, stdout, stderr, "AD Subnets")

    combined = stdout + stderr

    # Check for module errors/exceptions BEFORE parsing
    # Only check for actual Python exceptions, not general "error" messages
    exception_indicators = [
        "Traceback (most recent call last)",
        "UnicodeDecodeError",
        "AttributeError:",
        "TypeError:",
        "KeyError:",
        "IndexError:",
        "Exception:",
    ]
    if any(indicator in combined for indicator in exception_indicators):
        status("AD subnet enumeration failed (module error)", "error")
        output("")
        output(c("ALTERNATIVE: Query AD subnets directly with ldapsearch:", Colors.BLUE))
        # Get domain components from cache
        dns_domain = cache.domain_info.get("dns_domain", "") if cache.domain_info else ""
        if dns_domain:
            dc_parts = ",".join([f"DC={p}" for p in dns_domain.split(".")])
            base_dn = f"CN=Subnets,CN=Sites,CN=Configuration,{dc_parts}"
        else:
            base_dn = "CN=Subnets,CN=Sites,CN=Configuration,DC=domain,DC=local"
        output(f"    ldapsearch -H ldap://{target} -D '<user>@<domain>' -w '<pass>' \\")
        output(f"      -b '{base_dn}' '(objectClass=subnet)' cn siteObject")
        output("")
        if args.json_output:
            JSON_DATA["ad_subnets"] = {"error": "Module exception"}
        return

    subnets = []
    sites = set()

    # Parse output
    # Format varies, but typically:
    # LDAP IP PORT HOST [*] Site: SiteName
    # LDAP IP PORT HOST [*] Subnet: 10.0.0.0/24 -> SiteName
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        if is_nxc_noise_line(line):
            continue

        line_lower = line.lower()

        # Look for subnet lines
        if "subnet" in line_lower:
            # Extract subnet and site
            # Pattern: "Subnet: 10.0.0.0/24 -> SiteName" or "10.0.0.0/24 (SiteName)"
            subnet_match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", line)
            if subnet_match:
                subnet = subnet_match.group(1)
                # Try to find associated site
                site = None
                if "->" in line:
                    site = line.split("->")[-1].strip()
                elif "(" in line and ")" in line:
                    site_match = re.search(r"\(([^)]+)\)", line)
                    if site_match:
                        site = site_match.group(1)

                subnets.append(
                    {
                        "subnet": subnet,
                        "site": site,
                    }
                )
                if site:
                    sites.add(site)

        # Look for site lines
        elif "site" in line_lower and ":" in line:
            parts = line.split(":", 1)
            if len(parts) >= 2:
                site_name = parts[1].strip()
                if site_name and not site_name.startswith("["):
                    sites.add(site_name)

    # Store results
    cache.ad_subnets = subnets
    cache.ad_sites = list(sites)

    # Display results
    if subnets or sites:
        status(
            f"Found {len(subnets)} subnet(s) in {len(sites)} site(s)",
            "success",
        )
        output("")

        if sites:
            output(c("AD SITES", Colors.CYAN))
            output(f"{'-'*50}")
            for site in sorted(sites):
                output(f"  {c('[*]', Colors.CYAN)} {site}")
            output("")

        if subnets:
            output(c("AD SUBNETS", Colors.CYAN))
            output(f"{'Subnet':<20} {'Site'}")
            output(f"{'-'*20} {'-'*30}")
            for entry in sorted(subnets, key=lambda x: x["subnet"]):
                subnet = entry["subnet"]
                site = entry["site"] or "Unknown"
                output(f"{subnet:<20} {site}")
            output("")

            # Store copy-paste data
            cache.copy_paste_data["subnets"] = set(s["subnet"] for s in subnets)

    else:
        # Check for common errors (combined already defined above)
        if "STATUS_ACCESS_DENIED" in combined.upper():
            status("Access denied - cannot enumerate AD subnets", "error")
        elif "Module not found" in combined or (
            "module" in combined.lower() and "error" in combined.lower()
        ):
            status("get-network module not available", "error")
        else:
            status("No AD subnets found", "info")

    if args.json_output:
        JSON_DATA["ad_subnets"] = {
            "subnets": subnets,
            "sites": list(sites),
            "count": len(subnets),
        }
