"""AV/EDR detection (single credential)."""

import re

from ..core.runner import run_nxc
from ..core.output import status, print_section, debug_nxc, JSON_DATA
from ..core.colors import Colors, c
from ..parsing.nxc_output import is_nxc_noise_line


def enum_av(args, cache, is_admin: bool = True):
    """Enumerate installed AV/EDR solutions (requires local admin)."""
    print_section("AV/EDR Detection", args.target)

    if not is_admin:
        status("Skipping: requires local admin (current user is not admin)", "info")
        return

    auth = cache.auth_args
    status("Checking for installed security products")
    av_args = ["smb", args.target] + auth + ["-M", "enum_av"]
    rc, stdout, stderr = run_nxc(av_args, args.timeout)
    debug_nxc(av_args, stdout, stderr, "AV/EDR Detection")

    found_av = False
    av_products = []
    av_services = []  # Detailed service names from verbose/INFO output

    for line in stdout.split('\n'):
        # Parse detailed service names from INFO lines (verbose mode) FIRST
        # This must run BEFORE is_nxc_noise_line() which filters all INFO lines
        # Format: "INFO Detected installed service on <IP>: <Service Name>"
        # Use regex to be more specific and avoid false positives like "connection.py:67"
        service_match = re.search(r'Detected installed service[^:]*:\s*(.+?)(?:\s*$|\s+\()', line)
        if service_match:
            service_name = service_match.group(1).strip()
            # Filter out obviously wrong values (numbers, file paths, etc.)
            if service_name and not service_name.isdigit() and '.py' not in service_name:
                if service_name not in av_services:
                    av_services.append(service_name)
            continue  # Already processed this INFO line

        # Skip other noise lines (connection metadata, etc.)
        if is_nxc_noise_line(line):
            continue

        # Parse summary line: "Found Windows Defender INSTALLED"
        if 'Found' in line and ('INSTALLED' in line or 'Antivirus' in line or 'Defender' in line or 'EDR' in line):
            found_idx = line.find('Found')
            product_part = line[found_idx + 6:].strip()
            product_name = product_part.replace('INSTALLED', '').strip()
            if product_name and product_name not in av_products:
                status(f"{c(product_name, Colors.YELLOW)} detected", "warning")
                found_av = True
                av_products.append(product_name)

    if not found_av:
        status("No AV/EDR products detected (or module unavailable)", "info")

    cache.av_products = av_products
    cache.av_services = av_services  # Detailed service names if available

    if args.json_output:
        JSON_DATA['av_edr'] = {
            'products': av_products,
            'services': av_services
        }
