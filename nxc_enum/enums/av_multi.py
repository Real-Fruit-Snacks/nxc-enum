"""AV/EDR detection (multi-credential)."""

import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.constants import MULTI_ENUM_WORKERS, PROXY_MULTI_ENUM_WORKERS
from ..core.output import JSON_DATA, debug_nxc, is_proxy_mode, output, print_section, status
from ..core.runner import run_nxc

_lock = threading.Lock()


def enum_av_multi(args, creds: list, results, cache=None):
    """Enumerate AV/EDR for multiple credentials (requires local admin)."""
    target = cache.target if cache else args.target
    print_section("AV/EDR Detection", target, cache=cache)

    admin_creds = [cred for cred in creds if cred.is_admin]
    if not admin_creds:
        status("Skipping: requires local admin (no admin credentials available)", "info")
        results.av_skipped = [cred.display_name() for cred in creds]
        return

    non_admin_count = len(creds) - len(admin_creds)
    if non_admin_count > 0:
        msg = f"Running for {len(admin_creds)} admin user(s), "
        msg += f"skipping {non_admin_count} non-admin user(s)"
        status(msg)
        results.av_skipped = [cred.display_name() for cred in creds if not cred.is_admin]
    else:
        status(f"Checking for security products with {len(admin_creds)} admin user(s)...")
        results.av_skipped = []

    def get_av_for_cred(cred):
        auth = cred.auth_args()
        av_args = ["smb", target] + auth + ["-M", "enum_av"]
        rc, stdout, stderr = run_nxc(av_args, args.timeout)
        debug_nxc(av_args, stdout, stderr, f"AV/EDR ({cred.display_name()})")

        success = "ENUM_AV" in stdout
        products = []
        services = []  # Detailed service names from verbose INFO lines
        if success:
            for line in stdout.split("\n"):
                # Parse detailed service names from INFO lines (verbose mode)
                # Format: "INFO Detected installed service on <IP>: <Service Name>"
                # Use regex to be more specific and avoid false positives like "connection.py:67"
                service_match = re.search(
                    r"Detected installed service[^:]*:\s*(.+?)(?:\s*$|\s+\()", line
                )
                if service_match:
                    service_name = service_match.group(1).strip()
                    # Filter out obviously wrong values (numbers, file paths, etc.)
                    if service_name and not service_name.isdigit() and ".py" not in service_name:
                        if service_name not in services:
                            services.append(service_name)
                    continue

                if "Found" in line:
                    match = re.search(
                        r"Found\s+(.+?)\s+(INSTALLED|RUNNING|STOPPED)", line, re.IGNORECASE
                    )
                    if match:
                        products.append(match.group(1).strip())
        return cred.display_name(), success, products, services

    all_services = []  # Aggregate detailed service names from all credentials

    workers = PROXY_MULTI_ENUM_WORKERS if is_proxy_mode() else MULTI_ENUM_WORKERS
    with ThreadPoolExecutor(max_workers=min(len(admin_creds), workers)) as executor:
        futures = [executor.submit(get_av_for_cred, cred) for cred in admin_creds]
        for future in as_completed(futures):
            try:
                user, success, products, services = future.result()
                with _lock:
                    for product in products:
                        if product not in results.av_products:
                            results.av_products[product] = []
                        results.av_products[product].append(user)
                    # Aggregate detailed service names
                    for service in services:
                        if service not in all_services:
                            all_services.append(service)
            except Exception as e:
                status(f"Error enumerating AV products: {e}", "error")

    # Store aggregated services for potential use
    results.av_services = all_services

    output("")
    if results.av_products:
        output(f"{'Product':<25} {'Detected By'}")
        output(f"{'-'*25} {'-'*30}")
        for product, users in sorted(results.av_products.items()):
            output(f"{product:<25} {', '.join(users)}")
    else:
        status("No AV/EDR products detected", "info")

    if args.json_output:
        JSON_DATA["av_multi"] = {
            "products": {product: users for product, users in results.av_products.items()},
            "services": all_services,
            "skipped_users": results.av_skipped,
        }
