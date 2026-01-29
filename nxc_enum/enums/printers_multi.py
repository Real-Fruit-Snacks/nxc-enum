"""Printer enumeration (multi-credential)."""

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.colors import Colors, c
from ..core.constants import MULTI_ENUM_WORKERS, PROXY_MULTI_ENUM_WORKERS
from ..core.output import JSON_DATA, is_proxy_mode, output, print_section, status
from ..core.runner import run_nxc

# Import verbose parsing from single-cred module
from .printers import parse_verbose_spooler_info

_lock = threading.Lock()


def enum_printers_multi(args, creds: list, results, cache=None):
    """Enumerate printers for multiple credentials."""
    target = cache.target if cache else args.target
    print_section("Printers", target)  # No cache - tests multiple users
    status(f"Checking print spooler for {len(creds)} user(s)...")

    def get_printers_for_cred(cred):
        auth = cred.auth_args()
        rc, stdout, stderr = run_nxc(["smb", target] + auth + ["-M", "spooler"], args.timeout)
        success = "SPOOLER" in stdout
        spooler_running = "enabled" in stdout.lower() or "running" in stdout.lower()

        # Parse verbose output for additional details
        verbose_info = parse_verbose_spooler_info(stdout)

        return cred.display_name(), success, spooler_running, verbose_info

    all_verbose_info = {"printers": [], "print_servers": [], "drivers": [], "info_messages": []}

    workers = PROXY_MULTI_ENUM_WORKERS if is_proxy_mode() else MULTI_ENUM_WORKERS
    with ThreadPoolExecutor(max_workers=min(len(creds), workers)) as executor:
        futures = [executor.submit(get_printers_for_cred, cred) for cred in creds]
        for future in as_completed(futures):
            try:
                user, success, spooler_running, verbose_info = future.result()
                with _lock:
                    results.printers[user] = (success, spooler_running, verbose_info)
                    # Aggregate verbose data from all credentials
                    for printer in verbose_info.get("printers", []):
                        if printer not in all_verbose_info["printers"]:
                            all_verbose_info["printers"].append(printer)
                    for server in verbose_info.get("print_servers", []):
                        if server not in all_verbose_info["print_servers"]:
                            all_verbose_info["print_servers"].append(server)
                    for driver in verbose_info.get("drivers", []):
                        if driver not in all_verbose_info["drivers"]:
                            all_verbose_info["drivers"].append(driver)
                    for msg in verbose_info.get("info_messages", []):
                        if msg not in all_verbose_info["info_messages"]:
                            all_verbose_info["info_messages"].append(msg)
            except Exception as e:
                status(f"Error enumerating printers: {e}", "error")

    output("")
    spooler_detected = False
    for user in [cred.display_name() for cred in creds]:
        result_data = results.printers.get(user, (False, False, {}))
        success = result_data[0]
        spooler_running = result_data[1]
        if success:
            if spooler_running:
                status(f"{user}: Spooler RUNNING", "warning")
                spooler_detected = True
            else:
                status(f"{user}: Spooler not running", "info")
        else:
            status(f"{user}: Module failed", "error")

    if spooler_detected:
        output("")
        status("Print spooler running - check for PrintNightmare!", "warning")

    # Display aggregated verbose information
    if all_verbose_info["print_servers"]:
        output("")
        output(c("Print Servers:", Colors.CYAN))
        for server in all_verbose_info["print_servers"]:
            output(f"  {server}")

    if all_verbose_info["printers"]:
        output("")
        output(c(f"Printers Detected ({len(all_verbose_info['printers'])}):", Colors.CYAN))
        for printer in all_verbose_info["printers"]:
            name = printer.get("name", "Unknown")
            driver = printer.get("driver", "")
            port = printer.get("port", "")
            share = printer.get("share", "")
            location = printer.get("location", "")

            output(f"  {c(name, Colors.GREEN)}")
            if driver:
                output(f"    Driver: {driver}")
            if port:
                output(f"    Port: {port}")
            if share:
                output(f"    Share: {share}")
            if location:
                output(f"    Location: {location}")

    if all_verbose_info["drivers"] and not all_verbose_info["printers"]:
        # Show drivers if no full printer info but drivers were detected
        output("")
        output(c("Print Drivers:", Colors.CYAN))
        for driver in all_verbose_info["drivers"]:
            output(f"  {driver}")

    if args.json_output:
        JSON_DATA["printers_multi"] = {
            user: {
                "success": result[0],
                "spooler_running": result[1],
                "printers": result[2].get("printers", []) if len(result) > 2 else [],
                "print_servers": result[2].get("print_servers", []) if len(result) > 2 else [],
                "drivers": result[2].get("drivers", []) if len(result) > 2 else [],
            }
            for user, result in results.printers.items()
        }
