"""Printer enumeration (single credential)."""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line
from ..reporting.next_steps import get_external_tool_auth

# Patterns for verbose spooler output parsing
RE_SPOOLER_STATUS = re.compile(
    r"(Spooler|Print Spooler)[:\s]*(enabled|disabled|running|stopped)", re.IGNORECASE
)
# Match printer names but NOT SMB banner lines like "(name:DC01)"
RE_PRINTER_NAME = re.compile(
    r"(?:^|[\s\[])(?:Printer|PrinterName|Printer Name|Name)\s*:\s*([^\(\)]+?)(?:\s*$|\s+[A-Z])",
    re.IGNORECASE,
)
RE_PRINT_SERVER = re.compile(r"(Print Server|PrintServer|Server)[:\s]+(.+)", re.IGNORECASE)
RE_DRIVER_NAME = re.compile(r"(Driver|DriverName)[:\s]+(.+)", re.IGNORECASE)
RE_PORT_NAME = re.compile(r"(Port|PortName)[:\s]+(.+)", re.IGNORECASE)
RE_SHARE_NAME = re.compile(r"(ShareName|Share)[:\s]+(.+)", re.IGNORECASE)
RE_LOCATION = re.compile(r"Location[:\s]+(.+)", re.IGNORECASE)


def parse_verbose_spooler_info(stdout: str) -> dict:
    """Parse verbose spooler output for additional metadata.

    Returns dict with:
        - status: Spooler status (enabled/disabled/running/stopped)
        - printers: List of printer info dicts (name, driver, port, share, location)
        - print_servers: List of detected print server names
        - info_messages: List of relevant INFO lines
    """
    verbose_data = {
        "status": None,
        "printers": [],
        "print_servers": [],
        "drivers": [],
        "info_messages": [],
    }

    current_printer = {}

    for line in stdout.split("\n"):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Parse spooler status from INFO or regular lines
        status_match = RE_SPOOLER_STATUS.search(line_stripped)
        if status_match:
            verbose_data["status"] = status_match.group(2).lower()
            continue

        # Parse printer names - skip SMB banner lines
        # SMB banner lines contain patterns like "(name:DC01) (domain:...) (signing:...)"
        if "(domain:" in line_stripped and "(signing:" in line_stripped:
            continue

        printer_match = RE_PRINTER_NAME.search(line_stripped)
        if printer_match:
            printer_name = printer_match.group(1).strip()
            # Additional validation: skip if it looks like SMB banner content
            if printer_name and not any(
                x in printer_name.lower() for x in ["domain:", "signing:", "smbv1:"]
            ):
                # If we have a current printer being built, save it
                if current_printer and "name" in current_printer:
                    verbose_data["printers"].append(current_printer.copy())
                current_printer = {"name": printer_name}
            continue

        # Parse print server names
        server_match = RE_PRINT_SERVER.search(line_stripped)
        if server_match:
            server_name = server_match.group(2).strip()
            if server_name and server_name not in verbose_data["print_servers"]:
                verbose_data["print_servers"].append(server_name)
            continue

        # Parse driver names (associate with current printer if available)
        driver_match = RE_DRIVER_NAME.search(line_stripped)
        if driver_match:
            driver_name = driver_match.group(2).strip()
            if current_printer:
                current_printer["driver"] = driver_name
            if driver_name and driver_name not in verbose_data["drivers"]:
                verbose_data["drivers"].append(driver_name)
            continue

        # Parse port names
        port_match = RE_PORT_NAME.search(line_stripped)
        if port_match:
            if current_printer:
                current_printer["port"] = port_match.group(2).strip()
            continue

        # Parse share names
        share_match = RE_SHARE_NAME.search(line_stripped)
        if share_match:
            if current_printer:
                current_printer["share"] = share_match.group(2).strip()
            continue

        # Parse location
        location_match = RE_LOCATION.search(line_stripped)
        if location_match:
            if current_printer:
                current_printer["location"] = location_match.group(2).strip()
            continue

        # Capture relevant INFO messages
        if "[*]" in line_stripped or "INFO" in line_stripped.upper():
            # Filter for spooler/printer related info
            lower_line = line_stripped.lower()
            if any(kw in lower_line for kw in ["spooler", "printer", "print", "driver", "port"]):
                clean_msg = line_stripped
                for prefix in ["[*]", "INFO", "[INFO]"]:
                    clean_msg = clean_msg.replace(prefix, "").strip()
                if clean_msg and clean_msg not in verbose_data["info_messages"]:
                    verbose_data["info_messages"].append(clean_msg)

    # Save any remaining printer being parsed
    if current_printer and "name" in current_printer:
        verbose_data["printers"].append(current_printer)

    return verbose_data


def enum_printers(args, cache):
    """Enumerate printers via RPC."""
    target = cache.target if cache else args.target
    print_section("Printers via RPC", target, cache=cache)

    auth = cache.auth_args
    printers_args = ["smb", target] + auth + ["-M", "spooler"]
    rc, stdout, stderr = run_nxc(printers_args, args.timeout)
    debug_nxc(printers_args, stdout, stderr, "Printers (spooler)")

    # Parse verbose output for additional metadata
    verbose_info = parse_verbose_spooler_info(stdout)

    found_printers = False
    printers = []
    printer_names = []

    for line in stdout.split("\n"):
        if is_nxc_noise_line(line):
            continue
        if "Spooler" in line and "enabled" in line.lower():
            status(
                "Print spooler running - potential PrintNightmare (CVE-2021-34527) target!",
                "warning",
            )
            found_printers = True
            printers.append("Spooler enabled")
            cache.spooler_running = True

            # Add PrintNightmare recommendation
            auth_info = get_external_tool_auth(args, cache, tool="nxc")
            auth_hint = auth_info["auth_string"]
            cache.add_next_step(
                finding="Print spooler service running",
                command=f"nxc smb {target} {auth_hint} -M printnightmare",
                description="Check for PrintNightmare (CVE-2021-34527) vulnerability",
                priority="high",
            )
        elif "[+]" in line:
            content = line.split("[+]", 1)[-1].strip()
            if is_nxc_noise_line(content):
                continue
            if content:
                status(content, "success")
                found_printers = True
                printers.append(content)

    # Extract printer names from verbose data
    for printer in verbose_info["printers"]:
        if "name" in printer:
            name = printer["name"]
            if name not in printer_names:
                printer_names.append(name)

    # Store verbose data in cache
    cache.spooler_info = {
        "status": verbose_info["status"] or ("enabled" if cache.spooler_running else "unknown"),
        "print_servers": verbose_info["print_servers"],
        "drivers": verbose_info["drivers"],
    }
    cache.printer_names = printer_names

    if not found_printers:
        status("No printers returned (this is not an error)", "success")

    # Display verbose information if available
    if verbose_info["print_servers"]:
        output("")
        output(c("PRINT SERVERS:", Colors.CYAN))
        for server in verbose_info["print_servers"]:
            output(f"  {server}")

    if verbose_info["printers"]:
        output("")
        output(c(f"PRINTERS DETECTED ({len(verbose_info['printers'])}):", Colors.CYAN))
        for printer in verbose_info["printers"]:
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

    if verbose_info["drivers"] and not verbose_info["printers"]:
        # Show drivers if no full printer info but drivers were detected
        output("")
        output(c("PRINT DRIVERS:", Colors.CYAN))
        for driver in verbose_info["drivers"]:
            output(f"  {driver}")

    # Display relevant verbose INFO messages
    if verbose_info["info_messages"]:
        output("")
        output(c("VERBOSE INFO:", Colors.CYAN))
        for msg in verbose_info["info_messages"][:5]:  # Limit to first 5
            output(f"  {msg}")

    if args.json_output:
        JSON_DATA["printers"] = {
            "spooler_running": cache.spooler_running,
            "spooler_status": cache.spooler_info.get("status"),
            "messages": printers,
            "printer_names": printer_names,
            "printers": verbose_info["printers"],
            "print_servers": verbose_info["print_servers"],
            "drivers": verbose_info["drivers"],
        }
