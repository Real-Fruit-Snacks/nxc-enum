"""Listener/port scanning."""

from concurrent.futures import ThreadPoolExecutor

from ..core.runner import check_port
from ..core.output import status, print_section, JSON_DATA


def enum_listeners(args, listener_results: dict):
    """Scan for open ports in parallel."""
    print_section("Listener Scan", args.target)

    ports = [
        (389, "LDAP"),
        (636, "LDAPS"),
        (445, "SMB"),
        (139, "SMB over NetBIOS"),
    ]

    def check_single_port(port_info):
        port, name = port_info
        is_open = check_port(args.target, port)
        return (name, port, is_open)

    # Run all port checks in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(check_single_port, p) for p in ports]
        results = [f.result() for f in futures]

    # Process results in original order for consistent output
    for name, port, is_open in results:
        listener_results[name] = {'port': port, 'open': is_open}
        status(f"Checking {name}")
        if is_open:
            status(f"{name} is accessible on {port}/tcp", "success")
        else:
            status(f"{name} is not accessible on {port}/tcp", "error")

    if args.json_output:
        JSON_DATA['listeners'] = listener_results
