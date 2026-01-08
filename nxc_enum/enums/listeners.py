"""Listener/port scanning."""

from concurrent.futures import ThreadPoolExecutor

from ..core.constants import PORT_CHECK_TIMEOUT, PROXY_PORT_CHECK_TIMEOUT
from ..core.output import JSON_DATA, is_proxy_mode, print_section, status
from ..core.runner import check_port


def enum_listeners(args, listener_results: dict, cache=None):
    """Scan for open ports in parallel."""
    target = cache.target if cache else args.target
    print_section("Listener Scan", target)

    ports = [
        (389, "LDAP"),
        (636, "LDAPS"),
        (445, "SMB"),
        (139, "SMB over NetBIOS"),
    ]

    # Use proxy-aware timeout if proxy mode is enabled
    port_timeout = PROXY_PORT_CHECK_TIMEOUT if is_proxy_mode() else PORT_CHECK_TIMEOUT

    def check_single_port(port_info):
        port, name = port_info
        is_open = check_port(target, port, timeout=port_timeout)
        return (name, port, is_open)

    # Run all port checks in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(check_single_port, p) for p in ports]
        results = [f.result() for f in futures]

    # Process results in original order for consistent output
    for name, port, is_open in results:
        listener_results[name] = {"port": port, "open": is_open}
        status(f"Checking {name}")
        if is_open:
            status(f"{name} is accessible on {port}/tcp", "success")
        else:
            status(f"{name} is not accessible on {port}/tcp", "error")

    if args.json_output:
        JSON_DATA["listeners"] = listener_results
