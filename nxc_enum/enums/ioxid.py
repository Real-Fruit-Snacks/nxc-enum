"""iOXIDResolver enumeration for multi-homed host detection.

This module uses the DCOM iOXIDResolver interface (port 135) to enumerate
all network interfaces on a host. This works even without credentials.

This is pure DCOM RPC enumeration - queries IObjectExporter interface.
No authentication required, no command execution.

Pentest value: Discovers hidden network interfaces for pivoting.
"""

import re
import socket

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, is_proxy_mode, output, print_section, status
from ..core.runner import check_port
from ..reporting.next_steps import get_external_tool_auth

# DCOM port
DCOM_PORT = 135

# iOXIDResolver ServerAlive2 request
# This is a minimal DCE/RPC request to the IObjectExporter interface
IOXID_REQUEST = bytes(
    [
        # DCE/RPC Header
        0x05,
        0x00,  # Version 5.0
        0x0B,  # Packet type: bind
        0x03,  # Flags: first frag, last frag
        0x10,
        0x00,
        0x00,
        0x00,  # Data representation (little endian)
        0x48,
        0x00,  # Frag length
        0x00,
        0x00,  # Auth length
        0x01,
        0x00,
        0x00,
        0x00,  # Call ID
        # Bind context
        0xB8,
        0x10,  # Max xmit frag
        0xB8,
        0x10,  # Max recv frag
        0x00,
        0x00,
        0x00,
        0x00,  # Assoc group
        0x01,  # Number of context items
        0x00,
        0x00,
        0x00,  # Reserved
        # Context item
        0x00,
        0x00,  # Context ID
        0x01,  # Number of transfer syntaxes
        0x00,  # Reserved
        # IObjectExporter UUID: 99fcfec4-5260-101b-bbcb-00aa0021347a
        0xC4,
        0xFE,
        0xFC,
        0x99,
        0x60,
        0x52,
        0x1B,
        0x10,
        0xBB,
        0xCB,
        0x00,
        0xAA,
        0x00,
        0x21,
        0x34,
        0x7A,
        0x00,
        0x00,  # Version 0.0
        # Transfer syntax: NDR 8a885d04-1ceb-11c9-9fe8-08002b104860
        0x04,
        0x5D,
        0x88,
        0x8A,
        0xEB,
        0x1C,
        0xC9,
        0x11,
        0x9F,
        0xE8,
        0x08,
        0x00,
        0x2B,
        0x10,
        0x48,
        0x60,
        0x02,
        0x00,
        0x00,
        0x00,  # Version 2.0
    ]
)

# ServerAlive2 request (after bind)
SERVERALIVE2_REQUEST = bytes(
    [
        # DCE/RPC Header
        0x05,
        0x00,  # Version 5.0
        0x00,  # Packet type: request
        0x03,  # Flags: first frag, last frag
        0x10,
        0x00,
        0x00,
        0x00,  # Data representation
        0x18,
        0x00,  # Frag length
        0x00,
        0x00,  # Auth length
        0x02,
        0x00,
        0x00,
        0x00,  # Call ID
        0x00,
        0x00,
        0x00,
        0x00,  # Alloc hint
        0x00,
        0x00,  # Context ID
        0x05,
        0x00,  # Opnum: ServerAlive2
    ]
)


def query_ioxid(host: str, timeout: float = 5.0) -> list:
    """Query iOXIDResolver for network bindings.

    Returns list of IP addresses found in the response.
    """
    addresses = []

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, DCOM_PORT))

            # Send bind request
            sock.send(IOXID_REQUEST)
            response = sock.recv(4096)

            if len(response) < 24:
                return addresses

            # Check for bind_ack (type 0x0c)
            if response[2] != 0x0C:
                return addresses

            # Send ServerAlive2 request
            sock.send(SERVERALIVE2_REQUEST)
            response = sock.recv(8192)

            if len(response) < 50:
                return addresses

            # Parse response for addresses
            # Look for IP addresses in the string bindings
            # Format: ncacn_ip_tcp:IP_ADDRESS[PORT]
            response_str = response.decode("utf-8", errors="ignore")

            # Find all IPv4 addresses
            ipv4_pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
            for match in re.finditer(ipv4_pattern, response_str):
                ip = match.group(1)
                # Filter out obviously invalid IPs
                octets = [int(o) for o in ip.split(".")]
                if all(0 <= o <= 255 for o in octets):
                    if ip not in addresses and ip != "0.0.0.0":
                        addresses.append(ip)

            # Also look for raw binary IP addresses in the response
            # String bindings contain ncacn_ip_tcp followed by IP
            i = 0
            while i < len(response) - 4:
                # Look for the ncacn_ip_tcp tower identifier
                if response[i : i + 6] == b"ncacn":
                    # Find the IP after it
                    j = i + 6
                    while j < len(response) - 4:
                        if response[j] == ord("["):
                            break
                        j += 1
                    # Extract the IP between ncacn_ip_tcp: and [
                    ip_bytes = response[i:j]
                    ip_str = ip_bytes.decode("utf-8", errors="ignore")
                    for match in re.finditer(ipv4_pattern, ip_str):
                        ip = match.group(1)
                        if ip not in addresses and ip != "0.0.0.0":
                            addresses.append(ip)
                i += 1

    except (socket.timeout, socket.error, ConnectionRefusedError, OSError):
        pass

    return addresses


def enum_ioxid(args, cache):
    """Enumerate network interfaces via iOXIDResolver.

    Uses DCOM IObjectExporter::ServerAlive2 to discover all network
    bindings on a host. This works without authentication.

    Multi-homed hosts indicate potential pivot points between networks.
    """
    target = cache.target if cache else args.target
    print_section("iOXIDResolver Network Discovery", target, cache=cache)

    # Skip in proxy mode - DCOM raw sockets don't work over proxychains
    if is_proxy_mode():
        status("Skipped in proxy mode (DCOM incompatible with proxychains)", "info")
        if args.json_output:
            JSON_DATA["ioxid"] = {"addresses": [], "is_multi_homed": False}
        return

    status("Querying DCOM iOXIDResolver for network bindings...")

    # Check if port 135 is open
    if not check_port(target, DCOM_PORT, timeout=2.0):
        status("DCOM port 135 not accessible", "warning")
        if args.json_output:
            JSON_DATA["ioxid"] = {"addresses": [], "is_multi_homed": False}
        return

    # Query iOXIDResolver
    addresses = query_ioxid(target, timeout=args.timeout)

    # Store in cache
    cache.ioxid_addresses = addresses
    cache.ioxid_multi_homed = len(addresses) > 1

    if addresses:
        status(f"Found {len(addresses)} network binding(s)", "success")
        output("")

        # Check for multi-homed
        if len(addresses) > 1:
            output(
                c(
                    "[!] MULTI-HOMED HOST - Multiple network interfaces detected!",
                    Colors.YELLOW + Colors.BOLD,
                )
            )
            output("")

        output(c("NETWORK BINDINGS (iOXIDResolver)", Colors.CYAN))
        output(f"{'-'*50}")

        for ip in sorted(addresses):
            # Highlight addresses that differ from target
            if ip != target:
                output(
                    f"  {c('[!]', Colors.YELLOW)} "
                    f"{c(ip, Colors.GREEN + Colors.BOLD)} (additional network)"
                )
            else:
                output(f"  {c('[*]', Colors.BLUE)} {ip} (current target)")

        output("")

        # Other networks
        other_networks = [ip for ip in addresses if ip != target]
        if other_networks:
            output(c("[*] Additional networks discovered:", Colors.YELLOW))
            output(
                c(
                    "    These IPs may provide access to other network segments",
                    Colors.YELLOW,
                )
            )
            output("")

            # Add pivot recommendations
            auth_info = get_external_tool_auth(args, cache, tool="nxc")
            auth_hint = auth_info["auth_string"]
            for ip in other_networks[:3]:  # Limit to first 3
                cache.add_next_step(
                    finding=f"Additional network: {ip}",
                    command=f"nxc smb {ip} {auth_hint}",
                    description=f"Investigate network segment via {ip}",
                    priority="medium",
                )

        # Store for copy-paste
        cache.copy_paste_data["ioxid_addresses"] = set(addresses)
        if other_networks:
            cache.copy_paste_data["pivot_ips"] = set(other_networks)

    else:
        status("No additional network bindings discovered", "info")

    if args.json_output:
        JSON_DATA["ioxid"] = {
            "addresses": addresses,
            "is_multi_homed": len(addresses) > 1,
        }
