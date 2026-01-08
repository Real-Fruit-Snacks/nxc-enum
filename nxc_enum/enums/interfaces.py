"""Network interface enumeration.

This module enumerates network interfaces on the target system using
SMB IOCTL (FSCTL_QUERY_NETWORK_INTERFACE_INFO) or Remote Registry.

This is pure enumeration - uses SMB IOCTL or registry queries.
No command execution on the target.

Pentest value: Identifies multi-homed hosts for potential pivot points.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

# Regex patterns for parsing interface info
RE_IFACE_NAME = re.compile(r"Interface:\s*(.+)", re.IGNORECASE)
RE_IP_ADDR = re.compile(r"IP(?:v[46])?(?:\s+Address)?:\s*(\S+)", re.IGNORECASE)
RE_LINK_SPEED = re.compile(r"Link\s*Speed:\s*(\S+)", re.IGNORECASE)
RE_DHCP = re.compile(r"DHCP:\s*(\S+)", re.IGNORECASE)
RE_GATEWAY = re.compile(r"Gateway:\s*(\S+)", re.IGNORECASE)


def enum_interfaces(args, cache):
    """Enumerate network interfaces on the target.

    Uses nxc --interfaces flag which queries via SMB IOCTL
    (FSCTL_QUERY_NETWORK_INTERFACE_INFO) on SMB 2.x/3.x or falls
    back to Remote Registry on older systems.

    Multi-homed hosts are valuable pivot points in penetration tests.
    """
    target = cache.target if cache else args.target
    print_section("Network Interface Enumeration", target)

    auth = cache.auth_args
    status("Enumerating network interfaces...")

    # Query interfaces using nxc --interfaces
    iface_args = ["smb", target] + auth + ["--interfaces"]
    rc, stdout, stderr = run_nxc(iface_args, args.timeout)
    debug_nxc(iface_args, stdout, stderr, "Network Interfaces")

    interfaces = []
    current_iface = {}

    # Parse output
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            # Save current interface if we have data
            if current_iface.get("ip"):
                interfaces.append(current_iface.copy())
                current_iface = {}
            continue

        if is_nxc_noise_line(line):
            continue

        # Look for interface markers
        iface_match = RE_IFACE_NAME.search(line)
        if iface_match:
            # Save previous interface if exists
            if current_iface.get("ip"):
                interfaces.append(current_iface.copy())
            current_iface = {"name": iface_match.group(1).strip()}

        # Parse IP address
        ip_match = RE_IP_ADDR.search(line)
        if ip_match:
            ip = ip_match.group(1)
            if ip not in ("0.0.0.0", "127.0.0.1", "::1"):
                if "ip" not in current_iface:
                    current_iface["ip"] = []
                current_iface["ip"].append(ip)

        # Parse link speed
        speed_match = RE_LINK_SPEED.search(line)
        if speed_match:
            current_iface["speed"] = speed_match.group(1)

        # Parse DHCP status
        dhcp_match = RE_DHCP.search(line)
        if dhcp_match:
            current_iface["dhcp"] = dhcp_match.group(1)

        # Parse gateway
        gateway_match = RE_GATEWAY.search(line)
        if gateway_match:
            current_iface["gateway"] = gateway_match.group(1)

        # Alternative format: direct IP listing
        # "SMB IP HOSTNAME Interface: 10.0.0.5"
        if "Interface:" in line or "IP:" in line:
            parts = line.split()
            for i, part in enumerate(parts):
                # Look for IP addresses
                if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", part):
                    if part not in ("0.0.0.0", "127.0.0.1"):
                        if "ip" not in current_iface:
                            current_iface["ip"] = []
                        if part not in current_iface["ip"]:
                            current_iface["ip"].append(part)

    # Don't forget last interface
    if current_iface.get("ip"):
        interfaces.append(current_iface.copy())

    # Check for access/error conditions
    combined = stdout + stderr
    access_denied = "STATUS_ACCESS_DENIED" in combined.upper()
    requires_admin = "requires admin" in combined.lower()

    # Store in cache
    cache.network_interfaces = interfaces
    cache.is_multi_homed = len(interfaces) > 1

    if interfaces:
        # Count unique IPs
        all_ips = []
        for iface in interfaces:
            all_ips.extend(iface.get("ip", []))
        unique_ips = list(set(all_ips))

        status(
            f"Found {len(interfaces)} interface(s) with {len(unique_ips)} IP(s)",
            "success",
        )
        output("")

        # Check for multi-homed (potential pivot)
        if len(unique_ips) > 1:
            output(
                c(
                    "[!] MULTI-HOMED HOST DETECTED - Potential pivot point!",
                    Colors.YELLOW + Colors.BOLD,
                )
            )
            output("")

        output(c("NETWORK INTERFACES", Colors.CYAN))
        output(f"{'-'*60}")

        for iface in interfaces:
            name = iface.get("name", "Unknown")
            ips = iface.get("ip", [])
            speed = iface.get("speed", "")
            dhcp = iface.get("dhcp", "")
            gateway = iface.get("gateway", "")

            output(f"  {c('Interface:', Colors.CYAN)} {name}")
            for ip in ips:
                # Highlight non-target IPs (potential other networks)
                if ip != target:
                    output(f"    {c('IP:', Colors.GREEN)} {c(ip, Colors.GREEN + Colors.BOLD)}")
                else:
                    output(f"    {c('IP:', Colors.BLUE)} {ip}")
            if speed:
                output(f"    {c('Speed:', Colors.BLUE)} {speed}")
            if gateway:
                output(f"    {c('Gateway:', Colors.BLUE)} {gateway}")
            if dhcp:
                output(f"    {c('DHCP:', Colors.BLUE)} {dhcp}")
            output("")

        # Store IPs for copy-paste
        cache.copy_paste_data["interface_ips"] = set(unique_ips)

        # Add pivot recommendation if multi-homed
        if len(unique_ips) > 1:
            other_ips = [ip for ip in unique_ips if ip != target]
            cache.add_next_step(
                finding=f"Multi-homed host with {len(other_ips)} additional network(s)",
                command=f"# Additional networks: {', '.join(other_ips)}",
                description="Investigate other network segments for lateral movement",
                priority="medium",
            )

    elif access_denied or requires_admin:
        status("Requires local admin to enumerate interfaces", "warning")
    else:
        if not stdout.strip() or rc != 0:
            status("Could not enumerate network interfaces", "error")
        else:
            status("No additional network interfaces found", "info")

    if args.json_output:
        JSON_DATA["interfaces"] = {
            "interfaces": interfaces,
            "is_multi_homed": len(interfaces) > 1,
            "count": len(interfaces),
        }
