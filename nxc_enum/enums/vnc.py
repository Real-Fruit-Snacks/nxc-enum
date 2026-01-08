"""VNC (Virtual Network Computing) service detection.

This module detects VNC services running on the target by checking
common VNC ports and grabbing service banners.

This is pure network probing - TCP connect and banner grab.
No authentication attempts or command execution.

Pentest value: VNC often has weak/default passwords and provides GUI access.
"""

import re
import socket

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, is_proxy_mode, output, print_section, status
from ..core.runner import check_port, run_nxc

# Common VNC ports
VNC_PORTS = [5900, 5901, 5902, 5903, 5800, 5801]  # 5900+N for display N, 5800 for HTTP

# VNC banner pattern
RE_VNC_VERSION = re.compile(r"RFB\s+(\d+\.\d+)", re.IGNORECASE)


def grab_vnc_banner(host: str, port: int, timeout: float = 3.0) -> dict:
    """Attempt to grab VNC banner from a port.

    Returns dict with version info if VNC detected, empty dict otherwise.
    """
    result = {"port": port, "detected": False}

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))

            # VNC servers send version string immediately
            banner = sock.recv(1024).decode("utf-8", errors="ignore")

            if banner:
                result["banner"] = banner.strip()

                # Parse RFB version
                version_match = RE_VNC_VERSION.search(banner)
                if version_match:
                    result["detected"] = True
                    result["version"] = version_match.group(1)
                elif "RFB" in banner.upper():
                    result["detected"] = True
                    result["version"] = "Unknown"

    except (socket.timeout, socket.error, ConnectionRefusedError, OSError):
        pass

    return result


def enum_vnc(args, cache):
    """Detect VNC services on the target.

    Scans common VNC ports (5900-5903, 5800-5801) for VNC services.
    VNC provides remote GUI access and often has weak security.

    Attack paths:
    - Default/weak password authentication
    - Unauthenticated access (misconfigured)
    - Credential brute forcing
    - Screenshot capture for intel
    """
    target = cache.target if cache else args.target
    print_section("VNC Service Detection", target)

    # Skip in proxy mode - raw socket banner grab doesn't work over proxychains
    if is_proxy_mode():
        status("Skipped in proxy mode (raw sockets incompatible with proxychains)", "info")
        if args.json_output:
            JSON_DATA["vnc"] = {"services": [], "count": 0}
        return

    # Skip if port pre-scan determined VNC is unavailable
    if cache.vnc_available is False:
        status("VNC ports not open - skipping", "info")
        if args.json_output:
            JSON_DATA["vnc"] = {"services": [], "count": 0}
        return

    status("Scanning for VNC services...")

    vnc_services = []

    # First, try nxc vnc if available
    vnc_args = ["vnc", target]
    rc, stdout, stderr = run_nxc(vnc_args, args.timeout)
    debug_nxc(vnc_args, stdout, stderr, "VNC Detection")

    # Check if nxc vnc found anything
    if rc == 0 and stdout.strip():
        # Parse nxc vnc output
        for line in stdout.split("\n"):
            line = line.strip()
            if not line or "[*]" not in line and "[+]" not in line:
                continue

            # Look for VNC indicators
            if "VNC" in line.upper():
                version_match = RE_VNC_VERSION.search(line)
                vnc_info = {
                    "port": 5900,  # Default
                    "detected": True,
                    "version": version_match.group(1) if version_match else "Unknown",
                    "source": "nxc",
                }

                # Try to extract port from line
                port_match = re.search(r":(\d+)", line)
                if port_match:
                    vnc_info["port"] = int(port_match.group(1))

                # Check for authentication status
                if "no auth" in line.lower() or "none" in line.lower():
                    vnc_info["auth_required"] = False
                elif "auth" in line.lower():
                    vnc_info["auth_required"] = True

                vnc_services.append(vnc_info)

    # Manual port scanning as fallback/supplement
    for port in VNC_PORTS:
        # Skip if already found by nxc
        if any(s["port"] == port for s in vnc_services):
            continue

        # Quick port check first
        if check_port(target, port, timeout=1.0):
            # Try to grab banner
            banner_result = grab_vnc_banner(target, port)
            if banner_result.get("detected"):
                banner_result["source"] = "banner"
                vnc_services.append(banner_result)

    # Store in cache
    cache.vnc_services = vnc_services

    if vnc_services:
        status(f"Found {len(vnc_services)} VNC service(s)!", "success")
        output("")

        output(c("VNC SERVICES DETECTED", Colors.YELLOW + Colors.BOLD))
        output(f"{'Port':<10} {'Version':<15} {'Auth Required':<15} {'Notes'}")
        output(f"{'-'*10} {'-'*15} {'-'*15} {'-'*25}")

        for vnc in sorted(vnc_services, key=lambda x: x["port"]):
            port = vnc["port"]
            version = vnc.get("version", "Unknown")
            auth = vnc.get("auth_required")

            if auth is False:
                auth_str = c("NO AUTH!", Colors.RED + Colors.BOLD)
                notes = c("Unauthenticated access!", Colors.RED)
            elif auth is True:
                auth_str = "Yes"
                notes = "Password required"
            else:
                auth_str = "Unknown"
                notes = "Test manually"

            output(f"{port:<10} {version:<15} {auth_str:<15} {notes}")

        output("")

        # Security implications
        output(c("[!] VNC Security Considerations:", Colors.YELLOW))
        output(c("    - Often uses weak/default passwords", Colors.YELLOW))
        output(c("    - May allow unauthenticated access", Colors.YELLOW))
        output(c("    - Provides full GUI access to the system", Colors.YELLOW))
        output("")

        # Check for no-auth services (critical)
        no_auth = [v for v in vnc_services if v.get("auth_required") is False]
        if no_auth:
            output(
                c(
                    f"[!] {len(no_auth)} VNC service(s) with NO AUTHENTICATION!",
                    Colors.RED + Colors.BOLD,
                )
            )
            output("")

            cache.add_next_step(
                finding="VNC with no authentication",
                command=f"vncviewer {target}:{no_auth[0]['port']}",
                description="Connect to unauthenticated VNC for immediate access",
                priority="high",
            )

        # Add brute force suggestion for auth-required
        auth_required = [v for v in vnc_services if v.get("auth_required") is not False]
        if auth_required:
            cache.add_next_step(
                finding=f"VNC service on port {auth_required[0]['port']}",
                command=f"nxc vnc {target} -p {auth_required[0]['port']} -u '' -p passwords.txt",
                description="Attempt VNC password brute force",
                priority="medium",
            )

        # Store for copy-paste
        cache.copy_paste_data["vnc_ports"] = {str(v["port"]) for v in vnc_services}

    else:
        status("No VNC services detected on common ports", "info")

    if args.json_output:
        JSON_DATA["vnc"] = {
            "services": vnc_services,
            "count": len(vnc_services),
        }
