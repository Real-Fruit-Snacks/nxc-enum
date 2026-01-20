"""NXC command execution and network utilities.

Security Considerations:
    Credentials (passwords, NTLM hashes) are passed to nxc via command-line
    arguments. This is a limitation of the nxc tool design. Be aware that:

    1. Credentials may be briefly visible in process listings (ps aux)
    2. Shell history may capture commands with credentials
    3. Process monitoring tools may log credential arguments

    Mitigations applied:
    - Debug output redacts credential values (see output.py)
    - Output files are created with restricted permissions (0o600)
    - Credential files are checked for overly permissive access

    For maximum security in sensitive environments:
    - Use dedicated assessment systems
    - Clear shell history after use
    - Use hash-based authentication (-H) when possible
"""

import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Tuple

from .constants import (
    PORT_PRESCAN_TIMEOUT,
    PORT_PRESCAN_WORKERS,
    PROXY_PORT_PRESCAN_TIMEOUT,
    PROXY_PORT_PRESCAN_WORKERS,
    PROXY_SMB_VALIDATION_WORKERS,
    RE_DOMAIN,
    RE_HOSTNAME,
    RE_SIGNING,
    RE_SMBV1,
    SERVICE_PORTS,
    SERVICE_PRESCAN_TIMEOUT,
    SERVICE_PRESCAN_WORKERS,
    SMB_VALIDATION_WORKERS,
    VNC_PORTS,
)
from .output import is_proxy_mode

# DNS resolution cache for multi-target scenarios
# Avoids redundant DNS lookups across parallel operations
_dns_cache: dict[str, tuple[str, float]] = {}
_dns_cache_lock = threading.Lock()
DNS_CACHE_TTL = 300  # 5 minute TTL


def cached_resolve(hostname: str) -> str:
    """Resolve hostname to IP with caching.

    For IP addresses, returns them unchanged.
    For hostnames, caches DNS resolution results for DNS_CACHE_TTL seconds.

    Args:
        hostname: Hostname or IP address to resolve

    Returns:
        Resolved IP address (or original IP if already an IP)

    Note:
        This function uses the system's default DNS resolver (via socket.gethostbyname).
        Custom DNS servers (--dns-server) and DNS-over-TCP (--dns-tcp) options are
        not supported here as they would require the dnspython library. For operations
        that need custom DNS, pass the --dns-server and --dns-tcp options directly
        to nxc commands, which handles DNS resolution internally.
    """
    # Quick check: if it looks like an IPv4 address, return as-is
    parts = hostname.split(".")
    if len(parts) == 4:
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                return hostname
        except ValueError:
            pass  # Not a valid IP, proceed with DNS lookup

    # Check cache (with lock for thread safety)
    with _dns_cache_lock:
        if hostname in _dns_cache:
            ip, timestamp = _dns_cache[hostname]
            if time.time() - timestamp < DNS_CACHE_TTL:
                return ip
            # Cache expired, remove it
            del _dns_cache[hostname]

    # Perform DNS lookup
    try:
        ip = socket.gethostbyname(hostname)
        with _dns_cache_lock:
            _dns_cache[hostname] = (ip, time.time())
        return ip
    except socket.gaierror:
        # DNS resolution failed, return original (let caller handle error)
        return hostname


def run_nxc(
    args: list,
    timeout: int = 60,
    port: int | None = None,
    smb_timeout: int | None = None,
) -> tuple[int, str, str]:
    """Run netexec command and return exit code, stdout, stderr.

    All commands include --verbose for detailed output that enables
    better parsing and data extraction.

    Security Note:
        Credential arguments (-p, -H) are passed directly to nxc subprocess
        and may be visible in process listings. This is inherent to nxc's
        design. See module docstring for security considerations.

    Args:
        args: Command arguments to pass to nxc
        timeout: Maximum execution time in seconds (default: 60)
        port: Optional custom port to use (adds --port PORT to nxc command)
        smb_timeout: Optional SMB-specific timeout (overrides timeout for SMB ops)

    Returns:
        Tuple of (return_code, stdout, stderr)

    Note:
        DNS resolution options (--dns-server, --dns-tcp) should be passed
        directly in the args list when needed, as they are nxc-native options.
        This module's cached_resolve() uses system DNS; custom DNS servers
        would require the dnspython library which is not a dependency.
    """
    cmd = ["nxc"] + args

    # Add custom port if specified and not already in args
    if port is not None and "--port" not in args:
        cmd.extend(["--port", str(port)])

    # Always add --verbose for more detailed output to parse
    if "--verbose" not in args:
        cmd.append("--verbose")

    # Use SMB-specific timeout if provided, otherwise use general timeout
    effective_timeout = smb_timeout if smb_timeout is not None else timeout

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=effective_timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", "netexec (nxc) not found in PATH"
    except PermissionError:
        return -1, "", "Permission denied executing netexec"
    except OSError as e:
        return -1, "", f"OS error executing command: {e}"
    except Exception as e:
        return -1, "", f"Command execution failed: {e}"


def check_port(
    host: str,
    port: int,
    timeout: float = 2.0,
    ipv6: bool = False,
) -> bool:
    """Check if a port is open (uses DNS cache for hostnames).

    Args:
        host: Hostname or IP address to check
        port: Port number to check
        timeout: Connection timeout in seconds (default: 2.0)
        ipv6: If True, use IPv6 (AF_INET6) instead of IPv4 (AF_INET)

    Returns:
        True if port is open, False otherwise
    """
    sock = None
    try:
        # Use cached DNS resolution for hostnames
        resolved_host = cached_resolve(host)
        address_family = socket.AF_INET6 if ipv6 else socket.AF_INET
        sock = socket.socket(address_family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((resolved_host, port))
        return result == 0
    except (socket.error, socket.timeout, OSError):
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def validate_host_smb(
    target: str,
    timeout: int = 10,
    port: int | None = None,
    smb_timeout: int | None = None,
) -> Tuple[bool, dict]:
    """Validate host reachability via SMB instead of ICMP ping.

    Makes an unauthenticated SMB connection to check if host responds.
    Also extracts hostname/domain for the hosts resolution check.

    This is more reliable than ICMP ping because:
    - Firewalls commonly block ICMP but allow SMB
    - Confirms the target is actually running SMB services
    - Extracts useful information for subsequent checks

    Args:
        target: IP address or hostname to check
        timeout: Connection timeout in seconds
        port: Custom SMB port (default: 445)
        smb_timeout: SMB-specific timeout (overrides timeout for SMB operations)

    Returns:
        Tuple of (is_reachable, info_dict) where info_dict contains:
        - hostname, dns_domain, fqdn, domain_name (NetBIOS)
        - signing_required, smbv1_enabled
    """
    smb_args = ["smb", target, "-u", "", "-p", ""]
    rc, stdout, stderr = run_nxc(smb_args, timeout, port=port, smb_timeout=smb_timeout)
    combined = stdout + stderr

    # Host is reachable if we got ANY SMB response
    # [*] indicates banner received, STATUS_ indicates protocol-level response
    is_reachable = bool("[*]" in combined or "[+]" in combined or "STATUS_" in combined.upper())

    info = {
        "hostname": None,
        "dns_domain": None,
        "fqdn": None,
        "domain_name": None,
        "signing_required": None,
        "smbv1_enabled": None,
    }

    if is_reachable:
        # Extract hostname (e.g., "445  DC01  [*]")
        hostname_match = RE_HOSTNAME.search(combined)
        if hostname_match:
            info["hostname"] = hostname_match.group(1)

        # Extract domain (e.g., "(domain:corp.local)")
        domain_match = RE_DOMAIN.search(combined)
        if domain_match:
            info["dns_domain"] = domain_match.group(1)

        # Build FQDN and NetBIOS domain
        if info["hostname"] and info["dns_domain"]:
            info["fqdn"] = f"{info['hostname']}.{info['dns_domain']}"
            info["domain_name"] = info["dns_domain"].split(".")[0].upper()

        # Extract signing and SMBv1 status
        signing_match = RE_SIGNING.search(combined)
        if signing_match:
            info["signing_required"] = signing_match.group(1).lower() == "true"

        smbv1_match = RE_SMBV1.search(combined)
        if smbv1_match:
            info["smbv1_enabled"] = smbv1_match.group(1).lower() == "true"

    return is_reachable, info


def parallel_port_prescan(
    targets: list[str],
    port: int = 445,
    timeout: float = PORT_PRESCAN_TIMEOUT,
    workers: int = PORT_PRESCAN_WORKERS,
    progress_callback: Callable[[int, int], None] | None = None,
    ipv6: bool = False,
) -> list[str]:
    """Fast parallel TCP port scan to filter reachable hosts.

    For a /24 (256 hosts), completes in ~3-5 seconds with default settings.
    This is used as a fast pre-filter before running full SMB validation.

    Args:
        targets: List of IPs/hostnames to scan
        port: Port to check (default 445 for SMB)
        timeout: Per-host timeout in seconds (default 0.5s)
        workers: Max concurrent connections (default 100)
        progress_callback: Optional callback(completed, total) for progress updates
        ipv6: If True, use IPv6 (AF_INET6) instead of IPv4 (AF_INET)

    Returns:
        List of hosts with port open (order not preserved)
    """
    # Use proxy-aware settings if proxy mode is enabled
    effective_timeout = PROXY_PORT_PRESCAN_TIMEOUT if is_proxy_mode() else timeout
    effective_workers = PROXY_PORT_PRESCAN_WORKERS if is_proxy_mode() else workers

    def check_single(host: str) -> str | None:
        if check_port(host, port, effective_timeout, ipv6=ipv6):
            return host
        return None

    live_hosts = []
    completed = 0

    with ThreadPoolExecutor(max_workers=min(len(targets), effective_workers)) as executor:
        futures = {executor.submit(check_single, t): t for t in targets}
        for future in as_completed(futures):
            completed += 1
            if progress_callback:
                progress_callback(completed, len(targets))
            try:
                result = future.result()
                if result:
                    live_hosts.append(result)
            except Exception:
                # Host check failed - skip silently
                pass

    return live_hosts


def parallel_smb_validation(
    targets: list[str],
    timeout: int = 10,
    workers: int = SMB_VALIDATION_WORKERS,
    progress_callback: Callable[[int, int, str], None] | None = None,
    port: int | None = None,
    smb_timeout: int | None = None,
) -> dict[str, Tuple[bool, dict]]:
    """Parallel SMB validation for multiple hosts.

    Runs validate_host_smb() on multiple hosts concurrently. This extracts
    hostname, domain, signing status, and other SMB banner info.

    Args:
        targets: List of IPs/hostnames to validate
        timeout: Per-host SMB timeout in seconds (default 10)
        workers: Max concurrent nxc processes (default 20)
        progress_callback: Optional callback(completed, total, hostname) for updates
        port: Custom SMB port (default: 445)
        smb_timeout: SMB-specific timeout (overrides timeout for SMB operations)

    Returns:
        Dict mapping host -> (is_reachable, smb_info)
    """
    # Use proxy-aware workers if proxy mode is enabled
    effective_workers = PROXY_SMB_VALIDATION_WORKERS if is_proxy_mode() else workers

    results: dict[str, Tuple[bool, dict]] = {}
    completed = 0

    with ThreadPoolExecutor(max_workers=min(len(targets), effective_workers)) as executor:
        futures = {
            executor.submit(validate_host_smb, t, timeout, port=port, smb_timeout=smb_timeout): t
            for t in targets
        }
        for future in as_completed(futures):
            host = futures[future]
            completed += 1
            if progress_callback:
                progress_callback(completed, len(targets), host)
            try:
                results[host] = future.result()
            except Exception as e:
                # Store error info for this host
                results[host] = (False, {"error": str(e)})

    return results


def prescan_service_ports(
    target: str,
    timeout: float = SERVICE_PRESCAN_TIMEOUT,
    ipv6: bool = False,
) -> dict:
    """Pre-scan service ports to determine which services are reachable.

    Checks common service ports (RDP, MSSQL, FTP, NFS, VNC, WinRM, SSH) to
    skip enumeration modules for unreachable services. This saves significant
    time (~30-60 seconds per unreachable service) during enumeration.

    Args:
        target: IP address or hostname to scan
        timeout: Per-port timeout in seconds (default 1.0s)
        ipv6: If True, use IPv6 (AF_INET6) instead of IPv4 (AF_INET)

    Returns:
        Dict mapping service name to availability:
        {
            "rdp": True/False,
            "mssql": True/False,
            "ftp": True/False,
            "nfs": True/False,
            "vnc": True/False,  # True if any VNC port responds
            "winrm": True/False,
            "winrms": True/False,
            "ssh": True/False,
        }
    """
    # Use proxy-aware timeout if enabled
    effective_timeout = 5.0 if is_proxy_mode() else timeout

    results = {}

    # Check standard single-port services
    for service, port in SERVICE_PORTS.items():
        results[service] = check_port(target, port, effective_timeout, ipv6=ipv6)

    # Check VNC ports (multiple possible ports)
    vnc_available = False
    for vnc_port in VNC_PORTS:
        if check_port(target, vnc_port, effective_timeout, ipv6=ipv6):
            vnc_available = True
            break
    results["vnc"] = vnc_available

    return results


def parallel_prescan_services(
    target: str,
    timeout: float = SERVICE_PRESCAN_TIMEOUT,
    workers: int = SERVICE_PRESCAN_WORKERS,
    ipv6: bool = False,
) -> dict:
    """Parallel pre-scan of all service ports for faster startup.

    Scans all service ports concurrently to minimize total prescan time.
    For a single target, completes in ~1-2 seconds with default settings.

    Args:
        target: IP address or hostname to scan
        timeout: Per-port timeout in seconds (default 1.0s)
        workers: Max concurrent port checks (default 10)
        ipv6: If True, use IPv6 (AF_INET6) instead of IPv4 (AF_INET)

    Returns:
        Dict mapping service name to availability (same as prescan_service_ports)
    """
    # Use proxy-aware timeout if enabled
    effective_timeout = 5.0 if is_proxy_mode() else timeout

    # Build list of (service_name, port) tuples to check
    ports_to_check = [(name, port) for name, port in SERVICE_PORTS.items()]
    # Add VNC ports with special marker
    for vnc_port in VNC_PORTS:
        ports_to_check.append((f"vnc_{vnc_port}", vnc_port))

    results = {}
    vnc_found = False

    def check_single(service_port_tuple):
        service_name, port = service_port_tuple
        is_open = check_port(target, port, effective_timeout, ipv6=ipv6)
        return service_name, is_open

    with ThreadPoolExecutor(max_workers=min(len(ports_to_check), workers)) as executor:
        futures = [executor.submit(check_single, sp) for sp in ports_to_check]
        for future in as_completed(futures):
            try:
                service_name, is_open = future.result()
                # Handle VNC ports specially
                if service_name.startswith("vnc_"):
                    if is_open:
                        vnc_found = True
                else:
                    results[service_name] = is_open
            except Exception:
                pass

    # Consolidate VNC results
    results["vnc"] = vnc_found

    return results
