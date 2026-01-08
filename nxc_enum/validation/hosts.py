"""Hosts file resolution validation for target hostname."""

import socket
from typing import Optional, Tuple

from ..core.constants import RE_DOMAIN, RE_HOSTNAME
from ..core.output import is_proxy_mode, status
from ..core.runner import run_nxc


def early_hosts_check(target: str, timeout: int) -> Tuple[bool, Optional[str]]:
    """Perform early hosts resolution check before any enumeration.

    Makes an unauthenticated SMB connection to get the target hostname from the banner,
    then verifies that hostname resolves to the target IP.

    Args:
        target: Target IP address
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (success: bool, hosts_line: str | None)
        - success=True if hostname resolves correctly or check cannot be performed
        - hosts_line contains the /etc/hosts line suggestion if resolution failed
    """
    # Skip hostname validation in proxy mode (DNS bypasses proxy)
    if is_proxy_mode():
        status("Hostname validation skipped in proxy mode (use IP addresses)", "info")
        return True, None

    status("Verifying target hostname resolution...", "info")

    # Make unauthenticated SMB connection to get banner with hostname
    # Using empty creds just to grab the banner - will get auth failure but that's ok
    smb_args = ["smb", target, "-u", "", "-p", ""]
    rc, stdout, stderr = run_nxc(smb_args, timeout)

    combined = stdout + stderr
    if not combined:
        # Can't get any banner - skip check
        return True, None

    # Extract hostname from banner (e.g., "445  DC01  [")
    hostname = None
    hostname_match = RE_HOSTNAME.search(combined)
    if hostname_match:
        hostname = hostname_match.group(1)

    # Extract domain from banner (e.g., "(domain:corp.local)")
    dns_domain = None
    domain_match = RE_DOMAIN.search(combined)
    if domain_match:
        dns_domain = domain_match.group(1)

    # Cannot check without hostname or domain
    if not hostname or not dns_domain:
        return True, None

    # Build FQDN
    fqdn = f"{hostname}.{dns_domain}"
    netbios_domain = dns_domain.split(".")[0].upper()

    # Attempt DNS resolution
    try:
        resolved_ip = socket.gethostbyname(fqdn)
    except socket.gaierror:
        resolved_ip = None

    # Check if resolution matches target
    if resolved_ip == target:
        status(f"Target hostname '{fqdn}' resolves correctly", "success")
        return True, None

    # Generate hosts file line
    # Format: IP FQDN NETBIOS_DOMAIN HOSTNAME
    parts = [target, fqdn]
    if netbios_domain:
        parts.append(netbios_domain)
    parts.append(hostname)

    hosts_line = "  ".join(parts)
    return False, hosts_line


def extract_hostname_from_smb(cache) -> None:
    """Extract hostname/domain from cached SMB output into cache.domain_info.

    This allows hosts checking before enum_domain_intel() runs.
    Populates cache.domain_info with hostname, dns_domain, fqdn, and domain_name.
    """
    if cache.smb_basic is None:
        return

    _, stdout, _ = cache.smb_basic

    if not stdout:
        return

    # Initialize domain_info if not present
    if not hasattr(cache, "domain_info") or cache.domain_info is None:
        cache.domain_info = {}

    # Extract hostname from SMB output (e.g., "445  DC01  [*]")
    if not cache.domain_info.get("hostname"):
        hostname_match = RE_HOSTNAME.search(stdout)
        if hostname_match:
            cache.domain_info["hostname"] = hostname_match.group(1)

    # Extract domain from SMB output (e.g., "(domain:corp.local)")
    if not cache.domain_info.get("dns_domain"):
        domain_match = RE_DOMAIN.search(stdout)
        if domain_match:
            cache.domain_info["dns_domain"] = domain_match.group(1)

    # Derive FQDN from hostname + dns_domain
    hostname = cache.domain_info.get("hostname")
    dns_domain = cache.domain_info.get("dns_domain")
    if hostname and dns_domain and not cache.domain_info.get("fqdn"):
        cache.domain_info["fqdn"] = f"{hostname}.{dns_domain}"

    # Derive NetBIOS domain name from dns_domain (first component, uppercase)
    if dns_domain and not cache.domain_info.get("domain_name"):
        cache.domain_info["domain_name"] = dns_domain.split(".")[0].upper()


def check_hosts_resolution_from_info(target_ip: str, smb_info: dict) -> Tuple[bool, Optional[str]]:
    """Check hosts resolution using pre-extracted SMB info.

    This avoids a second SMB call since validate_host_smb() already extracted
    hostname and domain from the banner.

    Args:
        target_ip: The target IP address provided by user
        smb_info: Dict with hostname, dns_domain, fqdn, domain_name from SMB validation

    Returns:
        Tuple of (success: bool, hosts_line: str | None)
        - success=True if hostname resolves correctly or check cannot be performed
        - hosts_line contains the /etc/hosts line suggestion if resolution failed
    """
    hostname = smb_info.get("hostname")
    fqdn = smb_info.get("fqdn")
    domain_name = smb_info.get("domain_name", "")

    # Cannot check without hostname data
    if not hostname or not fqdn:
        return True, None

    # Attempt DNS resolution
    try:
        resolved_ip = socket.gethostbyname(fqdn)
    except socket.gaierror:
        resolved_ip = None

    # Check if resolution matches target
    if resolved_ip == target_ip:
        status(f"Target hostname '{fqdn}' resolves correctly", "success")
        return True, None

    # Generate hosts file line
    # Format: IP FQDN NETBIOS_DOMAIN HOSTNAME
    parts = [target_ip, fqdn]
    if domain_name:
        parts.append(domain_name)
    parts.append(hostname)

    hosts_line = "  ".join(parts)
    return False, hosts_line


def check_hosts_resolution(target_ip: str, cache) -> Tuple[bool, Optional[str]]:
    """Check if target hostname resolves to the target IP.

    Args:
        target_ip: The target IP address provided by user
        cache: EnumCache with domain_info populated

    Returns:
        Tuple of (success: bool, hosts_line: str | None)
        - success=True if hostname resolves correctly or check cannot be performed
        - hosts_line contains the /etc/hosts line suggestion if resolution failed
    """
    # Get hostname data from cache
    if not hasattr(cache, "domain_info") or cache.domain_info is None:
        return True, None

    hostname = cache.domain_info.get("hostname")
    fqdn = cache.domain_info.get("fqdn")
    netbios_domain = cache.domain_info.get("domain_name", "")

    # Cannot check without hostname data
    if not hostname or not fqdn:
        return True, None

    # Attempt DNS resolution
    try:
        resolved_ip = socket.gethostbyname(fqdn)
    except socket.gaierror:
        resolved_ip = None

    # Check if resolution matches target
    if resolved_ip == target_ip:
        return True, None

    # Generate hosts file line
    # Format: IP FQDN NETBIOS_DOMAIN HOSTNAME
    parts = [target_ip, fqdn]
    if netbios_domain:
        parts.append(netbios_domain)
    parts.append(hostname)

    hosts_line = "  ".join(parts)
    return False, hosts_line
