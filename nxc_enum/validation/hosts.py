"""Hosts file resolution validation for DC hostname."""

import socket
from typing import Optional, Tuple

from ..core.constants import RE_DOMAIN, RE_HOSTNAME


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


def check_hosts_resolution(
    target_ip: str, cache
) -> Tuple[bool, Optional[str]]:
    """Check if DC hostname resolves to the target IP.

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
