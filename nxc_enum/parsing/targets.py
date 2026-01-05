"""Target expansion for CIDR notation, IP ranges, and target files."""

import ipaddress
import os
import re
from typing import List

# Maximum number of targets to prevent accidental huge scans
MAX_TARGETS = 65536  # /16 network


class TargetExpansionError(Exception):
    """Error during target expansion."""

    pass


def expand_targets(target_spec: str) -> List[str]:
    """Expand target specification to a list of individual targets.

    Auto-detects target type using priority order:
    1. CIDR notation (contains "/") - e.g., 10.0.0.0/24
    2. IP range (contains "-" with digits) - e.g., 10.0.0.1-50
    3. Target file (file exists on disk) - auto-detected
    4. Hostname/IP (default) - e.g., dc01.corp.local or 10.0.0.1

    Note: If a file exists with the same name as a hostname you want to scan,
    the file takes precedence. Use the IP address or FQDN to avoid this.

    Args:
        target_spec: Target specification (IP, hostname, CIDR, range, or filename)

    Returns:
        List of individual target IPs/hostnames (deduplicated, order preserved)

    Raises:
        TargetExpansionError: If target specification is invalid or too large
    """
    if not target_spec:
        raise TargetExpansionError("No target specified.")

    target_spec = target_spec.strip()

    # Priority 1 & 2: CIDR and ranges are never files
    if "/" in target_spec or ("-" in target_spec and re.search(r"\d+-", target_spec)):
        targets = _expand_single_spec(target_spec)
    # Priority 3: Check if file exists on disk
    elif os.path.exists(target_spec):
        targets = _parse_targets_file(target_spec)
    # Priority 4: Treat as hostname/IP
    else:
        targets = [target_spec]

    # Deduplicate while preserving order
    seen = set()
    unique_targets = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)

    if not unique_targets:
        raise TargetExpansionError("No valid targets found.")

    if len(unique_targets) > MAX_TARGETS:
        raise TargetExpansionError(
            f"Too many targets ({len(unique_targets)}). Maximum is {MAX_TARGETS}. "
            "Use a smaller CIDR or split into multiple scans."
        )

    return unique_targets


def _expand_single_spec(spec: str) -> List[str]:
    """Expand a single target specification to list of targets.

    Args:
        spec: Target specification (IP, hostname, CIDR, or range)

    Returns:
        List of individual target IPs/hostnames
    """
    spec = spec.strip()
    if not spec:
        return []

    # Check for CIDR notation (contains /)
    if "/" in spec:
        return _expand_cidr(spec)

    # Check for IP range (contains - with numbers)
    if "-" in spec and re.search(r"\d+-", spec):
        return _expand_range(spec)

    # Single target (IP or hostname)
    return [spec]


def _expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR notation to list of host IPs.

    Args:
        cidr: CIDR notation (e.g., 10.0.0.0/24)

    Returns:
        List of host IPs (excludes network and broadcast for /31+)

    Raises:
        TargetExpansionError: If CIDR is invalid
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise TargetExpansionError(f"Invalid CIDR notation '{cidr}': {e}")

    # For /31 and /32, return all addresses
    # For larger networks, exclude network and broadcast addresses
    if network.prefixlen >= 31:
        hosts = list(network)
    else:
        hosts = list(network.hosts())

    if len(hosts) > MAX_TARGETS:
        raise TargetExpansionError(
            f"CIDR {cidr} expands to {len(hosts)} hosts. "
            f"Maximum is {MAX_TARGETS}. Use a smaller prefix."
        )

    return [str(ip) for ip in hosts]


def _expand_range(spec: str) -> List[str]:
    """Expand IP range to list of IPs.

    Supports two formats:
    - Short: 10.0.0.1-50 (last octet range)
    - Full: 10.0.0.1-10.0.0.50 (full IP range)

    Args:
        spec: Range specification

    Returns:
        List of IPs in range

    Raises:
        TargetExpansionError: If range is invalid
    """
    # Try full range format first: 10.0.0.1-10.0.0.50
    full_range_match = re.match(
        r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$",
        spec,
    )
    if full_range_match:
        return _expand_full_range(full_range_match.group(1), full_range_match.group(2))

    # Try short range format: 10.0.0.1-50
    short_range_match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$", spec)
    if short_range_match:
        base = short_range_match.group(1)
        start = int(short_range_match.group(2))
        end = int(short_range_match.group(3))

        if start > end:
            raise TargetExpansionError(f"Invalid range '{spec}': start ({start}) > end ({end})")
        if end > 255:
            raise TargetExpansionError(f"Invalid range '{spec}': end ({end}) > 255")

        count = end - start + 1
        if count > MAX_TARGETS:
            raise TargetExpansionError(
                f"Range {spec} expands to {count} hosts. Maximum is {MAX_TARGETS}."
            )

        return [f"{base}.{i}" for i in range(start, end + 1)]

    raise TargetExpansionError(
        f"Invalid range format '{spec}'. " "Use '10.0.0.1-50' or '10.0.0.1-10.0.0.50'"
    )


def _expand_full_range(start_ip: str, end_ip: str) -> List[str]:
    """Expand a full IP range (start-end) to list of IPs.

    Args:
        start_ip: Starting IP address
        end_ip: Ending IP address

    Returns:
        List of IPs in range

    Raises:
        TargetExpansionError: If IPs are invalid or range is too large
    """
    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
    except ValueError as e:
        raise TargetExpansionError(f"Invalid IP in range: {e}")

    if start > end:
        raise TargetExpansionError(f"Invalid range: start ({start_ip}) > end ({end_ip})")

    count = int(end) - int(start) + 1
    if count > MAX_TARGETS:
        raise TargetExpansionError(
            f"Range {start_ip}-{end_ip} expands to {count} hosts. " f"Maximum is {MAX_TARGETS}."
        )

    return [str(ipaddress.IPv4Address(int(start) + i)) for i in range(count)]


def _parse_targets_file(filepath: str) -> List[str]:
    """Parse targets from a file.

    File format:
    - One target per line
    - Supports IPs, hostnames, CIDR, and ranges
    - Lines starting with # are comments
    - Empty lines are ignored

    Args:
        filepath: Path to targets file

    Returns:
        List of expanded targets

    Raises:
        TargetExpansionError: If file cannot be read or contains invalid targets
    """
    if not os.path.exists(filepath):
        raise TargetExpansionError(f"Targets file not found: {filepath}")

    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
    except (IOError, OSError) as e:
        raise TargetExpansionError(f"Cannot read targets file '{filepath}': {e}")

    targets = []
    for line_num, line in enumerate(lines, 1):
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        try:
            expanded = _expand_single_spec(line)
            targets.extend(expanded)
        except TargetExpansionError as e:
            raise TargetExpansionError(f"Line {line_num} in '{filepath}': {e}")

    if not targets:
        raise TargetExpansionError(f"No valid targets found in '{filepath}'")

    return targets


def get_target_count_estimate(target_spec: str) -> int:
    """Get estimated count of targets without full expansion.

    Useful for validation and progress display before actual expansion.
    Uses same auto-detection logic as expand_targets().

    Args:
        target_spec: Target specification (IP, hostname, CIDR, range, or filename)

    Returns:
        Estimated number of targets
    """
    if not target_spec:
        return 0

    spec = target_spec.strip()

    # CIDR notation
    if "/" in spec:
        try:
            network = ipaddress.ip_network(spec, strict=False)
            if network.prefixlen < 31:
                return network.num_addresses - 2
            else:
                return network.num_addresses
        except ValueError:
            return 1  # Invalid, will fail later

    # IP range
    if "-" in spec and re.search(r"\d+-", spec):
        short_match = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.(\d{1,3})-(\d{1,3})$", spec)
        if short_match:
            return int(short_match.group(2)) - int(short_match.group(1)) + 1
        return 1  # Full range, harder to estimate quickly

    # Target file (auto-detected)
    if os.path.exists(spec):
        count = 0
        try:
            with open(spec, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        count += 1  # Simple estimate, doesn't expand CIDR in file
        except (IOError, OSError):
            pass
        return count if count > 0 else 1

    # Single hostname/IP
    return 1
