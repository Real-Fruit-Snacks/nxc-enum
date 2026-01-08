"""NXC output parsing utilities.

This module provides common utilities for parsing nxc command output,
including noise filtering and structured data extraction.
"""

from typing import Optional

from ..core.constants import ALL_ENUM_PORTS


def is_nxc_noise_line(line: str) -> bool:
    """Check if line is nxc connection/credential noise to filter out."""
    if not line.strip():
        return True
    # IMPORTANT: Lines with status indicators are NEVER noise - they contain protocol results
    # This prevents filtering out successful auth lines like:
    # "MSSQL 10.10.205.148 1433 MS02 [+] oscp.exam\Eric.Wallows:EricLikesRunning800"
    if "[+]" in line or "[-]" in line or "[*]" in line or "[!]" in line:
        return False
    # Skip credential confirmation lines (e.g., "hacksmarter.local\\faraday:hacksmarter123")
    if "\\" in line and ":" in line and "@" not in line:
        parts = line.split()
        for part in parts:
            if "\\" in part and ":" in part:
                return True
    # Skip connection metadata (name, domain, signing info)
    if "(name:" in line and "(domain:" in line and "(signing:" in line:
        return True
    # Skip SMB version lines
    if "SMBv1:" in line and "signing:" in line:
        return True
    # Skip verbose INFO lines (connection metadata, not actual data)
    # These appear with -v flag: INFO Socket info, INFO Creating SMBv3, etc.
    if line.strip().startswith("INFO ") or " INFO " in line:
        return True
    # Skip DEBUG lines
    if line.strip().startswith("DEBUG ") or " DEBUG " in line:
        return True
    # Skip connection metadata fragments (e.g., "link-local ipv6=False")
    # These can appear as standalone lines when verbose output is split
    if "link-local" in line.lower():
        return True
    # Skip Python tracebacks from NetExec (upstream bugs)
    # These clutter the output and are not actionable by the user
    if "Traceback (most recent call last)" in line:
        return True
    if line.strip().startswith("File ") and ", line " in line and " in " in line:
        return True
    # Skip common Python exception lines
    if any(
        exc in line
        for exc in (
            "PyAsn1UnicodeDecodeError",
            "AttributeError:",
            "KeyError:",
            "TypeError:",
            "ValueError:",
            "IndexError:",
            "impacket.",
            "ldap3.",
        )
    ):
        return True
    # Skip Rich-formatted traceback lines (box-drawing characters)
    # These appear in nxc verbose output for exceptions
    if any(
        char in line
        for char in (
            "╭─",  # Top border of Rich traceback box
            "│ ",  # Side border of Rich traceback box
            "╰─",  # Bottom border of Rich traceback box
            "❱",  # Rich error marker pointing to the error line
        )
    ):
        return True
    # Skip ERROR prefix lines from nxc (exception messages)
    if line.strip().startswith("ERROR ") or " ERROR " in line:
        return True
    # Skip nxc exception wrapper messages
    if "Exception while calling proto_flow()" in line:
        return True
    if "Exception while calling" in line:
        return True
    return False


def parse_nxc_output(stdout: str) -> list:
    """Parse nxc output lines and extract status indicators."""
    results = []
    for line in stdout.split("\n"):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue
        if "[+]" in line:
            content = line.split("[+]", 1)[-1].strip()
            # Skip if content is just credential noise
            if is_nxc_noise_line(content):
                continue
            results.append(("success", content))
        elif "[-]" in line:
            content = line.split("[-]", 1)[-1].strip()
            if is_nxc_noise_line(content):
                continue
            results.append(("error", content))
        elif "[*]" in line:
            content = line.split("[*]", 1)[-1].strip()
            if is_nxc_noise_line(content):
                continue
            results.append(("info", content))
        else:
            results.append(("raw", line))
    return results


def extract_after_port(parts: list, ports: tuple = ALL_ENUM_PORTS) -> list:
    """Extract content after the port number in nxc output line.

    NXC output lines typically start with: IP PORT HOSTNAME [STATUS] ...
    This function finds the port and returns everything after the hostname.

    Args:
        parts: List of space-split line parts
        ports: Tuple of port numbers to look for (default: all common enum ports)

    Returns:
        List of remaining parts after port+hostname, or empty list if not found
    """
    for i, part in enumerate(parts):
        if part in ports:
            # Port found at index i, hostname at i+1, content starts at i+2
            if i + 2 < len(parts):
                return parts[i + 2 :]
            break
    return []


def find_port_index(parts: list, ports: tuple = ALL_ENUM_PORTS) -> int:
    """Find the index of the port number in nxc output line parts.

    Args:
        parts: List of space-split line parts
        ports: Tuple of port numbers to look for

    Returns:
        Index of port in parts, or -1 if not found
    """
    for i, part in enumerate(parts):
        if part in ports:
            return i
    return -1


def extract_status_content(line: str) -> Optional[tuple[str, str]]:
    """Extract status indicator and content from an nxc output line.

    Args:
        line: Raw output line from nxc

    Returns:
        Tuple of (status, content) where status is 'success', 'error', 'info', or 'warning',
        or None if no status indicator found
    """
    line = line.strip()

    if "[+]" in line:
        return ("success", line.split("[+]", 1)[-1].strip())
    elif "[-]" in line:
        return ("error", line.split("[-]", 1)[-1].strip())
    elif "[*]" in line:
        return ("info", line.split("[*]", 1)[-1].strip())
    elif "[!]" in line:
        return ("warning", line.split("[!]", 1)[-1].strip())

    return None
