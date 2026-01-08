"""Output and display functions."""

import threading
from typing import List

from .colors import Colors, c
from .constants import INDICATORS

# Placeholder for redacted credentials in debug output
_REDACTED = "[REDACTED]"

# Flags that take credential arguments (next arg is sensitive)
_SENSITIVE_FLAGS = {"-p", "--password", "-H", "--hash"}


def _sanitize_cmd_args(cmd_args: List[str]) -> List[str]:
    """Sanitize command arguments by redacting sensitive values.

    Replaces values following sensitive flags (-p, --password, -H, --hash)
    with [REDACTED] to prevent credential exposure in logs/debug output.

    Args:
        cmd_args: List of command line arguments

    Returns:
        List of arguments with sensitive values redacted
    """
    if not cmd_args:
        return []

    result = []
    skip_next = False

    for arg in cmd_args:
        if skip_next:
            result.append(_REDACTED)
            skip_next = False
        elif arg in _SENSITIVE_FLAGS:
            result.append(arg)
            skip_next = True
        else:
            result.append(arg)

    return result


# Thread-local storage for parallel output buffering
_thread_local = threading.local()
_parallel_mode = False
_output_file_requested = False
_debug_mode = False

# Target-level parallel execution support
_target_parallel_mode = False
_target_local = threading.local()
_target_print_lock = threading.Lock()

# Thread lock for OUTPUT_BUFFER to prevent race conditions in parallel mode
_buffer_lock = threading.Lock()

# Global output capture for file output and JSON
OUTPUT_BUFFER = []
JSON_DATA = {}


def set_output_file_requested(value: bool):
    """Set the output file requested flag."""
    global _output_file_requested
    _output_file_requested = value


def get_output_file_requested() -> bool:
    """Get the output file requested flag."""
    return _output_file_requested


def set_debug_mode(value: bool):
    """Set the debug mode flag."""
    global _debug_mode
    _debug_mode = value


def get_debug_mode() -> bool:
    """Get the debug mode flag."""
    return _debug_mode


# Proxy mode state (for proxychains/SOCKS compatibility)
_proxy_mode = False


def set_proxy_mode(value: bool):
    """Set the proxy mode flag for proxychains/SOCKS compatibility."""
    global _proxy_mode
    _proxy_mode = value


def is_proxy_mode() -> bool:
    """Check if proxy mode is enabled."""
    return _proxy_mode


def set_parallel_mode(value: bool):
    """Set the parallel mode flag for buffered output during parallel execution."""
    global _parallel_mode
    _parallel_mode = value


def get_parallel_mode() -> bool:
    """Get the parallel mode flag."""
    return _parallel_mode


def get_thread_local():
    """Get thread-local storage for parallel output buffering."""
    return _thread_local


def set_target_parallel_mode(value: bool):
    """Set target-level parallel mode for multi-target execution.

    When enabled, all output is captured per-thread for later atomic printing.
    This prevents output interleaving when running multiple targets in parallel.
    """
    global _target_parallel_mode
    _target_parallel_mode = value


def get_target_parallel_mode() -> bool:
    """Get the target-level parallel mode flag."""
    return _target_parallel_mode


def get_target_local():
    """Get target-level thread-local storage."""
    return _target_local


def get_target_print_lock():
    """Get the lock for atomic target output printing."""
    return _target_print_lock


def output_direct(msg: str):
    """Print directly to stdout, bypassing all buffering.

    Used for printing buffered content without double-buffering.
    Still respects file output if requested.
    """
    print(msg)
    if _output_file_requested:
        with _buffer_lock:
            OUTPUT_BUFFER.append(msg)


def output(msg: str):
    """Print and optionally capture output. Supports parallel mode buffering.

    Supports two levels of buffering:
    1. Target-level: Buffers all output for a target to enable atomic printing
    2. Module-level: Buffers output during parallel module execution

    Target-level buffering takes precedence and captures module-level output.

    Thread-safe: Uses lock when appending to OUTPUT_BUFFER to prevent
    race conditions during parallel module execution.
    """
    # Target-level parallel buffering takes precedence
    if _target_parallel_mode and hasattr(_target_local, "buffer"):
        _target_local.buffer.append(msg)
        # File output is handled when target buffer is flushed
        return

    # Module-level parallel buffering
    if _parallel_mode and hasattr(_thread_local, "buffer"):
        _thread_local.buffer.append(msg)
    else:
        print(msg)

    # Only buffer if file output requested - use lock for thread safety
    if _output_file_requested:
        with _buffer_lock:
            OUTPUT_BUFFER.append(msg)


def print_banner():
    """Print tool banner."""
    output("NXC-ENUM - NetExec Enumeration Wrapper (v1.7.0)")
    output("")


def print_section(title: str, target: str = ""):
    """Print a section header in enum4linux-ng style.

    Args:
        title: Section title
        target: Target IP/hostname to append to title
    """
    if target:
        title = f"{title} for {target}"
    box_width = len(title) + 10
    output("")
    output(c(f" {'=' * box_width}", Colors.CYAN))
    output(c(f"|    {title}    |", Colors.CYAN))
    output(c(f" {'=' * box_width}", Colors.CYAN))


def status(msg: str, level: str = "info"):
    """Print a status message with indicator."""
    indicator = INDICATORS.get(level, INDICATORS["info"])
    output(f"{indicator} {msg}")


def _is_debug_noise_line(line: str) -> bool:
    """Check if line is noise that should be filtered from debug output.

    This is a more targeted filter for debug output - we keep INFO lines
    (useful for debugging) but filter tracebacks and Rich-formatted errors.
    """
    if not line.strip():
        return True
    # Skip Rich-formatted traceback lines (box-drawing characters)
    if any(
        char in line
        for char in ("╭─", "│ ", "╰─", "❱")
    ):
        return True
    # Skip Python traceback markers
    if "Traceback (most recent call last)" in line:
        return True
    if line.strip().startswith("File ") and ", line " in line and " in " in line:
        return True
    # Skip Python exception lines
    if any(
        exc in line
        for exc in (
            "PyAsn1UnicodeDecodeError",
            "AttributeError:",
            "KeyError:",
            "TypeError:",
            "ValueError:",
            "IndexError:",
        )
    ):
        return True
    # Skip ERROR prefix lines (exception wrapper messages)
    if line.strip().startswith("ERROR ") or " ERROR " in line:
        return True
    if "Exception while calling" in line:
        return True
    return False


def debug_nxc(cmd_args: list, stdout: str, stderr: str, label: str = ""):
    """Print raw nxc command and output when debug mode is enabled.

    Applies noise filtering to remove Python tracebacks and Rich-formatted
    error boxes from upstream nxc bugs, while preserving useful debug info.
    """
    if not _debug_mode:
        return

    # Show actual command with --verbose (always added by run_nxc)
    if "--verbose" not in cmd_args:
        cmd_str = "nxc " + " ".join(cmd_args) + " --verbose"
    else:
        cmd_str = "nxc " + " ".join(cmd_args)

    output("")
    output(c(f"{'─' * 60}", Colors.CYAN))
    if label:
        output(c(f"DEBUG [{label}]: {cmd_str}", Colors.CYAN))
    else:
        output(c(f"DEBUG: {cmd_str}", Colors.CYAN))
    output(c(f"{'─' * 60}", Colors.CYAN))

    if stdout.strip():
        output(c("STDOUT:", Colors.CYAN))
        for line in stdout.strip().split("\n"):
            if not _is_debug_noise_line(line):
                output(c(f"  {line}", Colors.CYAN))
    else:
        output(c("STDOUT: (empty)", Colors.CYAN))

    if stderr.strip():
        output(c("STDERR:", Colors.YELLOW))
        for line in stderr.strip().split("\n"):
            if not _is_debug_noise_line(line):
                output(c(f"  {line}", Colors.YELLOW))

    output(c(f"{'─' * 60}", Colors.CYAN))
    output("")


def print_target_header(target: str, index: int, total: int):
    """Print a target separator header for multi-target scans.

    Args:
        target: Current target IP/hostname
        index: Current target number (1-indexed)
        total: Total number of targets
    """
    header_text = f"TARGET {index} of {total}: {target}"
    width = max(80, len(header_text) + 8)

    output("")
    output(c("=" * width, Colors.CYAN + Colors.BOLD))
    output(c(header_text.center(width), Colors.CYAN + Colors.BOLD))
    output(c("=" * width, Colors.CYAN + Colors.BOLD))


def print_target_footer(target: str, status_str: str, elapsed: float):
    """Print a target completion footer for multi-target scans.

    Args:
        target: Target that was scanned
        status_str: "success" or "failed"
        elapsed: Time taken for this target
    """
    if status_str == "success":
        color = Colors.GREEN
        indicator = "[+]"
    else:
        color = Colors.RED
        indicator = "[-]"

    output("")
    output(c("-" * 80, Colors.CYAN))
    output(c(f"{indicator} {target} completed in {elapsed:.2f}s ({status_str})", color))
    output(c("-" * 80, Colors.CYAN))


def reset_output_buffer():
    """Reset the output buffer for a new target scan.

    Used in multi-target mode to start fresh for each target
    when not writing to a combined output file.
    """
    global OUTPUT_BUFFER
    with _buffer_lock:
        OUTPUT_BUFFER = []


def clear_json_data():
    """Clear JSON data dict for a new target scan."""
    global JSON_DATA
    JSON_DATA = {}


def get_json_data_copy() -> dict:
    """Get a deep copy of current JSON_DATA for per-target capture.

    Used to snapshot JSON data for a target before clearing for the next target.
    Returns a copy to avoid mutation issues.
    """
    import copy
    return copy.deepcopy(JSON_DATA)


def get_output_buffer_copy() -> list:
    """Get a copy of current OUTPUT_BUFFER for per-target capture.

    Thread-safe copy of the output buffer for saving per-target output.
    """
    with _buffer_lock:
        return list(OUTPUT_BUFFER)


def get_per_target_filename(base_output: str, target: str) -> str:
    """Generate per-target output filename.

    Args:
        base_output: Base output path (e.g., "results.txt" or "results.json")
        target: Target IP or hostname

    Returns:
        Modified filename with target appended (e.g., "results_192.168.1.1.txt")
    """
    import os

    base, ext = os.path.splitext(base_output)
    # Sanitize target for filename (IPv6 has colons, hostnames may have dots)
    safe_target = target.replace(":", "_").replace("/", "_")
    return f"{base}_{safe_target}{ext}"


def print_discovery_results(
    smb_results: dict,
    total_scanned: int,
    port_open_count: int,
    elapsed: float,
    verbose: bool = False,
) -> None:
    """Print discovery results for --discover-only mode.

    Args:
        smb_results: Dict mapping host -> (is_reachable, smb_info)
        total_scanned: Total number of hosts scanned
        port_open_count: Number of hosts with port 445 open
        elapsed: Total elapsed time in seconds
        verbose: If True, show detailed table with hostname/domain/signing
    """
    # Filter to only reachable hosts
    live_hosts = {
        host: info
        for host, (reachable, info) in smb_results.items()
        if reachable
    }

    output("")
    output(c("=" * 70, Colors.CYAN))
    output(c("  DISCOVERY RESULTS", Colors.CYAN + Colors.BOLD))
    output(c("=" * 70, Colors.CYAN))
    output("")

    # Statistics
    status(f"Hosts scanned: {total_scanned}", "info")
    status(f"Port 445 open: {port_open_count}", "info")
    status(f"SMB validated: {len(live_hosts)}", "success")
    status(f"Elapsed time: {elapsed:.2f}s", "info")
    output("")

    if not live_hosts:
        status("No live SMB hosts found", "warning")
        return

    if verbose:
        # Detailed table output
        output(c("-" * 70, Colors.CYAN))
        header = f"{'IP':<16} {'Hostname':<15} {'Domain':<20} {'Sign':<5} {'v1':<4}"
        output(c(header, Colors.BOLD))
        output(c("-" * 70, Colors.CYAN))

        for host in sorted(live_hosts.keys()):
            info = live_hosts[host]
            hostname = info.get("hostname") or "-"
            domain = info.get("dns_domain") or "-"
            signing = "Yes" if info.get("signing_required") else "No"
            smbv1 = "Yes" if info.get("smbv1_enabled") else "No"

            # Color signing status
            if info.get("signing_required"):
                signing = c(signing, Colors.GREEN)
            else:
                signing = c(signing, Colors.RED)

            # Color SMBv1 status (bad if enabled)
            if info.get("smbv1_enabled"):
                smbv1 = c(smbv1, Colors.RED)
            else:
                smbv1 = c(smbv1, Colors.GREEN)

            output(f"{host:<16} {hostname:<15} {domain:<20} {signing:<14} {smbv1}")

        output(c("-" * 70, Colors.CYAN))
        output("")
        output(c("Legend: Sign=SMB Signing Required, v1=SMBv1 Enabled", Colors.CYAN))
    else:
        # Simple list output (one IP per line)
        output(c("Live SMB Hosts:", Colors.BOLD))
        output(c("-" * 30, Colors.CYAN))
        for host in sorted(live_hosts.keys()):
            output(host)

    output("")


def get_discovery_json(
    smb_results: dict,
    total_scanned: int,
    port_open_count: int,
    elapsed: float,
) -> dict:
    """Generate JSON data for discovery results.

    Args:
        smb_results: Dict mapping host -> (is_reachable, smb_info)
        total_scanned: Total number of hosts scanned
        port_open_count: Number of hosts with port 445 open
        elapsed: Total elapsed time in seconds

    Returns:
        Dict with discovery results in JSON-serializable format
    """
    discovered_hosts = []

    for host, (reachable, info) in smb_results.items():
        if reachable:
            discovered_hosts.append({
                "ip": host,
                "hostname": info.get("hostname"),
                "fqdn": info.get("fqdn"),
                "domain": info.get("dns_domain"),
                "domain_netbios": info.get("domain_name"),
                "signing_required": info.get("signing_required"),
                "smbv1_enabled": info.get("smbv1_enabled"),
            })

    # Sort by IP
    discovered_hosts.sort(key=lambda x: x["ip"])

    return {
        "discovered_hosts": discovered_hosts,
        "scan_stats": {
            "total_scanned": total_scanned,
            "port_445_open": port_open_count,
            "smb_validated": len(discovered_hosts),
            "elapsed_time": round(elapsed, 2),
        },
    }
