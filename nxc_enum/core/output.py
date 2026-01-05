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


def output(msg: str):
    """Print and optionally capture output. Supports parallel mode buffering.

    Thread-safe: Uses lock when appending to OUTPUT_BUFFER to prevent
    race conditions during parallel module execution.
    """
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
    output("NXC-ENUM - NetExec Enumeration Wrapper (v1.5.1)")
    output("")


def print_section(title: str, target: str = ""):
    """Print a section header in enum4linux-ng style."""
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


def debug_nxc(cmd_args: list, stdout: str, stderr: str, label: str = ""):
    """Print raw nxc command and output when debug mode is enabled."""
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
            output(c(f"  {line}", Colors.CYAN))
    else:
        output(c("STDOUT: (empty)", Colors.CYAN))

    if stderr.strip():
        output(c("STDERR:", Colors.YELLOW))
        for line in stderr.strip().split("\n"):
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
