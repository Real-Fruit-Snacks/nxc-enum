"""Output and display functions."""

import threading

from .colors import Colors, c
from .constants import INDICATORS

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

# Credential-related arguments that should be redacted in debug output
_SENSITIVE_ARGS = ("-p", "-H", "--password", "--hash")
_REDACTED = "****REDACTED****"


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


def _sanitize_cmd_args(cmd_args: list) -> list:
    """Sanitize command arguments by redacting sensitive values like passwords and hashes.

    This prevents credentials from being exposed in debug output, log files,
    or screen recordings.

    Args:
        cmd_args: List of command-line arguments

    Returns:
        List with sensitive values replaced by _REDACTED
    """
    sanitized = []
    skip_next = False

    for arg in cmd_args:
        if skip_next:
            sanitized.append(_REDACTED)
            skip_next = False
            continue

        if arg in _SENSITIVE_ARGS:
            sanitized.append(arg)
            skip_next = True
        else:
            sanitized.append(arg)

    return sanitized


def debug_nxc(cmd_args: list, stdout: str, stderr: str, label: str = ""):
    """Print raw nxc command and output when debug mode is enabled.

    Security: Credentials (-p, -H, --password, --hash) are automatically
    redacted to prevent exposure in debug output or log files.
    """
    if not _debug_mode:
        return

    # Sanitize command args to hide credentials
    sanitized_args = _sanitize_cmd_args(cmd_args)

    # Show actual command with --verbose (always added by run_nxc)
    if "--verbose" not in sanitized_args:
        cmd_str = "nxc " + " ".join(sanitized_args) + " --verbose"
    else:
        cmd_str = "nxc " + " ".join(sanitized_args)

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
