"""ANSI color codes and color helper."""

import sys


class Colors:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"


def supports_color():
    """Check if terminal supports color."""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


USE_COLOR = supports_color()


def c(text: str, color: str) -> str:
    """Apply color to text if supported."""
    if USE_COLOR:
        return f"{color}{text}{Colors.RESET}"
    return text
