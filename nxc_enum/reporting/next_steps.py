"""Next steps / recommended commands section."""

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, output, print_section


def print_next_steps(args, cache):
    """Print collected next steps and recommended commands.

    This aggregates all actionable recommendations discovered during
    enumeration into a single section at the end of the output.
    """
    if not cache.next_steps:
        return

    # Filter out invalid steps (must have finding and command)
    valid_steps = [s for s in cache.next_steps if s.get("finding") and s.get("command")]

    if not valid_steps:
        return

    print_section("Recommended Next Steps", args.target)

    # Group by priority (default to 'medium' consistently)
    high_priority = [s for s in valid_steps if s.get("priority", "medium") == "high"]
    medium_priority = [s for s in valid_steps if s.get("priority", "medium") == "medium"]
    low_priority = [s for s in valid_steps if s.get("priority", "medium") == "low"]

    if high_priority:
        output(c(f"HIGH PRIORITY ({len(high_priority)})", Colors.RED + Colors.BOLD))
        output(c("-" * 60, Colors.RED))
        for step in high_priority:
            _print_step(step, Colors.RED)

    if medium_priority:
        output(c(f"MEDIUM PRIORITY ({len(medium_priority)})", Colors.YELLOW + Colors.BOLD))
        output(c("-" * 60, Colors.YELLOW))
        for step in medium_priority:
            _print_step(step, Colors.YELLOW)

    if low_priority:
        output(c(f"LOW PRIORITY ({len(low_priority)})", Colors.CYAN + Colors.BOLD))
        output(c("-" * 60, Colors.CYAN))
        for step in low_priority:
            _print_step(step, Colors.CYAN)

    # Add to JSON output if requested
    if args.json_output:
        JSON_DATA["next_steps"] = {
            "high": [
                {
                    "finding": s["finding"],
                    "command": s["command"],
                    "description": s.get("description", ""),
                }
                for s in high_priority
            ],
            "medium": [
                {
                    "finding": s["finding"],
                    "command": s["command"],
                    "description": s.get("description", ""),
                }
                for s in medium_priority
            ],
            "low": [
                {
                    "finding": s["finding"],
                    "command": s["command"],
                    "description": s.get("description", ""),
                }
                for s in low_priority
            ],
        }


def _print_step(step: dict, accent_color: str = Colors.CYAN):
    """Print a single next step recommendation."""
    finding = step.get("finding", "")
    command = step.get("command", "")
    description = step.get("description", "")

    output(f"  {c('→', accent_color)} {c(finding, Colors.BOLD)}")
    if description:
        output(f"    {description}")
    if command:
        output(f"    {c('$', Colors.GREEN)} {c(command, Colors.WHITE)}")
    output("")
