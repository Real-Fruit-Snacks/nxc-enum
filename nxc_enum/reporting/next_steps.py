"""Next steps / recommended commands section."""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, output, print_section


def _substitute_credentials(command: str, args, cache) -> str:
    """Substitute credential placeholders with actual values.

    Replaces patterns like <user>, <pass>, '<user>', '<pass>' with actual credentials.
    Also handles domain-specific formats like DOMAIN\\<user> and <user>@domain.
    """
    # Try to get credentials from args first, then fall back to cache.primary_credential
    user = args.user if hasattr(args, "user") and args.user else None
    password = args.password if hasattr(args, "password") and args.password else None
    ntlm_hash = args.hash if hasattr(args, "hash") and args.hash else None
    domain = args.domain if hasattr(args, "domain") and args.domain else None

    # Fall back to primary_credential from cache (for -C multi-cred mode)
    if not user and cache.primary_credential:
        cred = cache.primary_credential
        user = cred.user
        password = cred.password
        ntlm_hash = cred.hash if not password else None
        domain = cred.domain if cred.domain else domain

    # If still no credentials available, return command as-is
    if not user:
        return command

    result = command

    # Get domain from cache if not in args
    if not domain and cache.domain_info:
        domain = cache.domain_info.get("dns_domain") or cache.domain_info.get("netbios_domain")

    # Handle domain-qualified patterns FIRST (before replacing standalone <user>)
    # Pattern: 'DOMAIN\<user>' or DOMAIN\\<user> or "DOMAIN\<user>"
    if domain:
        # Handle 'domain\<user>' format (with quotes around whole thing)
        result = re.sub(r"'[A-Za-z0-9._-]+\\\\?<user>'", f"'{domain}\\\\{user}'", result)
        # Handle domain\<user> format (without quotes)
        result = re.sub(r"([A-Za-z0-9._-]+)\\\\?<user>", f"{domain}\\\\{user}", result)
        # Handle '<user>@domain.local' format
        result = re.sub(r"'<user>@[A-Za-z0-9._-]+'", f"'{user}@{domain}'", result)
        # Handle <user>@domain format without quotes
        result = re.sub(r"<user>@[A-Za-z0-9._-]+", f"{user}@{domain}", result)

    # Substitute password patterns (before user, to handle -p '<pass>' correctly)
    if password:
        # Handle -p '<pass>' (quotes around placeholder)
        result = re.sub(r"-p\s+'<pass(?:word)?>'", f"-p '{password}'", result)
        # Handle -p "<pass>"
        result = re.sub(r'-p\s+"<pass(?:word)?>"', f"-p '{password}'", result)
        # Handle -p <pass> (no quotes)
        result = re.sub(r"-p\s+<pass(?:word)?>", f"-p '{password}'", result)
        # Handle standalone '<pass>' or "<pass>"
        result = re.sub(r"'<pass(?:word)?>'", f"'{password}'", result)
        result = re.sub(r'"<pass(?:word)?>"', f"'{password}'", result)
        # Handle standalone <pass> (no quotes) - be careful not to break other things
        result = re.sub(r"(?<!['\"]):<pass(?:word)?>(?!['\"])", f":{password}", result)
    elif ntlm_hash:
        # Replace password auth with hash auth
        result = re.sub(r"-p\s+'<pass(?:word)?>'", f"-H '{ntlm_hash}'", result)
        result = re.sub(r'-p\s+"<pass(?:word)?>"', f"-H '{ntlm_hash}'", result)
        result = re.sub(r"-p\s+<pass(?:word)?>", f"-H '{ntlm_hash}'", result)

    # Substitute username patterns LAST
    # Handle -u '<user>' (quotes around placeholder)
    result = re.sub(r"-u\s+'<user>'", f"-u '{user}'", result)
    # Handle -u "<user>"
    result = re.sub(r'-u\s+"<user>"', f"-u '{user}'", result)
    # Handle -u <user> (no quotes)
    result = re.sub(r"-u\s+<user>(?!['\"])", f"-u '{user}'", result)
    # Handle standalone '<user>' in other contexts (like impacket tools)
    result = re.sub(r"'<user>'", f"'{user}'", result)
    # Handle standalone <user> that's not part of domain\user or user@domain
    result = re.sub(r"(?<![\\@])<user>(?!@)", user, result)

    # Handle generic placeholders
    if domain:
        result = re.sub(r"<domain>", domain, result)

    # Handle USER/PASS uppercase placeholders (like in os_info.py)
    if password:
        result = re.sub(r"-p\s+PASS\b", f"-p '{password}'", result)
    elif ntlm_hash:
        result = re.sub(r"-p\s+PASS\b", f"-H '{ntlm_hash}'", result)
    result = re.sub(r"-u\s+USER\b", f"-u '{user}'", result)

    return result


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

    target = cache.target if cache else args.target
    print_section("Recommended Next Steps", target)

    # Group by priority (default to 'medium' consistently)
    high_priority = [s for s in valid_steps if s.get("priority", "medium") == "high"]
    medium_priority = [s for s in valid_steps if s.get("priority", "medium") == "medium"]
    low_priority = [s for s in valid_steps if s.get("priority", "medium") == "low"]

    if high_priority:
        output(c(f"HIGH PRIORITY ({len(high_priority)})", Colors.RED + Colors.BOLD))
        output(c("-" * 60, Colors.RED))
        for step in high_priority:
            _print_step(step, args, cache, Colors.RED)

    if medium_priority:
        output(c(f"MEDIUM PRIORITY ({len(medium_priority)})", Colors.YELLOW + Colors.BOLD))
        output(c("-" * 60, Colors.YELLOW))
        for step in medium_priority:
            _print_step(step, args, cache, Colors.YELLOW)

    if low_priority:
        output(c(f"LOW PRIORITY ({len(low_priority)})", Colors.CYAN + Colors.BOLD))
        output(c("-" * 60, Colors.CYAN))
        for step in low_priority:
            _print_step(step, args, cache, Colors.CYAN)

    # Add to JSON output if requested (with substituted credentials)
    if args.json_output:
        JSON_DATA["next_steps"] = {
            "high": [
                {
                    "finding": s["finding"],
                    "command": _substitute_credentials(s["command"], args, cache),
                    "description": s.get("description", ""),
                }
                for s in high_priority
            ],
            "medium": [
                {
                    "finding": s["finding"],
                    "command": _substitute_credentials(s["command"], args, cache),
                    "description": s.get("description", ""),
                }
                for s in medium_priority
            ],
            "low": [
                {
                    "finding": s["finding"],
                    "command": _substitute_credentials(s["command"], args, cache),
                    "description": s.get("description", ""),
                }
                for s in low_priority
            ],
        }


def _print_step(step: dict, args, cache, accent_color: str = Colors.CYAN):
    """Print a single next step recommendation with credential substitution."""
    finding = step.get("finding", "")
    command = step.get("command", "")
    description = step.get("description", "")

    # Substitute placeholders with actual credentials
    command = _substitute_credentials(command, args, cache)

    output(f"  {c('→', accent_color)} {c(finding, Colors.BOLD)}")
    if description:
        output(f"    {description}")
    if command:
        output(f"    {c('$', Colors.GREEN)} {c(command, Colors.WHITE)}")
    output("")
