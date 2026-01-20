"""Domain computer enumeration."""

import re
from collections import Counter

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..reporting.next_steps import get_external_tool_auth

# Regex to parse computer entries from nxc ldap --computers output
# Format: LDAP  IP  PORT  HOST  ComputerName$  OSInfo  OSVersion
RE_COMPUTER_LINE = re.compile(r"^LDAP\s+\S+\s+\d+\s+\S+\s+(\S+)\$?\s*(.*?)$", re.IGNORECASE)

# Outdated/unsupported operating systems (security risk)
OUTDATED_OS_PATTERNS = [
    r"Windows\s*(XP|2000|2003|Vista)",
    r"Windows\s*7",
    r"Windows\s*8(\s|$|\.0)",  # Windows 8 (not 8.1)
    r"Windows\s*Server\s*2008",
    r"Windows\s*Server\s*2012(?!\s*R2)",  # 2012 but not 2012 R2
]
RE_OUTDATED_OS = [re.compile(p, re.IGNORECASE) for p in OUTDATED_OS_PATTERNS]

# End of support but still commonly seen
EOL_OS_PATTERNS = [
    r"Windows\s*8\.1",
    r"Windows\s*Server\s*2012\s*R2",
    r"Windows\s*Server\s*2016",
]
RE_EOL_OS = [re.compile(p, re.IGNORECASE) for p in EOL_OS_PATTERNS]


def _normalize_os_string(os_value) -> str:
    """Normalize OS value that may be a string or list from LDAP.

    LDAP multi-valued attributes can return as lists instead of strings.
    This helper ensures we always work with a string.
    """
    if isinstance(os_value, list):
        return os_value[0] if os_value else ""
    return os_value if os_value else ""


def is_outdated_os(os_string) -> bool:
    """Check if OS string matches an outdated/unsupported OS."""
    os_string = _normalize_os_string(os_string)
    if not os_string:
        return False
    return any(pattern.search(os_string) for pattern in RE_OUTDATED_OS)


def is_eol_os(os_string) -> bool:
    """Check if OS string matches an end-of-life (but not ancient) OS."""
    os_string = _normalize_os_string(os_string)
    if not os_string:
        return False
    return any(pattern.search(os_string) for pattern in RE_EOL_OS)


def categorize_os(os_string) -> str:
    """Categorize OS into simplified groups for summary."""
    os_string = _normalize_os_string(os_string)
    if not os_string:
        return "Unknown"

    os_lower = os_string.lower()

    # Server versions
    if "server" in os_lower:
        if "2022" in os_string:
            return "Windows Server 2022"
        elif "2019" in os_string:
            return "Windows Server 2019"
        elif "2016" in os_string:
            return "Windows Server 2016"
        elif "2012 r2" in os_lower:
            return "Windows Server 2012 R2"
        elif "2012" in os_string:
            return "Windows Server 2012"
        elif "2008 r2" in os_lower:
            return "Windows Server 2008 R2"
        elif "2008" in os_string:
            return "Windows Server 2008"
        elif "2003" in os_string:
            return "Windows Server 2003"
        else:
            return "Windows Server (other)"

    # Desktop versions
    if "windows 11" in os_lower:
        return "Windows 11"
    elif "windows 10" in os_lower:
        return "Windows 10"
    elif "windows 8.1" in os_lower:
        return "Windows 8.1"
    elif "windows 8" in os_lower:
        return "Windows 8"
    elif "windows 7" in os_lower:
        return "Windows 7"
    elif "windows vista" in os_lower:
        return "Windows Vista"
    elif "windows xp" in os_lower:
        return "Windows XP"

    return os_string[:30] if len(os_string) > 30 else os_string


def enum_computers(args, cache):
    """Enumerate domain computers."""
    target = cache.target if cache else args.target
    print_section("Domain Computers", target)

    # Skip if LDAP is unavailable (determined during cache priming)
    if not cache.ldap_available:
        status("LDAP unavailable - skipping computer enumeration", "error")
        return

    auth = cache.auth_args
    status("Querying domain computers...")

    # Try to use batch data first (populated during cache priming)
    batch_data = cache.get_computers_from_batch()
    if batch_data is not None:
        # Use pre-fetched batch data - much faster
        computers = []
        outdated_computers = []
        eol_computers = []
        for comp in batch_data:
            os_info = comp.get("os", "")
            computer = {
                "name": comp["name"],
                "os": os_info,
                "os_category": categorize_os(os_info),
                "outdated": is_outdated_os(os_info),
                "eol": is_eol_os(os_info),
            }
            computers.append(computer)
            if computer["outdated"]:
                outdated_computers.append(computer)
            elif computer["eol"]:
                eol_computers.append(computer)
        rc, stdout, stderr = 0, "", ""  # No individual query needed
    else:
        # Fall back to individual query
        # Run nxc ldap --computers
        comp_args = ["ldap", target] + auth + ["--computers"]
        rc, stdout, stderr = run_nxc(comp_args, args.timeout)
        debug_nxc(comp_args, stdout, stderr, "Computers Query")

        computers = []
        outdated_computers = []
        eol_computers = []

        for line in stdout.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Skip noise lines
            if "[*]" in line or "[+]" in line or "[-]" in line:
                continue
            if not line.startswith("LDAP"):
                continue

            # Parse computer entry
            parts = line.split()
            if len(parts) < 5:
                continue

            # Skip header-like lines
            if parts[4].lower() in ("computername", "name", "----"):
                continue

            # Extract computer name (may end with $)
            comp_name = parts[4].rstrip("$")

            # Rest is OS info (if present)
            os_info = " ".join(parts[5:]) if len(parts) > 5 else ""

            # Clean up OS info
            os_info = os_info.strip()

            # If no OS info from LDAP, try to use cached SMB banner info
            cached_os_info = getattr(cache, "os_info", None)
            if not os_info and cached_os_info:
                cached_hostname = cached_os_info.get("hostname", "").upper()
                if cached_hostname and comp_name.upper() == cached_hostname:
                    os_info = cached_os_info.get("os", "")

            computer = {
                "name": comp_name,
                "os": os_info,
                "os_category": categorize_os(os_info),
                "outdated": is_outdated_os(os_info),
                "eol": is_eol_os(os_info),
            }
            computers.append(computer)

            if computer["outdated"]:
                outdated_computers.append(computer)
            elif computer["eol"]:
                eol_computers.append(computer)

    # Store in cache
    cache.computers = computers
    cache.outdated_os_computers = outdated_computers

    if computers:
        status(f"Found {len(computers)} computer(s)", "success")
        output("")

        # OS Summary
        os_counts = Counter(c["os_category"] for c in computers)
        output(c("OPERATING SYSTEM SUMMARY", Colors.CYAN))
        output(f"{'Operating System':<30} {'Count':>6}")
        output(f"{'-'*30} {'-'*6}")

        # Sort by count (descending), then alphabetically
        for os_name, count in sorted(os_counts.items(), key=lambda x: (-x[1], x[0])):
            # Highlight outdated/EOL systems
            if any(p.search(os_name) for p in RE_OUTDATED_OS):
                os_display = c(os_name, Colors.RED)
                count_display = c(f"{count:>6}", Colors.RED)
            elif any(p.search(os_name) for p in RE_EOL_OS):
                os_display = c(os_name, Colors.YELLOW)
                count_display = c(f"{count:>6}", Colors.YELLOW)
            else:
                os_display = os_name
                count_display = f"{count:>6}"

            # Pad colored strings properly
            if any(p.search(os_name) for p in RE_OUTDATED_OS + RE_EOL_OS):
                output(f"{os_display:<40} {count_display}")
            else:
                output(f"{os_display:<30} {count_display}")

        # Warn about outdated systems
        if outdated_computers:
            output("")
            output(c(f"[!] OUTDATED/UNSUPPORTED SYSTEMS ({len(outdated_computers)})", Colors.RED))
            eol_msg = "    These systems are end-of-life and no longer receive security updates!"
            output(c(eol_msg, Colors.RED))
            for comp in outdated_computers[:10]:
                output(f"    - {c(comp['name'], Colors.RED)}: {comp['os']}")
            if len(outdated_computers) > 10:
                output(f"    ... and {len(outdated_computers) - 10} more")

            # Add next step for outdated systems
            comp_list = ", ".join(c["name"] for c in outdated_computers[:3])
            if len(outdated_computers) > 3:
                comp_list += f" (+{len(outdated_computers) - 3} more)"
            auth_info = get_external_tool_auth(args, cache, tool="nxc")
            auth_hint = auth_info["auth_string"]
            cache.add_next_step(
                finding=f"Outdated OS: {comp_list}",
                command=f"nxc smb {target} {auth_hint} --gen-relay-list outdated.txt",
                description="Generate relay target list - outdated systems may be vulnerable",
                priority="medium",
            )

        # Warn about EOL systems (less severe)
        if eol_computers:
            output("")
            output(c(f"[!] END-OF-LIFE SYSTEMS ({len(eol_computers)})", Colors.YELLOW))
            eol_warn = "    These systems are approaching or past end of extended support."
            output(c(eol_warn, Colors.YELLOW))
            for comp in eol_computers[:5]:
                output(f"    - {c(comp['name'], Colors.YELLOW)}: {comp['os']}")
            if len(eol_computers) > 5:
                output(f"    ... and {len(eol_computers) - 5} more")

        # Separate servers and workstations for detailed view
        # Ensure os_category is string before calling .lower() (defensive check)
        def get_os_category(comp):
            cat = comp.get("os_category", "")
            if isinstance(cat, list):
                cat = cat[0] if cat else ""
            return str(cat).lower() if cat else ""

        servers = [c for c in computers if "server" in get_os_category(c)]
        workstations = [c for c in computers if "server" not in get_os_category(c)]

        # Show server list (usually fewer, more important)
        if servers and len(servers) <= 20:
            output("")
            output(c(f"SERVERS ({len(servers)})", Colors.CYAN))
            output(f"{'Computer Name':<25} {'Operating System'}")
            output(f"{'-'*25} {'-'*40}")
            for comp in sorted(servers, key=lambda x: x["name"].lower()):
                name = comp["name"][:25]
                os_raw = comp["os"] or "(unknown)"
                # Truncate with "..." if too long, ensuring we don't leave unclosed parens
                if len(os_raw) > 40:
                    os_str = os_raw[:37] + "..."
                else:
                    os_str = os_raw
                if comp["outdated"]:
                    output(f"{c(name, Colors.RED):<35} {c(os_str, Colors.RED)}")
                elif comp["eol"]:
                    output(f"{c(name, Colors.YELLOW):<35} {c(os_str, Colors.YELLOW)}")
                else:
                    output(f"{name:<25} {os_str}")

        # Store for aggregated copy-paste section
        cache.copy_paste_data["computer_names"].update(comp["name"] for comp in computers)
        cache.copy_paste_data["server_names"].update(comp["name"] for comp in servers)
        cache.copy_paste_data["workstation_names"].update(comp["name"] for comp in workstations)

    else:
        # No computers found
        combined = stdout + stderr
        if "STATUS_ACCESS_DENIED" in combined.upper():
            status("Access denied - cannot enumerate computers", "error")
        elif "STATUS_LOGON_FAILURE" in combined.upper():
            status("Authentication failed - cannot enumerate computers", "error")
        else:
            status("No computers found or unable to enumerate", "info")

    if args.json_output:
        JSON_DATA["computers"] = computers
        if outdated_computers:
            JSON_DATA["outdated_computers"] = [c["name"] for c in outdated_computers]
