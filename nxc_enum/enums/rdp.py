"""RDP and NLA status check.

This module checks if RDP is enabled and whether Network Level Authentication
(NLA) is required on the target.

This is pure enumeration - no authentication attempt is made.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc

# Regex to extract NLA status from nxc output format: (nla:True) or (nla:False)
RE_NLA_STATUS = re.compile(r"\(nla:(\w+)\)", re.IGNORECASE)


def enum_rdp(args, cache):
    """Check RDP status and NLA requirements.

    Uses nxc rdp module to probe RDP configuration.
    """
    target = cache.target if cache else args.target
    print_section("RDP Status Check", target)

    # Skip if port pre-scan determined RDP is unavailable
    if cache.rdp_available is False:
        status("RDP port (3389) not open - skipping", "info")
        if args.json_output:
            JSON_DATA["rdp"] = {"enabled": False, "nla_required": None}
        return

    status("Checking RDP configuration...")

    # RDP check doesn't require authentication for basic status
    # Just probe the port to see if RDP is available and check NLA
    rdp_args = ["rdp", target]
    rc, stdout, stderr = run_nxc(rdp_args, args.timeout)
    debug_nxc(rdp_args, stdout, stderr, "RDP Check")

    rdp_info = {
        "enabled": False,
        "nla_required": None,
        "version": None,
        "hostname": None,
    }

    combined = stdout + stderr

    # Check if RDP is available
    if "RDP" in stdout:
        rdp_info["enabled"] = True

    # Look for NLA status in output
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        line_lower = line.lower()

        # Extract NLA from banner format: (nla:True) or (nla:False)
        nla_match = RE_NLA_STATUS.search(line)
        if nla_match:
            nla_value = nla_match.group(1).lower()
            rdp_info["nla_required"] = nla_value in ("true", "yes", "1")

        # Fallback: Check for NLA status in text form
        if rdp_info["nla_required"] is None and "nla" in line_lower:
            if "required" in line_lower or "enabled" in line_lower:
                rdp_info["nla_required"] = True
            elif "not required" in line_lower or "disabled" in line_lower:
                rdp_info["nla_required"] = False

        # Check for CredSSP/NLA indicators
        if rdp_info["nla_required"] is None and "credssp" in line_lower:
            if "required" in line_lower:
                rdp_info["nla_required"] = True

        # Extract hostname if shown
        if line.startswith("RDP"):
            parts = line.split()
            if len(parts) >= 4:
                # Format: RDP IP PORT HOSTNAME
                rdp_info["hostname"] = parts[3]

        # Look for version info
        version_match = re.search(r"(\d+\.\d+)", line)
        if version_match and "version" in line_lower:
            rdp_info["version"] = version_match.group(1)

    # Store results
    cache.rdp_info = rdp_info

    # Display results
    output("")
    output(c("RDP CONFIGURATION", Colors.CYAN))
    output(f"{'-'*50}")

    if rdp_info["enabled"]:
        output(f"  {c('[+]', Colors.GREEN)} RDP: {c('Enabled', Colors.GREEN)}")

        if rdp_info["hostname"]:
            output(f"  {c('[*]', Colors.CYAN)} Hostname: {rdp_info['hostname']}")

        if rdp_info["nla_required"] is True:
            output(f"  {c('[+]', Colors.GREEN)} NLA: {c('Required', Colors.GREEN)}")
            output(
                c(
                    "      Network Level Authentication protects against some attacks",
                    Colors.GREEN,
                )
            )
        elif rdp_info["nla_required"] is False:
            output(
                f"  {c('[!]', Colors.RED)} NLA: {c('Not Required', Colors.RED + Colors.BOLD)}"
            )
            output(
                c(
                    "      May be vulnerable to MITM and BlueKeep-style attacks",
                    Colors.RED,
                )
            )

            # Add next step for RDP without NLA
            cache.add_next_step(
                finding="RDP without NLA requirement",
                command=f"nxc rdp {target} -u '' -p '' --screenshot",
                description="Attempt to capture RDP screenshot (may reveal logged-in user)",
                priority="medium",
            )
        else:
            output(f"  {c('[?]', Colors.CYAN)} NLA: Unknown")

        output("")

    else:
        # Check if port is closed vs service not responding
        if "Connection refused" in combined or "port" in combined.lower():
            status("RDP port (3389) not open", "info")
        elif "timed out" in combined.lower():
            status("RDP connection timed out", "error")
        else:
            status("RDP not detected or not accessible", "info")

    if rdp_info["enabled"]:
        status(
            "RDP is enabled on target",
            "success" if rdp_info["nla_required"] else "warning",
        )

    if args.json_output:
        JSON_DATA["rdp"] = rdp_info
