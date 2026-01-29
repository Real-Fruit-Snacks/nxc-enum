"""Pre-Windows 2000 compatible computer enumeration.

This module identifies computer accounts created with "Pre-Windows 2000 Compatible"
option, which sets the password to the lowercase computer name (without $).

This is pure enumeration - identifies vulnerable accounts via LDAP query.
Does NOT attempt authentication.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line


def enum_pre2k(args, cache):
    """Enumerate computer accounts with pre-Windows 2000 compatibility.

    Uses the pre2k LDAP module to find vulnerable computer accounts.
    """
    target = cache.target if cache else args.target
    print_section("Pre-Windows 2000 Computers", target, cache=cache)

    # Skip if LDAP is unavailable (determined during cache priming)
    if not cache.ldap_available:
        status("LDAP unavailable - skipping pre2k enumeration", "error")
        return

    auth = cache.auth_args
    status("Checking for pre-Windows 2000 compatible computers...")

    # Use pre2k module
    pre2k_args = ["ldap", target] + auth + ["-M", "pre2k"]
    rc, stdout, stderr = run_nxc(pre2k_args, args.timeout)
    debug_nxc(pre2k_args, stdout, stderr, "Pre-2K Computers")

    pre2k_computers = []

    # Parse output
    # Format typically shows computer names that match the criteria
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        if is_nxc_noise_line(line):
            continue

        # Look for computer account names
        # Module output varies, but typically contains computer names ending with $
        if "PRE2K" in line.upper() or "$" in line:
            # Extract computer name
            parts = line.split()
            for part in parts:
                # Computer accounts end with $
                if part.endswith("$") and len(part) > 1:
                    computer = part.rstrip("$")
                    if computer not in pre2k_computers:
                        pre2k_computers.append(computer)
                # Some output may show without $
                elif re.match(r"^[A-Za-z0-9_-]+$", part) and len(part) > 2:
                    # Heuristic: looks like a computer name
                    if part.upper() not in ("LDAP", "SMB", "PRE2K", "MODULE"):
                        if part not in pre2k_computers and part + "$" not in pre2k_computers:
                            # Only add if it looks like a finding
                            if "vulnerable" in line.lower() or "found" in line.lower():
                                pre2k_computers.append(part)

    # Store results
    cache.pre2k_computers = pre2k_computers

    # Display results
    if pre2k_computers:
        status(
            f"Found {len(pre2k_computers)} computer(s) with pre-Windows 2000 compatibility!",
            "warning",
        )
        output("")

        output(
            c(
                "VULNERABLE COMPUTERS (Pre-Windows 2000)",
                Colors.RED + Colors.BOLD,
            )
        )
        output(c("[!] Password = lowercase computer name (without $)", Colors.RED))
        output(f"{'-'*60}")

        for computer in sorted(pre2k_computers):
            password_hint = computer.lower()
            output(f"  {c('[!]', Colors.RED)} {computer}$")
            output(f"      Password likely: {c(password_hint, Colors.YELLOW)}")

        output("")

        # Add next steps
        if pre2k_computers:
            example_computer = pre2k_computers[0]
            example_pass = example_computer.lower()

            cache.add_next_step(
                finding=f"Pre-2K computers: {len(pre2k_computers)} found",
                command=f"nxc smb {target} -u '{example_computer}$' -p '{example_pass}'",
                description="Authenticate with computer account (password = lowercase name)",
                priority="high",
            )

        # Store copy-paste data
        cache.copy_paste_data["pre2k_computers"] = set(f"{c}$" for c in pre2k_computers)

    else:
        # Check for common errors and LDAP failures
        combined = stdout + stderr
        combined_lower = combined.lower()
        ldap_failure_indicators = [
            "failed to connect",
            "connection refused",
            "timed out",
            "ldap ping failed",
            "failed to create connection",
            "kerberos sessionerror",
        ]
        if "STATUS_ACCESS_DENIED" in combined.upper():
            status("Access denied - cannot check pre-2K computers", "error")
        elif "STATUS_LOGON_FAILURE" in combined.upper():
            status("Authentication failed - cannot check pre-2K computers", "error")
        elif "Module not found" in combined or "module 'pre2k' not found" in combined_lower:
            status("pre2k module not available in nxc - update NetExec", "error")
        elif any(ind in combined_lower for ind in ldap_failure_indicators) or rc != 0:
            status("LDAP unavailable - cannot check pre-2K computers", "error")
        elif "No entries" in combined or "0 entries" in combined:
            status("No pre-Windows 2000 compatible computers found", "success")
        else:
            # Default to info when uncertain, not success
            status("No pre-Windows 2000 compatible computers found", "info")

    if args.json_output:
        JSON_DATA["pre2k_computers"] = {
            "computers": pre2k_computers,
            "count": len(pre2k_computers),
        }
