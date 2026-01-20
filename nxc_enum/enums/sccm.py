"""SCCM/MECM (System Center Configuration Manager) discovery.

This module discovers SCCM/MECM infrastructure in the domain by querying
LDAP for SCCM-related objects (site servers, management points, etc.).

This is pure LDAP enumeration - queries AD for SCCM service connection points.
No command execution on the target.

Pentest value: SCCM servers are high-value targets with admin access to managed systems.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

# LDAP filter for SCCM service connection points
SCCM_FILTER = "(objectClass=mSSMSSite)"

# Regex patterns
RE_CN = re.compile(r"CN=([^,]+)", re.IGNORECASE)
RE_SITE_CODE = re.compile(r"mSSMSSiteCode:\s*(\S+)", re.IGNORECASE)
RE_SERVER = re.compile(r"mSSMSMPName:\s*(\S+)", re.IGNORECASE)
RE_ROAMING = re.compile(r"mSSMSRoamingBoundaries:\s*(.+)", re.IGNORECASE)


def enum_sccm(args, cache):
    """Enumerate SCCM/MECM infrastructure from Active Directory.

    Queries LDAP for SCCM service connection points and site information.
    SCCM servers often have privileged access to managed workstations.

    Attack paths:
    - NAA (Network Access Account) credential extraction
    - Task sequence credential extraction
    - Admin access to managed systems via SCCM console
    """
    target = cache.target if cache else args.target
    print_section("SCCM/MECM Discovery", target)

    auth = cache.auth_args
    status("Searching for SCCM/MECM infrastructure...")

    # Run nxc sccm module
    sccm_args = ["ldap", target] + auth + ["-M", "sccm"]
    rc, stdout, stderr = run_nxc(sccm_args, args.timeout)
    debug_nxc(sccm_args, stdout, stderr, "SCCM Discovery")

    sccm_info = {
        "sites": [],
        "servers": [],
        "management_points": [],
        "distribution_points": [],
    }

    current_site = {}

    # Parse output
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        if is_nxc_noise_line(line):
            continue

        # Look for SCCM-related output
        if "SCCM" in line.upper() or "sccm" in line.lower():
            # Site code
            site_match = RE_SITE_CODE.search(line)
            if site_match:
                current_site["site_code"] = site_match.group(1)

            # Server name
            server_match = RE_SERVER.search(line)
            if server_match:
                server = server_match.group(1)
                if server not in sccm_info["servers"]:
                    sccm_info["servers"].append(server)
                current_site["server"] = server

            # Look for role-specific info
            if "management point" in line.lower() or "MP:" in line:
                mp_match = re.search(r"(?:MP|management point)[:\s]+(\S+)", line, re.IGNORECASE)
                if mp_match:
                    mp = mp_match.group(1)
                    if mp not in sccm_info["management_points"]:
                        sccm_info["management_points"].append(mp)

            if "distribution point" in line.lower() or "DP:" in line:
                dp_match = re.search(r"(?:DP|distribution point)[:\s]+(\S+)", line, re.IGNORECASE)
                if dp_match:
                    dp = dp_match.group(1)
                    if dp not in sccm_info["distribution_points"]:
                        sccm_info["distribution_points"].append(dp)

        # Alternative: direct site/server listing
        if "Site:" in line or "Server:" in line:
            parts = re.findall(r"(\w+):\s*(\S+)", line)
            for key, value in parts:
                if key.lower() == "site":
                    current_site["site_code"] = value
                elif key.lower() == "server":
                    if value not in sccm_info["servers"]:
                        sccm_info["servers"].append(value)
                    current_site["server"] = value

    # Save site if we have data
    if current_site.get("site_code"):
        sccm_info["sites"].append(current_site.copy())

    # Check for access/error conditions
    combined = stdout + stderr
    access_denied = "STATUS_ACCESS_DENIED" in combined.upper()
    no_sccm = "No SCCM" in combined or "not found" in combined.lower()
    ldap_failed = (
        "Failed to create connection" in combined
        or "Failed to connect" in combined.lower()
        or "ldap connection failed" in combined.lower()
    )

    # Store in cache
    cache.sccm_info = sccm_info
    cache.sccm_servers = sccm_info["servers"]

    has_results = (
        sccm_info["sites"]
        or sccm_info["servers"]
        or sccm_info["management_points"]
        or sccm_info["distribution_points"]
    )

    if has_results:
        status("SCCM/MECM infrastructure detected!", "success")
        output("")

        output(c("SCCM/MECM INFRASTRUCTURE", Colors.YELLOW + Colors.BOLD))
        output(f"{'-'*60}")

        # Sites
        if sccm_info["sites"]:
            output(c("Sites:", Colors.CYAN))
            for site in sccm_info["sites"]:
                site_code = site.get("site_code", "Unknown")
                server = site.get("server", "Unknown")
                output(f"  {c('[*]', Colors.BLUE)} Site {site_code}: {server}")
            output("")

        # Servers
        if sccm_info["servers"]:
            output(c("Site Servers:", Colors.CYAN))
            for server in sorted(set(sccm_info["servers"])):
                output(f"  {c('[!]', Colors.YELLOW)} {c(server, Colors.YELLOW)}")
            output("")

        # Management Points
        if sccm_info["management_points"]:
            output(c("Management Points:", Colors.CYAN))
            for mp in sorted(set(sccm_info["management_points"])):
                output(f"  {c('[*]', Colors.BLUE)} {mp}")
            output("")

        # Distribution Points
        if sccm_info["distribution_points"]:
            output(c("Distribution Points:", Colors.CYAN))
            for dp in sorted(set(sccm_info["distribution_points"])):
                output(f"  {c('[*]', Colors.BLUE)} {dp}")
            output("")

        # Security implications
        output(c("[!] SCCM servers are high-value targets:", Colors.RED))
        output(c("    - NAA (Network Access Account) may have domain creds", Colors.RED))
        output(c("    - Task sequences may contain embedded credentials", Colors.RED))
        output(c("    - Admin console grants access to managed systems", Colors.RED))
        output("")

        # Add next steps
        for server in sccm_info["servers"][:3]:  # Limit to first 3
            cache.add_next_step(
                finding=f"SCCM server found: {server}",
                command="# SCCM server - check for SharpSCCM/MalSCCM attacks",
                description="Investigate SCCM for NAA creds, task sequences, admin access",
                priority="medium",
            )

        # Store for copy-paste
        cache.copy_paste_data["sccm_servers"] = set(sccm_info["servers"])

    elif ldap_failed:
        status("LDAP unavailable - cannot check SCCM infrastructure", "error")
    elif access_denied:
        status("Access denied querying SCCM information", "warning")
    elif no_sccm:
        status("No SCCM/MECM infrastructure detected", "info")
    else:
        if not stdout.strip() or rc != 0:
            status("Could not query SCCM information", "error")
        else:
            status("No SCCM/MECM infrastructure detected", "info")

    if args.json_output:
        JSON_DATA["sccm"] = sccm_info
