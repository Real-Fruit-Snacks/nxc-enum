"""MSSQL database enumeration.

This module enumerates MSSQL databases, linked servers, and basic info.
Uses Windows integrated authentication with provided AD credentials.

This is pure enumeration - read-only queries, no command execution.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line


def enum_mssql(args, cache):
    """Enumerate MSSQL databases and configuration.

    Attempts Windows integrated authentication, then enumerates databases.
    """
    print_section("MSSQL Enumeration", args.target)

    auth = cache.auth_args
    status("Checking MSSQL connectivity...")

    # First, check basic connectivity
    mssql_args = ["mssql", args.target] + auth
    rc, stdout, stderr = run_nxc(mssql_args, args.timeout)
    debug_nxc(mssql_args, stdout, stderr, "MSSQL Connect")

    mssql_info = {
        "accessible": False,
        "version": None,
        "databases": [],
        "linked_servers": [],
        "is_sysadmin": False,
    }

    # Check if we connected
    combined = stdout + stderr
    if "STATUS_ACCESS_DENIED" in combined.upper() or "Login failed" in combined:
        status("MSSQL access denied with current credentials", "error")
        if args.json_output:
            JSON_DATA["mssql"] = mssql_info
        return

    if rc != 0 and "Connection refused" in combined:
        status("MSSQL port not open or service not running", "info")
        if args.json_output:
            JSON_DATA["mssql"] = mssql_info
        return

    # Check for successful connection indicators
    if "[+]" not in stdout and "Pwn3d" not in stdout:
        # May not have MSSQL or can't connect
        if "MSSQL" not in stdout.upper():
            status("MSSQL service not detected or not accessible", "info")
            if args.json_output:
                JSON_DATA["mssql"] = mssql_info
            return

    mssql_info["accessible"] = True

    # Check for sysadmin (Pwn3d!)
    if "Pwn3d" in stdout:
        mssql_info["is_sysadmin"] = True

    # Parse version from connection output
    version_match = re.search(r"Microsoft SQL Server (\d+)", stdout)
    if version_match:
        mssql_info["version"] = version_match.group(1)

    status("Connected to MSSQL, enumerating databases...", "success")
    output("")

    # Query databases
    db_query = "SELECT name FROM master.dbo.sysdatabases"
    db_args = ["mssql", args.target] + auth + ["-q", db_query]
    rc_db, stdout_db, stderr_db = run_nxc(db_args, args.timeout)
    debug_nxc(db_args, stdout_db, stderr_db, "MSSQL Databases")

    databases = []
    for line in stdout_db.split("\n"):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue
        # Look for database names in output
        # Format: "MSSQL IP PORT HOST  dbname"
        if line.startswith("MSSQL"):
            parts = line.split()
            if len(parts) >= 5:
                db_name = parts[-1]
                # Skip common non-database tokens
                if db_name not in ("[*]", "[+]", "[-]", "name", "---"):
                    if db_name not in databases:
                        databases.append(db_name)

    mssql_info["databases"] = databases

    # Query linked servers
    linked_query = "SELECT name FROM sys.servers WHERE is_linked = 1"
    linked_args = ["mssql", args.target] + auth + ["-q", linked_query]
    rc_linked, stdout_linked, stderr_linked = run_nxc(linked_args, args.timeout)
    debug_nxc(linked_args, stdout_linked, stderr_linked, "MSSQL Linked Servers")

    linked_servers = []
    for line in stdout_linked.split("\n"):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue
        if line.startswith("MSSQL"):
            parts = line.split()
            if len(parts) >= 5:
                server_name = parts[-1]
                if server_name not in (
                    "[*]",
                    "[+]",
                    "[-]",
                    "name",
                    "---",
                    "0",
                ):
                    if server_name not in linked_servers:
                        linked_servers.append(server_name)

    mssql_info["linked_servers"] = linked_servers

    # Store in cache
    cache.mssql_info = mssql_info
    cache.mssql_databases = databases
    cache.mssql_linked_servers = linked_servers

    # Display results
    output(c("MSSQL SERVER INFO", Colors.CYAN))
    output(f"{'-'*50}")

    if mssql_info["version"]:
        output(f"  Version: SQL Server {mssql_info['version']}")

    if mssql_info["is_sysadmin"]:
        output(f"  {c('[!] Current user has SYSADMIN privileges!', Colors.RED + Colors.BOLD)}")
    output("")

    if databases:
        output(c(f"DATABASES ({len(databases)})", Colors.CYAN))
        output(f"{'-'*50}")
        for db in sorted(databases):
            # Highlight system vs user databases
            if db in ("master", "tempdb", "model", "msdb"):
                output(f"  {c('[*]', Colors.CYAN)} {db} (system)")
            else:
                output(f"  {c('[+]', Colors.GREEN)} {c(db, Colors.GREEN)} (user)")
        output("")

        # Store copy-paste data
        cache.copy_paste_data["mssql_databases"] = set(databases)

    if linked_servers:
        output(
            c(
                f"LINKED SERVERS ({len(linked_servers)})",
                Colors.YELLOW + Colors.BOLD,
            )
        )
        output(f"{'-'*50}")
        for server in sorted(linked_servers):
            output(f"  {c('[!]', Colors.YELLOW)} {server}")
        output("")
        output(c("  [*] Linked servers may allow lateral movement", Colors.YELLOW))
        output("")

    # Add next steps if sysadmin
    if mssql_info["is_sysadmin"]:
        cache.add_next_step(
            finding="MSSQL sysadmin access",
            command=f"nxc mssql {args.target} {' '.join(auth)} -x 'whoami'",
            description="Execute OS commands via xp_cmdshell (if enabled)",
            priority="high",
        )

    if not databases and not linked_servers:
        status("Connected but no databases enumerated", "info")

    if args.json_output:
        JSON_DATA["mssql"] = mssql_info
