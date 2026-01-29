"""MSSQL service detection and authentication check.

This module detects MSSQL service availability and tests authentication.
It does NOT execute any SQL queries on the target.

All enumeration commands are provided as recommendations for manual execution.
"""

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line
from ..reporting.next_steps import get_external_tool_auth


def enum_mssql(args, cache):
    """Detect MSSQL service and test authentication.

    This module only:
    - Tests if MSSQL port (1433) is accessible
    - Tests if provided credentials authenticate
    - Detects if user has sysadmin privileges
    - Recommends enumeration commands for manual execution

    NO SQL queries are executed on the target.
    """
    target = cache.target if cache else args.target
    print_section("MSSQL Detection", target, cache=cache)

    # Skip if port pre-scan determined MSSQL is unavailable
    if cache.mssql_available is False:
        status("MSSQL port (1433) not open - skipping", "info")
        if args.json_output:
            JSON_DATA["mssql"] = {"accessible": False, "authenticated": False}
        return

    auth = cache.auth_args
    status("Testing MSSQL connectivity and authentication...")

    # Test connectivity and authentication only (no queries)
    mssql_args = ["mssql", target] + auth
    rc, stdout, stderr = run_nxc(mssql_args, args.timeout)
    debug_nxc(mssql_args, stdout, stderr, "MSSQL Connect")

    mssql_info = {
        "accessible": False,
        "authenticated": False,
        "is_sysadmin": False,
        "hostname": None,
        "domain": None,
    }

    # Check for connection/auth issues
    combined = stdout + stderr
    combined_upper = combined.upper()

    if "Connection refused" in combined or "timed out" in combined.lower():
        status("MSSQL port not open or service not running", "info")
        if args.json_output:
            JSON_DATA["mssql"] = mssql_info
        return

    if "STATUS_ACCESS_DENIED" in combined_upper or "Login failed" in combined:
        status("MSSQL access denied with current credentials", "warning")
        mssql_info["accessible"] = True  # Port is open, just auth failed
        if args.json_output:
            JSON_DATA["mssql"] = mssql_info
        return

    # Parse successful connection output
    for line in stdout.split("\n"):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue

        # Check for successful auth indicator
        if "[+]" in line and "MSSQL" in line:
            mssql_info["accessible"] = True
            mssql_info["authenticated"] = True

            # Parse hostname/domain from line
            # Format: "MSSQL IP PORT HOSTNAME [+] domain\user"
            parts = line.split()
            if len(parts) >= 4:
                mssql_info["hostname"] = parts[3]

        # Check for sysadmin (Pwn3d!)
        if "Pwn3d" in line:
            mssql_info["is_sysadmin"] = True

    # Store in cache
    cache.mssql_info = mssql_info

    # Display results
    if mssql_info["authenticated"]:
        status("MSSQL authentication successful", "success")
        output("")

        output(c("MSSQL SERVICE DETECTED", Colors.CYAN))
        output(f"{'-'*50}")
        if mssql_info["hostname"]:
            output(f"  Hostname: {mssql_info['hostname']}")
        output(f"  Authenticated: {c('Yes', Colors.GREEN)}")

        if mssql_info["is_sysadmin"]:
            output(f"  Privileges: {c('SYSADMIN', Colors.RED + Colors.BOLD)}")
            output("")
            output(c("[!] Current user has SYSADMIN privileges!", Colors.RED + Colors.BOLD))
        else:
            output("  Privileges: Standard user")

        output("")

        # Build auth string for recommendations
        auth_info = get_external_tool_auth(args, cache, tool="nxc")
        auth_str = auth_info["auth_string"]

        # Provide enumeration command recommendations
        output(c("RECOMMENDED ENUMERATION COMMANDS:", Colors.YELLOW))
        output(f"{'-'*50}")
        output("")

        # Database enumeration
        output(c("[*] List databases:", Colors.CYAN))
        output(f"    nxc mssql {target} {auth_str} -q 'SELECT name FROM master.dbo.sysdatabases'")
        output("")

        # Linked servers
        output(c("[*] List linked servers (lateral movement):", Colors.CYAN))
        query = "SELECT name FROM sys.servers WHERE is_linked=1"
        output(f"    nxc mssql {target} {auth_str} -q '{query}'")
        output("")

        # Current user info
        output(c("[*] Check current privileges:", Colors.CYAN))
        query = 'SELECT SYSTEM_USER, IS_SRVROLEMEMBER("sysadmin")'
        output(f"    nxc mssql {target} {auth_str} -q '{query}'")
        output("")

        # Impersonation check
        output(c("[*] Check impersonation privileges:", Colors.CYAN))
        output(f"    nxc mssql {target} {auth_str} -M mssql_priv")
        output("")

        # Logins enumeration
        output(c("[*] Enumerate SQL logins:", Colors.CYAN))
        output(f"    nxc mssql {target} {auth_str} -M enum_logins")
        output("")

        if mssql_info["is_sysadmin"]:
            output(c("[!] SYSADMIN COMMANDS (use with caution):", Colors.RED))
            output(f"{'-'*50}")
            output("")

            output(c("[*] Execute OS commands (if xp_cmdshell enabled):", Colors.RED))
            output(f"    nxc mssql {target} {auth_str} -x 'whoami'")
            output("")

            output(c("[*] Enable xp_cmdshell:", Colors.RED))
            query = "EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE"
            output(f'    nxc mssql {target} {auth_str} -q "{query}"')
            output("")

        # Add to next steps
        priv_level = "sysadmin" if mssql_info["is_sysadmin"] else "standard user"
        cache.add_next_step(
            finding=f"MSSQL authenticated ({priv_level})",
            command=f"nxc mssql {target} {auth_str} -q 'SELECT name FROM sysdatabases'",
            description="Enumerate databases on MSSQL server",
            priority="high" if mssql_info["is_sysadmin"] else "medium",
        )

        if mssql_info["is_sysadmin"]:
            cache.add_next_step(
                finding="MSSQL sysadmin access",
                command=f"nxc mssql {target} {auth_str} -x 'whoami'",
                description="Execute OS commands via xp_cmdshell (if enabled)",
                priority="high",
            )

    elif mssql_info["accessible"]:
        status("MSSQL port accessible but authentication failed", "warning")
    else:
        status("MSSQL service not detected", "info")

    if args.json_output:
        JSON_DATA["mssql"] = mssql_info
