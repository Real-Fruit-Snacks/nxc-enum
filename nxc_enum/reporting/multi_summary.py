"""Multi-target scan summary reporting."""

from typing import TYPE_CHECKING

from ..core.colors import Colors, c
from ..core.output import output
from .copy_paste import _print_list_section, merge_copy_paste_data

if TYPE_CHECKING:
    from ..models.multi_target import MultiTargetResults


def print_multi_target_summary(results: "MultiTargetResults", args=None):
    """Print aggregate summary for multi-target scan.

    Shows:
    - Per-target status (success/failed with elapsed time)
    - Aggregate findings across all successful targets
    - Key security issues found

    Args:
        results: MultiTargetResults with all target results
    """
    total = len(results.results)
    success = results.success_count
    failed = results.fail_count

    # Header
    output("")
    output(c("=" * 80, Colors.CYAN + Colors.BOLD))
    header = f"MULTI-TARGET SUMMARY ({total} targets)"
    output(c(header.center(80), Colors.CYAN + Colors.BOLD))
    output(c("=" * 80, Colors.CYAN + Colors.BOLD))
    output("")

    # Target Status Section
    output(c("TARGET STATUS", Colors.BOLD))
    output(c("-" * 50, Colors.CYAN))

    for target, result in results.results.items():
        if result.status == "success":
            status_icon = c("[+]", Colors.GREEN)
            status_text = f"Completed ({result.elapsed_time:.1f}s)"
            status_color = Colors.GREEN
        else:
            status_icon = c("[-]", Colors.RED)
            error_msg = result.error if result.error else "Unknown error"
            status_text = f"Failed: {error_msg}"
            status_color = Colors.RED

        output(f"  {status_icon} {target} - {c(status_text, status_color)}")

    output("")

    # Summary counts
    if success > 0:
        output(c(f"  Successful: {success}/{total}", Colors.GREEN))
    if failed > 0:
        output(c(f"  Failed: {failed}/{total}", Colors.RED))
    output("")

    # Only show aggregate findings if we have successful scans
    if success == 0:
        output(c("No successful scans to aggregate.", Colors.YELLOW))
        return

    # Aggregate Findings Section
    findings = results.get_aggregate_findings()

    output(c("AGGREGATE FINDINGS", Colors.BOLD))
    output(c("-" * 50, Colors.CYAN))

    # High-priority security issues
    issues_found = False

    # SMB Signing Disabled
    if findings["smb_signing_disabled"]:
        issues_found = True
        count = len(findings["smb_signing_disabled"])
        label = c("SMB Signing Disabled:", Colors.RED + Colors.BOLD)
        output(f"  {c('[!]', Colors.RED)} {label} {count} target(s)")
        for target in findings["smb_signing_disabled"]:
            output(f"      - {target}")

    # Anonymous Access
    if findings["anonymous_access"]:
        issues_found = True
        count = len(findings["anonymous_access"])
        label = c("Anonymous Access:", Colors.RED + Colors.BOLD)
        output(f"  {c('[!]', Colors.RED)} {label} {count} target(s)")
        for target in findings["anonymous_access"]:
            output(f"      - {target}")

    # WebDAV Enabled
    if findings["webdav_enabled"]:
        issues_found = True
        count = len(findings["webdav_enabled"])
        label = c("WebDAV Enabled:", Colors.YELLOW + Colors.BOLD)
        output(f"  {c('[!]', Colors.YELLOW)} {label} {count} target(s)")
        for target in findings["webdav_enabled"]:
            output(f"      - {target}")

    # Kerberoastable accounts
    if findings["kerberoastable_count"] > 0:
        issues_found = True
        output(
            f"  {c('[*]', Colors.CYAN)} {c('Kerberoastable Accounts:', Colors.BOLD)} "
            f"{findings['kerberoastable_count']} total"
        )

    # AS-REP Roastable accounts
    if findings["asreproastable_count"] > 0:
        issues_found = True
        output(
            f"  {c('[*]', Colors.CYAN)} {c('AS-REP Roastable Accounts:', Colors.BOLD)} "
            f"{findings['asreproastable_count']} total"
        )

    # Delegation accounts
    if findings["delegation_accounts"]:
        issues_found = True
        output(
            f"  {c('[*]', Colors.CYAN)} {c('Delegation Accounts:', Colors.BOLD)} "
            f"{len(findings['delegation_accounts'])} total"
        )

    # PASSWD_NOTREQD accounts
    if findings["pwd_not_required"]:
        issues_found = True
        output(
            f"  {c('[*]', Colors.CYAN)} {c('PASSWD_NOTREQD Accounts:', Colors.BOLD)} "
            f"{len(findings['pwd_not_required'])} total"
        )

    # AdminCount accounts
    if findings["admin_count_accounts"]:
        issues_found = True
        output(
            f"  {c('[*]', Colors.CYAN)} {c('AdminCount=1 Accounts:', Colors.BOLD)} "
            f"{len(findings['admin_count_accounts'])} total"
        )

    # Outdated OS
    if findings["outdated_os"]:
        issues_found = True
        label = c("Outdated/EOL Systems:", Colors.YELLOW + Colors.BOLD)
        output(f"  {c('[!]', Colors.YELLOW)} {label} {len(findings['outdated_os'])} total")

    if not issues_found:
        output(f"  {c('[*]', Colors.GREEN)} No critical security issues detected")

    output("")

    # Statistics
    output(c("STATISTICS", Colors.BOLD))
    output(c("-" * 50, Colors.CYAN))
    output(f"  Total Users Enumerated: {findings['total_users']}")
    output(f"  Total Shares Found: {findings['total_shares']}")
    output(f"  Total Scan Time: {results.total_elapsed:.2f}s")

    output("")

    # Aggregated copy-paste section for multi-target mode
    if args and getattr(args, "copy_paste", False):
        _print_aggregated_copy_paste(results)


def _print_aggregated_copy_paste(results: "MultiTargetResults") -> None:
    """Print aggregated copy-paste lists from all successful targets.

    Args:
        results: MultiTargetResults with all target results
    """
    # Create aggregate copy-paste data
    aggregate_data = {
        "usernames": set(),
        "group_names": set(),
        "share_names": set(),
        "kerberoastable_users": set(),
        "spns": set(),
        "asreproastable_users": set(),
        "delegation_accounts": set(),
        "target_services": set(),
        "dc_hostnames": set(),
        "dc_ips": set(),
        "computer_names": set(),
        "server_names": set(),
        "workstation_names": set(),
        "loggedon_users": set(),
        "pwd_not_required": set(),
        "admincount_accounts": set(),
        "laps_computers": set(),
        "local_admin_members": set(),
        "subnets": set(),
        "pre2k_computers": set(),
        "mssql_databases": set(),
        "ftp_files": set(),
        "nfs_exports": set(),
    }

    # Merge data from all successful targets
    for target, result in results.results.items():
        if result.status == "success" and result.cache:
            merge_copy_paste_data(aggregate_data, result.cache.copy_paste_data)

    # Check if there's any data to print
    has_data = any(v for v in aggregate_data.values())
    if not has_data:
        return

    # Header
    output(c("=" * 80, Colors.MAGENTA + Colors.BOLD))
    header = "AGGREGATED COPY-PASTE LISTS"
    output(c(header.center(80), Colors.MAGENTA + Colors.BOLD))
    output(c("=" * 80, Colors.MAGENTA + Colors.BOLD))

    # Print each category that has data
    _print_list_section("Usernames", aggregate_data.get("usernames", set()))
    _print_list_section("Group Names", aggregate_data.get("group_names", set()))
    _print_list_section("Share Names", aggregate_data.get("share_names", set()))
    _print_list_section(
        "Kerberoastable Usernames", aggregate_data.get("kerberoastable_users", set())
    )
    _print_list_section("SPNs", aggregate_data.get("spns", set()))
    _print_list_section(
        "AS-REP Roastable Usernames", aggregate_data.get("asreproastable_users", set())
    )
    _print_list_section("Delegation Accounts", aggregate_data.get("delegation_accounts", set()))
    _print_list_section("Target Services", aggregate_data.get("target_services", set()))
    _print_list_section("DC Hostnames", aggregate_data.get("dc_hostnames", set()))
    _print_list_section("DC IPs", aggregate_data.get("dc_ips", set()))
    _print_list_section("Computer Names", aggregate_data.get("computer_names", set()))
    _print_list_section("Server Names", aggregate_data.get("server_names", set()))
    _print_list_section("Workstation Names", aggregate_data.get("workstation_names", set()))
    _print_list_section("Logged-On Users", aggregate_data.get("loggedon_users", set()))
    _print_list_section("PASSWD_NOTREQD Accounts", aggregate_data.get("pwd_not_required", set()))
    _print_list_section("AdminCount=1 Accounts", aggregate_data.get("admincount_accounts", set()))
    _print_list_section("LAPS Computers", aggregate_data.get("laps_computers", set()))
    _print_list_section("Local Admin Members", aggregate_data.get("local_admin_members", set()))
    _print_list_section("AD Subnets", aggregate_data.get("subnets", set()))
    _print_list_section("Pre-2K Computers", aggregate_data.get("pre2k_computers", set()))
    _print_list_section("MSSQL Databases", aggregate_data.get("mssql_databases", set()))
    _print_list_section("FTP Files", aggregate_data.get("ftp_files", set()))
    _print_list_section("NFS Exports", aggregate_data.get("nfs_exports", set()))

    output("")
