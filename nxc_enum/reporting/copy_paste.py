"""Aggregated copy-paste output section."""

from pathlib import Path
from typing import TYPE_CHECKING

from ..core.colors import Colors, c
from ..core.output import output

if TYPE_CHECKING:
    from ..models.cache import EnumCache


def print_copy_paste_section(cache: "EnumCache", args) -> None:
    """Print aggregated copy-paste lists at the end of enumeration.

    This function outputs all copy-paste data collected during enumeration
    in a single consolidated section, making it easy to copy items into
    other tools.

    Args:
        cache: EnumCache with copy_paste_data populated by enum modules
        args: Parsed arguments (checked for copy_paste flag)
    """
    if not getattr(args, "copy_paste", False):
        return

    data = cache.copy_paste_data
    has_data = False

    # Check if there's any data to print
    for key, value in data.items():
        if value:
            has_data = True
            break

    if not has_data:
        return

    # Header
    output("")
    output(c("=" * 80, Colors.MAGENTA + Colors.BOLD))
    header = "COPY-PASTE LISTS"
    output(c(header.center(80), Colors.MAGENTA + Colors.BOLD))
    output(c("=" * 80, Colors.MAGENTA + Colors.BOLD))

    # Get domain info for qualified usernames
    domain_info = cache.domain_info or {}
    dns_domain = domain_info.get("dns_domain", "")
    hostname = domain_info.get("hostname", "")
    target = cache.target or ""

    # Print each category that has data
    _print_list_section("Targets (Enumerated)", data.get("targets", set()))
    _print_list_section("Usernames", data.get("usernames", set()))

    # Domain users: format as DOMAIN\user (only actual domain users, not local)
    domain_users = data.get("domain_usernames", set())
    if domain_users and dns_domain:
        domain_usernames = {f"{dns_domain}\\{u}" for u in domain_users}
        _print_list_section("Usernames (DOMAIN\\user)", domain_usernames)

    # Local users: format as HOST\user (only actual local users)
    local_users = data.get("local_usernames", set())
    if local_users and hostname:
        local_usernames = {f"{hostname}\\{u}" for u in local_users}
        _print_list_section("Usernames (HOST\\user)", local_usernames)
    _print_list_section("Group Names", data.get("group_names", set()))
    _print_list_section("Share Names", data.get("share_names", set()))

    # Generate UNC paths from share names
    share_names = data.get("share_names", set())
    if share_names and target:
        unc_paths = {f"\\\\{target}\\{s}" for s in share_names}
        _print_list_section("Share UNC Paths", unc_paths)
    _print_list_section("Kerberoastable Usernames", data.get("kerberoastable_users", set()))
    _print_list_section("SPNs", data.get("spns", set()))
    _print_list_section("AS-REP Roastable Usernames", data.get("asreproastable_users", set()))
    _print_list_section("Delegation Accounts", data.get("delegation_accounts", set()))
    _print_list_section("Delegation Target Services", data.get("target_services", set()))
    _print_list_section("DC Hostnames", data.get("dc_hostnames", set()))
    _print_list_section("DC IPs", data.get("dc_ips", set()))
    _print_list_section("Computer Names", data.get("computer_names", set()))
    _print_list_section("Server Names", data.get("server_names", set()))

    # Filter DCs from workstation names to avoid confusion
    dc_hostnames = data.get("dc_hostnames", set())
    workstation_names = data.get("workstation_names", set())
    if dc_hostnames and workstation_names:
        # Remove DCs from workstation list (case-insensitive comparison)
        dc_upper = {dc.upper() for dc in dc_hostnames}
        workstation_names = {ws for ws in workstation_names if ws.upper() not in dc_upper}
    _print_list_section("Workstation Names", workstation_names)
    _print_list_section("Logged-On Users", data.get("loggedon_users", set()))
    _print_list_section("PASSWD_NOTREQD Accounts", data.get("pwd_not_required", set()))
    _print_list_section("AdminCount=1 Accounts", data.get("admincount_accounts", set()))
    _print_list_section("LAPS Computers", data.get("laps_computers", set()))
    _print_list_section("Local Admin Members", data.get("local_admin_members", set()))
    _print_list_section("AD Subnets", data.get("subnets", set()))
    _print_list_section("Pre-2K Computers", data.get("pre2k_computers", set()))
    _print_list_section("MSSQL Databases", data.get("mssql_databases", set()))
    _print_list_section("FTP Files", data.get("ftp_files", set()))
    _print_list_section("NFS Exports", data.get("nfs_exports", set()))

    # New enumeration categories
    _print_list_section("gMSA Accounts", data.get("gmsa_accounts", set()))
    _print_list_section("GPP Credentials", data.get("gpp_passwords", set()))
    _print_list_section("Network Interface IPs", data.get("interface_ips", set()))
    _print_list_section("Disk Drives", data.get("disk_drives", set()))
    _print_list_section("Interesting Files", data.get("interesting_files", set()))
    _print_list_section("SCCM Servers", data.get("sccm_servers", set()))
    _print_list_section("VNC Ports", data.get("vnc_ports", set()))
    _print_list_section("Weak PSO Groups", data.get("weak_pso_groups", set()))
    _print_list_section("iOXID Addresses", data.get("ioxid_addresses", set()))
    _print_list_section("Potential Pivot IPs", data.get("pivot_ips", set()))
    _print_list_section("Custom Query Results", data.get("custom_query_names", set()))

    output("")


def _print_list_section(title: str, items, sort: bool = True) -> None:
    """Print a single copy-paste list section.

    Args:
        title: Section title
        items: Set, list, or other iterable of items to print
        sort: Whether to sort items alphabetically (default True)
    """
    if not items:
        return

    # Convert to list for counting and iteration
    item_list = list(items)

    output("")
    output(c(f"{title} ({len(item_list)}):", Colors.MAGENTA))
    output("-" * 30)

    if sort and not isinstance(items, list):
        # Sort sets and other iterables, preserve list order
        item_list = sorted(item_list)

    for item in item_list:
        output(str(item))


def merge_copy_paste_data(target_data: dict, source_data: dict) -> None:
    """Merge copy-paste data from source into target (for multi-target mode).

    Args:
        target_data: Destination copy_paste_data dict (modified in place)
        source_data: Source copy_paste_data dict to merge from
    """
    for key, value in source_data.items():
        if isinstance(value, set):
            if key not in target_data:
                target_data[key] = set()
            target_data[key].update(value)
        elif isinstance(value, list):
            if key not in target_data:
                target_data[key] = []
            target_data[key].extend(value)


def _title_to_filename(title: str) -> str:
    """Convert a section title to a safe filename.

    Args:
        title: Section title like "Kerberoastable Usernames"

    Returns:
        Safe filename like "kerberoastable_usernames.txt"
    """
    # Remove special chars, convert to lowercase with underscores
    safe = title.lower()
    safe = safe.replace("\\", "")
    safe = safe.replace("/", "")
    safe = safe.replace("(", "").replace(")", "")
    safe = safe.replace("=", "")
    safe = safe.replace("-", "_")
    safe = safe.replace(" ", "_")
    # Clean up multiple underscores
    while "__" in safe:
        safe = safe.replace("__", "_")
    safe = safe.strip("_")
    return f"{safe}.txt"


def _write_list_to_file(output_dir: Path, title: str, items, sort: bool = True) -> bool:
    """Write a single copy-paste list to a file.

    Args:
        output_dir: Directory to write file to
        title: Section title (used to generate filename)
        items: Set, list, or other iterable of items to write
        sort: Whether to sort items alphabetically (default True)

    Returns:
        True if file was written, False if no items to write
    """
    if not items:
        return False

    item_list = list(items)
    if sort and not isinstance(items, list):
        item_list = sorted(item_list)

    filename = _title_to_filename(title)
    filepath = output_dir / filename

    with open(filepath, "w") as f:
        for item in item_list:
            f.write(f"{item}\n")

    return True


def export_copy_paste_to_files(cache: "EnumCache", output_dir: str) -> int:
    """Export all copy-paste lists to individual files in a directory.

    Args:
        cache: EnumCache with copy_paste_data populated by enum modules
        output_dir: Directory path to write files to

    Returns:
        Number of files written
    """
    data = cache.copy_paste_data
    dir_path = Path(output_dir)

    # Create directory if it doesn't exist
    dir_path.mkdir(parents=True, exist_ok=True)

    # Get domain info for qualified usernames
    domain_info = cache.domain_info or {}
    dns_domain = domain_info.get("dns_domain", "")
    hostname = domain_info.get("hostname", "")
    target = cache.target or ""

    files_written = 0

    # Write each category - same logic as print_copy_paste_section
    if _write_list_to_file(dir_path, "Targets", data.get("targets", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "Usernames", data.get("usernames", set())):
        files_written += 1

    # Domain users with qualification
    domain_users = data.get("domain_usernames", set())
    if domain_users and dns_domain:
        domain_usernames = {f"{dns_domain}\\{u}" for u in domain_users}
        if _write_list_to_file(dir_path, "Domain Usernames", domain_usernames):
            files_written += 1

    # Local users with qualification
    local_users = data.get("local_usernames", set())
    if local_users and hostname:
        local_usernames = {f"{hostname}\\{u}" for u in local_users}
        if _write_list_to_file(dir_path, "Local Usernames", local_usernames):
            files_written += 1

    if _write_list_to_file(dir_path, "Group Names", data.get("group_names", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "Share Names", data.get("share_names", set())):
        files_written += 1

    # UNC paths from share names
    share_names = data.get("share_names", set())
    if share_names and target:
        unc_paths = {f"\\\\{target}\\{s}" for s in share_names}
        if _write_list_to_file(dir_path, "Share UNC Paths", unc_paths):
            files_written += 1

    if _write_list_to_file(
        dir_path, "Kerberoastable Users", data.get("kerberoastable_users", set())
    ):
        files_written += 1

    if _write_list_to_file(dir_path, "SPNs", data.get("spns", set())):
        files_written += 1

    if _write_list_to_file(
        dir_path, "ASREProastable Users", data.get("asreproastable_users", set())
    ):
        files_written += 1

    if _write_list_to_file(dir_path, "Delegation Accounts", data.get("delegation_accounts", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "Target Services", data.get("target_services", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "DC Hostnames", data.get("dc_hostnames", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "DC IPs", data.get("dc_ips", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "Computer Names", data.get("computer_names", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "Server Names", data.get("server_names", set())):
        files_written += 1

    # Filter DCs from workstation names
    dc_hostnames = data.get("dc_hostnames", set())
    workstation_names = data.get("workstation_names", set())
    if dc_hostnames and workstation_names:
        dc_upper = {dc.upper() for dc in dc_hostnames}
        workstation_names = {ws for ws in workstation_names if ws.upper() not in dc_upper}
    if _write_list_to_file(dir_path, "Workstation Names", workstation_names):
        files_written += 1

    if _write_list_to_file(dir_path, "Loggedon Users", data.get("loggedon_users", set())):
        files_written += 1

    if _write_list_to_file(
        dir_path, "PASSWD NOTREQD Accounts", data.get("pwd_not_required", set())
    ):
        files_written += 1

    if _write_list_to_file(dir_path, "AdminCount Accounts", data.get("admincount_accounts", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "LAPS Computers", data.get("laps_computers", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "Local Admin Members", data.get("local_admin_members", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "AD Subnets", data.get("subnets", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "Pre2K Computers", data.get("pre2k_computers", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "MSSQL Databases", data.get("mssql_databases", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "FTP Files", data.get("ftp_files", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "NFS Exports", data.get("nfs_exports", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "gMSA Accounts", data.get("gmsa_accounts", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "GPP Credentials", data.get("gpp_passwords", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "Interface IPs", data.get("interface_ips", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "Disk Drives", data.get("disk_drives", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "Interesting Files", data.get("interesting_files", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "SCCM Servers", data.get("sccm_servers", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "VNC Ports", data.get("vnc_ports", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "Weak PSO Groups", data.get("weak_pso_groups", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "iOXID Addresses", data.get("ioxid_addresses", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "Pivot IPs", data.get("pivot_ips", set())):
        files_written += 1

    if _write_list_to_file(dir_path, "Custom Query Results", data.get("custom_query_names", set())):
        files_written += 1

    return files_written
