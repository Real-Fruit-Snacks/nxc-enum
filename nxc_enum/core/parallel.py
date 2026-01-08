"""Parallel execution utilities for running enumeration modules concurrently."""

from concurrent.futures import ThreadPoolExecutor, as_completed

from .constants import PARALLEL_MODULE_WORKERS, PROXY_PARALLEL_MODULE_WORKERS
from .output import (
    OUTPUT_BUFFER,
    _buffer_lock,
    get_output_file_requested,
    get_target_parallel_mode,
    get_thread_local,
    is_proxy_mode,
    output,
    set_parallel_mode,
    status,
)


def run_parallel_modules(args, cache, is_admin: bool = False) -> None:
    """Run independent enumeration modules in parallel with buffered output.

    Modules are executed concurrently using a thread pool. Each module's output
    is buffered separately and then printed in the original order after all
    modules complete.

    Expanded from 7 to 20 modules based on dependency analysis:
    - 95% of modules are independent (no shared state dependencies)
    - Only domain_intel is truly blocking (provides base data for others)
    - Modules here run AFTER domain_intel/smb_info/users/groups have populated cache

    Args:
        args: Parsed command-line arguments
        cache: EnumCache instance for storing results
        is_admin: Whether the current credential has admin privileges
    """
    _thread_local = get_thread_local()

    # Import here to avoid circular imports
    from ..enums.adcs import enum_adcs
    from ..enums.admin_count import enum_admin_count
    from ..enums.asreproast import enum_asreproast
    from ..enums.av import enum_av
    from ..enums.computers import enum_computers
    from ..enums.dc_list import enum_dc_list
    from ..enums.delegation import enum_delegation
    from ..enums.disks import enum_disks
    from ..enums.dns import enum_dns
    from ..enums.ftp import enum_ftp
    from ..enums.gmsa import enum_gmsa
    from ..enums.gpp_password import enum_gpp_password
    from ..enums.interfaces import enum_interfaces
    from ..enums.ioxid import enum_ioxid
    from ..enums.kerberoastable import enum_kerberoastable
    from ..enums.laps import enum_laps
    from ..enums.ldap_signing import enum_ldap_signing
    from ..enums.local_groups import enum_local_groups
    from ..enums.loggedon import enum_loggedon
    from ..enums.maq import enum_maq
    from ..enums.mssql import enum_mssql
    from ..enums.nfs import enum_nfs
    from ..enums.policies import enum_policies
    from ..enums.pre2k import enum_pre2k
    from ..enums.printers import enum_printers
    from ..enums.pso import enum_pso
    from ..enums.pwd_not_required import enum_pwd_not_required
    from ..enums.rdp import enum_rdp
    from ..enums.sccm import enum_sccm
    from ..enums.sessions import enum_sessions
    from ..enums.shares import enum_shares
    from ..enums.signing import enum_signing
    from ..enums.subnets import enum_subnets
    from ..enums.vnc import enum_vnc
    from ..enums.webdav import enum_webdav

    # Modules: (function, name, requires_admin)
    # Expanded to 36 independent modules for maximum parallelization
    # These modules all make independent nxc calls with no shared state dependencies
    modules = [
        # Core enumeration modules
        (enum_shares, "Shares", False),
        (enum_policies, "Policies", False),
        (enum_sessions, "Sessions", True),  # Requires local admin
        (enum_loggedon, "Logged On", True),  # Requires local admin
        (enum_printers, "Printers", False),
        (enum_av, "AV/EDR", True),  # Requires local admin
        (enum_kerberoastable, "Kerberoastable", False),
        # LDAP-based enumeration
        (enum_delegation, "Delegation", False),
        (enum_pwd_not_required, "PASSWD_NOTREQD", False),
        (enum_maq, "MAQ", False),
        (enum_pre2k, "Pre2K", False),
        (enum_laps, "LAPS", False),
        (enum_ldap_signing, "LDAP Signing", False),
        (enum_gmsa, "gMSA", False),  # gMSA account enumeration
        (enum_pso, "PSO", False),  # Fine-Grained Password Policies
        (enum_sccm, "SCCM", False),  # SCCM/MECM discovery
        # SMB-based enumeration
        (enum_dns, "DNS", False),
        (enum_webdav, "WebDAV", False),
        (enum_local_groups, "Local Groups", True),  # Requires local admin
        (enum_gpp_password, "GPP Passwords", False),  # GPP cpassword extraction
        (enum_interfaces, "Interfaces", False),  # Network interfaces (handles perms internally)
        (enum_disks, "Disks", True),  # Requires local admin
        # Service enumeration
        (enum_mssql, "MSSQL", False),
        (enum_rdp, "RDP", False),
        (enum_ftp, "FTP", False),
        (enum_nfs, "NFS", False),
        (enum_vnc, "VNC", False),  # VNC service detection
        # Network discovery (no auth required)
        (enum_ioxid, "iOXID", False),  # Multi-homed host detection via DCOM
        # Previously sequential modules (moved to parallel for performance)
        (enum_computers, "Computers", False),  # Domain computers with OS info
        (enum_asreproast, "AS-REP Roast", False),  # AS-REP roastable accounts
        (enum_adcs, "ADCS", False),  # Certificate templates
        (enum_dc_list, "DC List", False),  # Domain controllers and trusts
        (enum_admin_count, "AdminCount", False),  # adminCount=1 accounts
        (enum_signing, "Signing", False),  # SMB signing requirements
        (enum_subnets, "Subnets", False),  # AD sites and subnets
    ]

    # LDAP-dependent modules - skip when LDAP is unavailable
    ldap_module_names = {
        "Kerberoastable",
        "Delegation",
        "PASSWD_NOTREQD",
        "MAQ",
        "Pre2K",
        "LAPS",
        "LDAP Signing",
        "gMSA",
        "PSO",
        "SCCM",
        "Computers",
        "AS-REP Roast",
        "ADCS",
        "DC List",
        "AdminCount",
        "Subnets",
    }

    # Filter out LDAP modules if LDAP is unavailable
    if cache and not cache.ldap_available:
        original_count = len(modules)
        modules = [
            (func, name, admin) for func, name, admin in modules if name not in ldap_module_names
        ]
        skipped = original_count - len(modules)
        if skipped > 0:
            status(f"LDAP unavailable - skipping {skipped} LDAP-dependent modules", "warning")

    results = {}  # Store buffered output by module name
    failed_modules = []  # Track modules that failed

    def run_with_buffer(func, name, needs_admin):
        """Execute a module with output buffering."""
        _thread_local.buffer = []
        if needs_admin:
            func(args, cache, is_admin)
        else:
            func(args, cache)
        return name, list(_thread_local.buffer)

    set_parallel_mode(True)
    # Use reduced workers in proxy mode to prevent proxy overload
    workers = PROXY_PARALLEL_MODULE_WORKERS if is_proxy_mode() else PARALLEL_MODULE_WORKERS
    with ThreadPoolExecutor(max_workers=workers) as executor:
        # Submit all modules and create a mapping from future to module name
        future_to_name = {}
        for func, name, needs_admin in modules:
            future = executor.submit(run_with_buffer, func, name, needs_admin)
            future_to_name[future] = name

        for future in as_completed(future_to_name):
            module_name = future_to_name[future]
            try:
                name, buffer = future.result()
                results[name] = buffer
            except Exception as e:
                failed_modules.append(module_name)
                status(f"Error in parallel module '{module_name}': {e}", "error")
                results[module_name] = []  # Store empty result for failed module
    set_parallel_mode(False)

    # Report failed modules summary if any
    if failed_modules:
        status(
            f"Warning: {len(failed_modules)} module(s) failed: {', '.join(failed_modules)}",
            "warning",
        )

    # Print buffered output in original order
    # Use output() to respect target-level parallel buffering when active
    for func, name, _ in modules:
        module_buffer = results.get(name, [])
        for line in module_buffer:
            if get_target_parallel_mode():
                # Target parallel mode: route through output() to capture in target buffer
                output(line)
            else:
                # No target parallel: print directly and handle file output
                print(line)
                if get_output_file_requested():
                    with _buffer_lock:
                        OUTPUT_BUFFER.append(line)
