"""Main entry point for nxc_enum.

This module orchestrates the nxc-enum enumeration workflow:
1. Parse and validate command-line arguments
2. Expand targets (CIDR, ranges, files)
3. Parse and validate credentials
4. Run enumeration modules (parallel where possible)
5. Generate reports and write output

Supports multi-target scanning with per-target output and aggregate summary.
"""

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.colors import Colors, c
from ..core.constants import (
    MULTI_TARGET_WORKERS,
    PRESCAN_THRESHOLD,
    PROXY_DEFAULT_COMMAND_TIMEOUT,
    PROXY_MULTI_TARGET_WORKERS,
    RE_ANSI_ESCAPE,
)
from ..core.output import (
    JSON_DATA,
    OUTPUT_BUFFER,
    get_discovery_json,
    get_json_data_copy,
    get_output_buffer_copy,
    get_per_target_filename,
    get_target_local,
    get_target_print_lock,
    is_proxy_mode,
    output,
    output_direct,
    print_banner,
    print_discovery_results,
    print_section,
    print_target_footer,
    print_target_header,
    set_debug_mode,
    set_output_file_requested,
    set_proxy_mode,
    set_target_parallel_mode,
    status,
)
from ..core.parallel import run_parallel_modules
from ..core.runner import (
    parallel_port_prescan,
    parallel_prescan_services,
    parallel_smb_validation,
    run_nxc,
    validate_host_smb,
)

# Import all enum functions
from ..enums import (
    enum_adcs,
    enum_admin_count,
    enum_asreproast,
    enum_av,
    enum_av_multi,
    enum_bitlocker,
    enum_computers,
    enum_custom_query,
    enum_dc_list,
    enum_delegation,
    enum_descriptions,
    enum_dns,
    enum_domain_intel,
    enum_ftp,
    enum_groups,
    enum_laps,
    enum_ldap_signing,
    enum_listeners,
    enum_local_groups,
    enum_loggedon,
    enum_loggedon_multi,
    enum_maq,
    enum_mssql,
    enum_nfs,
    enum_os_info,
    enum_policies,
    enum_pre2k,
    enum_printers,
    enum_printers_multi,
    enum_pwd_not_required,
    enum_rdp,
    enum_rpc_session,
    enum_sessions,
    enum_sessions_multi,
    enum_shares,
    enum_shares_multi,
    enum_signing,
    enum_smb_info,
    enum_subnets,
    enum_target_info,
    enum_users,
    enum_webdav,
)
from ..models.cache import EnumCache
from ..models.credential import CredentialError
from ..models.multi_target import MultiTargetResults, TargetResult
from ..models.results import MultiUserResults
from ..parsing.credentials import parse_credentials
from ..parsing.targets import TargetExpansionError, expand_targets

# Import reporting functions
from ..reporting import (
    export_copy_paste_to_files,
    print_copy_paste_section,
    print_executive_summary,
    print_executive_summary_multi,
    print_multi_target_summary,
    print_next_steps,
)
from ..validation.anonymous import probe_anonymous_sessions
from ..validation.hosts import check_hosts_resolution_from_info
from ..validation.multi import validate_credentials_multi
from ..validation.single import validate_credentials
from .args import create_parser


def _get_auth_type_from_args(args) -> str:
    """Determine authentication type from command-line arguments.

    Returns one of: 'password', 'hash', 'kerberos', 'certificate', 'anonymous', 'none'
    """
    # Check for Kerberos auth
    if getattr(args, "use_kcache", False) or getattr(args, "aes_key", None):
        return "kerberos"
    if getattr(args, "kerberos", False):
        return "kerberos"

    # Check for certificate auth
    if getattr(args, "pfx_cert", None) or getattr(args, "pem_cert", None):
        return "certificate"

    # Check for hash auth
    if getattr(args, "hash", None):
        return "hash"

    # Check for password auth
    if getattr(args, "password", None) is not None:
        return "password"

    # Check for anonymous
    if not getattr(args, "user", None):
        return "anonymous"

    return "none"


def _run_single_target(
    args, target: str, creds: list, smb_cache: dict | None = None
) -> TargetResult:
    """Run enumeration against a single target.

    This is the core enumeration logic extracted from main() to support
    multi-target scanning. Each call gets a fresh cache instance.

    Args:
        args: Parsed command-line arguments
        target: Single target IP/hostname to scan
        creds: List of credentials (parsed from args)
        smb_cache: Optional pre-computed SMB validation results from parallel pre-scan

    Returns:
        TargetResult with status, cache, and elapsed time
    """
    target_start = time.time()

    # ─────────────────────────────────────────────────────────────────────────
    # SMB REACHABILITY CHECK (use cache if available, else validate)
    # ─────────────────────────────────────────────────────────────────────────
    if smb_cache and target in smb_cache:
        # Use pre-computed validation from parallel pre-scan
        is_reachable, smb_info = smb_cache[target]
    elif getattr(args, "no_smb", False):
        # Skip SMB validation when --no-smb is set
        status("Skipping SMB validation (--no-smb)", "info")
        is_reachable, smb_info = True, {}
    else:
        # No cache - validate now
        status("Checking SMB reachability...", "info")
        is_reachable, smb_info = validate_host_smb(
            target,
            timeout=args.timeout,
            port=getattr(args, "port", None),
            smb_timeout=getattr(args, "smb_timeout", None),
        )

    if not is_reachable:
        status("Host not responding to SMB - skipping", "warning")
        elapsed = time.time() - target_start
        return TargetResult(
            target=target,
            status="skipped",
            error="Host unreachable (no SMB response)",
            elapsed_time=elapsed,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # HOSTS RESOLUTION CHECK (uses data from SMB validation - no second call)
    # ─────────────────────────────────────────────────────────────────────────
    if is_proxy_mode():
        # Skip hostname validation in proxy mode (DNS bypasses proxy)
        status("Hostname validation skipped in proxy mode (use IP addresses)", "info")
    elif not args.skip_hosts_check:
        # Only check if we got hostname data from SMB banner
        if smb_info.get("fqdn"):
            success, hosts_line = check_hosts_resolution_from_info(target, smb_info)
            if not success:
                status("Target hostname does not resolve to target IP", "error")
                output(f"  Add to /etc/hosts: {c(hosts_line, Colors.YELLOW)}")
                echo_cmd = 'echo "{}" | sudo tee -a /etc/hosts'.format(hosts_line)
                output(f"  Command: {c(echo_cmd, Colors.CYAN)}")
                output("")
                status(
                    "Use --skip-hosts-check to bypass this check (not recommended)",
                    "info",
                )
                elapsed = time.time() - target_start
                return TargetResult(
                    target=target,
                    status="failed",
                    error="Hostname resolution failed - add entry to /etc/hosts",
                    elapsed_time=elapsed,
                )
    else:
        status("Skipping hosts resolution check (--skip-hosts-check)", "warning")

    # Track if running in anonymous mode (null or guest session)
    anonymous_mode = False
    has_creds = bool(creds)
    working_creds = list(creds)  # Copy to avoid modifying original

    # Probe for null/guest sessions (security finding)
    anon_result = probe_anonymous_sessions(
        target,
        args.timeout,
        has_creds=has_creds,
        port=getattr(args, "port", None),
        smb_timeout=getattr(args, "smb_timeout", None),
    )

    # Store anonymous access findings in cache for reporting
    anon_findings = {
        "null_available": anon_result.null_success,
        "guest_available": anon_result.guest_success,
        "ldap_anonymous": anon_result.ldap_anonymous,
    }

    if not working_creds:
        # No credentials provided - use anonymous if available
        if anon_result.working_credential:
            working_creds = [anon_result.working_credential]
            anonymous_mode = True
            output("")
            status(
                f"Continuing with {anon_result.session_type} session - "
                "some modules may have limited results",
                "warning",
            )
        else:
            # No anonymous access available
            elapsed = time.time() - target_start
            return TargetResult(
                target=target,
                status="failed",
                error="No credentials and no anonymous access available",
                elapsed_time=elapsed,
            )
    else:
        # Credentials provided - report anonymous findings and continue with creds
        output("")
        if anon_result.null_success or anon_result.guest_success:
            status(
                "Note: Anonymous access detected but using provided credentials",
                "info",
            )

    # Detect multi-credential mode
    multi_cred_mode = len(working_creds) > 1

    listener_results = {}

    # Initialize cache for this target
    cache = EnumCache()
    cache.target = target
    cache.timeout = args.timeout
    cache.anonymous_mode = anonymous_mode
    cache.anonymous_access = anon_findings
    # Store network options for run_nxc calls
    cache.port = getattr(args, "port", None)
    cache.smb_timeout = getattr(args, "smb_timeout", None)
    cache.ipv6 = getattr(args, "ipv6", False)
    cache.dns_server = getattr(args, "dns_server", None)
    cache.dns_tcp = getattr(args, "dns_tcp", False)

    # Display network options in use (helps user understand what's being applied)
    network_opts = []
    if cache.port:
        network_opts.append(f"port={cache.port}")
    if cache.smb_timeout:
        network_opts.append(f"smb-timeout={cache.smb_timeout}s")
    if cache.ipv6:
        network_opts.append("IPv6")
    if cache.dns_server:
        network_opts.append(f"dns={cache.dns_server}")
    if cache.dns_tcp:
        network_opts.append("dns-tcp")
    if network_opts:
        status(f"Network options: {', '.join(network_opts)}", "info")

    # Initialize multi_results for multi-cred mode
    multi_results = None
    if multi_cred_mode:
        multi_results = MultiUserResults()

    # Validate credentials (skip for anonymous - already validated during probe)
    if not args.no_validate and not anonymous_mode:
        if multi_cred_mode:
            # Multi-credential validation (parallel)
            valid_creds = validate_credentials_multi(target, working_creds, args.timeout, args)
            if not valid_creds:
                status("Hint: Use --no-validate to skip credential validation", "info")
                elapsed = time.time() - target_start
                return TargetResult(
                    target=target,
                    status="failed",
                    error="No valid credentials found",
                    elapsed_time=elapsed,
                )
            working_creds = valid_creds

            # Select best credential for cached operations
            admin_creds = [cred for cred in working_creds if cred.is_admin]
            primary_cred = admin_creds[0] if admin_creds else working_creds[0]

            try:
                cache.auth_args = primary_cred.auth_args()
                cache.primary_credential = primary_cred
            except CredentialError as e:
                status(f"Credential error: {e}", "error")
                status("Hint: Use --no-validate to skip credential validation", "info")
                elapsed = time.time() - target_start
                return TargetResult(
                    target=target,
                    status="failed",
                    error=f"Credential error: {e}",
                    elapsed_time=elapsed,
                )

            if not admin_creds:
                status("Note: No admin credentials found - some modules may be limited", "warning")
        else:
            # Single credential validation
            status("Validating credentials...", "info")
            try:
                cache.auth_args = working_creds[0].auth_args()
                cache.primary_credential = working_creds[0]
            except CredentialError as e:
                status(f"Credential error: {e}", "error")
                status("Hint: Use --no-validate to skip credential validation", "info")
                elapsed = time.time() - target_start
                return TargetResult(
                    target=target,
                    status="failed",
                    error=f"Credential error: {e}",
                    elapsed_time=elapsed,
                )

            valid, is_admin = validate_credentials(target, cache.auth_args, cache)
            if not valid:
                status("Hint: Use --no-validate to skip credential validation", "info")
                elapsed = time.time() - target_start
                return TargetResult(
                    target=target,
                    status="failed",
                    error="Credential validation failed",
                    elapsed_time=elapsed,
                )
            working_creds[0].is_admin = is_admin
            admin_msg = c(" (LOCAL ADMIN)", Colors.RED) if is_admin else ""
            status(f"Credentials validated successfully{admin_msg}", "success")
    elif anonymous_mode:
        try:
            cache.auth_args = working_creds[0].auth_args()
            cache.primary_credential = working_creds[0]
        except CredentialError as e:
            status(f"Credential error: {e}", "error")
            elapsed = time.time() - target_start
            return TargetResult(
                target=target,
                status="failed",
                error=f"Credential error: {e}",
                elapsed_time=elapsed,
            )
    else:
        # --no-validate
        status("Skipping credential validation (--no-validate)", "warning")
        status("Admin detection disabled - admin-only modules will be skipped", "warning")
        try:
            cache.auth_args = working_creds[0].auth_args()
            cache.primary_credential = working_creds[0]
        except CredentialError as e:
            status(f"Credential error: {e}", "error")
            elapsed = time.time() - target_start
            return TargetResult(
                target=target,
                status="failed",
                error=f"Credential error: {e}",
                elapsed_time=elapsed,
            )

    # ─────────────────────────────────────────────────────────────────────────
    # VALIDATE-ONLY MODE - Skip enumeration, just show credential results
    # ─────────────────────────────────────────────────────────────────────────
    if args.validate_only:
        elapsed = time.time() - target_start
        print_section("Credential Validation Results", target)

        # Show target info
        hostname = smb_info.get("hostname", "")
        domain = smb_info.get("dns_domain", args.domain or "")
        if hostname:
            status(f"Target: {target} ({hostname})")
        else:
            status(f"Target: {target}")
        if domain:
            status(f"Domain: {domain}")

        output("")

        # Show validated credentials
        if multi_cred_mode:
            admin_creds = [cred for cred in working_creds if cred.is_admin]
            std_creds = [cred for cred in working_creds if not cred.is_admin]

            status(f"Validated {len(working_creds)} credential(s)", "success")
            output("")

            if admin_creds:
                output(c("LOCAL ADMIN CREDENTIALS", Colors.RED + Colors.BOLD))
                output(f"{'-'*50}")
                for cred in admin_creds:
                    auth_type = cred.auth_type()
                    if cred.password:
                        cred_str = cred.password
                    elif cred.hash:
                        cred_str = cred.hash[:32] + "..."
                    else:
                        cred_str = "N/A"
                    output(f"  {c('[ADMIN]', Colors.RED)} {cred.user}:{cred_str} ({auth_type})")
                output("")

            if std_creds:
                output(c("STANDARD CREDENTIALS", Colors.GREEN))
                output(f"{'-'*50}")
                for cred in std_creds:
                    auth_type = cred.auth_type()
                    if cred.password:
                        cred_str = cred.password
                    elif cred.hash:
                        cred_str = cred.hash[:32] + "..."
                    else:
                        cred_str = "N/A"
                    output(f"  {cred.user}:{cred_str} ({auth_type})")
                output("")

            # Summary
            if admin_creds:
                status(
                    f"{len(admin_creds)} admin credential(s) - can run privileged modules!",
                    "warning",
                )
        else:
            # Single credential
            cred = working_creds[0]
            auth_type = cred.auth_type()
            if cred.is_admin:
                status(f"Valid: {cred.user} ({auth_type}) - LOCAL ADMIN!", "success")
            else:
                status(f"Valid: {cred.user} ({auth_type})", "success")

        output("")
        status(f"Completed in {elapsed:.2f}s")

        return TargetResult(
            target=target,
            status="success",
            cache=cache,
            elapsed_time=elapsed,
        )

    # Store valid credentials in copy-paste data (format: domain\user:secret or user:secret)
    for cred in working_creds:
        # Build credential string in copy-pastable format
        user_part = cred.display_name()  # e.g., "domain\user" or "user"
        if cred.password:
            cred_str = f"{user_part}:{cred.password}"
        elif cred.hash:
            cred_str = f"{user_part}:{cred.hash}"
        elif cred.ccache_file:
            cred_str = f"{user_part}:KRB5CCACHE:{cred.ccache_file}"
        elif cred.pfx_file:
            cred_str = f"{user_part}:PFX:{cred.pfx_file}"
        elif cred.pem_file:
            cred_str = f"{user_part}:PEM:{cred.pem_file}"
        else:
            cred_str = f"{user_part}:(no secret)"
        cache.copy_paste_data["valid_credentials"].add(cred_str)

    # Determine which modules to run
    run_all = args.all or not any(
        (
            args.users,
            args.groups,
            args.shares,
            args.policies,
            args.sessions,
            args.loggedon,
            args.printers,
            args.av,
            args.computers,
            args.local_groups,
            args.subnets,
            args.delegation,
            args.asreproast,
            args.descriptions,
            args.maq,
            args.adcs,
            args.dc_list,
            args.pwd_not_reqd,
            args.admin_count,
            args.signing,
            args.webdav,
            args.dns,
            args.laps,
            args.ldap_signing,
            args.pre2k,
            args.bitlocker,
            args.mssql,
            args.rdp,
            args.ftp,
            args.nfs,
            args.query,
        )
    )

    # Target info always shown
    enum_target_info(args, working_creds, cache)

    if run_all:
        # Phase 1: Parallel port scanning
        enum_listeners(args, listener_results, cache)
        cache.listener_results = listener_results  # Store for use by other modules

        # Phase 1.5: Service port pre-scan (determines which protocols are available)
        # This saves ~30-60 seconds per unreachable service during enumeration
        status("Pre-scanning service ports...", "info")
        service_results = parallel_prescan_services(target, ipv6=getattr(args, "ipv6", False))
        cache.apply_service_prescan(service_results)

        # Log service availability (helps user understand what will be skipped)
        available_services = [svc for svc, avail in service_results.items() if avail]
        unavailable_services = [svc for svc, avail in service_results.items() if not avail]
        if available_services:
            status(f"Services available: {', '.join(available_services)}", "success")
        if unavailable_services:
            status(f"Services unavailable: {', '.join(unavailable_services)}", "info")

        # Phase 2: Parallel cache priming
        status("Priming caches in parallel...", "info")
        cache.prime_caches(target, cache.auth_args)

        # Phase 3: Sequential extraction from cached data
        enum_domain_intel(args, cache, listener_results)
        enum_smb_info(args, cache)
        enum_rpc_session(args, cache)
        enum_os_info(args, cache)
        enum_users(args, cache)
        enum_groups(args, cache)

        if multi_cred_mode:
            # Multi-cred mode: Run domain-wide modules in parallel, then per-credential modules
            # Domain-wide modules query AD data that's the same regardless of credential
            is_admin_multi = (
                any(cred.is_admin for cred in working_creds) if working_creds else False
            )
            run_parallel_modules(args, cache, is_admin_multi)

            # BitLocker requires admin
            enum_bitlocker(args, cache, is_admin_multi)

            # Per-credential modules: These compare access levels across credentials
            enum_shares_multi(args, working_creds, multi_results, cache)
            enum_sessions_multi(args, working_creds, multi_results, cache)
            enum_loggedon_multi(args, working_creds, multi_results, cache)
            enum_printers_multi(args, working_creds, multi_results, cache)
            enum_av_multi(args, working_creds, multi_results, cache)

            print_executive_summary_multi(args, cache, working_creds, multi_results)
        else:
            # Single-cred mode
            # run_parallel_modules now handles 20 modules in parallel:
            # shares, policies, sessions, loggedon, printers, av, kerberoastable,
            # delegation, pwd_not_required, maq, pre2k, dns, webdav, laps,
            # ldap_signing, local_groups, mssql, rdp, ftp, nfs
            is_admin = working_creds[0].is_admin if working_creds else False
            run_parallel_modules(args, cache, is_admin)

            # BitLocker requires admin and depends on computer list from parallel modules
            enum_bitlocker(args, cache, is_admin)

            print_executive_summary(args, cache)
    else:
        # Run selected modules only
        if args.users:
            enum_users(args, cache)
        if args.groups:
            enum_groups(args, cache)
        if args.shares:
            if multi_cred_mode:
                enum_shares_multi(args, working_creds, multi_results, cache)
            else:
                enum_shares(args, cache)
        if args.policies:
            enum_policies(args, cache)
        if args.sessions:
            if multi_cred_mode:
                enum_sessions_multi(args, working_creds, multi_results, cache)
            else:
                is_admin = working_creds[0].is_admin if working_creds else False
                enum_sessions(args, cache, is_admin)
        if args.loggedon:
            if multi_cred_mode:
                enum_loggedon_multi(args, working_creds, multi_results, cache)
            else:
                is_admin = working_creds[0].is_admin if working_creds else False
                enum_loggedon(args, cache, is_admin)
        if args.printers:
            if multi_cred_mode:
                enum_printers_multi(args, working_creds, multi_results, cache)
            else:
                enum_printers(args, cache)
        if args.av:
            if multi_cred_mode:
                enum_av_multi(args, working_creds, multi_results, cache)
            else:
                is_admin = working_creds[0].is_admin if working_creds else False
                enum_av(args, cache, is_admin)
        if args.computers:
            enum_computers(args, cache)
        if args.asreproast:
            enum_asreproast(args, cache)
        if args.delegation:
            enum_delegation(args, cache)
        if args.descriptions:
            enum_descriptions(args, cache)
        if args.maq:
            enum_maq(args, cache)
        if args.adcs:
            enum_adcs(args, cache)
        if args.dc_list:
            enum_dc_list(args, cache)
        if args.pwd_not_reqd:
            enum_pwd_not_required(args, cache)
        if args.admin_count:
            enum_admin_count(args, cache)
        if args.signing:
            enum_signing(args, cache)
        if args.webdav:
            enum_webdav(args, cache)
        if args.dns:
            enum_dns(args, cache)
        if args.laps:
            enum_laps(args, cache)
        if args.ldap_signing:
            enum_ldap_signing(args, cache)
        if args.local_groups:
            enum_local_groups(args, cache)
        if args.subnets:
            enum_subnets(args, cache)
        if args.pre2k:
            enum_pre2k(args, cache)
        if args.bitlocker:
            is_admin = working_creds[0].is_admin if working_creds else False
            enum_bitlocker(args, cache, is_admin)
        if args.mssql:
            enum_mssql(args, cache)
        if args.rdp:
            enum_rdp(args, cache)
        if args.ftp:
            enum_ftp(args, cache)
        if args.nfs:
            enum_nfs(args, cache)
        if args.query:
            # Custom LDAP query requires cache priming for LDAP availability check
            if not hasattr(cache, "ldap_available") or cache.ldap_available is None:
                cache.prime_caches(target, cache.auth_args)
            enum_custom_query(args, cache)

    # Add target to successfully enumerated targets list
    cache.copy_paste_data["targets"].add(target)

    # Print next steps for this target
    print_next_steps(args, cache)

    # Print aggregated copy-paste section
    print_copy_paste_section(cache, args)

    # Export copy-paste lists to individual files if requested
    if getattr(args, "copy_paste_dir", None):
        files_written = export_copy_paste_to_files(cache, args.copy_paste_dir)
        if files_written > 0:
            status(f"Wrote {files_written} copy-paste files to {args.copy_paste_dir}/", "success")

    elapsed = time.time() - target_start

    # Capture per-target data for separate output files
    target_json_data = get_json_data_copy()
    target_output_lines = get_output_buffer_copy()

    return TargetResult(
        target=target,
        status="success",
        cache=cache,
        elapsed_time=elapsed,
        json_data=target_json_data,
        output_lines=target_output_lines,
    )


def _run_target_parallel(
    args, target: str, creds: list, smb_cache: dict, idx: int, total: int
) -> tuple[TargetResult, list]:
    """Run single target with buffered output for parallel multi-target execution.

    This wrapper captures all output from _run_single_target() into a buffer,
    allowing atomic printing to prevent output interleaving between targets.

    Args:
        args: Parsed command-line arguments
        target: Target IP/hostname to scan
        creds: List of credentials
        smb_cache: Pre-computed SMB validation results
        idx: Target index (1-indexed)
        total: Total number of targets

    Returns:
        Tuple of (TargetResult, output_buffer_list)
    """
    _target_local = get_target_local()
    _target_local.buffer = []

    # Capture target header
    print_target_header(target, idx, total)

    # Run enumeration - all output goes to thread-local buffer
    result = _run_single_target(args, target, creds, smb_cache)

    # Capture target footer
    print_target_footer(target, result.status, result.elapsed_time)

    # Return result and captured output
    return result, list(_target_local.buffer)


def run_asreproast_spray(args, targets: list[str]) -> int:
    """Run unauthenticated AS-REP roasting against userlist.

    This mode bypasses normal credential validation and directly requests
    AS-REP tickets for each user in the list, similar to nxc's native behavior.

    Args:
        args: Parsed command-line arguments
        targets: List of target hosts

    Returns:
        Exit code (0 for success)
    """
    import tempfile

    # Read users from file or use single user
    users = []
    if args.userfile:
        try:
            with open(args.userfile, encoding="utf-8-sig") as f:
                users = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        except FileNotFoundError:
            print(f"Error: User file '{args.userfile}' not found")
            return 1
        except PermissionError:
            print(f"Error: Permission denied reading '{args.userfile}'")
            return 1
    elif args.user:
        users = [args.user]

    if not users:
        print("Error: No users provided for AS-REP roasting")
        return 1

    print_banner()
    status(
        f"AS-REP Roasting mode: Testing {len(users)} user(s) against {len(targets)} target(s)",
        "info",
    )
    status(
        "AS-REP Roasting requires only valid usernames (no password needed). "
        "Accounts with DONT_REQUIRE_PREAUTH return crackable hashes.",
        "info",
    )
    output("")

    all_hashes = []
    vulnerable_users = set()

    for target in targets:
        print_section("AS-REP Roasting", target)

        # Create temp file for hashes
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            hash_file = tmp.name

        # Build nxc command - pass users directly (nxc accepts multiple -u args or file)
        # Using empty password for unauthenticated AS-REP requests
        password = args.password if args.password is not None else ""

        # nxc can take multiple users via file or repeated -u flags
        # For simplicity, we'll pass the userfile directly if provided
        if args.userfile:
            cmd_args = [
                "ldap",
                target,
                "-u",
                args.userfile,
                "-p",
                password,
                "--asreproast",
                hash_file,
            ]
        else:
            cmd_args = ["ldap", target, "-u", args.user, "-p", password, "--asreproast", hash_file]

        # Add domain if specified
        if args.domain:
            cmd_args.extend(["-d", args.domain])

        status(f"Requesting AS-REP tickets for {len(users)} user(s)...", "info")
        rc, stdout, stderr = run_nxc(cmd_args, args.timeout)

        # Check for hashes in output file
        try:
            with open(hash_file, encoding="utf-8") as f:
                hashes = [ln.strip() for ln in f if ln.strip() and "$krb5asrep$" in ln]

            if hashes:
                status(f"Found {len(hashes)} AS-REP hash(es)!", "warning")
                output("")
                for h in hashes:
                    # Extract username from hash ($krb5asrep$23$user@domain@REALM:...)
                    # Format: user@domain.local@DOMAIN.LOCAL or user@DOMAIN.LOCAL
                    try:
                        user_part = h.split("$")[3]  # e.g., "j.rock@services.local@SERVICES.LOCAL"
                        # Split by @ and take first two parts (user@domain)
                        at_parts = user_part.split("@")
                        if len(at_parts) >= 2:
                            # user@domain format
                            username = f"{at_parts[0]}@{at_parts[1].upper()}"
                        else:
                            username = at_parts[0]
                        vulnerable_users.add(username)
                    except (IndexError, ValueError):
                        pass
                    # Print the full hash for copying
                    output(h)
                all_hashes.extend(hashes)
            else:
                # Check stdout for indicators
                if "DONT_REQ_PREAUTH" in stdout or "$krb5asrep$" in stdout:
                    status(
                        "AS-REP response received but hash extraction may have failed", "warning"
                    )
                    output(stdout)
                else:
                    status("No AS-REP roastable users found", "info")

            # Cleanup temp file
            os.unlink(hash_file)
        except FileNotFoundError:
            status("No hashes retrieved", "info")
        except Exception as e:
            status(f"Error reading hashes: {e}", "error")

        output("")

    # Summary
    if all_hashes:
        print_section("AS-REP Roasting Summary", "Results")
        status(f"Total vulnerable accounts: {len(vulnerable_users)}", "warning")
        output("")

        # Make vulnerable users REALLY stand out with a prominent box
        banner_width = 60
        output(c("=" * banner_width, Colors.RED + Colors.BOLD))
        output(c("  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗", Colors.RED + Colors.BOLD))
        output(c("  ██║   ██║██║   ██║██║     ████╗  ██║", Colors.RED + Colors.BOLD))
        output(c("  ██║   ██║██║   ██║██║     ██╔██╗ ██║", Colors.RED + Colors.BOLD))
        output(c("  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║", Colors.RED + Colors.BOLD))
        output(c("   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║", Colors.RED + Colors.BOLD))
        output(c("    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝", Colors.RED + Colors.BOLD))
        output(c("  DONT_REQUIRE_PREAUTH - NO PASSWORD NEEDED!", Colors.RED + Colors.BOLD))
        output(c("=" * banner_width, Colors.RED + Colors.BOLD))
        output("")
        for user in sorted(vulnerable_users):
            output(c(f"  >>> {user} <<<", Colors.RED + Colors.BOLD))
        output("")
        output(c("=" * banner_width, Colors.RED + Colors.BOLD))
        output("")

        # Show hashes for easy copying
        output(c("HASHES:", Colors.YELLOW))
        for h in all_hashes:
            output(h)
        output("")

        output(c("CRACK WITH:", Colors.YELLOW))
        output("  hashcat -m 18200 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule")
        output("  john --format=krb5asrep hashes.txt --wordlist=wordlist.txt")
        output("")

        # Add to copy-paste data - format: username:PASSWORD (placeholder for cracked password)
        output(c("COPY-PASTE FORMAT (after cracking):", Colors.CYAN))
        for user in sorted(vulnerable_users):
            cred_format = f"{user}:PASSWORD"
            output(f"  {cred_format}")
        output("")

        # Write hashes to output file if specified
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write("\n".join(all_hashes))
                status(f"Hashes written to {args.output}", "success")
            except Exception as e:
                status(f"Error writing output file: {e}", "error")
    else:
        status("No AS-REP roastable accounts found across all targets", "info")

    return 0


def run_kerberoast_spray(args, targets: list[str]) -> int:
    """Run kerberoasting against target accounts.

    Supports two modes:
    1. Standard: With valid credentials, request TGS for specified accounts
    2. No-preauth: Using an AS-REP roastable account (no password needed)

    Args:
        args: Parsed command-line arguments
        targets: List of target hosts

    Returns:
        Exit code (0 for success)
    """
    import tempfile

    # Determine the AS-REP roastable user (for authentication)
    asrep_user = None
    if args.userfile:
        try:
            with open(args.userfile, encoding="utf-8-sig") as f:
                users = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
                if users:
                    asrep_user = users[0]  # Use first user as AS-REP roastable account
        except (FileNotFoundError, PermissionError) as e:
            print(f"Error reading user file: {e}")
            return 1
    elif args.user:
        asrep_user = args.user

    if not asrep_user:
        print("Error: No user provided for kerberoasting")
        return 1

    # Check for no-preauth-targets file
    if not args.no_preauth_targets:
        print("Error: --kerberoast with empty password requires --no-preauth-targets FILE")
        print(
            "Usage: nxc-enum target -u asrep_user -p '' "
            "--kerberoast --no-preauth-targets accounts.txt"
        )
        return 1

    try:
        with open(args.no_preauth_targets, encoding="utf-8-sig") as f:
            target_accounts = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except FileNotFoundError:
        print(f"Error: Target accounts file '{args.no_preauth_targets}' not found")
        return 1
    except PermissionError:
        print(f"Error: Permission denied reading '{args.no_preauth_targets}'")
        return 1

    if not target_accounts:
        print("Error: No target accounts in file")
        return 1

    print_banner()
    status(
        f"Kerberoasting mode: Using AS-REP roastable user '{asrep_user}' to target "
        f"{len(target_accounts)} account(s)",
        "info",
    )
    status(
        "Kerberoasting targets service accounts with SPNs. "
        "TGS tickets contain crackable hashes for offline password recovery.",
        "info",
    )
    output("")

    all_hashes = []
    roasted_users = set()

    for target in targets:
        print_section("Kerberoasting (No Pre-Auth)", target)

        # Create temp file for hashes
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            hash_file = tmp.name

        # Build nxc command with --no-preauth-targets
        password = args.password if args.password is not None else ""
        cmd_args = [
            "ldap",
            target,
            "-u",
            asrep_user,
            "-p",
            password,
            "--no-preauth-targets",
            args.no_preauth_targets,
            "--kerberoasting",
            hash_file,
        ]

        # Add domain if specified
        if args.domain:
            cmd_args.extend(["-d", args.domain])

        status(f"Requesting TGS tickets for {len(target_accounts)} account(s)...", "info")
        rc, stdout, stderr = run_nxc(cmd_args, args.timeout)

        # Check for hashes in output file
        try:
            with open(hash_file, encoding="utf-8") as f:
                hashes = [ln.strip() for ln in f if ln.strip() and "$krb5tgs$" in ln]

            if hashes:
                status(f"Found {len(hashes)} TGS hash(es)!", "warning")
                output("")
                for h in hashes:
                    # Extract username from hash ($krb5tgs$23$*user$DOMAIN$spn*$...)
                    try:
                        parts = h.split("$")
                        if len(parts) >= 5:
                            user_part = parts[3].replace("*", "")  # username
                            domain_part = parts[4]  # DOMAIN
                            username = f"{domain_part}\\{user_part}"
                            roasted_users.add(username)
                    except (IndexError, ValueError):
                        pass
                    # Print the full hash for copying
                    output(h)
                all_hashes.extend(hashes)
            else:
                # Check stdout for indicators
                if "$krb5tgs$" in stdout:
                    status("TGS response received but hash extraction may have failed", "warning")
                    output(stdout)
                elif "KDC_ERR" in stdout or "KDC_ERR" in stderr:
                    status("Kerberos error - target accounts may not have SPNs", "error")
                else:
                    status("No kerberoastable accounts found", "info")

            # Cleanup temp file
            os.unlink(hash_file)
        except FileNotFoundError:
            status("No hashes retrieved", "info")
        except Exception as e:
            status(f"Error reading hashes: {e}", "error")

        output("")

    # Summary
    if all_hashes:
        print_section("Kerberoasting Summary", "Results")
        status(f"Total roasted accounts: {len(roasted_users)}", "warning")
        output("")

        output(c("KERBEROASTABLE SERVICE ACCOUNTS:", Colors.RED))
        for user in sorted(roasted_users):
            output(f"  {c(user, Colors.RED)}")
        output("")

        # Show hashes for easy copying
        output(c("HASHES:", Colors.YELLOW))
        for h in all_hashes:
            output(h)
        output("")

        output(c("CRACK WITH:", Colors.YELLOW))
        output("  hashcat -m 13100 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule")
        output("  john --format=krb5tgs hashes.txt --wordlist=wordlist.txt")
        output("")

        # Write hashes to output file if specified
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write("\n".join(all_hashes))
                status(f"Hashes written to {args.output}", "success")
            except Exception as e:
                status(f"Error writing output file: {e}", "error")
    else:
        status("No kerberoastable accounts found across all targets", "info")

    return 0


def detect_proxychains() -> bool:
    """Detect if running under proxychains via LD_PRELOAD environment variable."""
    ld_preload = os.environ.get("LD_PRELOAD", "")
    return "libproxychains" in ld_preload or "proxychains" in ld_preload


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    start_time = time.time()

    # Set global flags
    set_output_file_requested(bool(args.output))
    set_debug_mode(args.debug)

    # Detect and apply proxy mode for proxychains/SOCKS compatibility
    if args.proxy_mode or detect_proxychains():
        set_proxy_mode(True)
        if detect_proxychains() and not args.proxy_mode:
            status("Proxychains detected - automatically enabling proxy mode", "info")
        else:
            status("Proxy mode enabled - reduced concurrency, increased timeouts", "info")

        # Increase default timeout if user didn't override (30 is default)
        if args.timeout == 30:
            args.timeout = PROXY_DEFAULT_COMMAND_TIMEOUT
            status(f"Command timeout increased to {args.timeout}s for proxy", "info")

    # Error if --json is used without -o (output file)
    if args.json_output and not args.output:
        print("Error: --json requires -o/--output to specify the output file.")
        print("Usage: nxc-enum <target> ... --json -o results.json")
        sys.exit(1)

    # Check nxc availability at startup
    rc, stdout, stderr = run_nxc(["--version"], timeout=5)
    if "not found" in stderr.lower():
        print("Error: netexec (nxc) not found in PATH. Please install it first.")
        sys.exit(1)

    # Validate argument combinations
    if args.credfile and (args.userfile or args.passfile or args.user or args.password):
        print("Error: Cannot use -C with other credential options. Use -C alone.")
        sys.exit(1)
    if args.passfile and not (args.userfile or args.user):
        print("Error: -P (password file) requires -U (user file) or -u (single user).")
        sys.exit(1)
    if args.userfile and args.user:
        print("Error: Cannot use both -U (user file) and -u (single user).")
        sys.exit(1)
    if args.passfile and args.password:
        print("Error: Cannot use both -P (password file) and -p (single password).")
        sys.exit(1)
    if args.password and args.hash:
        print("Warning: Both -p and -H provided. Using password (-p), ignoring hash (-H).")

    # Expand targets (CIDR, ranges, files - auto-detects type)
    try:
        targets = expand_targets(args.target)
    except TargetExpansionError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # ─────────────────────────────────────────────────────────────────────────
    # UNAUTHENTICATED AS-REP ROASTING MODE
    # ─────────────────────────────────────────────────────────────────────────
    # Detect: userfile + empty/no password (no -H hash, no -C credfile)
    # This can run AS-REP roasting without credential validation
    can_asreproast_spray = (
        (args.userfile or args.user)
        and not args.hash
        and not args.credfile
        and not args.passfile
        and (args.password is None or args.password == "")
    )

    # If --asreproast explicitly requested, or -A with userlist + no password
    # Run AS-REP roasting spray (this is the only unauthenticated attack we can do)
    if can_asreproast_spray and (args.asreproast or args.all):
        sys.exit(run_asreproast_spray(args, targets))

    # ─────────────────────────────────────────────────────────────────────────
    # KERBEROASTING WITH AS-REP ROASTABLE USER (NO PASSWORD)
    # ─────────────────────────────────────────────────────────────────────────
    # Detect: --kerberoast with -U/-u and empty/no password + --no-preauth-targets
    # This mode uses an AS-REP roastable account to request TGS tickets
    is_nopreauth_kerberoast = (
        args.kerberoast
        and (args.userfile or args.user)
        and not args.hash
        and not args.credfile
        and not args.passfile
        and (args.password is None or args.password == "")
    )

    if is_nopreauth_kerberoast:
        sys.exit(run_kerberoast_spray(args, targets))

    multi_target_mode = len(targets) > 1

    # Print banner
    if not args.quiet:
        print_banner()

    # Show target expansion info for multi-target
    if multi_target_mode:
        status(f"Expanded to {len(targets)} targets", "info")
        output("")

    # ─────────────────────────────────────────────────────────────────────────
    # PARALLEL HOST DISCOVERY (for multi-target efficiency)
    # ─────────────────────────────────────────────────────────────────────────
    smb_validation_cache: dict = {}  # Cache SMB info to avoid re-validation in loop
    original_target_count = len(targets)  # Track for discovery stats
    port_open_count = 0  # Track hosts with port 445 open

    # Auto-enable for multiple targets unless --no-prescan specified
    # Also auto-enable for --discover-only regardless of target count
    use_prescan = (len(targets) > PRESCAN_THRESHOLD and not args.no_prescan) or args.discover_only

    if use_prescan:
        # Use custom port if specified, otherwise default to 445
        prescan_port = getattr(args, "port", None) or 445
        status(f"Pre-scanning {len(targets)} targets for SMB (port {prescan_port})...", "info")

        # Phase 1: Fast TCP port scan
        def port_progress(done: int, total: int) -> None:
            if done % 50 == 0 or done == total:
                status(f"Port scan: {done}/{total} hosts checked", "info")

        live_targets = parallel_port_prescan(
            targets,
            port=prescan_port,
            progress_callback=port_progress,
            ipv6=getattr(args, "ipv6", False),
        )

        port_open_count = len(live_targets)  # Track for discovery stats
        filtered = len(targets) - len(live_targets)
        if filtered:
            status(f"Filtered {filtered} hosts (port 445 closed/filtered)", "info")

        if not live_targets:
            if args.discover_only:
                # For discover-only, print empty results gracefully
                discovery_elapsed = time.time() - start_time
                print_discovery_results({}, original_target_count, 0, discovery_elapsed)
                return 0
            status("No hosts responded on port 445 - nothing to enumerate", "error")
            return 1

        # Phase 2: Parallel SMB validation on live hosts
        host_word = "host" if len(live_targets) == 1 else "hosts"
        status(f"Validating SMB on {len(live_targets)} live {host_word}...", "info")

        def smb_progress(done: int, total: int, host: str) -> None:
            if done % 10 == 0 or done == total:
                status(f"SMB validation: {done}/{total} complete", "info")

        # Use 10s timeout for SMB banner validation (faster than full command timeout)
        smb_validation_cache = parallel_smb_validation(
            live_targets,
            timeout=10,
            progress_callback=smb_progress,
            port=getattr(args, "port", None),
            smb_timeout=getattr(args, "smb_timeout", None),
        )

        # Filter to only reachable hosts (passed SMB validation)
        targets = [t for t in live_targets if smb_validation_cache.get(t, (False, {}))[0]]

        smb_filtered = len(live_targets) - len(targets)
        if smb_filtered:
            status(f"Filtered {smb_filtered} hosts (SMB not responding)", "info")

        if not targets:
            if args.discover_only:
                # For discover-only, show SMB validation results even if no hosts passed
                discovery_elapsed = time.time() - start_time
                print_discovery_results(
                    smb_validation_cache,
                    original_target_count,
                    port_open_count,
                    discovery_elapsed,
                    verbose=True,
                )
                return 0
            status("No hosts passed SMB validation - nothing to enumerate", "error")
            return 1

        # Show discovered hosts with hostnames (helpful before hosts check)
        output("")
        status("Discovered SMB hosts:", "success")
        for target_ip in sorted(targets):
            _, smb_info = smb_validation_cache.get(target_ip, (False, {}))
            hostname = smb_info.get("hostname", "")
            fqdn = smb_info.get("fqdn", "")
            domain = smb_info.get("dns_domain", "")
            # Build display string: IP (FQDN) or IP (hostname) or just IP
            if fqdn:
                display = f"{target_ip} ({fqdn})"
            elif hostname:
                display = f"{target_ip} ({hostname})"
            else:
                display = target_ip
            # Add domain info if available and different from hostname
            if domain and domain.lower() not in display.lower():
                display += f" [{domain}]"
            output(f"  {display}")
        output("")

        status(f"Proceeding with {len(targets)} reachable targets", "success")
        output("")

        # Update multi_target_mode based on filtered results
        multi_target_mode = len(targets) > 1

    # ─────────────────────────────────────────────────────────────────────────
    # DISCOVER-ONLY MODE: Early exit after host discovery
    # ─────────────────────────────────────────────────────────────────────────
    if args.discover_only:
        discovery_elapsed = time.time() - start_time

        # Print discovery results (pre-scan always runs in discover-only mode)
        print_discovery_results(
            smb_validation_cache,
            total_scanned=original_target_count,
            port_open_count=port_open_count,
            elapsed=discovery_elapsed,
            verbose=True,  # Always show detailed output in discover mode
        )

        # JSON output for discovery mode
        if args.json_output:
            discovery_json = get_discovery_json(
                smb_validation_cache,
                total_scanned=original_target_count,
                port_open_count=port_open_count,
                elapsed=discovery_elapsed,
            )
            JSON_DATA.update(discovery_json)

        # Write output to file if specified
        if args.output:
            fd = None
            try:
                fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    fd = None
                    if args.json_output:
                        json.dump(JSON_DATA, f, indent=2)
                    else:
                        for line in OUTPUT_BUFFER:
                            clean_line = RE_ANSI_ESCAPE.sub("", line)
                            f.write(clean_line + "\n")
                status(f"Output written to: {args.output} (permissions: 600)", "success")
            except (IOError, OSError) as e:
                status(f"Failed to write output file: {e}", "error")
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

        return 0

    # Parse credentials once (shared across all targets)
    creds = parse_credentials(args)

    # Initialize multi-target results collector
    multi_target_results = MultiTargetResults() if multi_target_mode else None

    # ─────────────────────────────────────────────────────────────────────────
    # PARALLEL TARGET ENUMERATION (for multi-target efficiency)
    # ─────────────────────────────────────────────────────────────────────────
    if multi_target_mode and len(targets) > 1:
        # Enable target-level parallel mode for buffered output
        set_target_parallel_mode(True)
        _print_lock = get_target_print_lock()
        completed_count = 0
        interrupted = False

        # Use reduced workers in proxy mode
        mt_workers = PROXY_MULTI_TARGET_WORKERS if is_proxy_mode() else MULTI_TARGET_WORKERS

        status(
            f"Running parallel enumeration on {len(targets)} targets " f"({mt_workers} workers)...",
            "info",
        )
        output("")

        try:
            with ThreadPoolExecutor(max_workers=mt_workers) as executor:
                # Submit all targets
                future_to_target = {}
                for idx, target in enumerate(targets, 1):
                    future = executor.submit(
                        _run_target_parallel,
                        args,
                        target,
                        creds,
                        smb_validation_cache,
                        idx,
                        len(targets),
                    )
                    future_to_target[future] = (target, idx)

                # Process results as they complete
                for future in as_completed(future_to_target):
                    target, idx = future_to_target[future]
                    try:
                        result, output_buffer = future.result()

                        # Print buffered output atomically
                        with _print_lock:
                            for line in output_buffer:
                                output_direct(line)

                        multi_target_results.add_result(target, result)
                        completed_count += 1

                    except Exception as e:
                        error_msg = str(e) if str(e) else type(e).__name__
                        # Print error atomically
                        with _print_lock:
                            status(f"Error scanning {target}: {error_msg}", "error")
                        multi_target_results.add_result(
                            target,
                            TargetResult(target=target, status="failed", error=error_msg),
                        )
                        completed_count += 1

        except KeyboardInterrupt:
            output("")
            status("Scan interrupted by user - waiting for running tasks...", "warning")
            interrupted = True
            # Remaining targets will be marked as failed by the executor shutdown

        finally:
            set_target_parallel_mode(False)

        if interrupted:
            # Mark any unprocessed targets as interrupted
            for future, (target, idx) in future_to_target.items():
                if not future.done():
                    multi_target_results.add_result(
                        target,
                        TargetResult(target=target, status="failed", error="Interrupted"),
                    )

    else:
        # Single target mode - run sequentially (no parallel overhead)
        for idx, target in enumerate(targets, 1):
            if multi_target_mode:
                print_target_header(target, idx, len(targets))

            try:
                result = _run_single_target(args, target, creds, smb_cache=smb_validation_cache)

                if multi_target_mode:
                    multi_target_results.add_result(target, result)
                    print_target_footer(target, result.status, result.elapsed_time)
            except KeyboardInterrupt:
                output("")
                status("Scan interrupted by user", "warning")
                if multi_target_mode and multi_target_results:
                    multi_target_results.add_result(
                        target,
                        TargetResult(target=target, status="failed", error="Interrupted"),
                    )
                break
            except Exception as e:
                error_msg = str(e) if str(e) else type(e).__name__
                status(f"Error scanning {target}: {error_msg}", "error")
                if multi_target_mode:
                    multi_target_results.add_result(
                        target,
                        TargetResult(target=target, status="failed", error=error_msg),
                    )
                    print_target_footer(target, "failed", 0)

    # Multi-target summary
    if multi_target_mode and multi_target_results:
        multi_target_results.total_elapsed = time.time() - start_time
        print_multi_target_summary(multi_target_results, args)

    elapsed = time.time() - start_time
    output("")
    output(f"Completed after {elapsed:.2f} seconds")

    # JSON output handling
    if args.json_output:
        if multi_target_mode and multi_target_results:
            JSON_DATA.update(multi_target_results.to_json())
        JSON_DATA["elapsed_time"] = elapsed

        # Add scan metadata to JSON
        JSON_DATA["scan_metadata"] = {
            # Authentication info
            "auth_type": _get_auth_type_from_args(args),
            # Network options
            "network_options": {
                "port": getattr(args, "port", None),
                "smb_timeout": getattr(args, "smb_timeout", None),
                "ipv6": getattr(args, "ipv6", False),
                "dns_server": getattr(args, "dns_server", None),
                "dns_tcp": getattr(args, "dns_tcp", False),
            },
            # Filter options
            "filters": {
                "active_users": getattr(args, "active_users", False),
                "shares_filter": getattr(args, "shares_filter", None),
                "local_groups_filter": getattr(args, "local_groups_filter", None),
            },
            # Spray options
            "spray_options": {
                "continue_on_success": getattr(args, "continue_on_success", False),
                "jitter": getattr(args, "jitter", None),
                "fail_limit": getattr(args, "fail_limit", None),
                "ufail_limit": getattr(args, "ufail_limit", None),
                "gfail_limit": getattr(args, "gfail_limit", None),
            },
        }

    # Write output to file if specified
    if args.output:
        # Auto per-target output: If multiple targets, write separate files for each
        if multi_target_mode and multi_target_results and len(live_targets) > 1:
            # Write per-target output files
            per_target_files = []
            for target, result in multi_target_results.results.items():
                if result.status == "success" and result.json_data:
                    target_file = get_per_target_filename(args.output, target)
                    fd = None
                    try:
                        fd = os.open(target_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        with os.fdopen(fd, "w") as f:
                            fd = None
                            if args.json_output:
                                json.dump(result.json_data, f, indent=2)
                            elif result.output_lines:
                                for line in result.output_lines:
                                    clean_line = RE_ANSI_ESCAPE.sub("", line)
                                    f.write(clean_line + "\n")
                        per_target_files.append(target_file)
                    except (IOError, OSError) as e:
                        status(f"Failed to write per-target file for {target}: {e}", "error")
                        if fd is not None:
                            try:
                                os.close(fd)
                            except OSError:
                                pass

            if per_target_files:
                status(f"Per-target output written to {len(per_target_files)} file(s)", "success")
                for tf in per_target_files[:3]:  # Show first 3 filenames
                    output(f"  - {tf}")
                if len(per_target_files) > 3:
                    output(f"  ... and {len(per_target_files) - 3} more")

        # Write combined summary file
        fd = None
        try:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                fd = None
                if args.json_output:
                    json.dump(JSON_DATA, f, indent=2)
                else:
                    for line in OUTPUT_BUFFER:
                        clean_line = RE_ANSI_ESCAPE.sub("", line)
                        f.write(clean_line + "\n")
            status(f"Summary output written to: {args.output} (permissions: 600)", "success")
        except (IOError, OSError) as e:
            status(f"Failed to write output file: {e}", "error")
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
