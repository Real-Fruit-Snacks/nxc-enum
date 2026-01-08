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
    else:
        # No cache - validate now
        status("Checking SMB reachability...", "info")
        is_reachable, smb_info = validate_host_smb(target, timeout=args.timeout)

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
    anon_result = probe_anonymous_sessions(target, args.timeout, has_creds=has_creds)

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

    # Initialize multi_results for multi-cred mode
    multi_results = None
    if multi_cred_mode:
        multi_results = MultiUserResults()

    # Validate credentials (skip for anonymous - already validated during probe)
    if not args.no_validate and not anonymous_mode:
        if multi_cred_mode:
            # Multi-credential validation (parallel)
            valid_creds = validate_credentials_multi(target, working_creds, args.timeout)
            if not valid_creds:
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
                elapsed = time.time() - target_start
                return TargetResult(
                    target=target,
                    status="failed",
                    error=f"Credential error: {e}",
                    elapsed_time=elapsed,
                )

            valid, is_admin = validate_credentials(target, cache.auth_args, cache)
            if not valid:
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
                    auth_type = "password" if cred.password else "hash"
                    cred_str = cred.password if cred.password else cred.hash[:32] + "..."
                    output(f"  {c('[ADMIN]', Colors.RED)} {cred.username}:{cred_str} ({auth_type})")
                output("")

            if std_creds:
                output(c("STANDARD CREDENTIALS", Colors.GREEN))
                output(f"{'-'*50}")
                for cred in std_creds:
                    auth_type = "password" if cred.password else "hash"
                    cred_str = cred.password if cred.password else cred.hash[:32] + "..."
                    output(f"  {cred.username}:{cred_str} ({auth_type})")
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
            auth_type = "password" if cred.password else "hash"
            if cred.is_admin:
                status(f"Valid: {cred.username} ({auth_type}) - LOCAL ADMIN!", "success")
            else:
                status(f"Valid: {cred.username} ({auth_type})", "success")

        output("")
        status(f"Completed in {elapsed:.2f}s")

        return TargetResult(
            target=target,
            status="success",
            cache=cache,
            elapsed_time=elapsed,
        )

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
        service_results = parallel_prescan_services(target)
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

    # Add target to successfully enumerated targets list
    cache.copy_paste_data["targets"].add(target)

    # Print next steps for this target
    print_next_steps(args, cache)

    # Print aggregated copy-paste section
    print_copy_paste_section(cache, args)

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
    if args.credfile and (args.userfile or args.passfile):
        print("Error: Cannot use -C with -U/-P. Use one or the other.")
        sys.exit(1)
    if (args.userfile and not args.passfile) or (args.passfile and not args.userfile):
        print("Error: -U and -P must be used together.")
        sys.exit(1)
    if (args.credfile or args.userfile) and args.user:
        print("Error: Cannot use -u with credential files. Use one or the other.")
        sys.exit(1)
    if args.password and args.hash:
        print("Warning: Both -p and -H provided. Using password (-p), ignoring hash (-H).")

    # Expand targets (CIDR, ranges, files - auto-detects type)
    try:
        targets = expand_targets(args.target)
    except TargetExpansionError as e:
        print(f"Error: {e}")
        sys.exit(1)

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
        status(f"Pre-scanning {len(targets)} targets for SMB (port 445)...", "info")

        # Phase 1: Fast TCP port scan
        def port_progress(done: int, total: int) -> None:
            if done % 50 == 0 or done == total:
                status(f"Port scan: {done}/{total} hosts checked", "info")

        live_targets = parallel_port_prescan(
            targets,
            port=445,
            progress_callback=port_progress,
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
