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

from ..core.colors import Colors, c
from ..core.constants import RE_ANSI_ESCAPE
from ..core.output import (
    JSON_DATA,
    OUTPUT_BUFFER,
    output,
    print_banner,
    print_target_footer,
    print_target_header,
    set_debug_mode,
    set_output_file_requested,
    status,
)
from ..core.parallel import run_parallel_modules
from ..core.runner import run_nxc

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
    enum_kerberoastable,
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
from ..validation.hosts import early_hosts_check
from ..validation.multi import validate_credentials_multi
from ..validation.single import validate_credentials
from .args import create_parser


def _run_single_target(args, target: str, creds: list) -> TargetResult:
    """Run enumeration against a single target.

    This is the core enumeration logic extracted from main() to support
    multi-target scanning. Each call gets a fresh cache instance.

    Args:
        args: Parsed command-line arguments
        target: Single target IP/hostname to scan
        creds: List of credentials (parsed from args)

    Returns:
        TargetResult with status, cache, and elapsed time
    """
    target_start = time.time()

    # ─────────────────────────────────────────────────────────────────────────
    # EARLY HOSTS RESOLUTION CHECK (before any enumeration)
    # ─────────────────────────────────────────────────────────────────────────
    if not args.skip_hosts_check:
        success, hosts_line = early_hosts_check(target, args.timeout)
        if not success:
            status("DC hostname does not resolve to target IP", "error")
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
                error="DC hostname resolution failed - add entry to /etc/hosts",
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
            # Multi-cred mode
            enum_policies(args, cache)
            enum_computers(args, cache)
            enum_kerberoastable(args, cache)
            enum_asreproast(args, cache)
            enum_delegation(args, cache)
            enum_maq(args, cache)
            enum_adcs(args, cache)
            enum_dc_list(args, cache)
            enum_pwd_not_required(args, cache)
            enum_admin_count(args, cache)
            enum_signing(args, cache)
            enum_webdav(args, cache)
            enum_dns(args, cache)
            enum_laps(args, cache)
            enum_ldap_signing(args, cache)
            enum_local_groups(args, cache)
            enum_subnets(args, cache)
            enum_pre2k(args, cache)
            enum_bitlocker(args, cache)
            enum_mssql(args, cache)
            enum_rdp(args, cache)
            enum_ftp(args, cache)
            enum_nfs(args, cache)

            # Per-user modules
            enum_shares_multi(args, working_creds, multi_results, cache)
            enum_sessions_multi(args, working_creds, multi_results, cache)
            enum_loggedon_multi(args, working_creds, multi_results, cache)
            enum_printers_multi(args, working_creds, multi_results, cache)
            enum_av_multi(args, working_creds, multi_results, cache)

            print_executive_summary_multi(args, cache, working_creds, multi_results)
        else:
            # Single-cred mode
            is_admin = working_creds[0].is_admin if working_creds else False
            run_parallel_modules(args, cache, is_admin)

            enum_computers(args, cache)
            enum_asreproast(args, cache)
            enum_delegation(args, cache)
            enum_maq(args, cache)
            enum_adcs(args, cache)
            enum_dc_list(args, cache)
            enum_pwd_not_required(args, cache)
            enum_admin_count(args, cache)
            enum_signing(args, cache)
            enum_webdav(args, cache)
            enum_dns(args, cache)
            enum_laps(args, cache)
            enum_ldap_signing(args, cache)
            enum_local_groups(args, cache)
            enum_subnets(args, cache)
            enum_pre2k(args, cache)
            enum_bitlocker(args, cache)
            enum_mssql(args, cache)
            enum_rdp(args, cache)
            enum_ftp(args, cache)
            enum_nfs(args, cache)

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
            enum_bitlocker(args, cache)
        if args.mssql:
            enum_mssql(args, cache)
        if args.rdp:
            enum_rdp(args, cache)
        if args.ftp:
            enum_ftp(args, cache)
        if args.nfs:
            enum_nfs(args, cache)

    # Print next steps for this target
    print_next_steps(args, cache)

    # Print aggregated copy-paste section
    print_copy_paste_section(cache, args)

    elapsed = time.time() - target_start
    return TargetResult(
        target=target,
        status="success",
        cache=cache,
        elapsed_time=elapsed,
    )


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    start_time = time.time()

    # Set global flags
    set_output_file_requested(bool(args.output))
    set_debug_mode(args.debug)

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

    # Parse credentials once (shared across all targets)
    creds = parse_credentials(args)

    # Initialize multi-target results collector
    multi_target_results = MultiTargetResults() if multi_target_mode else None

    # Process each target
    for idx, target in enumerate(targets, 1):
        if multi_target_mode:
            print_target_header(target, idx, len(targets))

        try:
            result = _run_single_target(args, target, creds)

            if multi_target_mode:
                multi_target_results.add_result(target, result)
                print_target_footer(target, result.status, result.elapsed_time)
        except KeyboardInterrupt:
            output("")
            status("Scan interrupted by user", "warning")
            if multi_target_mode and multi_target_results:
                # Mark current target as failed
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
