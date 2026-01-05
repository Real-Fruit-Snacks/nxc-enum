"""Main entry point for nxc_enum.

This module orchestrates the nxc-enum enumeration workflow:
1. Parse and validate command-line arguments
2. Parse and validate credentials
3. Run enumeration modules (parallel where possible)
4. Generate reports and write output
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
    enum_av,
    enum_av_multi,
    enum_dc_list,
    enum_delegation,
    enum_descriptions,
    enum_dns,
    enum_domain_intel,
    enum_groups,
    enum_kerberoastable,
    enum_listeners,
    enum_loggedon,
    enum_loggedon_multi,
    enum_maq,
    enum_os_info,
    enum_policies,
    enum_printers,
    enum_printers_multi,
    enum_pwd_not_required,
    enum_rpc_session,
    enum_sessions,
    enum_sessions_multi,
    enum_shares,
    enum_shares_multi,
    enum_signing,
    enum_smb_info,
    enum_target_info,
    enum_users,
    enum_webdav,
)
from ..models.cache import EnumCache
from ..models.credential import CredentialError
from ..models.results import MultiUserResults
from ..parsing.credentials import parse_credentials

# Import reporting functions
from ..reporting import (
    print_executive_summary,
    print_executive_summary_multi,
    print_next_steps,
)
from ..validation.anonymous import probe_anonymous_sessions
from ..validation.hosts import check_hosts_resolution, extract_hostname_from_smb
from ..validation.multi import validate_credentials_multi
from ..validation.single import validate_credentials
from .args import create_parser


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

    # Parse credentials (single or multi)
    creds = parse_credentials(args)

    # Track if running in anonymous mode (null or guest session)
    anonymous_mode = False
    has_creds = bool(creds)

    # Always probe for null/guest sessions first (security finding)
    if not args.quiet:
        print_banner()

    anon_result = probe_anonymous_sessions(args.target, args.timeout, has_creds=has_creds)

    # Store anonymous access findings in cache for reporting
    anon_findings = {
        "null_available": anon_result.null_success,
        "guest_available": anon_result.guest_success,
        "ldap_anonymous": anon_result.ldap_anonymous,
    }

    if not creds:
        # No credentials provided - use anonymous if available
        if anon_result.working_credential:
            creds = [anon_result.working_credential]
            anonymous_mode = True
            output("")
            status(
                f"Continuing with {anon_result.session_type} session - "
                "some modules may have limited results",
                "warning",
            )
        else:
            # probe_anonymous_sessions already printed helpful message
            sys.exit(1)
    else:
        # Credentials provided - report anonymous findings and continue with creds
        output("")
        if anon_result.null_success or anon_result.guest_success:
            status(
                "Note: Anonymous access detected but using provided credentials",
                "info",
            )

    # Detect multi-credential mode
    multi_cred_mode = len(creds) > 1

    listener_results = {}

    # Initialize cache early - will be used by all subsequent operations
    cache = EnumCache()
    cache.target = args.target
    cache.timeout = args.timeout
    cache.anonymous_mode = anonymous_mode
    cache.anonymous_access = anon_findings  # Store findings for reporting

    # Initialize multi_results for multi-cred mode (needed for selected-module branches too)
    multi_results = None
    if multi_cred_mode:
        multi_results = MultiUserResults()

    # Validate credentials (skip for anonymous - already validated during probe)
    if not args.no_validate and not anonymous_mode:
        if multi_cred_mode:
            # Multi-credential validation (parallel)
            valid_creds = validate_credentials_multi(args.target, creds, args.timeout)
            if not valid_creds:
                status("No valid credentials found. Exiting.", "error")
                sys.exit(1)
            creds = valid_creds

            # Explicitly select best credential for cached operations
            # Prefer admin credentials for maximum enumeration capability
            admin_creds = [cred for cred in creds if cred.is_admin]
            primary_cred = admin_creds[0] if admin_creds else creds[0]

            try:
                cache.auth_args = primary_cred.auth_args()
            except CredentialError as e:
                status(f"Credential error: {e}", "error")
                sys.exit(1)

            # Warn if no admin credentials found
            if not admin_creds:
                status("Note: No admin credentials found - some modules may be limited", "warning")

            # Hosts resolution check (multi-cred)
            if not args.skip_hosts_check:
                extract_hostname_from_smb(cache)
                success, hosts_line = check_hosts_resolution(args.target, cache)
                if not success:
                    status("DC hostname does not resolve to target IP", "error")
                    output("")
                    output(c("Add this line to /etc/hosts:", Colors.YELLOW))
                    output(f"  {c(hosts_line, Colors.BOLD)}")
                    output("")
                    status("Use --skip-hosts-check to bypass this check", "info")
                    sys.exit(1)
        else:
            # Single credential validation (original behavior)
            status("Validating credentials...", "info")
            try:
                cache.auth_args = creds[0].auth_args()
            except CredentialError as e:
                status(f"Credential error: {e}", "error")
                sys.exit(1)

            valid, is_admin = validate_credentials(args.target, cache.auth_args, cache)
            if not valid:
                status("Credential validation failed. Use --no-validate to skip.", "error")
                sys.exit(1)
            creds[0].is_admin = is_admin
            admin_msg = c(" (LOCAL ADMIN)", Colors.RED) if is_admin else ""
            status(f"Credentials validated successfully{admin_msg}", "success")

            # Hosts resolution check (single-cred)
            if not args.skip_hosts_check:
                extract_hostname_from_smb(cache)
                success, hosts_line = check_hosts_resolution(args.target, cache)
                if not success:
                    status("DC hostname does not resolve to target IP", "error")
                    output("")
                    output(c("Add this line to /etc/hosts:", Colors.YELLOW))
                    output(f"  {c(hosts_line, Colors.BOLD)}")
                    output("")
                    status("Use --skip-hosts-check to bypass this check", "info")
                    sys.exit(1)
    elif anonymous_mode:
        # Anonymous mode: credentials already validated during probe
        try:
            cache.auth_args = creds[0].auth_args()
        except CredentialError as e:
            status(f"Credential error: {e}", "error")
            sys.exit(1)
    else:
        # --no-validate: skip credential validation and admin detection
        status("Skipping credential validation (--no-validate)", "warning")
        status("Admin detection disabled - admin-only modules will be skipped", "warning")
        try:
            cache.auth_args = creds[0].auth_args()
        except CredentialError as e:
            status(f"Credential error: {e}", "error")
            sys.exit(1)

    # If no specific modules selected, default to -A behavior
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
            args.delegation,
            args.descriptions,
            args.maq,
            args.adcs,
            args.dc_list,
            args.pwd_not_reqd,
            args.admin_count,
            args.signing,
            args.webdav,
            args.dns,
        )
    )

    # Target info always shown (pass creds for admin detection)
    enum_target_info(args, creds)

    if run_all:
        # Phase 1: Parallel port scanning
        enum_listeners(args, listener_results)

        # Phase 2: Parallel cache priming (SMB, RID brute, LDAP all at once)
        status("Priming caches in parallel...", "info")
        cache.prime_caches(args.target, cache.auth_args)

        # Phase 3: Sequential extraction from cached data (UNIVERSAL - run once)
        enum_domain_intel(args, cache, listener_results)
        enum_smb_info(args, cache)
        enum_rpc_session(args, cache)
        enum_os_info(args, cache)
        enum_users(args, cache)
        enum_groups(args, cache)

        if multi_cred_mode:
            # Multi-cred mode: run per-user commands for each credential
            # Phase 4a: Universal modules (run once)
            enum_policies(args, cache)
            enum_kerberoastable(args, cache)

            # Phase 4a-extended: New enumeration modules (LDAP-based, run once)
            enum_delegation(args, cache)
            # Note: descriptions are shown in Users table, skip separate section
            enum_maq(args, cache)
            enum_adcs(args, cache)
            enum_dc_list(args, cache)
            enum_pwd_not_required(args, cache)
            enum_admin_count(args, cache)
            enum_signing(args, cache)
            enum_webdav(args, cache)
            enum_dns(args, cache)

            # Phase 4b: Per-user modules (run for each credential)
            enum_shares_multi(args, creds, multi_results)
            enum_sessions_multi(args, creds, multi_results)
            enum_loggedon_multi(args, creds, multi_results)
            enum_printers_multi(args, creds, multi_results)
            enum_av_multi(args, creds, multi_results)

            # Phase 5: Executive Summary (multi-cred version)
            print_executive_summary_multi(args, cache, creds, multi_results)
        else:
            # Single-cred mode: use original parallel modules
            # Phase 4: Parallel independent modules with buffered output
            is_admin = creds[0].is_admin if creds else False
            run_parallel_modules(args, cache, is_admin)

            # Phase 4-extended: New enumeration modules
            enum_delegation(args, cache)
            # Note: descriptions are shown in Users table, skip separate section
            enum_maq(args, cache)
            enum_adcs(args, cache)
            enum_dc_list(args, cache)
            enum_pwd_not_required(args, cache)
            enum_admin_count(args, cache)
            enum_signing(args, cache)
            enum_webdav(args, cache)
            enum_dns(args, cache)

            # Phase 5: Executive Summary
            print_executive_summary(args, cache)
    else:
        # Run selected modules
        if args.users:
            enum_users(args, cache)
        if args.groups:
            enum_groups(args, cache)
        if args.shares:
            if multi_cred_mode:
                enum_shares_multi(args, creds, multi_results)
            else:
                enum_shares(args, cache)
        if args.policies:
            enum_policies(args, cache)
        if args.sessions:
            if multi_cred_mode:
                enum_sessions_multi(args, creds, multi_results)
            else:
                is_admin = creds[0].is_admin if creds else False
                enum_sessions(args, cache, is_admin)
        if args.loggedon:
            if multi_cred_mode:
                enum_loggedon_multi(args, creds, multi_results)
            else:
                is_admin = creds[0].is_admin if creds else False
                enum_loggedon(args, cache, is_admin)
        if args.printers:
            if multi_cred_mode:
                enum_printers_multi(args, creds, multi_results)
            else:
                enum_printers(args, cache)
        if args.av:
            if multi_cred_mode:
                enum_av_multi(args, creds, multi_results)
            else:
                is_admin = creds[0].is_admin if creds else False
                enum_av(args, cache, is_admin)
        # New enumeration modules
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

    # Print next steps recommendations (collected during enumeration)
    print_next_steps(args, cache)

    elapsed = time.time() - start_time
    output("")
    output(f"Completed after {elapsed:.2f} seconds")

    if args.json_output:
        JSON_DATA["elapsed_time"] = elapsed

    # Write output to file if specified
    # Security: Create file with restricted permissions (owner read/write only)
    if args.output:
        fd = None
        try:
            # Create file with 0o600 permissions (owner read/write only)
            # This prevents other users from reading potentially sensitive enumeration results
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                fd = None  # fdopen takes ownership, don't close fd separately
                if args.json_output:
                    json.dump(JSON_DATA, f, indent=2)
                else:
                    # Strip ANSI codes for file output using pre-compiled regex
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
