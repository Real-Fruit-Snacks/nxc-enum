"""Anonymous session probing (null and guest sessions)."""

from dataclasses import dataclass
from typing import Optional

from ..core.colors import Colors, c
from ..core.output import debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..models.credential import Credential


@dataclass
class AnonymousSessionResult:
    """Result of anonymous session probing."""

    null_success: bool = False
    guest_success: bool = False
    ldap_anonymous: bool = False
    ldap_unavailable: bool = False  # LDAP service unreachable (not a DC)
    working_credential: Optional[Credential] = None
    session_type: Optional[str] = None  # "null", "guest", or None


def probe_null_session(
    target: str,
    timeout: int,
    port: int | None = None,
    smb_timeout: int | None = None,
) -> tuple[bool, str, str]:
    """Probe for null session access.

    Uses: nxc smb <target> -u '' -p ''

    Args:
        target: Target IP or hostname
        timeout: Command timeout in seconds
        port: Custom SMB port (default: 445)
        smb_timeout: SMB-specific timeout

    Returns:
        Tuple of (success, stdout, stderr)
    """
    cmd_args = ["smb", target, "-u", "", "-p", ""]
    rc, stdout, stderr = run_nxc(cmd_args, timeout, port=port, smb_timeout=smb_timeout)
    debug_nxc(cmd_args, stdout, stderr, "Null Session Probe")

    # Check for successful connection
    combined = stdout + stderr
    success = "[+]" in combined and "STATUS_LOGON_FAILURE" not in combined.upper()

    return success, stdout, stderr


def probe_guest_session(
    target: str,
    timeout: int,
    port: int | None = None,
    smb_timeout: int | None = None,
) -> tuple[bool, str, str]:
    """Probe for guest session access.

    Uses: nxc smb <target> -u 'Guest' -p ''

    Args:
        target: Target IP or hostname
        timeout: Command timeout in seconds
        port: Custom SMB port (default: 445)
        smb_timeout: SMB-specific timeout

    Returns:
        Tuple of (success, stdout, stderr)
    """
    cmd_args = ["smb", target, "-u", "Guest", "-p", ""]
    rc, stdout, stderr = run_nxc(cmd_args, timeout, port=port, smb_timeout=smb_timeout)
    debug_nxc(cmd_args, stdout, stderr, "Guest Session Probe")

    # Check for successful connection - guest may show [+] with (Guest) indicator
    combined = stdout + stderr
    success = "[+]" in combined and "STATUS_LOGON_FAILURE" not in combined.upper()

    return success, stdout, stderr


def probe_ldap_anonymous(
    target: str,
    timeout: int,
    port: int | None = None,
) -> tuple[bool, str, str, bool]:
    """Probe for LDAP anonymous bind access.

    Uses: nxc ldap <target> -u '' -p ''

    Args:
        target: Target IP or hostname
        timeout: Command timeout in seconds
        port: Custom LDAP port (default: 389)

    Returns:
        Tuple of (success, stdout, stderr, connection_failed)
        - success: True if LDAP anonymous bind worked
        - connection_failed: True if LDAP service itself is unreachable (not a DC)
    """
    cmd_args = ["ldap", target, "-u", "", "-p", ""]
    # Note: LDAP doesn't use smb_timeout, but we can pass port for custom LDAP port
    rc, stdout, stderr = run_nxc(cmd_args, timeout, port=port)
    debug_nxc(cmd_args, stdout, stderr, "LDAP Anonymous Bind Probe")

    # Check for successful LDAP connection
    combined = stdout + stderr
    combined_lower = combined.lower()

    # Check for explicit connection failures (LDAP service unavailable)
    failure_indicators = [
        "failed to create connection object",  # nxc LDAP-specific error
        "failed to connect",
        "connection refused",
        "timed out",
        "timeout",
        "error connecting",
        "unable to connect",
        "connection error",
        "no route to host",
        "network unreachable",
    ]
    has_connection_failure = any(ind in combined_lower for ind in failure_indicators)

    # LDAP success requires [+] indicator and no connection/auth failures
    success = (
        "[+]" in combined
        and not has_connection_failure
        and "STATUS_LOGON_FAILURE" not in combined.upper()
    )

    return success, stdout, stderr, has_connection_failure


def check_anonymous_access(
    target: str,
    timeout: int,
    port: int | None = None,
    smb_timeout: int | None = None,
) -> AnonymousSessionResult:
    """Check for anonymous access without detailed output (used when creds provided).

    Silently probes for null, guest, and LDAP anonymous sessions and returns results.
    Use this when you have credentials but want to check for anonymous access as a finding.

    Args:
        target: Target IP or hostname
        timeout: Command timeout in seconds
        port: Custom SMB port (default: 445)
        smb_timeout: SMB-specific timeout

    Returns:
        AnonymousSessionResult with findings
    """
    result = AnonymousSessionResult()

    # Try null session (SMB)
    null_success, _, _ = probe_null_session(target, timeout, port=port, smb_timeout=smb_timeout)
    if null_success:
        result.null_success = True
        result.session_type = "null"
        result.working_credential = Credential(
            user="",
            password="",
            domain=None,
            valid=True,
            is_admin=False,
        )

    # Try guest session (SMB)
    guest_success, _, _ = probe_guest_session(target, timeout, port=port, smb_timeout=smb_timeout)
    if guest_success:
        result.guest_success = True
        if not result.session_type:
            result.session_type = "guest"
            result.working_credential = Credential(
                user="Guest",
                password="",
                domain=None,
                valid=True,
                is_admin=False,
            )

    # Try LDAP anonymous bind
    ldap_success, _, _, ldap_conn_failed = probe_ldap_anonymous(target, timeout)
    if ldap_success:
        result.ldap_anonymous = True
    elif ldap_conn_failed:
        result.ldap_unavailable = True

    return result


def probe_anonymous_sessions(
    target: str,
    timeout: int,
    has_creds: bool = False,
    port: int | None = None,
    smb_timeout: int | None = None,
) -> AnonymousSessionResult:
    """Probe for anonymous access (null session, guest session, LDAP anonymous).

    This function attempts to check anonymous access to the target:
    1. Tries SMB null session (-u '' -p '')
    2. Tries SMB guest session (-u 'Guest' -p '')
    3. Tries LDAP anonymous bind (-u '' -p '')

    Args:
        target: Target IP or hostname
        timeout: Command timeout in seconds
        has_creds: If True, we have credentials so just report findings (don't exit)
        port: Custom SMB port (default: 445)
        smb_timeout: SMB-specific timeout

    Returns:
        AnonymousSessionResult with working credential if found
    """
    result = AnonymousSessionResult()

    print_section("Anonymous Session Probe", target)

    # SMB Null Session
    status("Probing SMB null session...", "info")
    null_success, null_stdout, null_stderr = probe_null_session(
        target, timeout, port=port, smb_timeout=smb_timeout
    )

    if null_success:
        result.null_success = True
        result.session_type = "null"
        result.working_credential = Credential(
            user="",
            password="",
            domain=None,
            valid=True,
            is_admin=False,
        )
        status("SMB null session available!", "success")
    else:
        # Parse actual NTSTATUS for informative message
        null_combined = (null_stdout + null_stderr).upper()
        if "STATUS_ACCESS_DENIED" in null_combined:
            status("SMB null session: Access denied", "info")
        elif "STATUS_LOGON_FAILURE" in null_combined:
            status("SMB null session: Authentication rejected", "info")
        else:
            status("SMB null session not available", "info")

    # SMB Guest Session
    status("Probing SMB guest session...", "info")
    guest_success, guest_stdout, guest_stderr = probe_guest_session(
        target, timeout, port=port, smb_timeout=smb_timeout
    )

    if guest_success:
        result.guest_success = True
        if not result.session_type:
            result.session_type = "guest"
            result.working_credential = Credential(
                user="Guest",
                password="",
                domain=None,
                valid=True,
                is_admin=False,
            )
        status("SMB guest session available!", "success")
    else:
        # Parse actual NTSTATUS for informative message
        guest_combined = (guest_stdout + guest_stderr).upper()
        if "STATUS_ACCOUNT_DISABLED" in guest_combined:
            status("SMB guest session: Guest account is disabled", "info")
        elif "STATUS_ACCESS_DENIED" in guest_combined:
            status("SMB guest session: Access denied", "info")
        elif "STATUS_LOGON_FAILURE" in guest_combined:
            status("SMB guest session: Authentication rejected", "info")
        else:
            status("SMB guest session not available", "info")

    # LDAP Anonymous Bind
    status("Probing LDAP anonymous bind...", "info")
    ldap_success, ldap_stdout, ldap_stderr, ldap_conn_failed = probe_ldap_anonymous(target, timeout)

    if ldap_success:
        result.ldap_anonymous = True
        # Check if searches actually work or just bind
        ldap_combined = ldap_stdout + ldap_stderr
        if "operationsError" in ldap_combined:
            status("LDAP anonymous bind works but search requires authentication", "info")
        else:
            status("LDAP anonymous bind available!", "success")
    elif ldap_conn_failed:
        # LDAP service itself is unreachable (not a Domain Controller)
        result.ldap_unavailable = True
        status("LDAP service unavailable (not a Domain Controller)", "info")
    else:
        ldap_combined = (ldap_stdout + ldap_stderr).upper()
        if "STATUS_ACCESS_DENIED" in ldap_combined:
            status("LDAP anonymous bind: Access denied", "info")
        else:
            status("LDAP anonymous bind not available", "info")

    # Summary
    output("")
    findings = []
    if result.null_success:
        findings.append("SMB null")
    if result.guest_success:
        findings.append("SMB guest")
    if result.ldap_anonymous:
        findings.append("LDAP anonymous")

    if findings:
        status(f"Anonymous access: {', '.join(findings)}", "warning")
    elif result.ldap_unavailable:
        # LDAP service unreachable - don't claim "(good)", just informational
        status("No anonymous access available (LDAP service unavailable)", "info")
    else:
        # All services accessible but explicitly rejected anonymous access
        if has_creds:
            status("No anonymous access available (good)", "success")
        else:
            status("No anonymous access available", "error")
            output("")
            output(c("No anonymous access permitted on this target.", Colors.YELLOW))
            output(c("Provide valid credentials to enumerate:", Colors.YELLOW))
            output(
                f"  {c('nxc-enum', Colors.CYAN)} {target} "
                f"{c('-u <user> -p <pass>', Colors.GREEN)}"
            )

    return result


def _show_failure_reason(stdout: str, stderr: str):
    """Display reason for session failure."""
    combined = (stdout + stderr).upper()

    if "STATUS_LOGON_FAILURE" in combined:
        output(f"  Reason: {c('STATUS_LOGON_FAILURE', Colors.YELLOW)}")
    elif "STATUS_ACCESS_DENIED" in combined:
        output(f"  Reason: {c('STATUS_ACCESS_DENIED', Colors.YELLOW)}")
    elif "STATUS_ACCOUNT_DISABLED" in combined:
        output(f"  Reason: {c('Guest account disabled', Colors.YELLOW)}")
    elif "CONNECTION" in combined and "REFUSED" in combined:
        output(f"  Reason: {c('Connection refused', Colors.YELLOW)}")
    elif "TIMEOUT" in combined:
        output(f"  Reason: {c('Connection timeout', Colors.YELLOW)}")
