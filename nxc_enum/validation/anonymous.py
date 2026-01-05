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
    working_credential: Optional[Credential] = None
    session_type: Optional[str] = None  # "null", "guest", or None


def probe_null_session(target: str, timeout: int) -> tuple[bool, str, str]:
    """Probe for null session access.

    Uses: nxc smb <target> -u '' -p ''

    Args:
        target: Target IP or hostname
        timeout: Command timeout in seconds

    Returns:
        Tuple of (success, stdout, stderr)
    """
    cmd_args = ["smb", target, "-u", "", "-p", ""]
    rc, stdout, stderr = run_nxc(cmd_args, timeout)
    debug_nxc(cmd_args, stdout, stderr, "Null Session Probe")

    # Check for successful connection
    combined = stdout + stderr
    success = "[+]" in combined and "STATUS_LOGON_FAILURE" not in combined.upper()

    return success, stdout, stderr


def probe_guest_session(target: str, timeout: int) -> tuple[bool, str, str]:
    """Probe for guest session access.

    Uses: nxc smb <target> -u 'Guest' -p ''

    Args:
        target: Target IP or hostname
        timeout: Command timeout in seconds

    Returns:
        Tuple of (success, stdout, stderr)
    """
    cmd_args = ["smb", target, "-u", "Guest", "-p", ""]
    rc, stdout, stderr = run_nxc(cmd_args, timeout)
    debug_nxc(cmd_args, stdout, stderr, "Guest Session Probe")

    # Check for successful connection - guest may show [+] with (Guest) indicator
    combined = stdout + stderr
    success = "[+]" in combined and "STATUS_LOGON_FAILURE" not in combined.upper()

    return success, stdout, stderr


def probe_ldap_anonymous(target: str, timeout: int) -> tuple[bool, str, str]:
    """Probe for LDAP anonymous bind access.

    Uses: nxc ldap <target> -u '' -p ''

    Args:
        target: Target IP or hostname
        timeout: Command timeout in seconds

    Returns:
        Tuple of (success, stdout, stderr)
    """
    cmd_args = ["ldap", target, "-u", "", "-p", ""]
    rc, stdout, stderr = run_nxc(cmd_args, timeout)
    debug_nxc(cmd_args, stdout, stderr, "LDAP Anonymous Bind Probe")

    # Check for successful LDAP connection
    combined = stdout + stderr
    # LDAP success typically shows domain info without auth errors
    success = (
        "[+]" in combined
        or "LDAP" in combined.upper()
    ) and "STATUS_LOGON_FAILURE" not in combined.upper()

    return success, stdout, stderr


def check_anonymous_access(target: str, timeout: int) -> AnonymousSessionResult:
    """Check for anonymous access without detailed output (used when creds provided).

    Silently probes for null, guest, and LDAP anonymous sessions and returns results.
    Use this when you have credentials but want to check for anonymous access as a finding.

    Args:
        target: Target IP or hostname
        timeout: Command timeout in seconds

    Returns:
        AnonymousSessionResult with findings
    """
    result = AnonymousSessionResult()

    # Try null session (SMB)
    null_success, _, _ = probe_null_session(target, timeout)
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
    guest_success, _, _ = probe_guest_session(target, timeout)
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
    ldap_success, _, _ = probe_ldap_anonymous(target, timeout)
    if ldap_success:
        result.ldap_anonymous = True

    return result


def probe_anonymous_sessions(
    target: str, timeout: int, has_creds: bool = False
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

    Returns:
        AnonymousSessionResult with working credential if found
    """
    result = AnonymousSessionResult()

    print_section("Anonymous Session Probe", target)

    # SMB Null Session
    status("Probing SMB null session...", "info")
    null_success, _, _ = probe_null_session(target, timeout)

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
        status("SMB null session not available", "info")

    # SMB Guest Session
    status("Probing SMB guest session...", "info")
    guest_success, _, _ = probe_guest_session(target, timeout)

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
        status("SMB guest session not available", "info")

    # LDAP Anonymous Bind
    status("Probing LDAP anonymous bind...", "info")
    ldap_success, _, _ = probe_ldap_anonymous(target, timeout)

    if ldap_success:
        result.ldap_anonymous = True
        status("LDAP anonymous bind available!", "success")
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
    else:
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
