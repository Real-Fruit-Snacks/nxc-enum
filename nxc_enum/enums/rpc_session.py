"""RPC session checking."""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc

# Patterns for verbose session output parsing
RE_CONNECTION_IP = re.compile(r"Connecting to (\d+\.\d+\.\d+\.\d+):(\d+)", re.IGNORECASE)
RE_SMB_DIALECT = re.compile(r"SMB(\d+(?:\.\d+)?)\s*(?:dialect|selected|negotiated)?", re.IGNORECASE)
RE_RPC_BIND = re.compile(
    r"(?:RPC|DCE/RPC|DCERPC)\s*(?:bind|binding|endpoint)[:\s]+(.+)", re.IGNORECASE
)
RE_AUTH_METHOD = re.compile(r"(?:authentication|auth)[:\s]+(\w+)", re.IGNORECASE)
RE_NTLM_INFO = re.compile(r"NTLM(?:v\d)?[:\s]+(.+)", re.IGNORECASE)
RE_SESSION_KEY = re.compile(r"session\s*key[:\s]+(.+)", re.IGNORECASE)
RE_STATUS_CODE = re.compile(r"(STATUS_\w+|NT_STATUS_\w+)", re.IGNORECASE)
RE_GUEST_FLAG = re.compile(
    r"(?:guest|anonymous)\s*(?:access|session|login)[:\s]*(\w+)?", re.IGNORECASE
)
RE_SIGNING_INFO = re.compile(r"signing[:\s]+(\w+)", re.IGNORECASE)
RE_INFO_LINE = re.compile(r"\[INFO\][:\s]*(.+)", re.IGNORECASE)
RE_SERVER_TIME = re.compile(r"(?:server\s*time|time)[:\s]+(.+)", re.IGNORECASE)
RE_SERVER_OS = re.compile(r"(?:OS|operating\s*system)[:\s]+(.+)", re.IGNORECASE)


def parse_verbose_session_info(stdout: str, stderr: str = "") -> dict:
    """Parse verbose output for session connection and authentication details.

    Returns dict with:
        - connection: dict with IP, port, dialect info
        - auth_info: dict with authentication method, NTLM details
        - rpc_bindings: list of RPC endpoint bindings detected
        - status_codes: list of NTSTATUS codes encountered
        - info_messages: list of relevant [INFO] lines
        - server_info: dict with server time, OS info if available
        - signing: signing status if detected
    """
    verbose_data = {
        "connection": {},
        "auth_info": {},
        "rpc_bindings": [],
        "status_codes": [],
        "info_messages": [],
        "server_info": {},
        "signing": None,
    }

    combined_output = stdout + "\n" + stderr

    for line in combined_output.split("\n"):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Parse connection details
        conn_match = RE_CONNECTION_IP.search(line_stripped)
        if conn_match:
            verbose_data["connection"]["ip"] = conn_match.group(1)
            verbose_data["connection"]["port"] = conn_match.group(2)
            continue

        # Parse SMB dialect version
        dialect_match = RE_SMB_DIALECT.search(line_stripped)
        if dialect_match:
            dialect = dialect_match.group(1)
            verbose_data["connection"]["smb_dialect"] = f"SMB{dialect}"
            continue

        # Parse RPC binding information
        rpc_match = RE_RPC_BIND.search(line_stripped)
        if rpc_match:
            binding = rpc_match.group(1).strip()
            if binding and binding not in verbose_data["rpc_bindings"]:
                verbose_data["rpc_bindings"].append(binding)
            continue

        # Parse authentication method
        auth_match = RE_AUTH_METHOD.search(line_stripped)
        if auth_match:
            verbose_data["auth_info"]["method"] = auth_match.group(1)
            continue

        # Parse NTLM information
        ntlm_match = RE_NTLM_INFO.search(line_stripped)
        if ntlm_match:
            verbose_data["auth_info"]["ntlm_info"] = ntlm_match.group(1).strip()
            continue

        # Parse session key info (without exposing actual keys)
        session_match = RE_SESSION_KEY.search(line_stripped)
        if session_match:
            verbose_data["auth_info"]["session_established"] = True
            continue

        # Capture NTSTATUS codes
        status_match = RE_STATUS_CODE.search(line_stripped)
        if status_match:
            status_code = status_match.group(1).upper()
            if status_code not in verbose_data["status_codes"]:
                verbose_data["status_codes"].append(status_code)
            continue

        # Parse guest/anonymous flag
        guest_match = RE_GUEST_FLAG.search(line_stripped)
        if guest_match:
            verbose_data["auth_info"]["guest_flag"] = guest_match.group(1) or "detected"
            continue

        # Parse signing status
        signing_match = RE_SIGNING_INFO.search(line_stripped)
        if signing_match:
            verbose_data["signing"] = signing_match.group(1).lower()
            continue

        # Parse server time
        time_match = RE_SERVER_TIME.search(line_stripped)
        if time_match:
            verbose_data["server_info"]["time"] = time_match.group(1).strip()
            continue

        # Parse server OS
        os_match = RE_SERVER_OS.search(line_stripped)
        if os_match:
            verbose_data["server_info"]["os"] = os_match.group(1).strip()
            continue

        # Capture [INFO] lines for additional context
        info_match = RE_INFO_LINE.search(line_stripped)
        if info_match:
            info_content = info_match.group(1).strip()
            # Filter for session/connection relevant info
            if any(
                kw in info_content.lower()
                for kw in [
                    "session",
                    "connect",
                    "auth",
                    "bind",
                    "rpc",
                    "smb",
                    "logon",
                    "login",
                    "credential",
                    "access",
                    "granted",
                    "denied",
                    "negotiate",
                    "dialect",
                ]
            ):
                if info_content not in verbose_data["info_messages"]:
                    verbose_data["info_messages"].append(info_content)

    return verbose_data


def check_session(args, session_type: str, cmd_args: list, label: str) -> tuple:
    """Check a session type and parse verbose output.

    Returns: (success: bool, verbose_data: dict, stdout: str, stderr: str)
    """
    rc, stdout, stderr = run_nxc(cmd_args, args.timeout)
    debug_nxc(cmd_args, stdout, stderr, label)

    verbose_data = parse_verbose_session_info(stdout, stderr)

    # Determine success based on output
    success = "[+]" in stdout or "STATUS_SUCCESS" in stdout.upper()

    return success, verbose_data, stdout, stderr


def enum_rpc_session(args, cache):
    """Check RPC session access (null, guest, authenticated)."""
    print_section("RPC Session Check", args.target)

    sessions = {}
    session_details = {}  # Store verbose details for each session type

    # Check null session
    status("Check for anonymous access (null session)")
    null_args = ["smb", args.target, "-u", "", "-p", ""]
    null_success, null_verbose, null_stdout, _ = check_session(
        args, "null", null_args, "Null Session"
    )
    sessions["null"] = null_success
    session_details["null"] = null_verbose

    if null_success:
        status("Server allows authentication via username '' and password ''", "success")
        # Show additional verbose info if available
        if null_verbose["status_codes"]:
            for code in null_verbose["status_codes"]:
                if "SUCCESS" in code:
                    continue  # Don't repeat success
                status(f"  Status: {code}", "info")
    else:
        # Check for specific error codes in verbose output
        error_msg = "Server does not allow null sessions"
        if null_verbose["status_codes"]:
            error_codes = [
                c
                for c in null_verbose["status_codes"]
                if "DENIED" in c or "FAILURE" in c or "INVALID" in c
            ]
            if error_codes:
                error_msg += f" ({error_codes[0]})"
        status(error_msg, "error")

    # Check authenticated session if credentials provided
    if args.user and (args.password or args.hash):
        status("Check for password authentication")
        auth = cache.auth_args
        rc, stdout, stderr = cache.get_smb_basic(args.target, auth)
        auth_verbose = parse_verbose_session_info(stdout, stderr)
        auth_success = "[+]" in stdout
        sessions["authenticated"] = auth_success
        session_details["authenticated"] = auth_verbose

        if auth_success:
            cred = args.password if args.password else f"hash {args.hash}"
            status(
                f"Server allows authentication via username '{args.user}' and password '{cred}'",
                "success",
            )
            # Show auth method if detected
            if auth_verbose["auth_info"].get("method"):
                status(f"  Authentication method: {auth_verbose['auth_info']['method']}", "info")
        else:
            status(f"Authentication failed for user '{args.user}'", "error")
            if auth_verbose["status_codes"]:
                for code in auth_verbose["status_codes"]:
                    if "DENIED" in code or "FAILURE" in code or "INVALID" in code:
                        status(f"  Status: {code}", "info")

    # Check guest session
    status("Check for guest access")
    guest_args = ["smb", args.target, "-u", "guest", "-p", ""]
    guest_success, guest_verbose, guest_stdout, _ = check_session(
        args, "guest", guest_args, "Guest Session"
    )
    sessions["guest"] = guest_success
    session_details["guest"] = guest_verbose

    if guest_success:
        status("Server allows guest access", "success")
        # Note if guest flag was explicitly detected in verbose output
        if guest_verbose["auth_info"].get("guest_flag"):
            status("  Guest account is enabled", "info")
    elif "[-]" in guest_stdout:
        # Parse actual NTSTATUS from output for accurate error message
        guest_upper = guest_stdout.upper()
        if "STATUS_ACCOUNT_DISABLED" in guest_upper:
            status("Guest account is disabled", "info")
        elif "STATUS_LOGON_FAILURE" in guest_upper:
            status("Could not establish guest session: STATUS_LOGON_FAILURE", "error")
        elif "STATUS_ACCESS_DENIED" in guest_upper:
            status("Could not establish guest session: STATUS_ACCESS_DENIED", "error")
        else:
            # Show any detected status codes
            if guest_verbose["status_codes"]:
                code_str = ", ".join(guest_verbose["status_codes"][:2])
                status(f"Could not establish guest session: {code_str}", "error")
            else:
                status("Could not establish guest session", "error")
    else:
        status("Guest session status unclear", "warning")
        # Show any status codes for debugging
        if guest_verbose["status_codes"]:
            for code in guest_verbose["status_codes"]:
                status(f"  Status: {code}", "info")

    # Display aggregated verbose information
    _display_verbose_summary(session_details)

    # Store session info in cache for other modules
    cache.rpc_session_info = {"sessions": sessions, "details": session_details}

    if args.json_output:
        JSON_DATA["rpc_sessions"] = sessions
        # Include verbose details in JSON output
        JSON_DATA["rpc_session_details"] = {
            session_type: {
                "connection": details.get("connection", {}),
                "auth_info": details.get("auth_info", {}),
                "rpc_bindings": details.get("rpc_bindings", []),
                "status_codes": details.get("status_codes", []),
                "signing": details.get("signing"),
                "server_info": details.get("server_info", {}),
            }
            for session_type, details in session_details.items()
        }


def _display_verbose_summary(session_details: dict):
    """Display a summary of verbose session information."""
    # Collect unique connection/server info across all sessions
    connection_info = {}
    rpc_bindings = set()
    server_info = {}
    info_messages = []
    signing_status = None

    for session_type, details in session_details.items():
        if details.get("connection"):
            connection_info.update(details["connection"])
        if details.get("rpc_bindings"):
            rpc_bindings.update(details["rpc_bindings"])
        if details.get("server_info"):
            server_info.update(details["server_info"])
        if details.get("info_messages"):
            info_messages.extend(details["info_messages"])
        if details.get("signing") and not signing_status:
            signing_status = details["signing"]

    # Only display if we have meaningful verbose data
    has_verbose_data = (
        connection_info.get("smb_dialect") or rpc_bindings or server_info or signing_status
    )

    if not has_verbose_data:
        return

    output("")
    output(c("SESSION DETAILS:", Colors.CYAN))

    # Connection info
    if connection_info:
        if connection_info.get("smb_dialect"):
            output(f"  SMB Dialect: {connection_info['smb_dialect']}")
        if connection_info.get("ip") and connection_info.get("port"):
            output(f"  Connection: {connection_info['ip']}:{connection_info['port']}")

    # Signing status
    if signing_status:
        if signing_status in ("true", "required", "enabled"):
            output(f"  Signing: {c('required', Colors.GREEN)}")
        else:
            output(f"  Signing: {c('not required', Colors.YELLOW)}")

    # Server info
    if server_info:
        if server_info.get("os"):
            output(f"  Server OS: {server_info['os']}")
        if server_info.get("time"):
            output(f"  Server Time: {server_info['time']}")

    # RPC bindings (useful for understanding what's exposed)
    if rpc_bindings:
        output(f"  RPC Endpoints: {len(rpc_bindings)} detected")
        for binding in sorted(rpc_bindings)[:5]:  # Limit display
            output(f"    - {binding}")
        if len(rpc_bindings) > 5:
            output(f"    ... and {len(rpc_bindings) - 5} more")

    # Unique info messages (limit to avoid noise)
    unique_msgs = list(set(info_messages))
    if unique_msgs:
        output("")
        output(c("VERBOSE INFO:", Colors.CYAN))
        for msg in unique_msgs[:5]:
            output(f"  {msg}")
        if len(unique_msgs) > 5:
            output(f"  ... and {len(unique_msgs) - 5} more messages")
