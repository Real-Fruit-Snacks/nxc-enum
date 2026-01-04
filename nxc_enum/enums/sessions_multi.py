"""Session enumeration (multi-credential)."""

import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.runner import run_nxc
from ..core.output import output, status, print_section, JSON_DATA
from ..parsing.nxc_output import is_nxc_noise_line

_lock = threading.Lock()


def _parse_session_info(line: str) -> dict | None:
    """Parse verbose INFO line for session details.

    Verbose output may include lines like:
    - INFO Session: <user> on <session_name> (State: Active, Idle: 0:00:00)
    - INFO Connected user: DOMAIN\\user via RDP
    - INFO Session ID: 2, Type: RDP-Tcp, State: Active

    IMPORTANT: Must NOT match on generic nxc INFO lines like:
    - INFO Socket info: host=..., kerberos=False, ipv6=False, link-local ipv6=False
    - INFO Creating SMBv3 connection to ...
    - INFO SMBv1 disabled on ...
    - INFO Resolved domain: ...
    """
    info = {}

    # Skip generic nxc verbose lines (connection metadata, not session data)
    # These contain keywords that would falsely match our patterns
    noise_keywords = [
        'Socket info:', 'Creating SMB', 'SMBv1 disabled', 'SMBv2 disabled',
        'SMBv3 connection', 'Resolved domain', 'kerberos=', 'ipv6=',
        'link-local', 'kdcHost:', 'hostname=', 'host='
    ]
    for keyword in noise_keywords:
        if keyword in line:
            return None

    # Check for session detail patterns in INFO lines
    # Only match if it looks like actual session data
    if 'Session' in line or 'session' in line:
        # Extract session ID if present
        session_id_match = re.search(r'Session\s*(?:ID)?[:\s]+(\d+)', line, re.IGNORECASE)
        if session_id_match:
            info['session_id'] = session_id_match.group(1)

        # Extract session type (RDP-Tcp, Console, etc.)
        type_match = re.search(r'Type[:\s]+([A-Za-z0-9\-_]+)', line, re.IGNORECASE)
        if type_match:
            info['session_type'] = type_match.group(1)

        # Extract session state (Active, Disconnected, etc.)
        # Be more specific to avoid matching "ipv6=False" type patterns
        state_match = re.search(r'\bState[:\s]+(\w+)', line, re.IGNORECASE)
        if state_match:
            state_val = state_match.group(1)
            # Only accept valid session states, not boolean values from other fields
            if state_val.lower() in ('active', 'disc', 'disconnected', 'connected', 'listen', 'idle', 'locked'):
                info['state'] = state_val

        # Extract idle time
        idle_match = re.search(r'Idle[:\s]+([0-9:]+|\.|\d+\s*(?:min|hour|day|sec)?)', line, re.IGNORECASE)
        if idle_match:
            info['idle_time'] = idle_match.group(1)

        # Extract username with domain
        user_match = re.search(r'(?:user|User)[:\s]+([A-Za-z0-9_\-\.\\]+)', line)
        if user_match:
            info['user'] = user_match.group(1)

        # Extract client name/IP for RDP sessions
        client_match = re.search(r'(?:Client|client|from)[:\s]+([A-Za-z0-9\.\-_]+)', line)
        if client_match:
            info['client'] = client_match.group(1)

    return info if info else None


def _parse_qwinsta_parts(parts: list) -> dict:
    """Parse qwinsta output parts into structured session data.

    qwinsta output format typically:
    SESSIONNAME  USERNAME  ID  STATE  TYPE  DEVICE
    or variations like:
    services     0         Disc
    console      user      1   Active
    rdp-tcp#0    user      2   Active  rdpwd
    """
    # Filter out "None" strings and empty values from raw display
    clean_parts = [p for p in parts if p and p.lower() != 'none']
    session = {'raw': ' '.join(clean_parts)}

    if len(parts) >= 1:
        session['session_name'] = parts[0]

    if len(parts) >= 2:
        # Check if second field is a number (session ID) or username
        if parts[1].isdigit():
            session['session_id'] = parts[1]
            if len(parts) >= 3:
                session['user'] = parts[2] if not parts[2].isdigit() else None
        else:
            session['user'] = parts[1]
            if len(parts) >= 3 and parts[2].isdigit():
                session['session_id'] = parts[2]

    if len(parts) >= 4:
        # Look for state keywords
        for part in parts[3:]:
            if part.lower() in ('active', 'disc', 'disconnected', 'connected', 'listen', 'locked'):
                session['state'] = part.capitalize()
                break

    # Try to extract timestamp from the line (format: YYYY/MM/DD HH:MM:SS)
    raw_line = ' '.join(clean_parts)
    timestamp_match = re.search(r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})', raw_line)
    if timestamp_match:
        session['timestamp'] = timestamp_match.group(1)

    return session


def enum_sessions_multi(args, creds: list, results):
    """Enumerate sessions for multiple credentials (requires local admin)."""
    print_section("Active Sessions", args.target)

    admin_creds = [cred for cred in creds if cred.is_admin]
    if not admin_creds:
        status("Skipping: requires local admin (no admin credentials available)", "info")
        for cred in creds:
            results.sessions[cred.display_name()] = (False, "Skipped (not admin)")
        return

    non_admin_count = len(creds) - len(admin_creds)
    if non_admin_count > 0:
        status(f"Running for {len(admin_creds)} admin user(s), skipping {non_admin_count} non-admin user(s)")
    else:
        status(f"Querying sessions for {len(admin_creds)} admin user(s)...")

    def get_sessions_for_cred(cred):
        auth = cred.auth_args()
        rc, stdout, stderr = run_nxc(["smb", args.target] + auth + ["--qwinsta"], args.timeout)
        success = '[+]' in stdout and 'DCERPC' not in stdout and 'access_denied' not in stdout.lower()
        sessions = []  # List of structured session dicts
        verbose_metadata = {}  # Additional info from verbose output
        error_msg = ""

        if success:
            for line in stdout.split('\n'):
                if 'SESSIONNAME' in line or '----' in line or '====' in line:
                    continue
                if is_nxc_noise_line(line):
                    continue

                # Parse verbose INFO lines for additional metadata
                if 'INFO' in line:
                    info = _parse_session_info(line)
                    if info:
                        for key, value in info.items():
                            if key not in verbose_metadata:
                                verbose_metadata[key] = []
                            if value not in verbose_metadata[key]:
                                verbose_metadata[key].append(value)
                    continue

                if '[*]' in line or '[+]' in line:
                    continue

                # Strip the SMB prefix (e.g., "SMB 10.0.24.230 445 DC01") from session lines
                # The prefix pattern is: SMB <IP> <PORT> <HOSTNAME>
                stripped_line = re.sub(r'^SMB\s+\S+\s+\d+\s+\S+\s+', '', line)

                parts = stripped_line.split()
                if len(parts) >= 2:
                    session_data = _parse_qwinsta_parts(parts)
                    sessions.append(session_data)
        else:
            if 'access_denied' in stdout.lower() or 'rpc_s_access_denied' in stdout.lower():
                error_msg = "ACCESS DENIED"
            elif 'DCERPC' in stdout:
                error_msg = "RPC Error"

        return cred.display_name(), success, sessions, verbose_metadata, error_msg

    for cred in creds:
        if not cred.is_admin:
            results.sessions[cred.display_name()] = (False, "Skipped (not admin)", {})

    all_metadata = {}  # Aggregate verbose metadata from all credentials

    with ThreadPoolExecutor(max_workers=min(len(admin_creds), 10)) as executor:
        futures = [executor.submit(get_sessions_for_cred, cred) for cred in admin_creds]
        for future in as_completed(futures):
            try:
                user, success, sessions, verbose_metadata, error_msg = future.result()
                with _lock:
                    results.sessions[user] = (success, sessions if success else error_msg, verbose_metadata)
                    # Merge verbose metadata
                    for key, values in verbose_metadata.items():
                        if key not in all_metadata:
                            all_metadata[key] = []
                        for val in values:
                            if val not in all_metadata[key]:
                                all_metadata[key].append(val)
            except Exception as e:
                status(f"Error enumerating sessions: {e}", "error")

    output("")
    all_sessions = []
    for user in [c.display_name() for c in creds]:
        result_data = results.sessions.get(user, (False, "Not checked", {}))
        success = result_data[0]
        data = result_data[1]
        if success:
            status(f"{user}: SUCCESS - {len(data)} session(s)", "success")
            all_sessions.extend(data)
        else:
            status(f"{user}: {data}", "error")

    # Display aggregated verbose metadata if found
    if all_metadata:
        if all_metadata.get('session_type'):
            types = ', '.join(all_metadata['session_type'])
            status(f"Session types found: {types}", "info")
        if all_metadata.get('state'):
            states = ', '.join(set(all_metadata['state']))
            status(f"Session states: {states}", "info")

    if all_sessions:
        output("")
        output("Combined Sessions:")
        for session in all_sessions:
            # Handle both dict and list formats
            if isinstance(session, dict):
                display = session.get('raw', str(session))
                output(f"  {display}")
            else:
                output(f"  {' '.join(session)}")

    if args.json_output:
        JSON_DATA['sessions_multi'] = {
            user: {
                'success': result[0],
                'sessions': result[1] if result[0] else None,
                'metadata': result[2] if len(result) > 2 else {},
                'error': result[1] if not result[0] else None
            }
            for user, result in results.sessions.items()
        }
