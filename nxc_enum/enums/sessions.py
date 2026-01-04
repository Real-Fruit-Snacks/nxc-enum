"""Session enumeration (single credential)."""

import re

from ..core.runner import run_nxc
from ..core.output import output, status, print_section, debug_nxc, JSON_DATA
from ..parsing.nxc_output import is_nxc_noise_line


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


def _parse_qwinsta_line(parts: list, start_idx: int) -> dict | None:
    """Parse a qwinsta output line into structured session data.

    Typical qwinsta output format:
    SESSIONNAME  USERNAME  ID  STATE  TYPE  DEVICE
    console      Admin     1   Active
    rdp-tcp#0    User1     2   Active
    """
    if len(parts) < start_idx + 2:
        return None

    remaining = parts[start_idx:]
    if not remaining or remaining[0].startswith('['):
        return None

    session = {'raw': ' '.join(remaining)}

    # Try to extract structured fields
    # Common patterns: session_name, username, id, state
    if len(remaining) >= 1:
        session['session_name'] = remaining[0]

    if len(remaining) >= 2:
        # Check if second field is a number (session ID) or username
        if remaining[1].isdigit():
            session['session_id'] = remaining[1]
            if len(remaining) >= 3:
                session['user'] = remaining[2] if not remaining[2].isdigit() else None
        else:
            session['user'] = remaining[1]
            if len(remaining) >= 3 and remaining[2].isdigit():
                session['session_id'] = remaining[2]

    if len(remaining) >= 4:
        # Look for state keywords
        for part in remaining[3:]:
            if part.lower() in ('active', 'disc', 'disconnected', 'connected', 'listen', 'locked'):
                session['state'] = part.capitalize()
                break

    # Try to extract timestamp from the line (format: YYYY/MM/DD HH:MM:SS)
    raw_line = ' '.join(remaining)
    timestamp_match = re.search(r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})', raw_line)
    if timestamp_match:
        session['timestamp'] = timestamp_match.group(1)

    return session


def enum_sessions(args, cache, is_admin: bool = True):
    """Enumerate active sessions (requires local admin)."""
    print_section("Active Sessions", args.target)

    if not is_admin:
        status("Skipping: requires local admin (current user is not admin)", "info")
        return

    auth = cache.auth_args
    status("Querying active sessions...")

    sessions_args = ["smb", args.target] + auth + ["--qwinsta"]
    rc, stdout, stderr = run_nxc(sessions_args, args.timeout)
    debug_nxc(sessions_args, stdout, stderr, "Sessions (qwinsta)")

    sessions = []  # Raw session strings for display
    session_details = []  # Structured session data
    verbose_metadata = {}  # Additional info from verbose output
    found_sessions = False

    for line in stdout.split('\n'):
        line = line.strip()
        if not line:
            continue
        if is_nxc_noise_line(line):
            continue
        if '[*]' in line and 'Windows' in line:
            continue
        if '[+]' in line and '\\' in line and ':' in line:
            continue

        # Parse verbose INFO lines for additional metadata
        if 'INFO' in line:
            info = _parse_session_info(line)
            if info:
                # Merge into verbose_metadata or match to existing session
                for key, value in info.items():
                    if key not in verbose_metadata:
                        verbose_metadata[key] = []
                    if value not in verbose_metadata[key]:
                        verbose_metadata[key].append(value)
            continue

        if '[+]' in line or '[*]' in line:
            for marker in ['[+]', '[*]', '[-]']:
                if marker in line:
                    content = line.split(marker, 1)[-1].strip()
                    if content and 'Windows' not in content:
                        status(content, "success" if marker == '[+]' else "info")
                        sessions.append(content)

                        # Try to parse session info from the content
                        session_info = _parse_session_info(content)
                        if session_info:
                            session_info['raw'] = content
                            session_details.append(session_info)
                        else:
                            session_details.append({'raw': content})

                        found_sessions = True
                    break
        elif line.startswith('SMB') or line.startswith('QWINSTA'):
            parts = line.split()
            if len(parts) >= 5:
                try:
                    port_idx = -1
                    for i, p in enumerate(parts):
                        if p == '445':
                            port_idx = i
                            break
                    if port_idx >= 0 and port_idx + 2 < len(parts):
                        remaining = ' '.join(parts[port_idx + 2:])
                        if remaining and not remaining.startswith('['):
                            output(f"  {remaining}")
                            sessions.append(remaining)

                            # Parse structured session data
                            session_data = _parse_qwinsta_line(parts, port_idx + 2)
                            if session_data:
                                session_details.append(session_data)
                            else:
                                session_details.append({'raw': remaining})

                            found_sessions = True
                except (ValueError, IndexError):
                    pass

    # Display verbose metadata if found
    if verbose_metadata:
        if verbose_metadata.get('session_type'):
            types = ', '.join(verbose_metadata['session_type'])
            status(f"Session types: {types}", "info")
        if verbose_metadata.get('state'):
            states = ', '.join(set(verbose_metadata['state']))
            status(f"Session states: {states}", "info")

    if not found_sessions:
        if 'access_denied' in stderr.lower() or 'access denied' in stdout.lower():
            status("Access denied (local admin required)", "error")
        else:
            status("No active sessions found", "info")

    # Store session data in cache for use by other modules
    cache.active_sessions = session_details
    cache.session_metadata = verbose_metadata

    if args.json_output:
        JSON_DATA['sessions'] = {
            'raw': sessions,
            'details': session_details,
            'metadata': verbose_metadata
        }
