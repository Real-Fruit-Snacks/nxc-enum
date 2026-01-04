"""Logged-on users enumeration (single credential)."""

import re

from ..core.runner import run_nxc
from ..core.output import output, status, print_section, debug_nxc, JSON_DATA
from ..core.colors import Colors, c
from ..parsing.nxc_output import is_nxc_noise_line

# Pre-compiled regex patterns for verbose output parsing (moved to module level for performance)
# User pattern: DOMAIN\username or just username
RE_LOGGEDON_USER = re.compile(r'(\S+\\[^\s\\]+)')
# Logon type pattern (common Windows logon types)
RE_LOGGEDON_LOGON_TYPE = re.compile(
    r'(?:logon\s*type|type)[:\s]*(\d+|Interactive|Network|Batch|Service|'
    r'Unlock|NetworkCleartext|NewCredentials|RemoteInteractive|CachedInteractive)',
    re.IGNORECASE
)
# Source address pattern
RE_LOGGEDON_SOURCE = re.compile(
    r'(?:source|from|client|workstation|address)[:\s]*([^\s,]+)',
    re.IGNORECASE
)
# Session ID pattern
RE_LOGGEDON_SESSION_ID = re.compile(r'(?:session\s*(?:id)?)[:\s]*(\d+)', re.IGNORECASE)
# Idle time pattern
RE_LOGGEDON_IDLE = re.compile(r'(?:idle)[:\s]*([^\s,]+)', re.IGNORECASE)

# Logon type numeric to string mapping
LOGON_TYPE_MAP = {
    '2': 'Interactive',
    '3': 'Network',
    '4': 'Batch',
    '5': 'Service',
    '7': 'Unlock',
    '8': 'NetworkCleartext',
    '9': 'NewCredentials',
    '10': 'RemoteInteractive',
    '11': 'CachedInteractive'
}


def parse_loggedon_verbose(stdout: str) -> dict:
    """Parse verbose --loggedon-users output for detailed session info.

    Verbose output may contain:
    - User session entries with DOMAIN\\username format
    - Logon type information (e.g., Interactive, Network, RemoteInteractive)
    - Source address/workstation information
    - Session state details

    Returns:
        dict with 'users' list and 'sessions' list of detailed session info
    """
    users = []
    sessions = []
    current_session = {}

    for line in stdout.split('\n'):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Skip noise lines
        if is_nxc_noise_line(line_stripped):
            continue

        # Skip connection/credential lines
        if '[*]' in line and ('Windows' in line or 'SMBv' in line):
            continue
        if '[+]' in line and '\\' in line and ':' in line:
            # Check if this is a credential confirmation line
            parts = line_stripped.split()
            for part in parts:
                if '\\' in part and ':' in part and '@' not in part:
                    # Looks like DOMAIN\user:password - skip
                    break
            else:
                # Not a credential line, process it
                pass

        # Extract user from the line
        user_match = RE_LOGGEDON_USER.search(line_stripped)
        if user_match:
            user = user_match.group(1)
            # Skip if this looks like a credential (has password after)
            if ':' in user:
                continue
            if user not in users:
                users.append(user)

            # Build session info for this user
            session_info = {'user': user}

            # Try to extract additional verbose details
            logon_match = RE_LOGGEDON_LOGON_TYPE.search(line_stripped)
            if logon_match:
                logon_type = logon_match.group(1)
                session_info['logon_type'] = LOGON_TYPE_MAP.get(logon_type, logon_type)

            source_match = RE_LOGGEDON_SOURCE.search(line_stripped)
            if source_match:
                session_info['source'] = source_match.group(1)

            session_id_match = RE_LOGGEDON_SESSION_ID.search(line_stripped)
            if session_id_match:
                session_info['session_id'] = session_id_match.group(1)

            idle_match = RE_LOGGEDON_IDLE.search(line_stripped)
            if idle_match:
                session_info['idle_time'] = idle_match.group(1)

            # Only add if we have the user at minimum
            if 'user' in session_info:
                # Check for duplicates before adding
                is_dup = False
                for existing in sessions:
                    if existing.get('user') == session_info.get('user'):
                        # Update existing with any new info
                        existing.update({k: v for k, v in session_info.items() if v})
                        is_dup = True
                        break
                if not is_dup:
                    sessions.append(session_info)

        # Check for INFO lines that might have additional session details
        elif '[*]' in line_stripped or 'INFO' in line_stripped.upper():
            # Parse potential session metadata from INFO lines
            content = line_stripped
            for marker in ['[*]', '[+]', '[-]', 'INFO']:
                if marker in content:
                    content = content.split(marker, 1)[-1].strip()

            # Look for logon type info in INFO lines
            logon_match = RE_LOGGEDON_LOGON_TYPE.search(content)
            source_match = RE_LOGGEDON_SOURCE.search(content)

            if logon_match or source_match:
                # This is metadata - try to associate with last user
                if sessions:
                    if logon_match and 'logon_type' not in sessions[-1]:
                        logon_type = logon_match.group(1)
                        sessions[-1]['logon_type'] = LOGON_TYPE_MAP.get(logon_type, logon_type)
                    if source_match and 'source' not in sessions[-1]:
                        sessions[-1]['source'] = source_match.group(1)

    return {'users': users, 'sessions': sessions}


def enum_loggedon(args, cache, is_admin: bool = True):
    """Enumerate logged on users (requires local admin)."""
    print_section("Logged On Users", args.target)

    if not is_admin:
        status("Skipping: requires local admin (current user is not admin)", "info")
        return

    auth = cache.auth_args
    loggedon_args = ["smb", args.target] + auth + ["--loggedon-users"]
    rc, stdout, stderr = run_nxc(loggedon_args, args.timeout)
    debug_nxc(loggedon_args, stdout, stderr, "Logged On Users")

    if rc != 0 and not stdout:
        status("Could not enumerate logged on users", "error")
        return

    status("Enumerating logged on users")

    # Parse verbose output for detailed session information
    parsed = parse_loggedon_verbose(stdout)
    users = parsed['users']
    sessions = parsed['sessions']

    if users:
        status(f"Found {len(users)} logged on user(s)", "success")
        output("")

        # Display in table format with available details
        has_details = any(
            s.get('logon_type') or s.get('source') or s.get('session_id')
            for s in sessions
        )

        if has_details:
            # Full table with details
            output(c("Logged On Users:", Colors.CYAN))
            output(f"{'User':<35}  {'Logon Type':<18}  {'Source':<20}  {'Session'}")
            output(f"{'-'*35}  {'-'*18}  {'-'*20}  {'-'*8}")

            for session in sessions:
                user = session.get('user', 'Unknown')[:35].ljust(35)
                logon_type = session.get('logon_type', '')[:18].ljust(18)
                source = session.get('source', '')[:20].ljust(20)
                session_id = session.get('session_id', '')

                output(f"{user}  {logon_type}  {source}  {session_id}")
        else:
            # Simple list if no additional details available
            output(c("Logged On Users:", Colors.CYAN))
            for user in users:
                output(f"  {user}")

        # Store in cache for potential use by other modules
        cache.loggedon_users = users
        cache.loggedon_sessions = sessions

        # Check for interesting findings
        domain = cache.domain_info.get('domain', '')
        for user in users:
            # Check if we found a domain admin logged in
            if domain and domain.upper() in user.upper():
                user_part = user.split('\\')[-1].lower()
                if user_part in ['administrator', 'admin']:
                    cache.add_next_step(
                        f"Domain admin '{user}' logged on to {args.target}",
                        f"# Consider credential harvesting with Mimikatz",
                        "High-value target for credential theft",
                        priority="high"
                    )
    else:
        status("No logged on users found", "info")
        cache.loggedon_users = []
        cache.loggedon_sessions = []

    if args.json_output:
        JSON_DATA['loggedon_users'] = {
            'users': users,
            'sessions': sessions,
            'count': len(users)
        }
