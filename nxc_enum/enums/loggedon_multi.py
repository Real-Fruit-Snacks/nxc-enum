"""Logged-on users enumeration (multi-credential)."""

import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.runner import run_nxc
from ..core.output import output, status, print_section, JSON_DATA
from ..core.colors import Colors, c
from ..parsing.nxc_output import is_nxc_noise_line

# Import verbose parsing from single-cred module
from .loggedon import parse_loggedon_verbose

_lock = threading.Lock()


def enum_loggedon_multi(args, creds: list, results):
    """Enumerate logged on users for multiple credentials (requires local admin)."""
    print_section("Logged On Users", args.target)

    admin_creds = [cred for cred in creds if cred.is_admin]
    if not admin_creds:
        status("Skipping: requires local admin (no admin credentials available)", "info")
        for cred in creds:
            results.loggedon[cred.display_name()] = (False, "Skipped (not admin)", {})
        return

    non_admin_count = len(creds) - len(admin_creds)
    if non_admin_count > 0:
        status(f"Running for {len(admin_creds)} admin user(s), skipping {non_admin_count} non-admin user(s)")
    else:
        status(f"Querying logged on users for {len(admin_creds)} admin user(s)...")

    def get_loggedon_for_cred(cred):
        auth = cred.auth_args()
        rc, stdout, stderr = run_nxc(["smb", args.target] + auth + ["--loggedon-users"], args.timeout)
        success = '[+]' in stdout and 'Error' not in stdout and 'access_denied' not in stdout.lower()
        error_msg = ""

        if success:
            # Use verbose parsing to get detailed session info
            parsed = parse_loggedon_verbose(stdout)
            users = parsed['users']
            sessions = parsed['sessions']
            return cred.display_name(), success, users, sessions, error_msg
        else:
            if 'access_denied' in stdout.lower() or 'Error' in stdout:
                error_msg = "ACCESS DENIED"
            return cred.display_name(), success, [], [], error_msg

    for cred in creds:
        if not cred.is_admin:
            results.loggedon[cred.display_name()] = (False, "Skipped (not admin)", {})

    all_sessions = []  # Aggregate sessions from all credentials

    with ThreadPoolExecutor(max_workers=min(len(admin_creds), 10)) as executor:
        futures = [executor.submit(get_loggedon_for_cred, cred) for cred in admin_creds]
        for future in as_completed(futures):
            try:
                user, success, loggedon_users, sessions, error_msg = future.result()
                with _lock:
                    results.loggedon[user] = (success, loggedon_users if success else error_msg, sessions)
                    if success:
                        all_sessions.extend(sessions)
            except Exception as e:
                status(f"Error enumerating loggedon users: {e}", "error")

    output("")
    all_loggedon = set()
    for user in [c.display_name() for c in creds]:
        result_data = results.loggedon.get(user, (False, "Not checked", {}))
        success = result_data[0]
        data = result_data[1]
        if success:
            status(f"{user}: SUCCESS - {len(data)} user(s)", "success")
            all_loggedon.update(data)
        else:
            status(f"{user}: {data}", "error")

    if all_loggedon:
        output("")
        # Check if we have detailed session info
        has_details = any(
            s.get('logon_type') or s.get('source') or s.get('session_id')
            for s in all_sessions
        )

        if has_details and all_sessions:
            # Full table with details
            output(c("Logged On Users:", Colors.CYAN))
            output(f"{'User':<35}  {'Logon Type':<18}  {'Source':<20}  {'Session'}")
            output(f"{'-'*35}  {'-'*18}  {'-'*20}  {'-'*8}")

            # Deduplicate sessions by user
            seen_users = set()
            for session in all_sessions:
                user = session.get('user', 'Unknown')
                if user in seen_users:
                    continue
                seen_users.add(user)

                user_display = user[:35].ljust(35)
                logon_type = session.get('logon_type', '')[:18].ljust(18)
                source = session.get('source', '')[:20].ljust(20)
                session_id = session.get('session_id', '')

                output(f"{user_display}  {logon_type}  {source}  {session_id}")
        else:
            # Simple list if no additional details available
            output(c("Logged On Users:", Colors.CYAN))
            for user in sorted(all_loggedon):
                output(f"  {user}")

    if args.json_output:
        JSON_DATA['loggedon_multi'] = {
            user: {
                'success': result[0],
                'users': list(result[1]) if result[0] and isinstance(result[1], (list, set)) else None,
                'sessions': result[2] if len(result) > 2 and result[0] else [],
                'error': result[1] if not result[0] else None
            }
            for user, result in results.loggedon.items()
        }
