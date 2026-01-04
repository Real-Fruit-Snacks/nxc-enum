"""Share enumeration (multi-credential)."""

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.runner import run_nxc
from ..core.output import output, status, print_section, JSON_DATA
from ..core.colors import Colors, c
from ..parsing.shares import parse_shares_from_output

_lock = threading.Lock()


def enum_shares_multi(args, creds: list, results):
    """Enumerate shares for multiple credentials and display as matrix."""
    print_section("Shares Matrix", args.target)
    status(f"Enumerating shares for {len(creds)} user(s)...")

    def get_shares_for_cred(cred):
        auth = cred.auth_args()
        rc, stdout, stderr = run_nxc(["smb", args.target] + auth + ["--shares"], args.timeout)
        shares = parse_shares_from_output(stdout)
        return cred.display_name(), shares

    with ThreadPoolExecutor(max_workers=min(len(creds), 10)) as executor:
        futures = [executor.submit(get_shares_for_cred, cred) for cred in creds]
        for future in as_completed(futures):
            try:
                user, shares = future.result()
                with _lock:
                    for name, perms, comment in shares:
                        if name not in results.shares:
                            results.shares[name] = {}
                            results.share_comments[name] = comment
                        results.shares[name][user] = perms
            except Exception as e:
                status(f"Error enumerating shares: {e}", "error")

    if results.shares:
        print_share_matrix(results, creds, args)
    else:
        status("No shares found", "error")


def print_share_matrix(results, creds: list, args):
    """Print share access matrix."""
    users = [c.display_name() for c in creds]
    shares = sorted(results.shares.keys())

    name_width = max(len(s) for s in shares) if shares else 10
    name_width = max(name_width, 10)
    user_width = max(len(u) for u in users) if users else 10
    user_width = max(user_width, 10)

    output("")
    header = f"{'Share':<{name_width}}"
    for user in users:
        header += f"  {user:<{user_width}}"
    output(header)
    output("-" * len(header))

    for share in shares:
        row = f"{share:<{name_width}}"
        for user in users:
            perms = results.shares[share].get(user, "-")
            if perms == "NO ACCESS":
                perms = "-"
            # Check permissions before truncating for display
            is_write = "WRITE" in perms
            is_read = "READ" in perms
            perms_padded = perms[:user_width].ljust(user_width)
            if is_write:
                perms_str = c(perms_padded, Colors.GREEN)
            elif is_read:
                perms_str = c(perms_padded, Colors.YELLOW)
            else:
                perms_str = perms_padded
            row += f"  {perms_str}"
        output(row)

    output("")
    output("Legend: " + c("WRITE", Colors.GREEN) + " | " + c("READ", Colors.YELLOW) + " | - = No Access")

    interesting_shares = []
    for share in shares:
        if share not in ('IPC$', 'NETLOGON', 'SYSVOL', 'ADMIN$', 'C$'):
            users_with_access = [u for u, p in results.shares[share].items() if p != '-' and p != 'NO ACCESS']
            if users_with_access:
                interesting_shares.append((share, users_with_access))

    if interesting_shares:
        output("")
        for share, users_with_access in interesting_shares:
            status(f"Non-default share '{share}' accessible by: {', '.join(users_with_access)}", "warning")

    if args.json_output:
        JSON_DATA['shares_matrix'] = {
            share: {user: results.shares[share].get(user, 'NO ACCESS') for user in users}
            for share in shares
        }
