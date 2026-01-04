"""Share access matrix printing."""

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, output, status


def print_share_matrix(results, creds, args):
    """Print share access matrix."""
    users = [c_obj.display_name() for c_obj in creds]
    shares = sorted(results.shares.keys())

    # Calculate column widths
    name_width = max(len(s) for s in shares) if shares else 10
    name_width = max(name_width, 10)  # Minimum width
    user_width = max(len(u) for u in users) if users else 10
    user_width = max(user_width, 10)

    output("")
    # Header row
    header = f"{'Share':<{name_width}}"
    for user in users:
        header += f"  {user:<{user_width}}"
    output(header)
    output("-" * len(header))

    # Data rows
    for share in shares:
        row = f"{share:<{name_width}}"
        for user in users:
            perms = results.shares[share].get(user, "-")
            if perms == "NO ACCESS":
                perms = "-"
            # Color code (pad before coloring to fix alignment)
            perms_padded = perms[:user_width].ljust(user_width)
            if "WRITE" in perms:
                perms_str = c(perms_padded, Colors.GREEN)
            elif "READ" in perms:
                perms_str = c(perms_padded, Colors.YELLOW)
            else:
                perms_str = perms_padded
            row += f"  {perms_str}"
        output(row)

    output("")
    output(
        "Legend: "
        + c("WRITE", Colors.GREEN)
        + " | "
        + c("READ", Colors.YELLOW)
        + " | - = No Access"
    )

    # Find interesting shares
    interesting_shares = []
    for share in shares:
        if share not in ("IPC$", "NETLOGON", "SYSVOL", "ADMIN$", "C$"):
            users_with_access = [
                u for u, p in results.shares[share].items() if p != "-" and p != "NO ACCESS"
            ]
            if users_with_access:
                interesting_shares.append((share, users_with_access))

    if interesting_shares:
        output("")
        for share, users_with_access in interesting_shares:
            status(
                f"Non-default share '{share}' accessible by: {', '.join(users_with_access)}",
                "warning",
            )

    if args.json_output:
        JSON_DATA["shares_matrix"] = {
            share: {user: results.shares[share].get(user, "NO ACCESS") for user in users}
            for share in shares
        }
