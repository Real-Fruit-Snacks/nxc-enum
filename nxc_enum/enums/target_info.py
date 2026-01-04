"""Target information display."""

from ..core.output import output, status, print_section, JSON_DATA
from ..core.colors import Colors, c


def enum_target_info(args, creds: list = None):
    """Display target information."""
    print_section("Target Information")
    status(f"Target ........... {args.target}")

    if creds and len(creds) > 1:
        admin_creds = [cred for cred in creds if cred.is_admin]
        std_creds = [cred for cred in creds if not cred.is_admin]

        status(f"Credentials ...... {len(creds)} validated user(s)")

        if admin_creds:
            output(c("  Local Admins:", Colors.RED))
            for cred in admin_creds:
                auth_type = "password" if cred.password else "hash" if cred.hash else "unknown"
                output(f"    - {cred.display_name()} ({auth_type})")

        if std_creds:
            output("  Standard Users:")
            for cred in std_creds:
                auth_type = "password" if cred.password else "hash" if cred.hash else "unknown"
                output(f"    - {cred.display_name()} ({auth_type})")
    else:
        if args.user:
            admin_tag = ""
            if creds and len(creds) == 1 and creds[0].is_admin:
                admin_tag = c(" [LOCAL ADMIN]", Colors.RED)
            status(f"Username ......... '{args.user}'{admin_tag}")
        if args.password:
            status(f"Password ......... '{args.password}'")
        if args.hash:
            status(f"Hash ............. '{args.hash}'")

    if args.domain:
        status(f"Domain ........... '{args.domain}'")
    status(f"Timeout .......... {args.timeout} second(s)")

    if args.json_output:
        if creds and len(creds) > 1:
            JSON_DATA['target'] = {
                'ip': args.target,
                'credentials': [c.display_name() for c in creds],
                'domain': args.domain,
                'timeout': args.timeout
            }
        else:
            JSON_DATA['target'] = {
                'ip': args.target,
                'user': args.user,
                'domain': args.domain,
                'timeout': args.timeout
            }
