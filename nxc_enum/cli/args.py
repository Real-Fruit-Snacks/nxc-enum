"""Argument parser for nxc_enum."""

import argparse
import textwrap


class CustomHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom formatter for cleaner help output."""

    def __init__(self, prog, indent_increment=2, max_help_position=40, width=100):
        super().__init__(prog, indent_increment, max_help_position, width)

    def _format_action_invocation(self, action):
        if not action.option_strings:
            return super()._format_action_invocation(action)
        # Format as: -short, --long
        parts = []
        if action.option_strings:
            parts.extend(action.option_strings)
        return ", ".join(parts)


def create_parser():
    """Create and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="nxc-enum",
        description=textwrap.dedent(
            """
            ╔═══════════════════════════════════════════════════════════════════╗
            ║  nxc-enum - NetExec AD Enumeration with enum4linux-ng Style       ║
            ╚═══════════════════════════════════════════════════════════════════╝

            A comprehensive Active Directory enumeration tool that wraps NetExec
            commands and formats output in the familiar enum4linux-ng style.
            30+ enumeration modules across multiple protocols.

            Features:
              • Multi-protocol enumeration (SMB, LDAP, MSSQL, RDP, FTP, NFS)
              • Automatic null/guest session probing when no credentials provided
              • Multi-credential support with share access matrix
              • Local admin detection and admin-aware command execution
              • Actionable "Next Steps" recommendations based on findings
              • Pure enumeration only (no command execution on targets)
        """
        ),
        formatter_class=CustomHelpFormatter,
        epilog=textwrap.dedent(
            """
            ─────────────────────────────────────────────────────────────────────
            Examples:

              Anonymous enumeration (auto-probes null/guest sessions):
                nxc-enum 10.0.24.230

              Single credential:
                nxc-enum 10.0.24.230 -u admin -p 'Password123' -d CORP
                nxc-enum 10.0.24.230 -u admin -H <ntlm_hash>

              Multi-credential (compare access levels):
                nxc-enum 10.0.24.230 -C creds.txt -d CORP
                nxc-enum 10.0.24.230 -U users.txt -P passes.txt

              Multi-target (CIDR, ranges, files):
                nxc-enum 10.0.0.0/24 -u admin -p pass          # CIDR notation
                nxc-enum 10.0.0.1-50 -u admin -p pass          # IP range
                nxc-enum 10.0.0.1-10.0.0.50 -u admin -p pass   # Full range
                nxc-enum targets.txt -u admin -p pass          # Targets file (auto-detected)

              Specific modules:
                nxc-enum 10.0.24.230 -u admin -p pass --shares --users
                nxc-enum 10.0.24.230 -u admin -p pass --delegation --adcs
                nxc-enum 10.0.24.230 -u admin -p pass --laps --ldap-signing

              Other protocols:
                nxc-enum 10.0.24.230 -u admin -p pass --mssql    # MSSQL databases
                nxc-enum 10.0.24.230 -u admin -p pass --rdp      # RDP/NLA status
                nxc-enum 10.0.24.230 --ftp                       # FTP anonymous (no auth)
                nxc-enum 10.0.24.230 --nfs                       # NFS exports (no auth)

              Output options:
                nxc-enum 10.0.24.230 -u admin -p pass -o results.txt
                nxc-enum 10.0.24.230 -u admin -p pass -j -o results.json

            Credential File Formats:

              creds.txt (user:password or user:hash per line):
                admin:Password123
                svc_backup:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

              users.txt + passes.txt (paired line-by-line):
                admin           Password123
                svc_backup      Summer2024!
            ─────────────────────────────────────────────────────────────────────
        """
        ),
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Target
    # ─────────────────────────────────────────────────────────────────────────
    target_group = parser.add_argument_group(
        "Target",
        "Target specification (auto-detects: IP, hostname, CIDR, range, or file)",
    )
    target_group.add_argument(
        "target",
        metavar="TARGET",
        help="IP, hostname, CIDR, range, or targets file (auto-detected if file exists)",
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Authentication
    # ─────────────────────────────────────────────────────────────────────────
    auth_group = parser.add_argument_group(
        "Authentication",
        "Single credential authentication options",
    )
    auth_group.add_argument(
        "-u",
        "--user",
        metavar="USER",
        help="Username",
    )
    auth_group.add_argument(
        "-p",
        "--password",
        metavar="PASS",
        help="Password",
    )
    auth_group.add_argument(
        "-H",
        "--hash",
        metavar="HASH",
        help="NTLM hash (LM:NT or NT only)",
    )
    auth_group.add_argument(
        "-d",
        "--domain",
        metavar="DOMAIN",
        help="Domain name",
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Multi-Credential
    # ─────────────────────────────────────────────────────────────────────────
    multi_group = parser.add_argument_group(
        "Multi-Credential Mode",
        "Test multiple credentials with access comparison",
    )
    multi_group.add_argument(
        "-C",
        "--credfile",
        metavar="FILE",
        help="Credentials file (user:password per line)",
    )
    multi_group.add_argument(
        "-U",
        "--userfile",
        metavar="FILE",
        help="Usernames file (one per line)",
    )
    multi_group.add_argument(
        "-P",
        "--passfile",
        metavar="FILE",
        help="Passwords file (one per line, paired with -U)",
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Enumeration Modules
    # ─────────────────────────────────────────────────────────────────────────
    enum_group = parser.add_argument_group(
        "Enumeration Modules",
        "Select specific modules to run (default: all)",
    )
    enum_group.add_argument(
        "-A",
        "--all",
        action="store_true",
        help="Run all enumeration modules",
    )
    enum_group.add_argument(
        "--users",
        action="store_true",
        help="Domain users via RPC",
    )
    enum_group.add_argument(
        "--groups",
        action="store_true",
        help="Domain groups with members",
    )
    enum_group.add_argument(
        "--shares",
        action="store_true",
        help="SMB shares and permissions",
    )
    enum_group.add_argument(
        "--policies",
        action="store_true",
        help="Password and lockout policies",
    )
    enum_group.add_argument(
        "--sessions",
        action="store_true",
        help="Active sessions [admin]",
    )
    enum_group.add_argument(
        "--loggedon",
        action="store_true",
        help="Logged on users [admin]",
    )
    enum_group.add_argument(
        "--printers",
        action="store_true",
        help="Printers and spooler status",
    )
    enum_group.add_argument(
        "--av",
        action="store_true",
        help="AV/EDR products [admin]",
    )
    enum_group.add_argument(
        "--computers",
        action="store_true",
        help="Domain computers with OS info",
    )
    enum_group.add_argument(
        "--local-groups",
        action="store_true",
        help="Local groups and members",
    )
    enum_group.add_argument(
        "--subnets",
        action="store_true",
        help="AD sites and subnets",
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Security Checks (LDAP-based)
    # ─────────────────────────────────────────────────────────────────────────
    security_group = parser.add_argument_group(
        "Security Checks",
        "LDAP-based security and misconfiguration checks",
    )
    security_group.add_argument(
        "--laps",
        action="store_true",
        help="LAPS deployment check",
    )
    security_group.add_argument(
        "--ldap-signing",
        action="store_true",
        help="LDAP signing requirements",
    )
    security_group.add_argument(
        "--pre2k",
        action="store_true",
        help="Pre-Windows 2000 computers",
    )
    security_group.add_argument(
        "--bitlocker",
        action="store_true",
        help="BitLocker status [admin]",
    )
    security_group.add_argument(
        "--delegation",
        action="store_true",
        help="Delegation misconfigurations",
    )
    security_group.add_argument(
        "--asreproast",
        action="store_true",
        help="AS-REP roastable accounts",
    )
    security_group.add_argument(
        "--adcs",
        action="store_true",
        help="ADCS certificate templates",
    )
    security_group.add_argument(
        "--dc-list",
        action="store_true",
        help="Domain controllers and trusts",
    )
    security_group.add_argument(
        "--pwd-not-reqd",
        action="store_true",
        help="Accounts with PASSWD_NOTREQD",
    )
    security_group.add_argument(
        "--admin-count",
        action="store_true",
        help="Accounts with adminCount=1",
    )
    security_group.add_argument(
        "--maq",
        action="store_true",
        help="Machine account quota",
    )
    security_group.add_argument(
        "--descriptions",
        action="store_true",
        help="User description fields",
    )
    security_group.add_argument(
        "--signing",
        action="store_true",
        help="SMB signing requirements",
    )
    security_group.add_argument(
        "--webdav",
        action="store_true",
        help="WebClient service status",
    )
    security_group.add_argument(
        "--dns",
        action="store_true",
        help="DNS records",
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Other Protocols
    # ─────────────────────────────────────────────────────────────────────────
    protocol_group = parser.add_argument_group(
        "Other Protocols",
        "Additional protocol enumeration (MSSQL, RDP, FTP, NFS)",
    )
    protocol_group.add_argument(
        "--mssql",
        action="store_true",
        help="MSSQL databases and linked servers",
    )
    protocol_group.add_argument(
        "--rdp",
        action="store_true",
        help="RDP status and NLA check",
    )
    protocol_group.add_argument(
        "--ftp",
        action="store_true",
        help="FTP anonymous access",
    )
    protocol_group.add_argument(
        "--nfs",
        action="store_true",
        help="NFS share exports",
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Output Options
    # ─────────────────────────────────────────────────────────────────────────
    output_group = parser.add_argument_group(
        "Output",
        "Output format and destination options",
    )
    output_group.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write output to file",
    )
    output_group.add_argument(
        "-j",
        "--json",
        dest="json_output",
        action="store_true",
        help="JSON format (requires -o)",
    )
    output_group.add_argument(
        "--copy-paste",
        action="store_true",
        help="Include copy-pastable lists",
    )
    output_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress banner",
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Runtime Behavior
    # ─────────────────────────────────────────────────────────────────────────
    behavior_group = parser.add_argument_group(
        "Behavior",
        "Runtime behavior and validation options",
    )
    behavior_group.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        metavar="SEC",
        help="Command timeout (default: 30)",
    )
    behavior_group.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip credential validation",
    )
    behavior_group.add_argument(
        "--skip-hosts-check",
        action="store_true",
        help="Bypass mandatory hosts resolution check (not recommended)",
    )
    behavior_group.add_argument(
        "--debug",
        action="store_true",
        help="Show raw nxc command output",
    )

    return parser
