"""Argument parser for nxc_enum."""

import argparse


def create_parser():
    """Create and return the argument parser."""
    parser = argparse.ArgumentParser(
        description="NetExec wrapper with enum4linux-ng style output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nxc-enum 10.0.24.230 -u user -p password
  nxc-enum 10.0.24.230 -u user -p password -A
  nxc-enum 10.0.24.230 -u user -H <ntlm_hash>
  nxc-enum 10.0.24.230 --shares --users
  nxc-enum 10.0.24.230 -u user -p pass -o results.txt
  nxc-enum 10.0.24.230 -u user -p pass -j -o results.json

Multi-credential mode:
  nxc-enum 10.0.24.230 -C creds.txt -A              # user:password per line
  nxc-enum 10.0.24.230 -U users.txt -P passes.txt   # paired line-by-line
        """,
    )

    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-u", "--user", help="Username for authentication")
    parser.add_argument("-p", "--password", help="Password for authentication")
    parser.add_argument("-H", "--hash", help="NTLM hash for pass-the-hash")
    parser.add_argument("-d", "--domain", help="Domain name")
    parser.add_argument("-U", "--userfile", help="File containing usernames (one per line)")
    parser.add_argument("-P", "--passfile", help="File containing passwords (one per line)")
    parser.add_argument("-C", "--credfile", help="File with credentials (user:password per line)")
    parser.add_argument("-A", "--all", action="store_true", help="Run all enumeration modules")
    parser.add_argument("--users", action="store_true", help="Enumerate users")
    parser.add_argument("--groups", action="store_true", help="Enumerate groups")
    parser.add_argument("--shares", action="store_true", help="Enumerate shares")
    parser.add_argument("--policies", action="store_true", help="Enumerate password policies")
    parser.add_argument("--sessions", action="store_true", help="Enumerate sessions")
    parser.add_argument("--loggedon", action="store_true", help="Enumerate logged on users")
    parser.add_argument("--printers", action="store_true", help="Enumerate printers")
    parser.add_argument("--av", action="store_true", help="Enumerate AV/EDR products")
    # New enumeration features
    parser.add_argument(
        "--delegation", action="store_true", help="Find delegation misconfigurations"
    )
    parser.add_argument(
        "--descriptions", action="store_true", help="Extract user description fields"
    )
    parser.add_argument("--maq", action="store_true", help="Check machine account quota")
    parser.add_argument("--adcs", action="store_true", help="Enumerate ADCS certificate templates")
    parser.add_argument("--dc-list", action="store_true", help="List domain controllers and trusts")
    parser.add_argument(
        "--pwd-not-reqd", action="store_true", help="Find accounts without password requirement"
    )
    parser.add_argument(
        "--admin-count", action="store_true", help="Find accounts with adminCount attribute"
    )
    parser.add_argument("--signing", action="store_true", help="Check SMB signing requirements")
    parser.add_argument("--webdav", action="store_true", help="Check WebClient service status")
    parser.add_argument("--dns", action="store_true", help="Enumerate DNS records")
    parser.add_argument(
        "-t", "--timeout", type=int, default=30, help="Timeout in seconds (default: 30)"
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress banner")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument(
        "-j", "--json", dest="json_output", action="store_true", help="Output in JSON format"
    )
    parser.add_argument("--no-validate", action="store_true", help="Skip credential validation")
    parser.add_argument(
        "--debug", action="store_true", help="Show raw nxc output before parsed data"
    )

    return parser
