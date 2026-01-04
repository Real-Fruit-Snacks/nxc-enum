"""Credential parsing from command-line arguments and files."""

import os
import stat
import sys

from ..core.constants import RE_NTLM_HASH
from ..models.credential import Credential


def _check_file_permissions(filepath: str) -> None:
    """Check and warn if credential file has overly permissive permissions.

    Security: Credential files should not be readable by group or other users.
    This function warns the user but does not block execution.

    Args:
        filepath: Path to the credential file to check
    """
    try:
        file_stat = os.stat(filepath)
        mode = file_stat.st_mode

        # Check if group or other has any access
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            print(f"Warning: Credential file '{filepath}' has loose permissions")
            # Get the actual permission string
            perms = oct(mode)[-3:]
            print(f"  Current permissions: {perms}")
            print(f"  Recommended: chmod 600 {filepath}")
            print()
    except OSError:
        # Can't check permissions - might be Windows or other issue
        pass


def parse_credentials(args) -> list[Credential]:
    """Parse credentials from args into list of Credential objects.

    Security: Checks file permissions on credential files and warns if
    they are world-readable or group-readable.
    """
    creds = []

    if args.credfile:
        # Security check: warn about loose file permissions
        _check_file_permissions(args.credfile)

        # Parse user:password or user:hash lines from credential file
        try:
            with open(args.credfile, encoding="utf-8-sig") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        # Split on first colon only (passwords may contain colons)
                        user, secret = line.split(":", 1)
                        user = user.strip()
                        secret = secret.strip()
                        if not user:
                            continue
                        # Detect hash vs password (32:32 or 32 hex chars = NTLM hash)
                        # Note: 32-char hex passwords will be treated as hashes
                        if RE_NTLM_HASH.match(secret):
                            creds.append(Credential(user=user, hash=secret, domain=args.domain))
                        else:
                            creds.append(Credential(user=user, password=secret, domain=args.domain))
        except FileNotFoundError:
            print(f"Error: Credential file '{args.credfile}' not found")
            sys.exit(1)
        except PermissionError:
            print(f"Error: Permission denied reading '{args.credfile}'")
            sys.exit(1)
        except UnicodeDecodeError:
            print(f"Error: File encoding issue in '{args.credfile}' - ensure UTF-8 encoding")
            sys.exit(1)

    elif args.userfile and args.passfile:
        # Security check: warn about loose file permissions
        _check_file_permissions(args.userfile)
        _check_file_permissions(args.passfile)

        # Pair users and passwords line by line
        try:
            with open(args.userfile, encoding="utf-8-sig") as uf:
                users = [l.strip() for l in uf if l.strip() and not l.startswith("#")]
            with open(args.passfile, encoding="utf-8-sig") as pf:
                passwords = [l.strip() for l in pf if l.strip() and not l.startswith("#")]
            # Warn before processing if counts don't match
            if len(users) != len(passwords):
                print(
                    f"Warning: User count ({len(users)}) != password count ({len(passwords)}), pairing will be truncated to {min(len(users), len(passwords))}"
                )
            for user, password in zip(users, passwords):
                creds.append(Credential(user=user, password=password, domain=args.domain))
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
        except PermissionError as e:
            print(f"Error: Permission denied - {e}")
            sys.exit(1)
        except UnicodeDecodeError as e:
            print(f"Error: File encoding issue - ensure UTF-8 encoding: {e}")
            sys.exit(1)

    elif args.user:
        # Single credential (backward compatible)
        creds.append(
            Credential(user=args.user, password=args.password, hash=args.hash, domain=args.domain)
        )

    return creds
