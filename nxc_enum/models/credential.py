"""Credential dataclass for authentication."""

from dataclasses import dataclass
from typing import Optional


class CredentialError(ValueError):
    """Raised when credential configuration is invalid."""

    pass


@dataclass
class Credential:
    """Represents a single credential pair for authentication.

    Attributes:
        user: Username for authentication
        password: Password (mutually exclusive with hash, both can be None for null auth)
        hash: NTLM hash for pass-the-hash authentication
        domain: Optional domain name
        valid: Whether credential has been validated successfully
        is_admin: True if user has local admin privileges on target
    """

    user: str
    password: Optional[str] = None
    hash: Optional[str] = None
    domain: Optional[str] = None
    valid: bool = False
    is_admin: bool = False  # True if user has local admin privileges on target

    def has_auth(self) -> bool:
        """Check if credential has at least one authentication method.

        Returns:
            True if password is not None (including empty string) or hash is set
        """
        return self.password is not None or bool(self.hash)

    def auth_args(self) -> list:
        """Build nxc auth arguments for this credential.

        Returns:
            List of command-line arguments for nxc authentication

        Raises:
            CredentialError: If neither password nor hash is provided
        """
        auth = ["-u", self.user]
        # Handle password (including empty string for null auth)
        if self.password is not None:
            auth.extend(["-p", self.password])
        elif self.hash:
            auth.extend(["-H", self.hash])
        else:
            raise CredentialError(
                f"Credential for '{self.user}' has no password or hash. "
                "Provide either -p/--password or -H/--hash."
            )
        if self.domain:
            auth.extend(["-d", self.domain])
        return auth

    def display_name(self) -> str:
        """Short name for display (e.g., 'admin' or 'DOMAIN\\admin')."""
        if self.domain:
            return f"{self.domain}\\{self.user}"
        return self.user

    def auth_type(self) -> str:
        """Return the authentication type being used.

        Returns:
            'password', 'hash', or 'none'
        """
        if self.password is not None:
            return "password"
        elif self.hash:
            return "hash"
        return "none"

    def __repr__(self) -> str:
        """Return a safe string representation that redacts sensitive fields.

        Security: Password and hash values are always redacted to prevent
        accidental exposure in logs, debug output, or error messages.
        """
        pwd_display = "****REDACTED****" if self.password is not None else "None"
        hash_display = "****REDACTED****" if self.hash else "None"
        return (
            f"Credential(user={self.user!r}, password={pwd_display}, "
            f"hash={hash_display}, domain={self.domain!r}, "
            f"valid={self.valid}, is_admin={self.is_admin})"
        )
