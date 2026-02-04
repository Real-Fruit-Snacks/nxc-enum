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
        local_auth: Use local authentication instead of domain
        delegate: Target user for S4U2proxy delegation
        delegate_self: Use S4U2self extension for delegation
        kerberos: Use Kerberos authentication
        use_kcache: Use Kerberos credentials from ccache file
        aes_key: AES key for Kerberos authentication
        kdc_host: KDC hostname for Kerberos authentication
        pfx_cert: Path to PFX certificate file for PKINIT authentication
        pem_cert: Path to PEM certificate file for PKINIT authentication
        pem_key: Path to PEM private key file for PKINIT authentication
        pfx_pass: Password for PFX certificate file
    """

    user: str
    password: Optional[str] = None
    hash: Optional[str] = None
    domain: Optional[str] = None
    valid: bool = False
    is_admin: bool = False  # True if user has local admin privileges on target
    local_auth: bool = False  # Use local authentication instead of domain
    delegate: Optional[str] = None  # Target user for S4U2proxy delegation
    delegate_self: bool = False  # Use S4U2self extension
    kerberos: bool = False  # Use Kerberos authentication
    use_kcache: bool = False  # Use credentials from ccache file
    aes_key: Optional[str] = None  # AES key for Kerberos auth
    kdc_host: Optional[str] = None  # KDC hostname
    pfx_cert: Optional[str] = None  # Path to PFX certificate
    pem_cert: Optional[str] = None  # Path to PEM certificate
    pem_key: Optional[str] = None  # Path to PEM private key
    pfx_pass: Optional[str] = None  # Password for PFX certificate

    def has_auth(self) -> bool:
        """Check if credential has at least one authentication method.

        Returns:
            True if password, hash, kcache, aes_key, or certificate is available
        """
        return (
            self.password is not None
            or bool(self.hash)
            or self.use_kcache
            or bool(self.aes_key)
            or bool(self.pfx_cert)
            or bool(self.pem_cert)
        )

    def auth_args(self) -> list:
        """Build nxc auth arguments for this credential.

        Returns:
            List of command-line arguments for nxc authentication

        Raises:
            CredentialError: If no valid authentication method is provided
        """
        auth = ["-u", self.user]

        # Certificate authentication (PKINIT)
        if self.pfx_cert:
            auth.extend(["--pfx-cert", self.pfx_cert])
            if self.pfx_pass:
                auth.extend(["--pfx-pass", self.pfx_pass])
        elif self.pem_cert:
            auth.extend(["--pem-cert", self.pem_cert])
            if self.pem_key:
                auth.extend(["--pem-key", self.pem_key])
        # Kerberos with kcache or AES key doesn't require password/hash
        elif self.use_kcache:
            auth.append("--use-kcache")
        elif self.aes_key:
            auth.extend(["--aesKey", self.aes_key])
        elif self.password is not None:
            # Handle password (including empty string for null auth)
            auth.extend(["-p", self.password])
        elif self.hash:
            auth.extend(["-H", self.hash])
        else:
            raise CredentialError(
                f"Credential for '{self.user}' has no password, hash, kcache, "
                "AES key, or certificate. Use -p, -H, --use-kcache, --aesKey, "
                "or --pfx-cert/--pem-cert."
            )

        if self.domain:
            auth.extend(["-d", self.domain])

        # Kerberos authentication flag
        if self.kerberos:
            auth.append("-k")

        # KDC host for Kerberos
        if self.kdc_host:
            auth.extend(["--kdcHost", self.kdc_host])

        # Local authentication flag (authenticate against local SAM, not domain)
        if self.local_auth:
            auth.append("--local-auth")

        # Delegation options for S4U2proxy/S4U2self
        if self.delegate:
            auth.extend(["--delegate", self.delegate])
            if self.delegate_self:
                auth.append("--self")

        return auth

    def display_name(self) -> str:
        """Short name for display (e.g., 'admin' or 'DOMAIN\\admin')."""
        # Handle anonymous sessions
        if self.is_anonymous:
            if self.user.lower() == "guest":
                return "Guest"
            return "NULL SESSION"
        if self.domain:
            return f"{self.domain}\\{self.user}"
        return self.user

    @property
    def is_anonymous(self) -> bool:
        """Check if this is an anonymous/null/guest session credential."""
        # Null session: empty user and empty password
        if self.user == "" and self.password == "":
            return True
        # Guest session: user is "Guest" (case-insensitive) and empty password
        if self.user.lower() == "guest" and self.password == "":
            return True
        return False

    def auth_type(self) -> str:
        """Return the authentication type being used.

        Returns:
            'null', 'guest', 'password', 'hash', 'kerberos', 'certificate', or 'none'
        """
        # Check for anonymous sessions first
        if self.is_anonymous:
            if self.user.lower() == "guest":
                return "guest"
            return "null"
        if self.pfx_cert or self.pem_cert:
            return "certificate"
        elif self.use_kcache or self.aes_key:
            return "kerberos"
        elif self.password is not None:
            return "password"
        elif self.hash:
            return "hash"
        return "none"

    def __repr__(self) -> str:
        """Return a safe string representation that redacts sensitive fields.

        Security: Password, hash, AES key, and PFX password values are always redacted
        to prevent accidental exposure in logs, debug output, or error messages.
        """
        pwd_display = "****REDACTED****" if self.password is not None else "None"
        hash_display = "****REDACTED****" if self.hash else "None"
        aes_display = "****REDACTED****" if self.aes_key else "None"
        pfx_pass_display = "****REDACTED****" if self.pfx_pass else "None"
        return (
            f"Credential(user={self.user!r}, password={pwd_display}, "
            f"hash={hash_display}, domain={self.domain!r}, "
            f"valid={self.valid}, is_admin={self.is_admin}, "
            f"local_auth={self.local_auth}, delegate={self.delegate!r}, "
            f"delegate_self={self.delegate_self}, kerberos={self.kerberos}, "
            f"use_kcache={self.use_kcache}, aes_key={aes_display}, "
            f"kdc_host={self.kdc_host!r}, pfx_cert={self.pfx_cert!r}, "
            f"pem_cert={self.pem_cert!r}, pem_key={self.pem_key!r}, "
            f"pfx_pass={pfx_pass_display})"
        )
