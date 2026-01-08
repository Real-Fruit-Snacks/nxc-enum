"""Credential validation functions."""

from .anonymous import (
    AnonymousSessionResult,
    check_anonymous_access,
    probe_anonymous_sessions,
)
from .hosts import (
    check_hosts_resolution,
    check_hosts_resolution_from_info,
    early_hosts_check,
    extract_hostname_from_smb,
)
from .multi import validate_credentials_multi
from .single import validate_credentials

__all__ = [
    "validate_credentials",
    "validate_credentials_multi",
    "check_hosts_resolution",
    "check_hosts_resolution_from_info",
    "early_hosts_check",
    "extract_hostname_from_smb",
    "probe_anonymous_sessions",
    "check_anonymous_access",
    "AnonymousSessionResult",
]
