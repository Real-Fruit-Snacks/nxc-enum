"""Credential validation functions."""

from .single import validate_credentials
from .multi import validate_credentials_multi

__all__ = ["validate_credentials", "validate_credentials_multi"]
