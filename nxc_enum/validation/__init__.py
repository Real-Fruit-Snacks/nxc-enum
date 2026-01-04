"""Credential validation functions."""

from .multi import validate_credentials_multi
from .single import validate_credentials

__all__ = ["validate_credentials", "validate_credentials_multi"]
