"""Enumeration modules - each function in its own file."""

# Core enumeration
from .target_info import enum_target_info
from .listeners import enum_listeners
from .domain_intel import enum_domain_intelligence
# Alias for shorter import
enum_domain_intel = enum_domain_intelligence
from .smb_info import enum_smb_info
from .rpc_session import enum_rpc_session
from .os_info import enum_os_info

# User/Group enumeration
from .users import enum_users
from .groups import enum_groups, get_group_members
from .descriptions import enum_descriptions

# Resource enumeration
from .shares import enum_shares
from .shares_multi import enum_shares_multi
from .printers import enum_printers
from .printers_multi import enum_printers_multi

# Session enumeration
from .sessions import enum_sessions
from .sessions_multi import enum_sessions_multi
from .loggedon import enum_loggedon
from .loggedon_multi import enum_loggedon_multi

# Security enumeration
from .policies import enum_policies
from .av import enum_av
from .av_multi import enum_av_multi
from .signing import enum_signing
from .webdav import enum_webdav
from .kerberoastable import enum_kerberoastable

# LDAP enumeration
from .delegation import enum_delegation
from .maq import enum_maq
from .adcs import enum_adcs
from .dc_list import enum_dc_list
from .pwd_not_required import enum_pwd_not_required
from .admin_count import enum_admin_count
from .dns import enum_dns

__all__ = [
    # Core
    "enum_target_info", "enum_listeners", "enum_domain_intelligence", "enum_domain_intel",
    "enum_smb_info", "enum_rpc_session", "enum_os_info",
    # User/Group
    "enum_users", "enum_groups", "get_group_members", "enum_descriptions",
    # Resource
    "enum_shares", "enum_shares_multi", "enum_printers", "enum_printers_multi",
    # Session
    "enum_sessions", "enum_sessions_multi", "enum_loggedon", "enum_loggedon_multi",
    # Security
    "enum_policies", "enum_av", "enum_av_multi", "enum_signing", "enum_webdav",
    "enum_kerberoastable",
    # LDAP
    "enum_delegation", "enum_maq", "enum_adcs", "enum_dc_list",
    "enum_pwd_not_required", "enum_admin_count", "enum_dns",
]
