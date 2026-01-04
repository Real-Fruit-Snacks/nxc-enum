"""Enumeration modules - each function in its own file."""

# Core enumeration
from .domain_intel import enum_domain_intelligence
from .listeners import enum_listeners
from .target_info import enum_target_info

# Alias for shorter import
enum_domain_intel = enum_domain_intelligence
from .adcs import enum_adcs
from .admin_count import enum_admin_count
from .av import enum_av
from .av_multi import enum_av_multi
from .dc_list import enum_dc_list

# LDAP enumeration
from .delegation import enum_delegation
from .descriptions import enum_descriptions
from .dns import enum_dns
from .groups import enum_groups, get_group_members
from .kerberoastable import enum_kerberoastable
from .loggedon import enum_loggedon
from .loggedon_multi import enum_loggedon_multi
from .maq import enum_maq
from .os_info import enum_os_info

# Security enumeration
from .policies import enum_policies
from .printers import enum_printers
from .printers_multi import enum_printers_multi
from .pwd_not_required import enum_pwd_not_required
from .rpc_session import enum_rpc_session

# Session enumeration
from .sessions import enum_sessions
from .sessions_multi import enum_sessions_multi

# Resource enumeration
from .shares import enum_shares
from .shares_multi import enum_shares_multi
from .signing import enum_signing
from .smb_info import enum_smb_info

# User/Group enumeration
from .users import enum_users
from .webdav import enum_webdav

__all__ = [
    # Core
    "enum_target_info",
    "enum_listeners",
    "enum_domain_intelligence",
    "enum_domain_intel",
    "enum_smb_info",
    "enum_rpc_session",
    "enum_os_info",
    # User/Group
    "enum_users",
    "enum_groups",
    "get_group_members",
    "enum_descriptions",
    # Resource
    "enum_shares",
    "enum_shares_multi",
    "enum_printers",
    "enum_printers_multi",
    # Session
    "enum_sessions",
    "enum_sessions_multi",
    "enum_loggedon",
    "enum_loggedon_multi",
    # Security
    "enum_policies",
    "enum_av",
    "enum_av_multi",
    "enum_signing",
    "enum_webdav",
    "enum_kerberoastable",
    # LDAP
    "enum_delegation",
    "enum_maq",
    "enum_adcs",
    "enum_dc_list",
    "enum_pwd_not_required",
    "enum_admin_count",
    "enum_dns",
]
