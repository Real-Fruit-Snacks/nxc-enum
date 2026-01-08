"""Enumeration modules - each function in its own file."""

# Core enumeration
from .adcs import enum_adcs
from .admin_count import enum_admin_count
from .asreproast import enum_asreproast
from .av import enum_av
from .av_multi import enum_av_multi
from .bitlocker import enum_bitlocker
from .computers import enum_computers
from .dc_list import enum_dc_list

# LDAP enumeration
from .delegation import enum_delegation
from .descriptions import enum_descriptions

# Resource enumeration
from .disks import enum_disks
from .dns import enum_dns
from .domain_intel import enum_domain_intelligence
from .ftp import enum_ftp
from .gmsa import enum_gmsa
from .gpp_password import enum_gpp_password
from .groups import enum_groups, get_group_members
from .interfaces import enum_interfaces
from .ioxid import enum_ioxid
from .kerberoastable import enum_kerberoastable
from .laps import enum_laps
from .ldap_signing import enum_ldap_signing
from .listeners import enum_listeners
from .local_groups import enum_local_groups
from .loggedon import enum_loggedon
from .loggedon_multi import enum_loggedon_multi
from .maq import enum_maq
from .mssql import enum_mssql
from .nfs import enum_nfs
from .os_info import enum_os_info

# Security enumeration
from .policies import enum_policies
from .pre2k import enum_pre2k
from .printers import enum_printers
from .printers_multi import enum_printers_multi
from .pso import enum_pso
from .pwd_not_required import enum_pwd_not_required
from .rdp import enum_rdp
from .rpc_session import enum_rpc_session
from .sccm import enum_sccm

# Session enumeration
from .sessions import enum_sessions
from .sessions_multi import enum_sessions_multi
from .shares import enum_shares
from .shares_multi import enum_shares_multi
from .signing import enum_signing
from .smb_info import enum_smb_info
from .spider import enum_spider
from .subnets import enum_subnets
from .target_info import enum_target_info

# User/Group enumeration
from .users import enum_users
from .vnc import enum_vnc
from .webdav import enum_webdav

# Alias for shorter import
enum_domain_intel = enum_domain_intelligence

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
    "enum_computers",
    "enum_local_groups",
    # Resource
    "enum_shares",
    "enum_shares_multi",
    "enum_printers",
    "enum_printers_multi",
    "enum_subnets",
    "enum_disks",
    "enum_interfaces",
    "enum_ioxid",
    "enum_spider",
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
    "enum_asreproast",
    "enum_laps",
    "enum_ldap_signing",
    "enum_pre2k",
    "enum_bitlocker",
    # LDAP
    "enum_delegation",
    "enum_maq",
    "enum_adcs",
    "enum_dc_list",
    "enum_pwd_not_required",
    "enum_admin_count",
    "enum_dns",
    "enum_gmsa",
    "enum_gpp_password",
    "enum_pso",
    "enum_sccm",
    # Other protocols
    "enum_mssql",
    "enum_rdp",
    "enum_ftp",
    "enum_nfs",
    "enum_vnc",
]
