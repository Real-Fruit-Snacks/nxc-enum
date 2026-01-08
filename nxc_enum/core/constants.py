"""Pre-compiled regex patterns and constant values."""

import re

from .colors import Colors, c

# Pre-compiled regex patterns for performance
RE_SIGNING = re.compile(r"\(signing:(\w+)\)")
RE_SMBV1 = re.compile(r"\(SMBv1:(\w+)\)")
RE_DOMAIN_SID = re.compile(r"(S-1-5-21-\d+-\d+-\d+)")
RE_DOMAIN_SID_FULL = re.compile(r"(S-1-5-21-\d+-\d+-\d+)-\d+")
RE_NAME = re.compile(r"\(name:([^)]+)\)")
RE_DOMAIN = re.compile(r"\(domain:([^)]+)\)")
RE_HOSTNAME = re.compile(r"445\s+(\S+)\s+\[\*\]")
RE_OS = re.compile(r"\[\*\]\s+([^(]+)\s+\(name:")
RE_BUILD = re.compile(r"Build\s+(\d+)")
RE_USER = re.compile(r"(\S+)\\(\S+)\s+badpwdcount:\s*(\d+)(?:\s+desc:\s*(.*))?", re.IGNORECASE)
RE_RID_USER = re.compile(r"(\d+):\s*(?:\S+\\)?(\S+)\s+\(SidTypeUser\)")
# Regex that captures the domain/hostname prefix separately for local vs domain user detection
# Group 1: RID, Group 2: Domain/Host prefix, Group 3: Username
RE_RID_USER_WITH_DOMAIN = re.compile(r"(\d+):\s*(\S+)\\(\S+)\s+\(SidTypeUser\)")
RE_RID_GROUP = re.compile(r"(\d+):\s*(?:\S+\\)?(.+?)\s+\(SidTypeGroup\)")
RE_RID_ALIAS = re.compile(r"(\d+):\s*(?:\S+\\)?(.+?)\s+\(SidTypeAlias\)")
RE_GROUP = re.compile(r"Group:\s*(.+?)\s+membercount:\s*(\d+)", re.IGNORECASE)
# Verbose group output patterns
RE_GROUP_DESC = re.compile(r"description:\s*(.+)", re.IGNORECASE)
RE_GROUP_TYPE = re.compile(r"grouptype:\s*(.+)", re.IGNORECASE)
RE_GROUP_SCOPE = re.compile(r"groupscope:\s*(.+)", re.IGNORECASE)
RE_GROUP_DN = re.compile(r"distinguishedName:\s*(.+)", re.IGNORECASE)
RE_GROUP_SAM = re.compile(r"sAMAccountName:\s*(.+)", re.IGNORECASE)
RE_DOMAIN_NAME = re.compile(r"\d+:\s*(\S+)\\")
RE_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
RE_LDAP_CN = re.compile(r"CN=([^,]+)")
RE_NTLM_HASH = re.compile(r"^([a-fA-F0-9]{32}:)?[a-fA-F0-9]{32}$")

# High-value groups for pentesting (highlight in red)
HIGH_VALUE_GROUPS = {
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "DnsAdmins",
    "Group Policy Creator Owners",
    "Key Admins",
    "Enterprise Key Admins",
}

# Service account detection patterns
SERVICE_ACCOUNT_SUFFIXES = (".svc", "svc", "_svc", "-svc")
SERVICE_ACCOUNT_PREFIXES = ("svc_", "svc-", "svc.")

# Pre-computed status indicators
INDICATORS = {
    "info": f"[{c('*', Colors.BLUE)}]",
    "success": f"[{c('+', Colors.GREEN)}]",
    "error": f"[{c('-', Colors.RED)}]",
    "warning": f"[{c('!', Colors.YELLOW)}]",
}

# ============================================================================
# Numeric Constants (avoiding magic numbers in code)
# ============================================================================

# User account thresholds
HIGH_BADPWD_THRESHOLD = 3  # Bad password count threshold for highlighting

# Windows RID ranges for account classification
BUILTIN_ACCOUNT_RID_MAX = 999  # RIDs < 1000 are built-in accounts
BUILTIN_GROUP_RID_MIN = 544  # Built-in group RIDs (Administrators, Users, etc.)
BUILTIN_GROUP_RID_MAX = 582  # End of Windows built-in group range
DOMAIN_GROUP_RID_MIN = 512  # Domain-managed group RIDs (Domain Admins, etc.)
DOMAIN_GROUP_RID_MAX = 527  # End of domain-managed group range

# Thread pool configuration
PARALLEL_MODULE_WORKERS = 15  # Number of workers for parallel module execution (29 modules)
CACHE_PRIME_WORKERS = 5  # Number of workers for cache priming (expanded to 5 queries)
MAX_CREDENTIAL_VALIDATION_WORKERS = 10  # Max workers for credential validation
GROUP_MEMBER_QUERY_WORKERS = 4  # Workers for parallel group member queries
MULTI_TARGET_WORKERS = 5  # Workers for parallel multi-target enumeration

# Host discovery workers (for multi-target pre-scanning)
PORT_PRESCAN_WORKERS = 100  # High concurrency for TCP connect checks
PORT_PRESCAN_TIMEOUT = 0.5  # 500ms timeout for port check (fast filter)
SMB_VALIDATION_WORKERS = 20  # Moderate concurrency for nxc SMB validation
PRESCAN_THRESHOLD = 5  # Auto-enable prescan above this target count

# Network defaults
DEFAULT_COMMAND_TIMEOUT = 60  # Default timeout for nxc commands (seconds)
PORT_CHECK_TIMEOUT = 2.0  # Timeout for port connectivity checks (seconds)

# Tiered timeout configuration (operation-specific)
TIMEOUT_PORT_SCAN = 0.5  # Fast TCP connect check
TIMEOUT_SMB_VALIDATION = 5  # SMB banner grab
TIMEOUT_LDAP_QUERY = 15  # Standard LDAP queries
TIMEOUT_MODULE_DEFAULT = 30  # Default module execution timeout
TIMEOUT_HEAVY_MODULE = 120  # Heavy modules (spider, large enumeration)

# Common network ports
SMB_PORTS = ("445", "139")
LDAP_PORTS = ("389", "636")
ALL_ENUM_PORTS = ("445", "139", "389", "636")

# Service ports for pre-scanning (skip enum modules if port is closed)
# These ports are checked at startup to avoid wasting time on unreachable services
SERVICE_PORTS = {
    "rdp": 3389,
    "mssql": 1433,
    "ftp": 21,
    "nfs": 2049,  # NFS RPC portmapper uses 111, but 2049 is standard NFS port
    "winrm": 5985,  # WinRM HTTP
    "winrms": 5986,  # WinRM HTTPS
    "ssh": 22,
}

# VNC uses multiple potential ports (base port + display number)
VNC_PORTS = (5900, 5901, 5902, 5903, 5800, 5801)

# Pre-scan configuration
SERVICE_PRESCAN_TIMEOUT = 1.0  # Fast timeout for service port checks (seconds)
SERVICE_PRESCAN_WORKERS = 10  # Concurrent workers for service pre-scanning

# ============================================================================
# PROXY MODE CONFIGURATION
# ============================================================================
# Reduced concurrency and increased timeouts for proxychains/SOCKS operation
# Proxychains typically supports 10-20 concurrent connections max

# Proxy mode worker counts (reduced to prevent proxy overload)
PROXY_PARALLEL_MODULE_WORKERS = 2  # Reduced from 15
PROXY_CACHE_PRIME_WORKERS = 2  # Reduced from 5
PROXY_CREDENTIAL_VALIDATION_WORKERS = 2  # Reduced from 10
PROXY_GROUP_MEMBER_QUERY_WORKERS = 2  # Reduced from 4
PROXY_MULTI_TARGET_WORKERS = 1  # Reduced from 5 (sequential)
PROXY_PORT_PRESCAN_WORKERS = 5  # Reduced from 100
PROXY_SMB_VALIDATION_WORKERS = 2  # Reduced from 20
MULTI_ENUM_WORKERS = 10  # Default for *_multi.py files
PROXY_MULTI_ENUM_WORKERS = 2  # Reduced from 10

# Proxy mode timeouts (increased for proxy latency ~500ms-2s per connection)
PROXY_PORT_PRESCAN_TIMEOUT = 5.0  # Increased from 0.5s
PROXY_PORT_CHECK_TIMEOUT = 10.0  # Increased from 2.0s
PROXY_SMB_VALIDATION_TIMEOUT = 30  # Increased from 5s
PROXY_DEFAULT_COMMAND_TIMEOUT = 120  # Increased from 60s
