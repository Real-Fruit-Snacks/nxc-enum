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
RE_RID_USER = re.compile(r"(\d+):\s*\S+\\(\S+)\s+\(SidTypeUser\)")
RE_RID_GROUP = re.compile(r"(\d+):\s*\S+\\(.+?)\s+\(SidTypeGroup\)")
RE_RID_ALIAS = re.compile(r"(\d+):\s*\S+\\(.+?)\s+\(SidTypeAlias\)")
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
PARALLEL_MODULE_WORKERS = 7  # Number of workers for parallel module execution
CACHE_PRIME_WORKERS = 3  # Number of workers for cache priming
MAX_CREDENTIAL_VALIDATION_WORKERS = 10  # Max workers for credential validation
GROUP_MEMBER_QUERY_WORKERS = 4  # Workers for parallel group member queries

# Network defaults
DEFAULT_COMMAND_TIMEOUT = 60  # Default timeout for nxc commands (seconds)
PORT_CHECK_TIMEOUT = 2.0  # Timeout for port connectivity checks (seconds)

# Common network ports
SMB_PORTS = ("445", "139")
LDAP_PORTS = ("389", "636")
ALL_ENUM_PORTS = ("445", "139", "389", "636")
