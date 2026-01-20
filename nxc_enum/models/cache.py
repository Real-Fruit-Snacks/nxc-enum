"""Enumeration cache for avoiding redundant NXC calls."""

import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Optional

from ..core.constants import (
    CACHE_PRIME_WORKERS,
    DEFAULT_COMMAND_TIMEOUT,
    PROXY_CACHE_PRIME_WORKERS,
)
from ..core.output import debug_nxc, is_proxy_mode
from ..core.runner import run_nxc

# Set up logging for cache errors (won't output unless configured)
_logger = logging.getLogger(__name__)


class EnumCache:
    """Cache for nxc command results to avoid redundant calls.

    This class stores results from nxc commands to prevent redundant
    network calls. Results are cached on first access and reused
    for subsequent requests.

    Attributes:
        smb_basic: Cached SMB connection result (rc, stdout, stderr)
        rid_brute: Cached RID brute enumeration result
        ldap_basic: Cached LDAP connection result
        auth_args: Authentication arguments for nxc commands
        target: Target IP or hostname
        timeout: Command timeout in seconds
    """

    def __init__(self):
        # Cached command results (None = not yet fetched)
        self.smb_basic: Optional[tuple[int, str, str]] = None
        self.rid_brute: Optional[tuple[int, str, str]] = None
        self.ldap_basic: Optional[tuple[int, str, str]] = None
        self.pass_pol: Optional[tuple[int, str, str]] = None
        self.ldap_users: Optional[tuple[int, str, str]] = None

        # LDAP batch query results for performance optimization
        # These comprehensive queries fetch data for multiple modules at once
        self.ldap_user_batch: Optional[tuple[int, str, str]] = None
        self.ldap_computer_batch: Optional[tuple[int, str, str]] = None

        # Parsed batch data (populated from batch query results)
        # user_batch_parsed: list of dicts with user attributes
        # Keys: sAMAccountName, servicePrincipalName, userAccountControl, adminCount, description
        self.user_batch_parsed: Optional[list[dict]] = None
        # computer_batch_parsed: list of dicts with computer/gMSA attributes
        # Keys: cn, sAMAccountName, operatingSystem, ms-Mcs-AdmPwd, objectClass
        self.computer_batch_parsed: Optional[list[dict]] = None

        # Configuration
        self.auth_args: Optional[list] = None
        self.primary_credential = None  # Primary Credential object for command substitution
        self.target: Optional[str] = None
        self.timeout: int = DEFAULT_COMMAND_TIMEOUT
        # Network options (set from args in main.py)
        self.port: Optional[int] = None  # Custom SMB port (default: 445)
        self.smb_timeout: Optional[int] = None  # SMB-specific timeout
        self.ipv6: bool = False  # Use IPv6 for connections
        self.dns_server: Optional[str] = None  # Custom DNS server
        self.dns_tcp: bool = False  # Use TCP for DNS queries
        self.domain_info = {}
        self.smb_info = {}
        self.policy_info = {}
        self.policy_verbose_info = {}  # Verbose policy data (FGPP, functional level, etc.)
        self.user_count = 0
        self.group_count = 0
        self.share_count = 0
        self.service_accounts = []
        self.spooler_running = False
        self.spooler_info = {}  # Verbose spooler metadata (status, server details)
        self.printer_names = []  # List of discovered printer names
        self.av_products = []
        self.av_check_skipped = False  # Track if AV check was skipped due to permissions
        self.privileged_users = []
        self.kerberoastable = []
        self.asreproastable = []  # Accounts without Kerberos pre-auth required
        self.computers = []  # Domain computers with OS info
        self.outdated_os_computers = []  # Computers running outdated/EOL operating systems
        self.delegation_accounts = []
        self.user_descriptions = []
        self.group_descriptions = []
        self.machine_account_quota = None
        self.adcs_templates = []
        self.adcs_info = {}
        self.domain_controllers = []
        self.domain_trusts = []
        self.dc_verbose_info = {}  # Verbose DC data (roles, sites, trust details)
        self.pwd_not_required = []
        self.pwd_not_required_details = []  # Detailed verbose data (UAC flags, timestamps, etc.)
        self.admin_count_accounts = []
        self.admin_count_details = []  # Structured adminCount data with verbose info
        self.smb_signing_disabled = []
        self.smb_signing_info = {}  # Verbose signing data (dialect, capabilities, per-host status)
        self.webdav_enabled = []
        self.webdav_info = {}  # Verbose WebDAV service details (endpoints, errors)
        self.dns_records = []
        # Active session data from qwinsta enumeration
        self.active_sessions = []  # Structured session details
        self.session_metadata = {}  # Verbose metadata (types, states, etc.)
        # Logged on users data
        self.loggedon_users = []  # List of DOMAIN\user entries
        self.loggedon_sessions = []  # Detailed session info (logon type, source, etc.)
        # Verbose share enumeration metadata (permission checks, errors, types)
        self.share_verbose_info = {}
        # Verbose user enumeration data
        self.disabled_accounts = []
        self.locked_accounts = []
        self.pwd_never_expires_accounts = []
        self.high_badpwd_users = []  # List of (username, count) tuples
        self.never_logged_users = []
        # Collected recommendations for "Next Steps" section
        self.next_steps = []
        # RPC session verbose data (connection, auth, bindings)
        self.rpc_session_info = {}
        # Anonymous session mode (null or guest session without credentials)
        self.anonymous_mode: bool = False
        # Protocol availability (determined during cache priming)
        self.ldap_available: bool = True  # Assume available, set False if connection fails
        self.is_workgroup: bool = False  # Set True if target is workgroup (not domain-joined)
        # Anonymous access findings (checked regardless of credentials)
        self.anonymous_access: dict = {
            "null_available": False,
            "guest_available": False,
            "ldap_anonymous": False,
        }

        # LAPS enumeration data
        self.laps_computers = []  # Computers with LAPS configured
        self.laps_readable = False  # Whether current user can read LAPS passwords

        # LDAP signing check
        self.ldap_signing_required = None  # True/False/None
        self.ldap_channel_binding = None
        self.ldap_signing_info = {}

        # Local groups enumeration
        self.local_groups = {}  # {group_name: [members]}
        self.local_admin_members = []

        # AD sites and subnets
        self.ad_subnets = []  # [{subnet, site}]
        self.ad_sites = []

        # Pre-Windows 2000 computers
        self.pre2k_computers = []

        # BitLocker status
        self.bitlocker_status = {}  # {drive: status}
        self.encrypted_drives = []
        self.unencrypted_drives = []

        # MSSQL enumeration
        self.mssql_info = {}
        self.mssql_databases = []
        self.mssql_linked_servers = []

        # RDP status
        self.rdp_info = {}

        # FTP enumeration
        self.ftp_info = {}
        self.ftp_anonymous = None

        # NFS enumeration
        self.nfs_info = {}
        self.nfs_exports = []

        # gMSA enumeration
        self.gmsa_accounts = []
        self.gmsa_readable = False

        # GPP password enumeration
        self.gpp_passwords = []

        # Network interfaces
        self.network_interfaces = []
        self.is_multi_homed = False

        # Disk drives
        self.disk_drives = []

        # Spider/file listing
        self.spider_files = []
        self.spider_interesting = []
        self.spider_total = 0

        # SCCM/MECM discovery
        self.sccm_info = {}
        self.sccm_servers = []

        # VNC services
        self.vnc_services = []

        # Fine-Grained Password Policies (PSO)
        self.pso_policies = []

        # iOXIDResolver (multi-homed detection)
        self.ioxid_addresses = []
        self.ioxid_multi_homed = False

        # Service availability flags (determined via port pre-scan at startup)
        # These flags allow enum modules to skip when services are unreachable,
        # saving significant time (~30-60 seconds per closed service)
        self.rdp_available: bool | None = None
        self.mssql_available: bool | None = None
        self.ftp_available: bool | None = None
        self.nfs_available: bool | None = None
        self.vnc_available: bool | None = None
        self.winrm_available: bool | None = None
        self.ssh_available: bool | None = None

        # Aggregated copy-paste data (populated by enum modules, printed at end)
        self.copy_paste_data: dict = {
            "targets": set(),  # Successfully enumerated targets (IPs that responded to ping)
            "usernames": set(),  # All usernames (lowercase for deduplication)
            "domain_usernames": set(),  # Domain users only (from DOMAIN\user RID output)
            "local_usernames": set(),  # Local users only (from HOST\user RID output)
            "group_names": set(),
            "share_names": set(),
            "share_unc_paths": set(),  # UNC paths (\\target\share) for multi-target aggregation
            "kerberoastable_users": set(),
            "spns": set(),
            "asreproastable_users": set(),
            "delegation_accounts": set(),
            "target_services": set(),
            "dc_hostnames": set(),
            "dc_ips": set(),
            "computer_names": set(),
            "server_names": set(),
            "workstation_names": set(),
            "loggedon_users": set(),
            "pwd_not_required": set(),
            "admincount_accounts": set(),
            # New copy-paste categories
            "laps_computers": set(),
            "local_admin_members": set(),
            "subnets": set(),
            "pre2k_computers": set(),
            "mssql_databases": set(),
            "ftp_files": set(),
            "nfs_exports": set(),
            # New enumeration module categories
            "gmsa_accounts": set(),
            "gpp_usernames": set(),
            "gpp_passwords": set(),
            "interface_ips": set(),
            "disk_drives": set(),
            "interesting_files": set(),
            "sccm_servers": set(),
            "vnc_ports": set(),
            "weak_pso_groups": set(),
            "ioxid_addresses": set(),
            "pivot_ips": set(),
            # Custom query results (sAMAccountName values from --query)
            "custom_query_names": set(),
        }

    def add_next_step(
        self, finding: str, command: str, description: str = "", priority: str = "medium"
    ):
        """Add a recommended next step based on a finding.

        Args:
            finding: What was discovered (e.g., "Kerberoastable account found")
            command: The command to run (e.g., "nxc ldap ... --kerberoasting")
            description: Optional explanation of what the command does
            priority: "high", "medium", or "low" for sorting
        """
        self.next_steps.append(
            {
                "finding": finding,
                "command": command,
                "description": description,
                "priority": priority,
            }
        )

    def get_dns_args(self) -> list:
        """Build DNS-related arguments for nxc commands.

        Returns:
            List of DNS arguments (e.g., ["--dns-server", "10.0.0.1", "--dns-tcp"])
        """
        dns_args = []
        if self.dns_server:
            dns_args.extend(["--dns-server", self.dns_server])
        if self.dns_tcp:
            dns_args.append("--dns-tcp")
        return dns_args

    def run_nxc_cached(self, args: list, cache_attr: str | None = None) -> tuple[int, str, str]:
        """Run nxc command with cache's network options applied.

        This helper method automatically applies port, smb_timeout, and DNS options
        from the cache configuration.

        Args:
            args: Command arguments to pass to nxc
            cache_attr: Optional attribute name to cache the result

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        # Add DNS arguments if configured
        full_args = args + self.get_dns_args()

        result = run_nxc(
            full_args,
            self.timeout,
            port=self.port,
            smb_timeout=self.smb_timeout,
        )

        if cache_attr:
            setattr(self, cache_attr, result)

        return result

    def apply_service_prescan(self, prescan_results: dict) -> None:
        """Apply service port pre-scan results to cache flags.

        Args:
            prescan_results: Dict from parallel_prescan_services() with service -> bool mapping
        """
        self.rdp_available = prescan_results.get("rdp")
        self.mssql_available = prescan_results.get("mssql")
        self.ftp_available = prescan_results.get("ftp")
        self.nfs_available = prescan_results.get("nfs")
        self.vnc_available = prescan_results.get("vnc")
        self.winrm_available = prescan_results.get("winrm") or prescan_results.get("winrms")
        self.ssh_available = prescan_results.get("ssh")

    def get_smb_basic(self, target: str, auth: list) -> tuple[int, str, str]:
        """Get cached or fresh SMB basic info."""
        if self.smb_basic is None:
            cmd_args = ["smb", target] + auth
            self.smb_basic = self.run_nxc_cached(cmd_args)
            debug_nxc(cmd_args, self.smb_basic[1], self.smb_basic[2], "SMB Basic")
        return self.smb_basic

    def get_rid_brute(self, target: str, auth: list) -> tuple[int, str, str]:
        """Get cached or fresh RID brute results."""
        if self.rid_brute is None:
            cmd_args = ["smb", target] + auth + ["--rid-brute"]
            self.rid_brute = self.run_nxc_cached(cmd_args)
            debug_nxc(cmd_args, self.rid_brute[1], self.rid_brute[2], "RID Brute")
        return self.rid_brute

    def get_ldap_basic(self, target: str, auth: list) -> tuple[int, str, str]:
        """Get cached or fresh LDAP basic info."""
        if self.ldap_basic is None:
            cmd_args = ["ldap", target] + auth
            self.ldap_basic = self.run_nxc_cached(cmd_args)
            debug_nxc(cmd_args, self.ldap_basic[1], self.ldap_basic[2], "LDAP Basic")
        return self.ldap_basic

    def get_kerberoastable_from_batch(self) -> list[dict] | None:
        """Extract kerberoastable accounts from user batch data.

        Returns list of {"username": str, "spns": list} or None if batch unavailable.
        """
        if not self.user_batch_parsed:
            return None

        kerberoastable = []
        for user in self.user_batch_parsed:
            sam = user.get("sAMAccountName")
            spn = user.get("servicePrincipalName")
            cn = user.get("cn", "")

            # Skip if no SPN or no username
            if not spn or not (sam or cn):
                continue

            # Skip computer accounts, krbtgt
            username = sam or cn
            if username.endswith("$") or username.lower() == "krbtgt":
                continue

            # Handle multi-valued SPNs
            spns = spn if isinstance(spn, list) else [spn]

            kerberoastable.append({"username": username, "spns": spns})

        return kerberoastable if kerberoastable else None

    def get_asreproastable_from_batch(self) -> list[dict] | None:
        """Extract AS-REP roastable accounts from user batch data.

        Returns list of {"username": str, "domain": str|None} or None if unavailable.
        """
        if not self.user_batch_parsed:
            return None

        # UAC flag for DONT_REQUIRE_PREAUTH = 0x400000 = 4194304
        DONT_REQUIRE_PREAUTH = 4194304

        asreproastable = []
        for user in self.user_batch_parsed:
            sam = user.get("sAMAccountName")
            uac = user.get("userAccountControl")
            cn = user.get("cn", "")

            if not (sam or cn):
                continue

            username = sam or cn
            # Skip computer accounts
            if username.endswith("$"):
                continue

            # Check UAC flag
            try:
                uac_val = int(uac) if uac else 0
                if uac_val & DONT_REQUIRE_PREAUTH:
                    asreproastable.append({"username": username, "domain": None})
            except (ValueError, TypeError):
                continue

        return asreproastable if asreproastable else None

    def get_pwd_not_required_from_batch(self) -> list[dict] | None:
        """Extract PASSWD_NOTREQD accounts from user batch data.

        Returns list of dicts with username and UAC info or None if unavailable.
        """
        if not self.user_batch_parsed:
            return None

        # UAC flag for PASSWD_NOTREQD = 0x0020 = 32
        # UAC flag for ACCOUNTDISABLE = 0x0002 = 2
        PASSWD_NOTREQD = 32
        ACCOUNTDISABLE = 2

        pwd_not_required = []
        for user in self.user_batch_parsed:
            sam = user.get("sAMAccountName")
            uac = user.get("userAccountControl")
            cn = user.get("cn", "")

            if not (sam or cn):
                continue

            username = sam or cn

            # Check UAC flag
            try:
                uac_val = int(uac) if uac else 0
                if uac_val & PASSWD_NOTREQD:
                    is_disabled = bool(uac_val & ACCOUNTDISABLE)
                    pwd_not_required.append(
                        {
                            "username": username,
                            "is_disabled": is_disabled,
                            "uac_value": uac_val,
                            "status": "disabled" if is_disabled else "enabled",
                        }
                    )
            except (ValueError, TypeError):
                continue

        return pwd_not_required if pwd_not_required else None

    def get_admin_count_from_batch(self) -> list[str] | None:
        """Extract adminCount=1 accounts from user batch data.

        Returns list of account names or None if batch unavailable.
        """
        if not self.user_batch_parsed:
            return None

        admin_accounts = []
        for user in self.user_batch_parsed:
            sam = user.get("sAMAccountName")
            admin_count = user.get("adminCount")
            cn = user.get("cn", "")

            if not (sam or cn):
                continue

            username = sam or cn

            # Check adminCount attribute
            try:
                if admin_count and int(admin_count) == 1:
                    admin_accounts.append(username)
            except (ValueError, TypeError):
                continue

        return admin_accounts if admin_accounts else None

    def get_computers_from_batch(self) -> list[dict] | None:
        """Extract computer info from computer batch data.

        Returns list of {"name": str, "os": str} or None if unavailable.
        """
        if not self.computer_batch_parsed:
            return None

        computers = []
        for obj in self.computer_batch_parsed:
            obj_class = obj.get("objectClass", "")
            # Only process computer objects, not gMSA
            if "msDS-GroupManagedServiceAccount" in str(obj_class):
                continue

            cn = obj.get("cn", "")
            sam = obj.get("sAMAccountName", "")
            os_info = obj.get("operatingSystem", "")
            os_ver = obj.get("operatingSystemVersion", "")

            # LDAP attributes may be lists - ensure strings
            if isinstance(cn, list):
                cn = cn[0] if cn else ""
            if isinstance(sam, list):
                sam = sam[0] if sam else ""
            if isinstance(os_info, list):
                os_info = os_info[0] if os_info else ""
            if isinstance(os_ver, list):
                os_ver = os_ver[0] if os_ver else ""

            name = cn or sam.rstrip("$")
            if not name:
                continue

            full_os = f"{os_info} {os_ver}".strip() if os_ver else os_info
            computers.append({"name": name, "os": full_os})

        return computers if computers else None

    def get_laps_computers_from_batch(self) -> list[str] | None:
        """Extract LAPS-enabled computers from computer batch data.

        Returns list of computer names with LAPS or None if unavailable.
        """
        if not self.computer_batch_parsed:
            return None

        laps_computers = []
        for obj in self.computer_batch_parsed:
            cn = obj.get("cn", "")
            sam = obj.get("sAMAccountName", "")
            laps_pwd = obj.get("ms-Mcs-AdmPwd")

            # LDAP attributes may be lists - ensure strings
            if isinstance(cn, list):
                cn = cn[0] if cn else ""
            if isinstance(sam, list):
                sam = sam[0] if sam else ""

            if laps_pwd:  # Has LAPS attribute
                name = cn or sam.rstrip("$")
                if name:
                    laps_computers.append(name)

        return laps_computers if laps_computers else None

    def get_gmsa_accounts_from_batch(self) -> list[dict] | None:
        """Extract gMSA accounts from computer batch data.

        Returns list of {"name": str, "sam": str} or None if unavailable.
        """
        if not self.computer_batch_parsed:
            return None

        gmsa_accounts = []
        for obj in self.computer_batch_parsed:
            obj_class = obj.get("objectClass", "")
            # Only gMSA objects
            if "msDS-GroupManagedServiceAccount" not in str(obj_class):
                continue

            cn = obj.get("cn", "")
            sam = obj.get("sAMAccountName", "")
            pwd_id = obj.get("msDS-ManagedPasswordId")

            # LDAP attributes may be lists - ensure strings
            if isinstance(cn, list):
                cn = cn[0] if cn else ""
            if isinstance(sam, list):
                sam = sam[0] if sam else ""

            if cn or sam:
                gmsa_accounts.append(
                    {
                        "name": cn or sam.rstrip("$"),
                        "sam": sam or f"{cn}$",
                        "has_password_id": bool(pwd_id),
                    }
                )

        return gmsa_accounts if gmsa_accounts else None

    def get_cn_to_sam_map(self) -> dict:
        """Build a mapping of CN (display name) to sAMAccountName.

        Used to resolve group member names (returned as CN by LDAP --groups)
        to their sAMAccountName for consistency with user enumeration output.

        Returns:
            Dict mapping lowercase CN to sAMAccountName
            Example: {"tom admin": "tom_admin"}
        """
        if not self.user_batch_parsed:
            return {}

        cn_to_sam = {}
        for user in self.user_batch_parsed:
            cn = user.get("cn", "")
            sam = user.get("sAMAccountName", "")

            # LDAP attributes may be lists - ensure strings
            if isinstance(cn, list):
                cn = cn[0] if cn else ""
            if isinstance(sam, list):
                sam = sam[0] if sam else ""

            if cn and sam:
                # Store lowercase CN for case-insensitive matching
                cn_to_sam[cn.lower()] = sam

        return cn_to_sam

    def _parse_ldap_batch(self, stdout: str) -> list[dict]:
        """Parse LDAP --query output into list of object dictionaries.

        Parses nxc LDAP query output format:
            LDAP  IP  PORT  HOST  Response for object: CN=Name,OU=...
            LDAP  IP  PORT  HOST    attrName: value
            LDAP  IP  PORT  HOST    attrName: value
            ...

        Returns list of dicts, each containing attributes for one LDAP object.
        """
        import re

        objects = []
        current_obj = {}

        # Pattern for "Response for object:" line - starts new object
        re_object = re.compile(r"Response for object:\s*CN=([^,]+)", re.IGNORECASE)
        # Pattern for attribute lines - "attrName: value" or "attrName value"
        re_attr = re.compile(r"^\s*(\w[\w-]*)\s*[:\s]\s*(.+)$")

        for line in stdout.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Check for new object
            obj_match = re_object.search(line)
            if obj_match:
                # Save previous object if it has data
                if current_obj and current_obj.get("cn"):
                    objects.append(current_obj)
                # Start new object
                current_obj = {"cn": obj_match.group(1)}
                continue

            # Skip noise lines
            if "[*]" in line or "[+]" in line or "[!]" in line:
                continue

            # Parse attribute line
            # Find the attribute portion after the host column
            # LDAP output format: "LDAP  IP  PORT  HOST  attr: value"
            parts = line.split()
            if len(parts) >= 5 and parts[0].upper() == "LDAP":
                # Reconstruct attribute portion (everything after first 4 columns)
                attr_part = " ".join(parts[4:])
                attr_match = re_attr.match(attr_part)
                if attr_match and current_obj:
                    attr_name = attr_match.group(1)
                    attr_value = attr_match.group(2).strip()
                    # Handle multi-valued attributes (append to list)
                    if attr_name in current_obj:
                        existing = current_obj[attr_name]
                        if isinstance(existing, list):
                            existing.append(attr_value)
                        else:
                            current_obj[attr_name] = [existing, attr_value]
                    else:
                        current_obj[attr_name] = attr_value

        # Don't forget last object
        if current_obj and current_obj.get("cn"):
            objects.append(current_obj)

        return objects

    def prime_caches(self, target: str, auth: list) -> None:
        """Pre-populate all caches in parallel for maximum performance.

        Runs multiple common queries concurrently using a thread pool:
        - SMB basic info (signing, OS, hostname)
        - RID brute (users, groups)
        - LDAP basic info (domain, DC)
        - Password policy
        - LDAP users query (for user enumeration)
        - LDAP user batch (comprehensive user attributes for multiple modules)
        - LDAP computer batch (computer + gMSA attributes for multiple modules)

        Errors are logged but don't stop execution - the cache stores error
        information for later inspection.

        Args:
            target: Target IP or hostname
            auth: Authentication arguments for nxc
        """
        # Batch query: User security attributes
        # Fetches data for: kerberoastable, asreproast, admin_count, pwd_not_required, descriptions
        user_batch_filter = "(&(objectCategory=person)(objectClass=user))"
        user_batch_attrs = (
            "sAMAccountName servicePrincipalName userAccountControl " "adminCount description"
        )

        # Batch query: Computer and gMSA attributes
        # Fetches data for: computers, laps, gmsa
        computer_batch_filter = (
            "(|(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))"
        )
        computer_batch_attrs = (
            "cn sAMAccountName operatingSystem operatingSystemVersion "
            "ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime msDS-ManagedPasswordId objectClass"
        )

        # Define all queries to prime
        queries = {
            "smb_basic": (["smb", target] + auth, "smb_basic"),
            "rid_brute": (["smb", target] + auth + ["--rid-brute"], "rid_brute"),
            "ldap_basic": (["ldap", target] + auth, "ldap_basic"),
            "pass_pol": (["smb", target] + auth + ["--pass-pol"], "pass_pol"),
            "ldap_users": (["ldap", target] + auth + ["--users"], "ldap_users"),
            "ldap_user_batch": (
                ["ldap", target] + auth + ["--query", user_batch_filter, user_batch_attrs],
                "ldap_user_batch",
            ),
            "ldap_computer_batch": (
                ["ldap", target] + auth + ["--query", computer_batch_filter, computer_batch_attrs],
                "ldap_computer_batch",
            ),
        }

        def fetch_query(args):
            # Add DNS args to each query
            full_args = args + self.get_dns_args()
            return run_nxc(full_args, self.timeout, port=self.port, smb_timeout=self.smb_timeout)

        # Store results in a dict
        results = {}

        # Use proxy-aware workers if proxy mode is enabled
        workers = PROXY_CACHE_PRIME_WORKERS if is_proxy_mode() else CACHE_PRIME_WORKERS
        with ThreadPoolExecutor(max_workers=workers) as executor:
            # Submit all queries
            futures = {executor.submit(fetch_query, args): name for args, name in queries.values()}

            # Collect results
            for future in futures:
                name = futures[future]
                try:
                    results[name] = future.result()
                except FuturesTimeoutError:
                    _logger.warning(f"{name} fetch timed out")
                    results[name] = (-1, "", f"Timeout during {name} fetch")
                except subprocess.SubprocessError as e:
                    _logger.warning(f"{name} subprocess error: {e}")
                    results[name] = (-1, "", f"Subprocess error during {name}: {e}")
                except Exception as e:
                    _logger.warning(f"Unexpected error in {name}: {e}")
                    results[name] = (-1, "", f"Unexpected error during {name}: {e}")

        # Assign results to cache attributes
        self.smb_basic = results.get("smb_basic", (-1, "", "Not fetched"))
        self.rid_brute = results.get("rid_brute", (-1, "", "Not fetched"))
        self.ldap_basic = results.get("ldap_basic", (-1, "", "Not fetched"))
        self.pass_pol = results.get("pass_pol", (-1, "", "Not fetched"))
        self.ldap_users = results.get("ldap_users", (-1, "", "Not fetched"))
        self.ldap_user_batch = results.get("ldap_user_batch", (-1, "", "Not fetched"))
        self.ldap_computer_batch = results.get("ldap_computer_batch", (-1, "", "Not fetched"))

        # Determine LDAP availability from connection result
        # Check both stdout and stderr for LDAP failure indicators
        ldap_result = self.ldap_basic
        ldap_combined = (ldap_result[1] + ldap_result[2]).lower()
        ldap_failure_indicators = [
            "failed to create connection",
            "failed to connect",
            "connection refused",
            "ldap ping failed",
            "error",
        ]
        if ldap_result[0] != 0 or any(ind in ldap_combined for ind in ldap_failure_indicators):
            self.ldap_available = False

        # Parse batch query results if successful
        if self.ldap_user_batch and self.ldap_user_batch[0] == 0:
            self.user_batch_parsed = self._parse_ldap_batch(self.ldap_user_batch[1])
        if self.ldap_computer_batch and self.ldap_computer_batch[0] == 0:
            self.computer_batch_parsed = self._parse_ldap_batch(self.ldap_computer_batch[1])

        # Debug output for cached results
        for args, name in queries.values():
            if name in results:
                debug_nxc(args, results[name][1], results[name][2], f"{name} (cached)")
