"""Enumeration cache for avoiding redundant NXC calls."""

import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Optional

from ..core.runner import run_nxc
from ..core.output import debug_nxc
from ..core.constants import CACHE_PRIME_WORKERS, DEFAULT_COMMAND_TIMEOUT

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

        # Configuration
        self.auth_args: Optional[list] = None
        self.target: Optional[str] = None
        self.timeout: int = DEFAULT_COMMAND_TIMEOUT
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
        self.privileged_users = []
        self.kerberoastable = []
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

    def add_next_step(self, finding: str, command: str, description: str = "", priority: str = "medium"):
        """Add a recommended next step based on a finding.

        Args:
            finding: What was discovered (e.g., "Kerberoastable account found")
            command: The command to run (e.g., "nxc ldap ... --kerberoasting")
            description: Optional explanation of what the command does
            priority: "high", "medium", or "low" for sorting
        """
        self.next_steps.append({
            'finding': finding,
            'command': command,
            'description': description,
            'priority': priority
        })

    def get_smb_basic(self, target: str, auth: list) -> tuple[int, str, str]:
        """Get cached or fresh SMB basic info."""
        if self.smb_basic is None:
            cmd_args = ["smb", target] + auth
            self.smb_basic = run_nxc(cmd_args, self.timeout)
            debug_nxc(cmd_args, self.smb_basic[1], self.smb_basic[2], "SMB Basic")
        return self.smb_basic

    def get_rid_brute(self, target: str, auth: list) -> tuple[int, str, str]:
        """Get cached or fresh RID brute results."""
        if self.rid_brute is None:
            cmd_args = ["smb", target] + auth + ["--rid-brute"]
            self.rid_brute = run_nxc(cmd_args, self.timeout)
            debug_nxc(cmd_args, self.rid_brute[1], self.rid_brute[2], "RID Brute")
        return self.rid_brute

    def get_ldap_basic(self, target: str, auth: list) -> tuple[int, str, str]:
        """Get cached or fresh LDAP basic info."""
        if self.ldap_basic is None:
            cmd_args = ["ldap", target] + auth
            self.ldap_basic = run_nxc(cmd_args, self.timeout)
            debug_nxc(cmd_args, self.ldap_basic[1], self.ldap_basic[2], "LDAP Basic")
        return self.ldap_basic

    def prime_caches(self, target: str, auth: list) -> None:
        """Pre-populate all caches in parallel for maximum performance.

        Runs SMB, RID brute, and LDAP queries concurrently using a thread pool.
        Errors are logged but don't stop execution - the cache stores error
        information for later inspection.

        Args:
            target: Target IP or hostname
            auth: Authentication arguments for nxc
        """
        smb_args = ["smb", target] + auth
        rid_args = ["smb", target] + auth + ["--rid-brute"]
        ldap_args = ["ldap", target] + auth

        def fetch_smb():
            return run_nxc(smb_args, self.timeout)

        def fetch_rid():
            return run_nxc(rid_args, self.timeout)

        def fetch_ldap():
            return run_nxc(ldap_args, self.timeout)

        with ThreadPoolExecutor(max_workers=CACHE_PRIME_WORKERS) as executor:
            smb_future = executor.submit(fetch_smb)
            rid_future = executor.submit(fetch_rid)
            ldap_future = executor.submit(fetch_ldap)

            # Handle SMB result with specific exception types
            try:
                self.smb_basic = smb_future.result()
            except FuturesTimeoutError:
                _logger.warning("SMB fetch timed out")
                self.smb_basic = (-1, "", "Timeout during SMB fetch")
            except subprocess.SubprocessError as e:
                _logger.warning(f"SMB subprocess error: {e}")
                self.smb_basic = (-1, "", f"Subprocess error during SMB fetch: {e}")
            except Exception as e:
                _logger.warning(f"Unexpected error in SMB fetch: {e}")
                self.smb_basic = (-1, "", f"Unexpected error during SMB fetch: {e}")

            # Handle RID brute result
            try:
                self.rid_brute = rid_future.result()
            except FuturesTimeoutError:
                _logger.warning("RID brute fetch timed out")
                self.rid_brute = (-1, "", "Timeout during RID brute")
            except subprocess.SubprocessError as e:
                _logger.warning(f"RID brute subprocess error: {e}")
                self.rid_brute = (-1, "", f"Subprocess error during RID brute: {e}")
            except Exception as e:
                _logger.warning(f"Unexpected error in RID brute: {e}")
                self.rid_brute = (-1, "", f"Unexpected error during RID brute: {e}")

            # Handle LDAP result
            try:
                self.ldap_basic = ldap_future.result()
            except FuturesTimeoutError:
                _logger.warning("LDAP fetch timed out")
                self.ldap_basic = (-1, "", "Timeout during LDAP fetch")
            except subprocess.SubprocessError as e:
                _logger.warning(f"LDAP subprocess error: {e}")
                self.ldap_basic = (-1, "", f"Subprocess error during LDAP fetch: {e}")
            except Exception as e:
                _logger.warning(f"Unexpected error in LDAP fetch: {e}")
                self.ldap_basic = (-1, "", f"Unexpected error during LDAP fetch: {e}")

        # Debug output for all cached results
        debug_nxc(smb_args, self.smb_basic[1], self.smb_basic[2], "SMB Basic (cached)")
        debug_nxc(rid_args, self.rid_brute[1], self.rid_brute[2], "RID Brute (cached)")
        debug_nxc(ldap_args, self.ldap_basic[1], self.ldap_basic[2], "LDAP Basic (cached)")
