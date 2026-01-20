"""Tests for module filter options (active users, shares filter, local groups filter)."""

import os
import sys
import unittest
from argparse import Namespace
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nxc_enum.models.cache import EnumCache  # noqa: E402


class TestActiveUsersFilter(unittest.TestCase):
    """Test --active-users filter functionality in enum_users."""

    def _make_args(self, **kwargs):
        """Create args namespace with defaults."""
        defaults = {
            "target": "10.0.0.1",
            "timeout": 30,
            "json_output": False,
            "active_users": False,
        }
        defaults.update(kwargs)
        return Namespace(**defaults)

    def _make_cache(self, target: str = "10.0.0.1"):
        """Create a mock EnumCache with required attributes."""
        cache = EnumCache()
        cache.target = target
        cache.auth_args = ["-u", "user", "-p", "pass"]
        cache.domain_info = {"hostname": "DC01"}
        return cache

    @patch("nxc_enum.enums.users.run_nxc")
    @patch("nxc_enum.enums.users.print_section")
    @patch("nxc_enum.enums.users.status")
    @patch("nxc_enum.enums.users.output")
    def test_active_users_filter_removes_disabled(
        self, mock_output, mock_status, mock_print_section, mock_run_nxc
    ):
        """Test that disabled accounts are filtered when --active-users is set."""
        from nxc_enum.enums.users import enum_users

        args = self._make_args(active_users=True)
        cache = self._make_cache()

        # Mock --users output (querydispinfo)
        users_output = """SMB  10.0.0.1  445  DC01  Administrator  Admin User
SMB  10.0.0.1  445  DC01  jsmith  John Smith
SMB  10.0.0.1  445  DC01  disableduser  Disabled Account
"""

        # Mock --rid-brute output with status info
        rid_output = """SMB  10.0.0.1  445  DC01  500 - CORP\\Administrator
SMB  10.0.0.1  445  DC01  1001 - CORP\\jsmith
SMB  10.0.0.1  445  DC01  1002 - CORP\\disableduser
INFO  10.0.0.1  disableduser - Status: Account Disabled
"""

        mock_run_nxc.return_value = (0, users_output, "")
        cache.rid_brute = (0, rid_output, "")

        enum_users(args, cache)

        # Check that filtered status message was output
        filter_calls = [
            call
            for call in mock_status.call_args_list
            if "Filtered" in str(call) and "disabled" in str(call)
        ]
        self.assertEqual(len(filter_calls), 1)

        # Check that disableduser was filtered out (user count should be 2)
        self.assertEqual(cache.user_count, 2)

    @patch("nxc_enum.enums.users.run_nxc")
    @patch("nxc_enum.enums.users.print_section")
    @patch("nxc_enum.enums.users.status")
    @patch("nxc_enum.enums.users.output")
    def test_no_filter_shows_all_users(
        self, mock_output, mock_status, mock_print_section, mock_run_nxc
    ):
        """Test that all users are shown when --active-users is not set."""
        from nxc_enum.enums.users import enum_users

        args = self._make_args(active_users=False)
        cache = self._make_cache()

        # Mock --users output (querydispinfo)
        users_output = """SMB  10.0.0.1  445  DC01  Administrator  Admin User
SMB  10.0.0.1  445  DC01  jsmith  John Smith
SMB  10.0.0.1  445  DC01  disableduser  Disabled Account
"""

        # Mock --rid-brute output with status info
        rid_output = """SMB  10.0.0.1  445  DC01  500 - CORP\\Administrator
SMB  10.0.0.1  445  DC01  1001 - CORP\\jsmith
SMB  10.0.0.1  445  DC01  1002 - CORP\\disableduser
INFO  10.0.0.1  disableduser - Status: Account Disabled
"""

        mock_run_nxc.return_value = (0, users_output, "")
        cache.rid_brute = (0, rid_output, "")

        enum_users(args, cache)

        # Check that no filter message was output
        filter_calls = [
            call
            for call in mock_status.call_args_list
            if "Filtered" in str(call) and "disabled" in str(call)
        ]
        self.assertEqual(len(filter_calls), 0)

        # All 3 users should be present
        self.assertEqual(cache.user_count, 3)

    @patch("nxc_enum.enums.users.run_nxc")
    @patch("nxc_enum.enums.users.print_section")
    @patch("nxc_enum.enums.users.status")
    @patch("nxc_enum.enums.users.output")
    def test_active_users_with_no_disabled(
        self, mock_output, mock_status, mock_print_section, mock_run_nxc
    ):
        """Test --active-users when there are no disabled accounts."""
        from nxc_enum.enums.users import enum_users

        args = self._make_args(active_users=True)
        cache = self._make_cache()

        # Mock --users output (querydispinfo) - no disabled users
        users_output = """SMB  10.0.0.1  445  DC01  Administrator  Admin User
SMB  10.0.0.1  445  DC01  jsmith  John Smith
"""

        # Mock --rid-brute output - no disabled status
        rid_output = """SMB  10.0.0.1  445  DC01  500 - CORP\\Administrator
SMB  10.0.0.1  445  DC01  1001 - CORP\\jsmith
"""

        mock_run_nxc.return_value = (0, users_output, "")
        cache.rid_brute = (0, rid_output, "")

        enum_users(args, cache)

        # No filter message should be output (nothing to filter)
        filter_calls = [
            call
            for call in mock_status.call_args_list
            if "Filtered" in str(call) and "disabled" in str(call)
        ]
        self.assertEqual(len(filter_calls), 0)

        # Both users should be present
        self.assertEqual(cache.user_count, 2)


class TestSharesFilter(unittest.TestCase):
    """Test --shares-filter functionality in enum_shares."""

    def _make_args(self, **kwargs):
        """Create args namespace with defaults."""
        defaults = {
            "target": "10.0.0.1",
            "timeout": 30,
            "json_output": False,
            "shares_filter": None,
            "user": None,  # Required by enum_shares for smbclient command generation
        }
        defaults.update(kwargs)
        return Namespace(**defaults)

    def _make_cache(self, target: str = "10.0.0.1"):
        """Create a mock EnumCache with required attributes."""
        cache = EnumCache()
        cache.target = target
        cache.auth_args = ["-u", "user", "-p", "pass"]
        return cache

    @patch("nxc_enum.enums.shares.run_nxc")
    @patch("nxc_enum.enums.shares.print_section")
    @patch("nxc_enum.enums.shares.status")
    @patch("nxc_enum.enums.shares.output")
    def test_read_filter_only_shows_readable(
        self, mock_output, mock_status, mock_print_section, mock_run_nxc
    ):
        """Test --shares-filter READ only shows shares with READ access."""
        from nxc_enum.enums.shares import enum_shares

        args = self._make_args(shares_filter="READ")
        cache = self._make_cache()

        # Mock --shares output
        shares_output = """SMB  10.0.0.1  445  DC01  [*] Enumerated shares
SMB  10.0.0.1  445  DC01  Share           Permissions     Remark
SMB  10.0.0.1  445  DC01  -----           -----------     ------
SMB  10.0.0.1  445  DC01  ADMIN$          NO ACCESS       Remote Admin
SMB  10.0.0.1  445  DC01  C$              NO ACCESS       Default share
SMB  10.0.0.1  445  DC01  IPC$            READ            Remote IPC
SMB  10.0.0.1  445  DC01  NETLOGON        READ            Logon scripts
SMB  10.0.0.1  445  DC01  SYSVOL          READ            Group Policy
SMB  10.0.0.1  445  DC01  Finance         READ,WRITE      Finance data
"""

        mock_run_nxc.return_value = (0, shares_output, "")

        enum_shares(args, cache)

        # Check for filter status message
        filter_calls = [
            call
            for call in mock_status.call_args_list
            if "Filtered" in str(call) and "READ" in str(call)
        ]
        self.assertEqual(len(filter_calls), 1)

        # Check that accessible section was output (READ filter includes all readable shares)
        accessible_calls = [
            call for call in mock_output.call_args_list if "ACCESSIBLE" in str(call)
        ]
        self.assertTrue(len(accessible_calls) > 0)

        # NO ACCESS section should not be output when filtering
        no_access_calls = [call for call in mock_output.call_args_list if "NO ACCESS" in str(call)]
        self.assertEqual(len(no_access_calls), 0)

    @patch("nxc_enum.enums.shares.run_nxc")
    @patch("nxc_enum.enums.shares.print_section")
    @patch("nxc_enum.enums.shares.status")
    @patch("nxc_enum.enums.shares.output")
    def test_write_filter_only_shows_writable(
        self, mock_output, mock_status, mock_print_section, mock_run_nxc
    ):
        """Test --shares-filter WRITE only shows shares with WRITE access."""
        from nxc_enum.enums.shares import enum_shares

        args = self._make_args(shares_filter="WRITE")
        cache = self._make_cache()

        # Mock --shares output
        shares_output = """SMB  10.0.0.1  445  DC01  [*] Enumerated shares
SMB  10.0.0.1  445  DC01  Share           Permissions     Remark
SMB  10.0.0.1  445  DC01  -----           -----------     ------
SMB  10.0.0.1  445  DC01  ADMIN$          NO ACCESS       Remote Admin
SMB  10.0.0.1  445  DC01  C$              NO ACCESS       Default share
SMB  10.0.0.1  445  DC01  IPC$            READ            Remote IPC
SMB  10.0.0.1  445  DC01  NETLOGON        READ            Logon scripts
SMB  10.0.0.1  445  DC01  SYSVOL          READ            Group Policy
SMB  10.0.0.1  445  DC01  Finance         READ,WRITE      Finance data
SMB  10.0.0.1  445  DC01  Upload          WRITE           Upload folder
"""

        mock_run_nxc.return_value = (0, shares_output, "")

        enum_shares(args, cache)

        # Check for filter status message
        filter_calls = [
            call
            for call in mock_status.call_args_list
            if "Filtered" in str(call) and "WRITE" in str(call)
        ]
        self.assertEqual(len(filter_calls), 1)

    @patch("nxc_enum.enums.shares.run_nxc")
    @patch("nxc_enum.enums.shares.print_section")
    @patch("nxc_enum.enums.shares.status")
    @patch("nxc_enum.enums.shares.output")
    def test_no_filter_shows_all_shares(
        self, mock_output, mock_status, mock_print_section, mock_run_nxc
    ):
        """Test no filter shows all shares including NO ACCESS."""
        from nxc_enum.enums.shares import enum_shares

        args = self._make_args(shares_filter=None)
        cache = self._make_cache()

        # Mock --shares output
        shares_output = """SMB  10.0.0.1  445  DC01  [*] Enumerated shares
SMB  10.0.0.1  445  DC01  Share           Permissions     Remark
SMB  10.0.0.1  445  DC01  -----           -----------     ------
SMB  10.0.0.1  445  DC01  ADMIN$          NO ACCESS       Remote Admin
SMB  10.0.0.1  445  DC01  C$              NO ACCESS       Default share
SMB  10.0.0.1  445  DC01  IPC$            READ            Remote IPC
SMB  10.0.0.1  445  DC01  NETLOGON        READ            Logon scripts
"""

        mock_run_nxc.return_value = (0, shares_output, "")

        enum_shares(args, cache)

        # Check that no filter message was output
        filter_calls = [call for call in mock_status.call_args_list if "Filtered" in str(call)]
        self.assertEqual(len(filter_calls), 0)

        # Both ACCESSIBLE and NO ACCESS sections should be present
        accessible_calls = [
            call for call in mock_output.call_args_list if "ACCESSIBLE" in str(call)
        ]
        no_access_calls = [
            call
            for call in mock_output.call_args_list
            if "NO ACCESS" in str(call) and "(" in str(call)
        ]
        self.assertTrue(len(accessible_calls) > 0)
        self.assertTrue(len(no_access_calls) > 0)

    @patch("nxc_enum.enums.shares.run_nxc")
    @patch("nxc_enum.enums.shares.print_section")
    @patch("nxc_enum.enums.shares.status")
    @patch("nxc_enum.enums.shares.output")
    def test_read_filter_includes_read_write_shares(
        self, mock_output, mock_status, mock_print_section, mock_run_nxc
    ):
        """Test READ filter includes shares with READ,WRITE (not just READ-only)."""
        from nxc_enum.enums.shares import enum_shares

        args = self._make_args(shares_filter="READ")
        cache = self._make_cache()

        # Mock --shares output with only one READ,WRITE share
        shares_output = """SMB  10.0.0.1  445  DC01  [*] Enumerated shares
SMB  10.0.0.1  445  DC01  Share           Permissions     Remark
SMB  10.0.0.1  445  DC01  -----           -----------     ------
SMB  10.0.0.1  445  DC01  Finance         READ,WRITE      Finance data
"""

        mock_run_nxc.return_value = (0, shares_output, "")

        enum_shares(args, cache)

        # The READ filter should match READ,WRITE shares (since they include READ)
        # Check that accessible section was output
        accessible_calls = [
            call for call in mock_output.call_args_list if "ACCESSIBLE" in str(call)
        ]
        self.assertTrue(len(accessible_calls) > 0)


class TestLocalGroupsFilter(unittest.TestCase):
    """Test --local-groups-filter functionality in enum_local_groups."""

    def _make_args(self, **kwargs):
        """Create args namespace with defaults."""
        defaults = {
            "target": "10.0.0.1",
            "timeout": 30,
            "json_output": False,
            "local_groups_filter": None,
        }
        defaults.update(kwargs)
        return Namespace(**defaults)

    def _make_cache(self, target: str = "10.0.0.1"):
        """Create a mock EnumCache with required attributes."""
        cache = EnumCache()
        cache.target = target
        cache.auth_args = ["-u", "admin", "-p", "pass"]
        return cache

    @patch("nxc_enum.enums.local_groups.run_nxc")
    @patch("nxc_enum.enums.local_groups.print_section")
    @patch("nxc_enum.enums.local_groups.status")
    @patch("nxc_enum.enums.local_groups.output")
    def test_filter_matches_group_case_insensitive(
        self, mock_output, mock_status, mock_print_section, mock_run_nxc
    ):
        """Test filter matches group name case-insensitively."""
        from nxc_enum.enums.local_groups import enum_local_groups

        # Test lowercase filter matching uppercase group
        args = self._make_args(local_groups_filter="administrators")
        cache = self._make_cache()

        # Mock --local-groups output
        groups_output = """SMB  10.0.0.1  445  DC01  [+] Enumerated local groups
SMB  10.0.0.1  445  DC01  544 - Administrators
SMB  10.0.0.1  445  DC01  545 - Users
SMB  10.0.0.1  445  DC01  546 - Guests
SMB  10.0.0.1  445  DC01  549 - Server Operators
"""

        mock_run_nxc.return_value = (0, groups_output, "")

        enum_local_groups(args, cache, is_admin=True)

        # Check for successful match message
        success_calls = [
            call
            for call in mock_status.call_args_list
            if "Found" in str(call) and "matching" in str(call)
        ]
        self.assertEqual(len(success_calls), 1)

        # Check that "FILTERED LOCAL GROUPS" header was output
        filtered_calls = [call for call in mock_output.call_args_list if "FILTERED" in str(call)]
        self.assertTrue(len(filtered_calls) > 0)

    @patch("nxc_enum.enums.local_groups.run_nxc")
    @patch("nxc_enum.enums.local_groups.print_section")
    @patch("nxc_enum.enums.local_groups.status")
    @patch("nxc_enum.enums.local_groups.output")
    def test_filter_with_nonexistent_group(
        self, mock_output, mock_status, mock_print_section, mock_run_nxc
    ):
        """Test filter with non-existent group shows error."""
        from nxc_enum.enums.local_groups import enum_local_groups

        args = self._make_args(local_groups_filter="NonExistentGroup")
        cache = self._make_cache()

        # Mock --local-groups output
        groups_output = """SMB  10.0.0.1  445  DC01  [+] Enumerated local groups
SMB  10.0.0.1  445  DC01  544 - Administrators
SMB  10.0.0.1  445  DC01  545 - Users
SMB  10.0.0.1  445  DC01  546 - Guests
"""

        mock_run_nxc.return_value = (0, groups_output, "")

        enum_local_groups(args, cache, is_admin=True)

        # Check for "not found" error message
        error_calls = [
            call
            for call in mock_status.call_args_list
            if "not found" in str(call) and "NonExistentGroup" in str(call)
        ]
        self.assertEqual(len(error_calls), 1)

    @patch("nxc_enum.enums.local_groups.run_nxc")
    @patch("nxc_enum.enums.local_groups.print_section")
    @patch("nxc_enum.enums.local_groups.status")
    @patch("nxc_enum.enums.local_groups.output")
    def test_no_filter_shows_all_groups(
        self, mock_output, mock_status, mock_print_section, mock_run_nxc
    ):
        """Test no filter shows all groups."""
        from nxc_enum.enums.local_groups import enum_local_groups

        args = self._make_args(local_groups_filter=None)
        cache = self._make_cache()

        # Mock --local-groups output
        groups_output = """SMB  10.0.0.1  445  DC01  [+] Enumerated local groups
SMB  10.0.0.1  445  DC01  544 - Administrators
SMB  10.0.0.1  445  DC01  545 - Users
SMB  10.0.0.1  445  DC01  546 - Guests
SMB  10.0.0.1  445  DC01  549 - Server Operators
"""

        mock_run_nxc.return_value = (0, groups_output, "")

        enum_local_groups(args, cache, is_admin=True)

        # Check for success message with total count
        success_calls = [
            call
            for call in mock_status.call_args_list
            if "Found" in str(call) and "local group" in str(call)
        ]
        self.assertEqual(len(success_calls), 1)

        # Check that "ALL LOCAL GROUPS" header was output (not "FILTERED")
        all_groups_calls = [
            call for call in mock_output.call_args_list if "ALL LOCAL GROUPS" in str(call)
        ]
        self.assertTrue(len(all_groups_calls) > 0)

        # 4 groups should be stored in cache
        self.assertEqual(len(cache.local_groups), 4)

    @patch("nxc_enum.enums.local_groups.run_nxc")
    @patch("nxc_enum.enums.local_groups.print_section")
    @patch("nxc_enum.enums.local_groups.status")
    @patch("nxc_enum.enums.local_groups.output")
    def test_filter_stores_all_groups_in_cache(
        self, mock_output, mock_status, mock_print_section, mock_run_nxc
    ):
        """Test filter still stores all groups in cache (before filtering)."""
        from nxc_enum.enums.local_groups import enum_local_groups

        args = self._make_args(local_groups_filter="Administrators")
        cache = self._make_cache()

        # Mock --local-groups output
        groups_output = """SMB  10.0.0.1  445  DC01  [+] Enumerated local groups
SMB  10.0.0.1  445  DC01  544 - Administrators
SMB  10.0.0.1  445  DC01  545 - Users
SMB  10.0.0.1  445  DC01  546 - Guests
"""

        mock_run_nxc.return_value = (0, groups_output, "")

        enum_local_groups(args, cache, is_admin=True)

        # All 3 groups should be stored in cache (filter only affects display)
        self.assertEqual(len(cache.local_groups), 3)

    @patch("nxc_enum.enums.local_groups.run_nxc")
    @patch("nxc_enum.enums.local_groups.print_section")
    @patch("nxc_enum.enums.local_groups.status")
    @patch("nxc_enum.enums.local_groups.output")
    def test_requires_admin_privileges(
        self, mock_output, mock_status, mock_print_section, mock_run_nxc
    ):
        """Test that local groups enumeration requires admin privileges."""
        from nxc_enum.enums.local_groups import enum_local_groups

        args = self._make_args()
        cache = self._make_cache()

        enum_local_groups(args, cache, is_admin=False)

        # Check that skipping message was output
        skip_calls = [
            call
            for call in mock_status.call_args_list
            if "requires local admin" in str(call) or "Skipping" in str(call)
        ]
        self.assertEqual(len(skip_calls), 1)

        # run_nxc should not be called
        mock_run_nxc.assert_not_called()


class TestFilteredOutputIntegration(unittest.TestCase):
    """Integration tests for filter output consistency."""

    def test_json_output_with_share_filter(self):
        """Test JSON output includes filter information when shares filter is applied."""
        from nxc_enum.core.output import JSON_DATA
        from nxc_enum.enums.shares import enum_shares

        args = Namespace(
            target="10.0.0.1",
            timeout=30,
            json_output=True,
            shares_filter="READ",
        )
        cache = EnumCache()
        cache.target = "10.0.0.1"
        cache.auth_args = ["-u", "user", "-p", "pass"]

        # Clear any previous JSON data
        JSON_DATA.clear()

        with (
            patch("nxc_enum.enums.shares.run_nxc") as mock_run_nxc,
            patch("nxc_enum.enums.shares.print_section"),
            patch("nxc_enum.enums.shares.status"),
            patch("nxc_enum.enums.shares.output"),
        ):

            shares_output = """SMB  10.0.0.1  445  DC01  [*] Enumerated shares
SMB  10.0.0.1  445  DC01  IPC$  READ  Remote IPC
SMB  10.0.0.1  445  DC01  ADMIN$  NO ACCESS  Remote Admin
"""
            mock_run_nxc.return_value = (0, shares_output, "")

            enum_shares(args, cache)

        # Check that shares were added to JSON_DATA
        self.assertIn("shares", JSON_DATA)
        # All shares should be in JSON (filter only affects display)
        self.assertEqual(len(JSON_DATA["shares"]), 2)

    def test_json_output_with_local_groups_filter(self):
        """Test JSON output includes filter information when local groups filter is applied."""
        from nxc_enum.core.output import JSON_DATA
        from nxc_enum.enums.local_groups import enum_local_groups

        args = Namespace(
            target="10.0.0.1",
            timeout=30,
            json_output=True,
            local_groups_filter="Administrators",
        )
        cache = EnumCache()
        cache.target = "10.0.0.1"
        cache.auth_args = ["-u", "admin", "-p", "pass"]

        # Clear any previous JSON data
        JSON_DATA.clear()

        with (
            patch("nxc_enum.enums.local_groups.run_nxc") as mock_run_nxc,
            patch("nxc_enum.enums.local_groups.print_section"),
            patch("nxc_enum.enums.local_groups.status"),
            patch("nxc_enum.enums.local_groups.output"),
        ):

            groups_output = """SMB  10.0.0.1  445  DC01  [+] Enumerated local groups
SMB  10.0.0.1  445  DC01  544 - Administrators
SMB  10.0.0.1  445  DC01  545 - Users
"""
            mock_run_nxc.return_value = (0, groups_output, "")

            enum_local_groups(args, cache, is_admin=True)

        # Check that local groups were added to JSON_DATA with filter info
        self.assertIn("local_groups", JSON_DATA)
        self.assertEqual(JSON_DATA["local_groups"]["filter"], "Administrators")
        self.assertEqual(JSON_DATA["local_groups"]["total_groups"], 2)
        self.assertEqual(len(JSON_DATA["local_groups"]["filtered_groups"]), 1)


class TestParseInfoLines(unittest.TestCase):
    """Test parse_info_lines function for extracting user status from verbose output."""

    def test_parse_disabled_status(self):
        """Test parsing disabled account status from INFO lines."""
        from nxc_enum.enums.users import parse_info_lines

        users = {
            "disableduser": {"name": "(null)", "description": "(null)"},
            "activeuser": {"name": "(null)", "description": "(null)"},
        }

        stdout = """INFO  10.0.0.1  disableduser - Status: Account Disabled
INFO  10.0.0.1  activeuser - Status: Active
"""

        notable = parse_info_lines(stdout, users)

        self.assertIn("disableduser", notable["disabled"])
        self.assertNotIn("activeuser", notable["disabled"])

    def test_parse_locked_status(self):
        """Test parsing locked account status from INFO lines."""
        from nxc_enum.enums.users import parse_info_lines

        users = {
            "lockeduser": {"name": "(null)", "description": "(null)"},
        }

        stdout = """INFO  10.0.0.1  lockeduser - Status: Account Locked
"""

        notable = parse_info_lines(stdout, users)

        self.assertIn("lockeduser", notable["locked"])

    def test_parse_pwd_never_expires(self):
        """Test parsing password never expires status from INFO lines."""
        from nxc_enum.enums.users import parse_info_lines

        users = {
            "svc_account": {"name": "(null)", "description": "(null)"},
        }

        stdout = """INFO  10.0.0.1  svc_account - Status: Password never expires
"""

        notable = parse_info_lines(stdout, users)

        self.assertIn("svc_account", notable["pwd_never_expires"])


class TestVerboseShareInfo(unittest.TestCase):
    """Test parse_verbose_share_info function for extracting share metadata."""

    def test_parse_share_check(self):
        """Test parsing share check lines."""
        from nxc_enum.enums.shares import parse_verbose_share_info

        stdout = """Checking share: ADMIN$
Status: Access denied
Checking share: NETLOGON
Status: OK
"""

        verbose = parse_verbose_share_info(stdout)

        # Should have two permission checks
        self.assertEqual(len(verbose["permission_checks"]), 2)

    def test_parse_access_denied(self):
        """Test parsing access denied errors."""
        from nxc_enum.enums.shares import parse_verbose_share_info

        stdout = """Checking share: ADMIN$
NT_STATUS_ACCESS_DENIED: Access denied to share
"""

        verbose = parse_verbose_share_info(stdout)

        # Should have access error
        self.assertTrue(len(verbose["access_errors"]) > 0)


if __name__ == "__main__":
    unittest.main()
