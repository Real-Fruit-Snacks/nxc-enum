"""Tests for credential validation with spray control options."""

import os
import sys
import unittest
from argparse import Namespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nxc_enum.models.credential import Credential  # noqa: E402
from nxc_enum.validation.multi import _test_single_cred, validate_credentials_multi  # noqa: E402


class TestSprayControlOptions(unittest.TestCase):
    """Test spray control options for credential validation."""

    def _make_args(self, **kwargs):
        """Create args namespace with defaults."""
        defaults = {
            "continue_on_success": False,
            "jitter": None,
            "fail_limit": None,
            "ufail_limit": None,
            "gfail_limit": None,
        }
        defaults.update(kwargs)
        return Namespace(**defaults)

    def _make_cred(self, user: str, password: str = "pass"):
        """Create a test credential."""
        return Credential(user=user, password=password)

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_continue_on_success_stops_on_first_valid(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that without continue_on_success, validation stops on first valid."""
        creds = [self._make_cred(f"user{i}") for i in range(3)]
        args = self._make_args(continue_on_success=False, jitter=0)  # Force sequential

        # First two fail, third succeeds
        mock_test.side_effect = [
            (creds[0], False, False, "STATUS_LOGON_FAILURE"),
            (creds[1], True, False, ""),  # Valid - should stop here
            (creds[2], True, False, ""),  # Should not be reached
        ]

        result = validate_credentials_multi("target", creds, 30, args)

        self.assertEqual(len(result), 1)
        self.assertEqual(mock_test.call_count, 2)  # Only called twice

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_continue_on_success_finds_all_valid(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that with continue_on_success, all credentials are tested."""
        creds = [self._make_cred(f"user{i}") for i in range(3)]
        args = self._make_args(continue_on_success=True, jitter=0)  # Force sequential

        # All succeed
        mock_test.side_effect = [
            (creds[0], True, False, ""),
            (creds[1], True, False, ""),
            (creds[2], True, False, ""),
        ]

        result = validate_credentials_multi("target", creds, 30, args)

        self.assertEqual(len(result), 3)
        self.assertEqual(mock_test.call_count, 3)

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_fail_limit_stops_at_threshold(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that fail_limit stops after N total failures."""
        creds = [self._make_cred(f"user{i}") for i in range(5)]
        args = self._make_args(fail_limit=2, jitter=0)

        # All fail
        mock_test.return_value = (creds[0], False, False, "STATUS_LOGON_FAILURE")

        result = validate_credentials_multi("target", creds, 30, args)

        self.assertEqual(len(result), 0)
        self.assertEqual(mock_test.call_count, 2)  # Stopped at fail_limit

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_gfail_limit_stops_on_consecutive_failures(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that gfail_limit stops after N consecutive failures."""
        creds = [self._make_cred(f"user{i}") for i in range(5)]
        args = self._make_args(gfail_limit=3, jitter=0)

        # Success, then consecutive failures
        mock_test.side_effect = [
            (creds[0], True, False, ""),  # Success - resets counter
            (creds[1], False, False, "STATUS_LOGON_FAILURE"),  # Fail 1
            (creds[2], False, False, "STATUS_LOGON_FAILURE"),  # Fail 2
            (creds[3], False, False, "STATUS_LOGON_FAILURE"),  # Fail 3 - stops
            (creds[4], False, False, "STATUS_LOGON_FAILURE"),  # Not reached
        ]

        args.continue_on_success = True  # Don't stop on first success

        result = validate_credentials_multi("target", creds, 30, args)

        self.assertEqual(len(result), 1)
        self.assertEqual(mock_test.call_count, 4)

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_ufail_limit_skips_user_after_threshold(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that ufail_limit skips a user after N failures for that user."""
        # Multiple attempts for same user
        creds = [
            self._make_cred("user1", "pass1"),
            self._make_cred("user1", "pass2"),
            self._make_cred("user1", "pass3"),
            self._make_cred("user2", "pass1"),
        ]
        args = self._make_args(ufail_limit=2, jitter=0)

        mock_test.side_effect = [
            (creds[0], False, False, "STATUS_LOGON_FAILURE"),  # user1 fail 1
            (creds[1], False, False, "STATUS_LOGON_FAILURE"),  # user1 fail 2
            # user1 pass3 should be skipped
            (creds[3], True, False, ""),  # user2 success
        ]

        args.continue_on_success = True

        result = validate_credentials_multi("target", creds, 30, args)

        self.assertEqual(mock_test.call_count, 3)  # user1 pass3 skipped

    @patch("nxc_enum.validation.multi.time.sleep")
    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_jitter_applies_delay(
        self, mock_output, mock_status, mock_print_section, mock_test, mock_sleep
    ):
        """Test that jitter applies random delay between attempts."""
        creds = [self._make_cred(f"user{i}") for i in range(3)]
        args = self._make_args(jitter=2.0, continue_on_success=True)

        mock_test.return_value = (creds[0], False, False, "STATUS_LOGON_FAILURE")

        validate_credentials_multi("target", creds, 30, args)

        # Sleep should be called for each credential
        self.assertEqual(mock_sleep.call_count, 3)
        # Check that sleep was called with values between 0 and jitter
        for call in mock_sleep.call_args_list:
            delay = call[0][0]
            self.assertGreaterEqual(delay, 0)
            self.assertLessEqual(delay, 2.0)

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_parallel_mode_without_spray_options(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that parallel mode is used when no spray options are set."""
        creds = [self._make_cred(f"user{i}") for i in range(3)]
        args = self._make_args()  # No spray options

        mock_test.return_value = (creds[0], True, False, "")

        # This should use parallel mode (ThreadPoolExecutor)
        # We can't easily verify parallel execution, but we can verify it runs
        result = validate_credentials_multi("target", creds, 30, args)

        self.assertEqual(len(result), 3)


class TestCredentialTestFunction(unittest.TestCase):
    """Test the single credential test function."""

    @patch("nxc_enum.validation.multi.run_nxc")
    def test_successful_auth_detected(self, mock_run_nxc):
        """Test that successful authentication is detected."""
        mock_run_nxc.return_value = (0, "[+] target 10.0.0.1 admin", "")
        cred = Credential(user="admin", password="pass")

        result_cred, success, is_admin, error = _test_single_cred("target", cred, 30)

        self.assertTrue(success)
        self.assertFalse(is_admin)
        self.assertEqual(error, "")

    @patch("nxc_enum.validation.multi.run_nxc")
    def test_admin_detected(self, mock_run_nxc):
        """Test that admin access (Pwn3d!) is detected."""
        mock_run_nxc.return_value = (0, "[+] target 10.0.0.1 admin (Pwn3d!)", "")
        cred = Credential(user="admin", password="pass")

        result_cred, success, is_admin, error = _test_single_cred("target", cred, 30)

        self.assertTrue(success)
        self.assertTrue(is_admin)

    @patch("nxc_enum.validation.multi.run_nxc")
    def test_failed_auth_detected(self, mock_run_nxc):
        """Test that failed authentication is detected."""
        mock_run_nxc.return_value = (
            0,
            "[-] target 10.0.0.1 admin STATUS_LOGON_FAILURE",
            "",
        )
        cred = Credential(user="admin", password="wrong")

        result_cred, success, is_admin, error = _test_single_cred("target", cred, 30)

        self.assertFalse(success)
        self.assertFalse(is_admin)
        self.assertEqual(error, "STATUS_LOGON_FAILURE")


if __name__ == "__main__":
    unittest.main()
