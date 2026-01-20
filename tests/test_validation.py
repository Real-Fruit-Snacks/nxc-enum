"""Tests for credential validation with spray control options."""

import os
import sys
import unittest
from argparse import Namespace
from unittest.mock import patch

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

        validate_credentials_multi("target", creds, 30, args)

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


class TestSprayControlFeedback(unittest.TestCase):
    """Test spray control feedback messages."""

    def _make_args(self, **kwargs):
        """Create args namespace with defaults."""
        defaults = {
            "continue_on_success": False,
            "jitter": None,
            "fail_limit": None,
            "ufail_limit": None,
            "gfail_limit": None,
            "port": None,
            "smb_timeout": None,
        }
        defaults.update(kwargs)
        return Namespace(**defaults)

    def _make_cred(self, user: str, password: str = "pass"):
        """Create a test credential."""
        return Credential(user=user, password=password)

    def _get_status_messages(self, mock_status):
        """Extract all status messages from mock calls."""
        return [call[0][0] for call in mock_status.call_args_list]

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_jitter_indication_shown_when_jitter_positive(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that jitter message is shown when jitter > 0."""
        creds = [self._make_cred("user1")]
        args = self._make_args(jitter=5)

        mock_test.return_value = (creds[0], True, False, "")

        validate_credentials_multi("target", creds, 30, args)

        messages = self._get_status_messages(mock_status)
        jitter_msgs = [m for m in messages if "jitter enabled" in m]
        self.assertEqual(len(jitter_msgs), 1)
        self.assertIn("0-5s delay", jitter_msgs[0])

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_jitter_indication_not_shown_when_jitter_zero(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that jitter message is NOT shown when jitter is 0."""
        creds = [self._make_cred("user1")]
        args = self._make_args(jitter=0)

        mock_test.return_value = (creds[0], True, False, "")

        validate_credentials_multi("target", creds, 30, args)

        messages = self._get_status_messages(mock_status)
        jitter_msgs = [m for m in messages if "jitter enabled" in m]
        self.assertEqual(len(jitter_msgs), 0)

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_sequential_mode_notification_shown(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that sequential mode message appears when spray controls are active."""
        creds = [self._make_cred("user1")]
        args = self._make_args(fail_limit=5)  # Any spray control triggers sequential

        mock_test.return_value = (creds[0], True, False, "")

        validate_credentials_multi("target", creds, 30, args)

        messages = self._get_status_messages(mock_status)
        seq_msgs = [m for m in messages if "sequential mode" in m]
        self.assertEqual(len(seq_msgs), 1)
        self.assertIn("Spray control: using sequential mode", seq_msgs[0])

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_sequential_mode_notification_for_all_controls(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that sequential mode shown for each spray control type."""
        creds = [self._make_cred("user1")]

        # Test with jitter
        args = self._make_args(jitter=1)
        mock_test.return_value = (creds[0], True, False, "")
        validate_credentials_multi("target", creds, 30, args)
        self.assertIn(
            "Spray control: using sequential mode",
            self._get_status_messages(mock_status),
        )

        # Test with ufail_limit
        mock_status.reset_mock()
        args = self._make_args(ufail_limit=3)
        validate_credentials_multi("target", creds, 30, args)
        self.assertIn(
            "Spray control: using sequential mode",
            self._get_status_messages(mock_status),
        )

        # Test with gfail_limit
        mock_status.reset_mock()
        args = self._make_args(gfail_limit=5)
        validate_credentials_multi("target", creds, 30, args)
        self.assertIn(
            "Spray control: using sequential mode",
            self._get_status_messages(mock_status),
        )

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_progress_counter_format(self, mock_output, mock_status, mock_print_section, mock_test):
        """Test that progress format [X/Y] is shown in sequential mode."""
        creds = [self._make_cred(f"user{i}") for i in range(3)]
        args = self._make_args(jitter=0, continue_on_success=True)

        mock_test.side_effect = [
            (creds[0], True, False, ""),
            (creds[1], False, False, "STATUS_LOGON_FAILURE"),
            (creds[2], True, False, ""),
        ]

        validate_credentials_multi("target", creds, 30, args)

        messages = self._get_status_messages(mock_status)

        # Check for progress format [1/3], [2/3], [3/3]
        progress_msgs = [m for m in messages if "[1/3]" in m or "[2/3]" in m or "[3/3]" in m]
        self.assertEqual(len(progress_msgs), 3)

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_progress_counter_increments_correctly(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that progress counter increments from 1 to total."""
        creds = [self._make_cred(f"user{i}") for i in range(5)]
        args = self._make_args(jitter=0, continue_on_success=True)

        mock_test.side_effect = [(creds[i], True, False, "") for i in range(5)]

        validate_credentials_multi("target", creds, 30, args)

        messages = self._get_status_messages(mock_status)

        # Verify each progress indicator appears
        for i in range(1, 6):
            expected_pattern = f"[{i}/5]"
            matching = [m for m in messages if expected_pattern in m]
            self.assertEqual(len(matching), 1, f"Expected {expected_pattern} to appear once")

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_skipped_credentials_summary_shown(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that ufail_limit skip count is shown at end."""
        # Multiple passwords for same user to trigger skips
        creds = [
            self._make_cred("user1", "pass1"),
            self._make_cred("user1", "pass2"),
            self._make_cred("user1", "pass3"),
            self._make_cred("user1", "pass4"),
        ]
        args = self._make_args(ufail_limit=2, continue_on_success=True)

        mock_test.side_effect = [
            (creds[0], False, False, "STATUS_LOGON_FAILURE"),  # user1 fail 1
            (creds[1], False, False, "STATUS_LOGON_FAILURE"),  # user1 fail 2
            # pass3 and pass4 should be skipped
        ]

        validate_credentials_multi("target", creds, 30, args)

        messages = self._get_status_messages(mock_status)
        skip_msgs = [m for m in messages if "Skipped" in m and "per-user fail limit" in m]
        self.assertEqual(len(skip_msgs), 1)
        self.assertIn("2 credential(s)", skip_msgs[0])

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_skipped_summary_not_shown_when_zero(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that skip summary is not shown when no credentials skipped."""
        creds = [self._make_cred(f"user{i}") for i in range(3)]  # Different users
        args = self._make_args(ufail_limit=2, continue_on_success=True)

        mock_test.side_effect = [
            (creds[0], False, False, "STATUS_LOGON_FAILURE"),
            (creds[1], False, False, "STATUS_LOGON_FAILURE"),
            (creds[2], True, False, ""),
        ]

        validate_credentials_multi("target", creds, 30, args)

        messages = self._get_status_messages(mock_status)
        skip_msgs = [m for m in messages if "Skipped" in m and "per-user fail limit" in m]
        self.assertEqual(len(skip_msgs), 0)

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_fail_limit_stop_message_includes_counts(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that fail_limit stop message includes failure counts."""
        creds = [self._make_cred(f"user{i}") for i in range(5)]
        args = self._make_args(fail_limit=3, jitter=0)

        mock_test.return_value = (creds[0], False, False, "STATUS_LOGON_FAILURE")

        validate_credentials_multi("target", creds, 30, args)

        messages = self._get_status_messages(mock_status)
        stop_msgs = [m for m in messages if "Stopped early" in m]
        self.assertEqual(len(stop_msgs), 1)
        self.assertIn("3/3 failures", stop_msgs[0])

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_gfail_limit_stop_message_includes_counts(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that gfail_limit stop message includes consecutive failure counts."""
        creds = [self._make_cred(f"user{i}") for i in range(5)]
        args = self._make_args(gfail_limit=2, jitter=0)

        mock_test.return_value = (creds[0], False, False, "STATUS_LOGON_FAILURE")

        validate_credentials_multi("target", creds, 30, args)

        messages = self._get_status_messages(mock_status)
        stop_msgs = [m for m in messages if "Stopped early" in m]
        self.assertEqual(len(stop_msgs), 1)
        self.assertIn("consecutive fail limit", stop_msgs[0])
        self.assertIn("2/2 consecutive failures", stop_msgs[0])

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_valid_cred_stop_message(self, mock_output, mock_status, mock_print_section, mock_test):
        """Test that stop message shown when valid cred found without continue_on_success."""
        creds = [self._make_cred(f"user{i}") for i in range(3)]
        args = self._make_args(jitter=0, continue_on_success=False)

        mock_test.return_value = (creds[0], True, False, "")

        validate_credentials_multi("target", creds, 30, args)

        messages = self._get_status_messages(mock_status)
        stop_msgs = [m for m in messages if "Stopped early" in m]
        self.assertEqual(len(stop_msgs), 1)
        self.assertIn("found valid credential", stop_msgs[0])

    @patch("nxc_enum.validation.multi._test_single_cred")
    @patch("nxc_enum.validation.multi.print_section")
    @patch("nxc_enum.validation.multi.status")
    @patch("nxc_enum.validation.multi.output")
    def test_parallel_mode_no_progress_counters(
        self, mock_output, mock_status, mock_print_section, mock_test
    ):
        """Test that parallel mode does not show [X/Y] progress counters."""
        creds = [self._make_cred(f"user{i}") for i in range(3)]
        args = self._make_args()  # No spray options = parallel mode

        mock_test.return_value = (creds[0], True, False, "")

        validate_credentials_multi("target", creds, 30, args)

        messages = self._get_status_messages(mock_status)
        # In parallel mode, no [X/Y] prefixes
        progress_msgs = [m for m in messages if "[1/3]" in m or "[2/3]" in m or "[3/3]" in m]
        self.assertEqual(len(progress_msgs), 0)


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
