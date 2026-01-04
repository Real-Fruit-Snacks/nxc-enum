"""Security-focused tests for nxc-enum.

Tests credential sanitization, file permissions, and other security features.
"""

import os
import stat
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nxc_enum.core.output import _sanitize_cmd_args, _SENSITIVE_ARGS, _REDACTED
from nxc_enum.models.credential import Credential, CredentialError
from nxc_enum.parsing.credentials import _check_file_permissions


class TestCredentialSanitization(unittest.TestCase):
    """Test credential sanitization in debug output."""

    def test_sanitize_password_arg(self):
        """Test that -p password arguments are redacted."""
        cmd_args = ["smb", "10.0.0.1", "-u", "admin", "-p", "SecretPassword123"]
        sanitized = _sanitize_cmd_args(cmd_args)

        self.assertIn("-p", sanitized)
        self.assertIn(_REDACTED, sanitized)
        self.assertNotIn("SecretPassword123", sanitized)

    def test_sanitize_hash_arg(self):
        """Test that -H hash arguments are redacted."""
        cmd_args = ["smb", "10.0.0.1", "-u", "admin", "-H", "aad3b435b51404ee:31d6cfe0d16ae931"]
        sanitized = _sanitize_cmd_args(cmd_args)

        self.assertIn("-H", sanitized)
        self.assertIn(_REDACTED, sanitized)
        self.assertNotIn("aad3b435b51404ee:31d6cfe0d16ae931", sanitized)

    def test_sanitize_long_password_flag(self):
        """Test that --password arguments are redacted."""
        cmd_args = ["smb", "10.0.0.1", "-u", "admin", "--password", "Secret"]
        sanitized = _sanitize_cmd_args(cmd_args)

        self.assertIn("--password", sanitized)
        self.assertIn(_REDACTED, sanitized)
        self.assertNotIn("Secret", sanitized)

    def test_sanitize_long_hash_flag(self):
        """Test that --hash arguments are redacted."""
        cmd_args = ["smb", "10.0.0.1", "-u", "admin", "--hash", "abc123"]
        sanitized = _sanitize_cmd_args(cmd_args)

        self.assertIn("--hash", sanitized)
        self.assertIn(_REDACTED, sanitized)
        self.assertNotIn("abc123", sanitized)

    def test_sanitize_preserves_other_args(self):
        """Test that non-sensitive arguments are preserved."""
        cmd_args = ["smb", "10.0.0.1", "-u", "admin", "-p", "pass", "-d", "CORP", "--shares"]
        sanitized = _sanitize_cmd_args(cmd_args)

        self.assertIn("smb", sanitized)
        self.assertIn("10.0.0.1", sanitized)
        self.assertIn("-u", sanitized)
        self.assertIn("admin", sanitized)
        self.assertIn("-d", sanitized)
        self.assertIn("CORP", sanitized)
        self.assertIn("--shares", sanitized)

    def test_sanitize_multiple_sensitive_args(self):
        """Test sanitization of multiple sensitive arguments."""
        cmd_args = ["-p", "pass1", "-H", "hash1", "-p", "pass2"]
        sanitized = _sanitize_cmd_args(cmd_args)

        # Count redacted values
        redacted_count = sanitized.count(_REDACTED)
        self.assertEqual(redacted_count, 3)  # 2 passwords + 1 hash

    def test_sanitize_empty_args(self):
        """Test sanitization of empty argument list."""
        cmd_args = []
        sanitized = _sanitize_cmd_args(cmd_args)
        self.assertEqual(sanitized, [])


class TestCredentialValidation(unittest.TestCase):
    """Test Credential class validation."""

    def test_auth_args_with_password(self):
        """Test auth_args() with password authentication."""
        cred = Credential(user="admin", password="secret", domain="CORP")
        args = cred.auth_args()

        self.assertEqual(args, ["-u", "admin", "-p", "secret", "-d", "CORP"])

    def test_auth_args_with_hash(self):
        """Test auth_args() with hash authentication."""
        cred = Credential(user="admin", hash="aad3b435:31d6cfe0", domain="CORP")
        args = cred.auth_args()

        self.assertEqual(args, ["-u", "admin", "-H", "aad3b435:31d6cfe0", "-d", "CORP"])

    def test_auth_args_with_empty_password(self):
        """Test auth_args() with empty password (null auth)."""
        cred = Credential(user="guest", password="")
        args = cred.auth_args()

        self.assertEqual(args, ["-u", "guest", "-p", ""])

    def test_auth_args_raises_without_auth(self):
        """Test that auth_args() raises CredentialError without password or hash."""
        cred = Credential(user="admin")

        with self.assertRaises(CredentialError) as context:
            cred.auth_args()

        self.assertIn("admin", str(context.exception))
        self.assertIn("no password or hash", str(context.exception))

    def test_has_auth_with_password(self):
        """Test has_auth() returns True with password."""
        cred = Credential(user="admin", password="secret")
        self.assertTrue(cred.has_auth())

    def test_has_auth_with_hash(self):
        """Test has_auth() returns True with hash."""
        cred = Credential(user="admin", hash="abc123")
        self.assertTrue(cred.has_auth())

    def test_has_auth_with_empty_password(self):
        """Test has_auth() returns True with empty password (null auth)."""
        cred = Credential(user="guest", password="")
        self.assertTrue(cred.has_auth())

    def test_has_auth_without_auth(self):
        """Test has_auth() returns False without password or hash."""
        cred = Credential(user="admin")
        self.assertFalse(cred.has_auth())

    def test_auth_type_password(self):
        """Test auth_type() returns 'password'."""
        cred = Credential(user="admin", password="secret")
        self.assertEqual(cred.auth_type(), 'password')

    def test_auth_type_hash(self):
        """Test auth_type() returns 'hash'."""
        cred = Credential(user="admin", hash="abc123")
        self.assertEqual(cred.auth_type(), 'hash')

    def test_auth_type_none(self):
        """Test auth_type() returns 'none'."""
        cred = Credential(user="admin")
        self.assertEqual(cred.auth_type(), 'none')

    def test_display_name_with_domain(self):
        """Test display_name() with domain."""
        cred = Credential(user="admin", password="pass", domain="CORP")
        self.assertEqual(cred.display_name(), "CORP\\admin")

    def test_display_name_without_domain(self):
        """Test display_name() without domain."""
        cred = Credential(user="admin", password="pass")
        self.assertEqual(cred.display_name(), "admin")

    def test_repr_redacts_password(self):
        """Test that __repr__() redacts password."""
        cred = Credential(user="admin", password="SuperSecretPassword123", domain="CORP")
        repr_str = repr(cred)

        self.assertIn("admin", repr_str)
        self.assertIn("CORP", repr_str)
        self.assertNotIn("SuperSecretPassword123", repr_str)
        self.assertIn("****REDACTED****", repr_str)

    def test_repr_redacts_hash(self):
        """Test that __repr__() redacts hash."""
        cred = Credential(user="admin", hash="aad3b435b51404ee:31d6cfe0d16ae931")
        repr_str = repr(cred)

        self.assertIn("admin", repr_str)
        self.assertNotIn("aad3b435b51404ee:31d6cfe0d16ae931", repr_str)
        self.assertIn("****REDACTED****", repr_str)

    def test_repr_shows_none_when_no_auth(self):
        """Test that __repr__() shows None when no password/hash."""
        cred = Credential(user="admin")
        repr_str = repr(cred)

        self.assertIn("admin", repr_str)
        self.assertIn("password=None", repr_str)
        self.assertIn("hash=None", repr_str)


class TestFilePermissions(unittest.TestCase):
    """Test file permission checking."""

    def test_check_file_permissions_secure(self):
        """Test that secure permissions don't generate warnings."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("admin:password\n")
            temp_path = f.name

        try:
            # Set secure permissions (owner only)
            os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

            # Should not print warning - capture stdout
            with patch('builtins.print') as mock_print:
                _check_file_permissions(temp_path)
                # No warning should be printed for secure permissions
                for call in mock_print.call_args_list:
                    self.assertNotIn("Warning", str(call))
        finally:
            os.unlink(temp_path)

    def test_check_file_permissions_insecure_group(self):
        """Test that group-readable permissions generate warnings."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("admin:password\n")
            temp_path = f.name

        try:
            # Set insecure permissions (group readable)
            os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)  # 0o640

            # Should print warning
            with patch('builtins.print') as mock_print:
                _check_file_permissions(temp_path)
                # Check if warning was printed
                warning_printed = any("Warning" in str(call) for call in mock_print.call_args_list)
                self.assertTrue(warning_printed)
        finally:
            os.unlink(temp_path)

    def test_check_file_permissions_insecure_world(self):
        """Test that world-readable permissions generate warnings."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("admin:password\n")
            temp_path = f.name

        try:
            # Set insecure permissions (world readable)
            os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)  # 0o604

            # Should print warning
            with patch('builtins.print') as mock_print:
                _check_file_permissions(temp_path)
                warning_printed = any("Warning" in str(call) for call in mock_print.call_args_list)
                self.assertTrue(warning_printed)
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()
