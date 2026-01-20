"""Security-focused tests for nxc-enum.

Tests credential sanitization, file permissions, and other security features.
"""

import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nxc_enum.core.output import _REDACTED, _sanitize_cmd_args  # noqa: E402
from nxc_enum.models.credential import Credential, CredentialError  # noqa: E402
from nxc_enum.parsing.credentials import _check_file_permissions  # noqa: E402


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
        """Test that auth_args() raises CredentialError without any auth method."""
        cred = Credential(user="admin")

        with self.assertRaises(CredentialError) as context:
            cred.auth_args()

        self.assertIn("admin", str(context.exception))
        self.assertIn("no password, hash, kcache, AES key, or certificate", str(context.exception))

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
        self.assertEqual(cred.auth_type(), "password")

    def test_auth_type_hash(self):
        """Test auth_type() returns 'hash'."""
        cred = Credential(user="admin", hash="abc123")
        self.assertEqual(cred.auth_type(), "hash")

    def test_auth_type_none(self):
        """Test auth_type() returns 'none'."""
        cred = Credential(user="admin")
        self.assertEqual(cred.auth_type(), "none")

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


class TestLocalAuthentication(unittest.TestCase):
    """Test local authentication flag support."""

    def test_auth_args_with_local_auth(self):
        """Test auth_args() includes --local-auth when set."""
        cred = Credential(user="admin", password="pass", local_auth=True)
        args = cred.auth_args()

        self.assertIn("--local-auth", args)

    def test_auth_args_without_local_auth(self):
        """Test auth_args() excludes --local-auth when not set."""
        cred = Credential(user="admin", password="pass", local_auth=False)
        args = cred.auth_args()

        self.assertNotIn("--local-auth", args)

    def test_auth_args_local_auth_position(self):
        """Test that --local-auth comes at the end of args."""
        cred = Credential(user="admin", password="pass", domain="CORP", local_auth=True)
        args = cred.auth_args()

        self.assertEqual(args[-1], "--local-auth")

    def test_auth_args_local_auth_with_hash(self):
        """Test local_auth works with hash authentication."""
        cred = Credential(user="admin", hash="aad3b435:31d6cfe0", local_auth=True)
        args = cred.auth_args()

        self.assertIn("-H", args)
        self.assertIn("--local-auth", args)

    def test_local_auth_default_false(self):
        """Test that local_auth defaults to False."""
        cred = Credential(user="admin", password="pass")
        self.assertFalse(cred.local_auth)

    def test_repr_includes_local_auth(self):
        """Test that __repr__() includes local_auth field."""
        cred = Credential(user="admin", password="pass", local_auth=True)
        repr_str = repr(cred)

        self.assertIn("local_auth=True", repr_str)


class TestDelegation(unittest.TestCase):
    """Test Kerberos delegation options support."""

    def test_auth_args_with_delegate(self):
        """Test auth_args() includes --delegate when set."""
        cred = Credential(user="admin", password="pass", delegate="target_user")
        args = cred.auth_args()

        self.assertIn("--delegate", args)
        self.assertIn("target_user", args)

    def test_auth_args_delegate_value_position(self):
        """Test that target user follows --delegate flag."""
        cred = Credential(user="admin", password="pass", delegate="target_user")
        args = cred.auth_args()

        delegate_idx = args.index("--delegate")
        self.assertEqual(args[delegate_idx + 1], "target_user")

    def test_auth_args_without_delegate(self):
        """Test auth_args() excludes --delegate when not set."""
        cred = Credential(user="admin", password="pass")
        args = cred.auth_args()

        self.assertNotIn("--delegate", args)

    def test_auth_args_with_delegate_self(self):
        """Test auth_args() includes --self when delegate_self is True."""
        cred = Credential(user="admin", password="pass", delegate="target_user", delegate_self=True)
        args = cred.auth_args()

        self.assertIn("--delegate", args)
        self.assertIn("--self", args)

    def test_auth_args_self_requires_delegate(self):
        """Test that --self is not included without --delegate."""
        cred = Credential(user="admin", password="pass", delegate_self=True)
        args = cred.auth_args()

        self.assertNotIn("--self", args)

    def test_delegate_default_none(self):
        """Test that delegate defaults to None."""
        cred = Credential(user="admin", password="pass")
        self.assertIsNone(cred.delegate)

    def test_delegate_self_default_false(self):
        """Test that delegate_self defaults to False."""
        cred = Credential(user="admin", password="pass")
        self.assertFalse(cred.delegate_self)

    def test_repr_includes_delegate(self):
        """Test that __repr__() includes delegate field."""
        cred = Credential(user="admin", password="pass", delegate="target_user")
        repr_str = repr(cred)

        self.assertIn("delegate='target_user'", repr_str)

    def test_repr_includes_delegate_self(self):
        """Test that __repr__() includes delegate_self field."""
        cred = Credential(user="admin", password="pass", delegate="target", delegate_self=True)
        repr_str = repr(cred)

        self.assertIn("delegate_self=True", repr_str)


class TestKerberosAuthentication(unittest.TestCase):
    """Test Kerberos authentication options support."""

    def test_auth_args_with_kerberos_flag(self):
        """Test auth_args() includes -k when kerberos is True."""
        cred = Credential(user="admin", password="pass", kerberos=True)
        args = cred.auth_args()

        self.assertIn("-k", args)

    def test_auth_args_without_kerberos_flag(self):
        """Test auth_args() excludes -k when kerberos is False."""
        cred = Credential(user="admin", password="pass", kerberos=False)
        args = cred.auth_args()

        self.assertNotIn("-k", args)

    def test_auth_args_with_kcache(self):
        """Test auth_args() includes --use-kcache when set."""
        cred = Credential(user="admin", use_kcache=True)
        args = cred.auth_args()

        self.assertIn("--use-kcache", args)
        self.assertNotIn("-p", args)  # No password needed
        self.assertNotIn("-H", args)  # No hash needed

    def test_auth_args_with_aeskey(self):
        """Test auth_args() includes --aesKey when set."""
        cred = Credential(user="admin", aes_key="0123456789abcdef" * 4)
        args = cred.auth_args()

        self.assertIn("--aesKey", args)
        self.assertIn("0123456789abcdef" * 4, args)

    def test_auth_args_with_kdchost(self):
        """Test auth_args() includes --kdcHost when set."""
        cred = Credential(user="admin", password="pass", kdc_host="dc01.corp.local")
        args = cred.auth_args()

        self.assertIn("--kdcHost", args)
        self.assertIn("dc01.corp.local", args)

    def test_has_auth_with_kcache(self):
        """Test has_auth() returns True with kcache."""
        cred = Credential(user="admin", use_kcache=True)
        self.assertTrue(cred.has_auth())

    def test_has_auth_with_aeskey(self):
        """Test has_auth() returns True with AES key."""
        cred = Credential(user="admin", aes_key="abc123")
        self.assertTrue(cred.has_auth())

    def test_auth_type_kerberos_with_kcache(self):
        """Test auth_type() returns 'kerberos' with kcache."""
        cred = Credential(user="admin", use_kcache=True)
        self.assertEqual(cred.auth_type(), "kerberos")

    def test_auth_type_kerberos_with_aeskey(self):
        """Test auth_type() returns 'kerberos' with AES key."""
        cred = Credential(user="admin", aes_key="abc123")
        self.assertEqual(cred.auth_type(), "kerberos")

    def test_repr_redacts_aeskey(self):
        """Test that __repr__() redacts AES key."""
        cred = Credential(user="admin", aes_key="secret_aes_key_123")
        repr_str = repr(cred)

        self.assertNotIn("secret_aes_key_123", repr_str)
        self.assertIn("****REDACTED****", repr_str)

    def test_repr_includes_kerberos_fields(self):
        """Test that __repr__() includes Kerberos fields."""
        cred = Credential(user="admin", password="pass", kerberos=True, kdc_host="dc01.corp.local")
        repr_str = repr(cred)

        self.assertIn("kerberos=True", repr_str)
        self.assertIn("kdc_host='dc01.corp.local'", repr_str)

    def test_kerberos_defaults(self):
        """Test that Kerberos fields default correctly."""
        cred = Credential(user="admin", password="pass")

        self.assertFalse(cred.kerberos)
        self.assertFalse(cred.use_kcache)
        self.assertIsNone(cred.aes_key)
        self.assertIsNone(cred.kdc_host)

    def test_auth_args_kerberos_with_password(self):
        """Test Kerberos flag with password authentication."""
        cred = Credential(user="admin", password="pass", kerberos=True, kdc_host="dc01")
        args = cred.auth_args()

        self.assertIn("-u", args)
        self.assertIn("-p", args)
        self.assertIn("-k", args)
        self.assertIn("--kdcHost", args)


class TestCertificateAuthentication(unittest.TestCase):
    """Test certificate authentication options support."""

    def test_auth_args_with_pfx_cert(self):
        """Test auth_args() includes --pfx-cert when set."""
        cred = Credential(user="admin", pfx_cert="/path/to/cert.pfx")
        args = cred.auth_args()

        self.assertIn("--pfx-cert", args)
        self.assertIn("/path/to/cert.pfx", args)

    def test_auth_args_with_pfx_pass(self):
        """Test auth_args() includes --pfx-pass when set."""
        cred = Credential(user="admin", pfx_cert="/path/cert.pfx", pfx_pass="certpass")
        args = cred.auth_args()

        self.assertIn("--pfx-cert", args)
        self.assertIn("--pfx-pass", args)
        self.assertIn("certpass", args)

    def test_auth_args_with_pem_cert(self):
        """Test auth_args() includes --pem-cert when set."""
        cred = Credential(user="admin", pem_cert="/path/to/cert.pem")
        args = cred.auth_args()

        self.assertIn("--pem-cert", args)
        self.assertIn("/path/to/cert.pem", args)

    def test_auth_args_with_pem_cert_and_key(self):
        """Test auth_args() includes --pem-cert and --pem-key when set."""
        cred = Credential(user="admin", pem_cert="/path/cert.pem", pem_key="/path/key.pem")
        args = cred.auth_args()

        self.assertIn("--pem-cert", args)
        self.assertIn("--pem-key", args)
        self.assertIn("/path/cert.pem", args)
        self.assertIn("/path/key.pem", args)

    def test_has_auth_with_pfx_cert(self):
        """Test has_auth() returns True with PFX certificate."""
        cred = Credential(user="admin", pfx_cert="/path/cert.pfx")
        self.assertTrue(cred.has_auth())

    def test_has_auth_with_pem_cert(self):
        """Test has_auth() returns True with PEM certificate."""
        cred = Credential(user="admin", pem_cert="/path/cert.pem")
        self.assertTrue(cred.has_auth())

    def test_auth_type_certificate_pfx(self):
        """Test auth_type() returns 'certificate' with PFX cert."""
        cred = Credential(user="admin", pfx_cert="/path/cert.pfx")
        self.assertEqual(cred.auth_type(), "certificate")

    def test_auth_type_certificate_pem(self):
        """Test auth_type() returns 'certificate' with PEM cert."""
        cred = Credential(user="admin", pem_cert="/path/cert.pem")
        self.assertEqual(cred.auth_type(), "certificate")

    def test_repr_redacts_pfx_pass(self):
        """Test that __repr__() redacts PFX password."""
        cred = Credential(user="admin", pfx_cert="/path/cert.pfx", pfx_pass="secret_cert_pass")
        repr_str = repr(cred)

        self.assertNotIn("secret_cert_pass", repr_str)
        self.assertIn("****REDACTED****", repr_str)

    def test_repr_includes_cert_paths(self):
        """Test that __repr__() includes certificate paths."""
        cred = Credential(user="admin", pem_cert="/path/cert.pem", pem_key="/path/key.pem")
        repr_str = repr(cred)

        self.assertIn("pem_cert='/path/cert.pem'", repr_str)
        self.assertIn("pem_key='/path/key.pem'", repr_str)

    def test_certificate_defaults(self):
        """Test that certificate fields default correctly."""
        cred = Credential(user="admin", password="pass")

        self.assertIsNone(cred.pfx_cert)
        self.assertIsNone(cred.pem_cert)
        self.assertIsNone(cred.pem_key)
        self.assertIsNone(cred.pfx_pass)


class TestFilePermissions(unittest.TestCase):
    """Test file permission checking."""

    def test_check_file_permissions_secure(self):
        """Test that secure permissions don't generate warnings."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("admin:password\n")
            temp_path = f.name

        try:
            # Set secure permissions (owner only)
            os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

            # Should not print warning - capture stdout
            with patch("builtins.print") as mock_print:
                _check_file_permissions(temp_path)
                # No warning should be printed for secure permissions
                for call in mock_print.call_args_list:
                    self.assertNotIn("Warning", str(call))
        finally:
            os.unlink(temp_path)

    def test_check_file_permissions_insecure_group(self):
        """Test that group-readable permissions generate warnings."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("admin:password\n")
            temp_path = f.name

        try:
            # Set insecure permissions (group readable)
            os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)  # 0o640

            # Should print warning
            with patch("builtins.print") as mock_print:
                _check_file_permissions(temp_path)
                # Check if warning was printed
                warning_printed = any("Warning" in str(call) for call in mock_print.call_args_list)
                self.assertTrue(warning_printed)
        finally:
            os.unlink(temp_path)

    def test_check_file_permissions_insecure_world(self):
        """Test that world-readable permissions generate warnings."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("admin:password\n")
            temp_path = f.name

        try:
            # Set insecure permissions (world readable)
            os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)  # 0o604

            # Should print warning
            with patch("builtins.print") as mock_print:
                _check_file_permissions(temp_path)
                warning_printed = any("Warning" in str(call) for call in mock_print.call_args_list)
                self.assertTrue(warning_printed)
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main()
