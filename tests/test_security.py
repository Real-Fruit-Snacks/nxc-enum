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


class TestAnonymousSessions(unittest.TestCase):
    """Test anonymous/null/guest session detection."""

    def test_is_anonymous_null_session(self):
        """Test is_anonymous for null session (empty user and password)."""
        cred = Credential(user="", password="")
        self.assertTrue(cred.is_anonymous)

    def test_is_anonymous_guest_session(self):
        """Test is_anonymous for guest session."""
        cred = Credential(user="Guest", password="")
        self.assertTrue(cred.is_anonymous)

    def test_is_anonymous_guest_case_insensitive(self):
        """Test is_anonymous for guest session is case insensitive."""
        cred = Credential(user="guest", password="")
        self.assertTrue(cred.is_anonymous)
        cred = Credential(user="GUEST", password="")
        self.assertTrue(cred.is_anonymous)

    def test_is_anonymous_false_for_regular_cred(self):
        """Test is_anonymous is False for regular credentials."""
        cred = Credential(user="admin", password="secret")
        self.assertFalse(cred.is_anonymous)

    def test_is_anonymous_false_for_guest_with_password(self):
        """Test is_anonymous is False for Guest user with password."""
        cred = Credential(user="Guest", password="somepassword")
        self.assertFalse(cred.is_anonymous)

    def test_auth_type_null_session(self):
        """Test auth_type() returns 'null' for null session."""
        cred = Credential(user="", password="")
        self.assertEqual(cred.auth_type(), "null")

    def test_auth_type_guest_session(self):
        """Test auth_type() returns 'guest' for guest session."""
        cred = Credential(user="Guest", password="")
        self.assertEqual(cred.auth_type(), "guest")

    def test_display_name_null_session(self):
        """Test display_name() returns 'NULL SESSION' for null session."""
        cred = Credential(user="", password="")
        self.assertEqual(cred.display_name(), "NULL SESSION")

    def test_display_name_guest_session(self):
        """Test display_name() returns 'Guest' for guest session."""
        cred = Credential(user="Guest", password="")
        self.assertEqual(cred.display_name(), "Guest")


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


class TestExternalToolAuth(unittest.TestCase):
    """Test get_external_tool_auth() function for external tool authentication string generation."""

    def _make_args(
        self,
        user=None,
        password=None,
        hash_val=None,
        domain=None,
        use_kcache=False,
        aes_key=None,
        kerberos=False,
        pfx_cert=None,
        pem_cert=None,
    ):
        """Create mock args object for testing."""

        class MockArgs:
            pass

        args = MockArgs()
        args.user = user
        args.password = password
        args.hash = hash_val
        args.domain = domain
        args.use_kcache = use_kcache
        args.aes_key = aes_key
        args.kerberos = kerberos
        args.pfx_cert = pfx_cert
        args.pem_cert = pem_cert
        return args

    def _make_cache(self, domain_info=None, primary_credential=None):
        """Create mock cache object for testing."""

        class MockCache:
            pass

        cache = MockCache()
        cache.domain_info = domain_info or {}
        cache.primary_credential = primary_credential
        return cache

    # =====================================================================
    # Password Authentication Tests
    # =====================================================================

    def test_password_auth_impacket(self):
        """Test password auth string for impacket tools."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", password="P@ssw0rd!", domain="CORP.LOCAL")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="impacket")

        self.assertEqual(result["auth_type"], "password")
        self.assertEqual(result["credential_format"], "'CORP.LOCAL/admin:P@ssw0rd!'")
        self.assertEqual(result["auth_string"], "")  # No extra flags for password
        self.assertFalse(result["is_kerberos"])

    def test_password_auth_certipy(self):
        """Test password auth string for certipy."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", password="Secret123", domain="corp.local")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="certipy")

        self.assertEqual(result["auth_type"], "password")
        self.assertIn("-u 'admin@corp.local'", result["auth_string"])
        self.assertIn("-p 'Secret123'", result["auth_string"])
        self.assertFalse(result["is_kerberos"])

    def test_password_auth_nxc(self):
        """Test password auth string for nxc (NetExec)."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", password="secret", domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="nxc")

        self.assertEqual(result["auth_type"], "password")
        self.assertIn("-u 'admin'", result["auth_string"])
        self.assertIn("-p 'secret'", result["auth_string"])
        self.assertIn("-d 'CORP'", result["auth_string"])
        self.assertFalse(result["is_kerberos"])

    def test_password_auth_adidnsdump(self):
        """Test password auth string for adidnsdump."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", password="pass123", domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="adidnsdump")

        self.assertEqual(result["auth_type"], "password")
        self.assertIn("-u 'CORP\\\\admin'", result["auth_string"])
        self.assertIn("-p 'pass123'", result["auth_string"])
        self.assertFalse(result["is_kerberos"])

    def test_password_auth_rusthound(self):
        """Test password auth string for rusthound."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", password="hunter2", domain="corp.local")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="rusthound")

        self.assertEqual(result["auth_type"], "password")
        self.assertIn("-u 'admin@corp.local'", result["auth_string"])
        self.assertIn("-p 'hunter2'", result["auth_string"])
        self.assertFalse(result["is_kerberos"])

    def test_password_auth_empty_password_is_no_auth(self):
        """Test that empty password is treated as no auth (by function design).

        Note: The function explicitly converts empty string passwords to None,
        treating them as "no authentication". This is by design - for null session
        auth, use the actual Credential class which handles empty passwords differently.
        """
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="guest", password="", domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="nxc")

        # Empty password is converted to None and treated as no auth
        self.assertEqual(result["auth_type"], "none")
        self.assertIn("<pass>", result["auth_string"])

    # =====================================================================
    # Hash Authentication Tests
    # =====================================================================

    def test_hash_auth_impacket(self):
        """Test hash auth string for impacket tools."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(
            user="admin", hash_val="aad3b435b51404ee:31d6cfe0d16ae931", domain="CORP"
        )
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="impacket")

        self.assertEqual(result["auth_type"], "hash")
        self.assertEqual(result["credential_format"], "'CORP/admin'")
        self.assertIn("-hashes", result["auth_string"])
        self.assertIn(":aad3b435b51404ee:31d6cfe0d16ae931", result["auth_string"])
        self.assertFalse(result["is_kerberos"])

    def test_hash_auth_certipy(self):
        """Test hash auth string for certipy."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", hash_val="abc123def456", domain="corp.local")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="certipy")

        self.assertEqual(result["auth_type"], "hash")
        self.assertIn("-u 'admin@corp.local'", result["auth_string"])
        self.assertIn("-hashes ':abc123def456'", result["auth_string"])
        self.assertFalse(result["is_kerberos"])

    def test_hash_auth_nxc(self):
        """Test hash auth string for nxc."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", hash_val="aabbccdd", domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="nxc")

        self.assertEqual(result["auth_type"], "hash")
        self.assertIn("-u 'admin'", result["auth_string"])
        self.assertIn("-H 'aabbccdd'", result["auth_string"])
        self.assertIn("-d 'CORP'", result["auth_string"])
        self.assertFalse(result["is_kerberos"])

    def test_hash_auth_adidnsdump(self):
        """Test hash auth string for adidnsdump."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", hash_val="ntlmhash", domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="adidnsdump")

        self.assertEqual(result["auth_type"], "hash")
        self.assertIn("-u 'CORP\\\\admin'", result["auth_string"])
        self.assertIn("--hashes ':ntlmhash'", result["auth_string"])
        self.assertFalse(result["is_kerberos"])

    def test_hash_auth_rusthound_shows_limitation(self):
        """Test that rusthound shows limitation note for hash auth."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", hash_val="somehash", domain="corp.local")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="rusthound")

        # rusthound doesn't support hashes directly
        self.assertEqual(result["auth_type"], "hash")
        self.assertIn("rusthound needs password", result["alt_auth_hint"])

    # =====================================================================
    # Kerberos with Ccache Tests
    # =====================================================================

    def test_kcache_auth_impacket(self):
        """Test kcache auth string for impacket tools."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", use_kcache=True, domain="CORP.LOCAL")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="impacket")

        self.assertEqual(result["auth_type"], "kerberos")
        self.assertTrue(result["is_kerberos"])
        self.assertEqual(result["credential_format"], "'CORP.LOCAL/admin'")
        self.assertIn("-k", result["auth_string"])
        self.assertIn("-no-pass", result["auth_string"])
        self.assertIn("KRB5CCNAME", result["kerberos_hint"])

    def test_kcache_auth_certipy(self):
        """Test kcache auth string for certipy."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", use_kcache=True, domain="corp.local")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="certipy")

        self.assertEqual(result["auth_type"], "kerberos")
        self.assertTrue(result["is_kerberos"])
        self.assertIn("-u 'admin@corp.local'", result["auth_string"])
        self.assertIn("-k", result["auth_string"])
        self.assertIn("-no-pass", result["auth_string"])
        self.assertIn("KRB5CCNAME", result["kerberos_hint"])

    def test_kcache_auth_nxc(self):
        """Test kcache auth string for nxc."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", use_kcache=True, domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="nxc")

        self.assertEqual(result["auth_type"], "kerberos")
        self.assertTrue(result["is_kerberos"])
        self.assertIn("-u 'admin'", result["auth_string"])
        self.assertIn("--use-kcache", result["auth_string"])
        self.assertIn("KRB5CCNAME", result["kerberos_hint"])

    def test_kcache_auth_adidnsdump(self):
        """Test kcache auth string for adidnsdump."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", use_kcache=True, domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="adidnsdump")

        self.assertEqual(result["auth_type"], "kerberos")
        self.assertTrue(result["is_kerberos"])
        self.assertIn("-u 'CORP\\\\admin'", result["auth_string"])
        self.assertIn("-k", result["auth_string"])
        self.assertIn("KRB5CCNAME", result["kerberos_hint"])

    def test_kcache_auth_rusthound(self):
        """Test kcache auth string for rusthound."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", use_kcache=True, domain="corp.local")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="rusthound")

        self.assertEqual(result["auth_type"], "kerberos")
        self.assertTrue(result["is_kerberos"])
        self.assertIn("-u 'admin@corp.local'", result["auth_string"])
        self.assertIn("-k", result["auth_string"])

    # =====================================================================
    # Kerberos with AES Key Tests
    # =====================================================================

    def test_aeskey_auth_impacket(self):
        """Test AES key auth string for impacket tools."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        aes_key = "0123456789abcdef" * 4  # 64-char AES256 key
        args = self._make_args(user="admin", aes_key=aes_key, domain="CORP.LOCAL")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="impacket")

        self.assertEqual(result["auth_type"], "kerberos")
        self.assertTrue(result["is_kerberos"])
        self.assertEqual(result["credential_format"], "'CORP.LOCAL/admin'")
        self.assertIn("-aesKey", result["auth_string"])
        self.assertIn(aes_key, result["auth_string"])

    def test_aeskey_auth_certipy(self):
        """Test AES key auth string for certipy (needs ticket first)."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        aes_key = "0123456789abcdef" * 4
        args = self._make_args(user="admin", aes_key=aes_key, domain="corp.local")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="certipy")

        self.assertEqual(result["auth_type"], "kerberos")
        self.assertTrue(result["is_kerberos"])
        # Certipy doesn't support aesKey directly, uses kcache
        self.assertIn("-k", result["auth_string"])
        self.assertIn("-no-pass", result["auth_string"])
        self.assertIn("getTGT.py", result["kerberos_hint"])

    def test_aeskey_auth_nxc(self):
        """Test AES key auth string for nxc."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        aes_key = "aabbccdd" * 8
        args = self._make_args(user="admin", aes_key=aes_key, domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="nxc")

        self.assertEqual(result["auth_type"], "kerberos")
        self.assertTrue(result["is_kerberos"])
        self.assertIn("-u 'admin'", result["auth_string"])
        self.assertIn("--aesKey", result["auth_string"])
        self.assertIn(aes_key, result["auth_string"])

    def test_aeskey_auth_adidnsdump(self):
        """Test AES key auth string for adidnsdump (needs ticket first)."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        aes_key = "0123456789abcdef" * 4
        args = self._make_args(user="admin", aes_key=aes_key, domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="adidnsdump")

        self.assertEqual(result["auth_type"], "kerberos")
        self.assertTrue(result["is_kerberos"])
        # adidnsdump uses -k, not direct aesKey
        self.assertIn("-k", result["auth_string"])
        self.assertIn("getTGT.py", result["kerberos_hint"])

    # =====================================================================
    # Certificate Authentication Tests
    # =====================================================================

    def test_pfx_cert_auth_impacket(self):
        """Test PFX certificate auth string for impacket tools."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", pfx_cert="/path/to/cert.pfx", domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="impacket")

        self.assertEqual(result["auth_type"], "certificate")
        self.assertEqual(result["credential_format"], "'CORP/admin'")
        self.assertIn("-pfx", result["auth_string"])
        self.assertIn("/path/to/cert.pfx", result["auth_string"])

    def test_pem_cert_auth_impacket(self):
        """Test PEM certificate auth string for impacket tools."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", pem_cert="/path/to/cert.pem", domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="impacket")

        self.assertEqual(result["auth_type"], "certificate")
        self.assertEqual(result["credential_format"], "'CORP/admin'")
        self.assertIn("-cert-pfx", result["auth_string"])
        self.assertIn("/path/to/cert.pem", result["auth_string"])

    def test_pfx_cert_auth_certipy(self):
        """Test PFX certificate auth string for certipy."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", pfx_cert="/certs/user.pfx", domain="corp.local")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="certipy")

        self.assertEqual(result["auth_type"], "certificate")
        self.assertIn("-u 'admin@corp.local'", result["auth_string"])
        self.assertIn("-pfx '/certs/user.pfx'", result["auth_string"])

    def test_pem_cert_auth_certipy(self):
        """Test PEM certificate auth string for certipy."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", pem_cert="/certs/user.pem", domain="corp.local")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="certipy")

        self.assertEqual(result["auth_type"], "certificate")
        self.assertIn("-u 'admin@corp.local'", result["auth_string"])
        self.assertIn("-cert '/certs/user.pem'", result["auth_string"])

    def test_pfx_cert_auth_nxc(self):
        """Test PFX certificate auth string for nxc."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", pfx_cert="/path/cert.pfx", domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="nxc")

        self.assertEqual(result["auth_type"], "certificate")
        self.assertIn("-u 'admin'", result["auth_string"])
        self.assertIn("--pfx-cert '/path/cert.pfx'", result["auth_string"])

    def test_pem_cert_auth_nxc(self):
        """Test PEM certificate auth string for nxc."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", pem_cert="/path/cert.pem", domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="nxc")

        self.assertEqual(result["auth_type"], "certificate")
        self.assertIn("-u 'admin'", result["auth_string"])
        self.assertIn("--pem-cert '/path/cert.pem'", result["auth_string"])

    # =====================================================================
    # Edge Cases and Fallbacks
    # =====================================================================

    def test_no_auth_returns_placeholders(self):
        """Test that missing auth returns placeholder values."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args()  # No credentials
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="impacket")

        self.assertEqual(result["auth_type"], "none")
        self.assertIn("<user>", result["credential_format"])
        self.assertIn("<pass>", result["credential_format"])

    def test_domain_from_cache(self):
        """Test that domain is pulled from cache if not in args."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", password="pass")  # No domain
        cache = self._make_cache(domain_info={"dns_domain": "cached.domain.local"})

        result = get_external_tool_auth(args, cache, tool="impacket")

        self.assertIn("cached.domain.local", result["credential_format"])
        self.assertEqual(result["domain"], "cached.domain.local")

    def test_fallback_to_primary_credential(self):
        """Test fallback to cache.primary_credential when args has no user."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        # Create mock credential
        class MockCredential:
            user = "cred_user"
            password = "cred_pass"
            hash = None
            domain = "CRED_DOMAIN"
            use_kcache = False
            aes_key = None
            kerberos = False
            pfx_cert = None
            pem_cert = None

        args = self._make_args()  # Empty args
        cache = self._make_cache(primary_credential=MockCredential())

        result = get_external_tool_auth(args, cache, tool="nxc")

        self.assertEqual(result["auth_type"], "password")
        self.assertIn("cred_user", result["auth_string"])
        self.assertIn("cred_pass", result["auth_string"])
        self.assertIn("CRED_DOMAIN", result["auth_string"])

    def test_include_domain_false(self):
        """Test include_domain=False excludes domain from user string."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", password="pass", domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="nxc", include_domain=False)

        # Domain should not be in auth_string when include_domain=False
        self.assertNotIn("-d 'CORP'", result["auth_string"])

    def test_generic_fallback_tool(self):
        """Test generic fallback for unknown tool names."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", password="secret", domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="unknown_tool")

        self.assertEqual(result["auth_type"], "password")
        self.assertIn("-u 'admin'", result["auth_string"])
        self.assertIn("-p 'secret'", result["auth_string"])

    def test_kerberos_flag_with_password(self):
        """Test Kerberos flag combined with password auth."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", password="pass", kerberos=True, domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="impacket")

        self.assertEqual(result["auth_type"], "kerberos")
        self.assertTrue(result["is_kerberos"])
        # Should have password in credential format and -k flag
        self.assertIn("pass", result["credential_format"])
        self.assertIn("-k", result["auth_string"])

    def test_kerberos_flag_with_password_nxc(self):
        """Test Kerberos flag combined with password for nxc."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", password="pass", kerberos=True, domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="nxc")

        self.assertEqual(result["auth_type"], "kerberos")
        self.assertTrue(result["is_kerberos"])
        self.assertIn("-u 'admin'", result["auth_string"])
        self.assertIn("-p 'pass'", result["auth_string"])
        self.assertIn("-k", result["auth_string"])

    def test_result_dict_contains_all_expected_keys(self):
        """Test that result dict always contains all expected keys."""
        from nxc_enum.reporting.next_steps import get_external_tool_auth

        args = self._make_args(user="admin", password="pass", domain="CORP")
        cache = self._make_cache()

        result = get_external_tool_auth(args, cache, tool="impacket")

        expected_keys = [
            "auth_string",
            "credential_format",
            "kerberos_hint",
            "alt_auth_hint",
            "auth_type",
            "is_kerberos",
            "user",
            "domain",
        ]
        for key in expected_keys:
            self.assertIn(key, result)


if __name__ == "__main__":
    unittest.main()
