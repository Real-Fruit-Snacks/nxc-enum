"""Tests for parsing utilities."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nxc_enum.parsing.classify import (  # noqa: E402
    classify_groups,
    classify_users,
    is_builtin_account,
    is_computer_account,
    is_service_account,
    safe_int,
)
from nxc_enum.parsing.nxc_output import (  # noqa: E402
    extract_after_port,
    extract_status_content,
    find_port_index,
    is_nxc_noise_line,
    parse_nxc_output,
)


class TestNxcOutputParsing(unittest.TestCase):
    """Test NXC output parsing utilities."""

    def test_is_nxc_noise_line_empty(self):
        """Test that empty lines are filtered."""
        self.assertTrue(is_nxc_noise_line(""))
        self.assertTrue(is_nxc_noise_line("   "))

    def test_is_nxc_noise_line_credential_echo(self):
        """Test that credential echo lines are filtered."""
        self.assertTrue(is_nxc_noise_line("CORP\\admin:password123"))
        self.assertTrue(is_nxc_noise_line("10.0.0.1 445 CORP\\admin:password"))

    def test_is_nxc_noise_line_connection_metadata(self):
        """Test that connection metadata is filtered."""
        self.assertTrue(
            is_nxc_noise_line("SMB 10.0.0.1 445 (name:DC01) (domain:CORP) (signing:True)")
        )

    def test_is_nxc_noise_line_info_lines(self):
        """Test that INFO verbose lines are filtered."""
        self.assertTrue(is_nxc_noise_line("INFO Socket info: host=10.0.0.1"))
        self.assertTrue(is_nxc_noise_line("SMB INFO Creating SMBv3 connection"))

    def test_is_nxc_noise_line_debug_lines(self):
        """Test that DEBUG lines are filtered."""
        self.assertTrue(is_nxc_noise_line("DEBUG some debug info"))
        self.assertTrue(is_nxc_noise_line("SMB DEBUG connection details"))

    def test_is_nxc_noise_line_valid_data(self):
        """Test that valid data lines are not filtered."""
        self.assertFalse(is_nxc_noise_line("[+] admin has local admin rights"))
        self.assertFalse(is_nxc_noise_line("[*] Enumerated 10 users"))
        self.assertFalse(is_nxc_noise_line("[-] Access denied"))

    def test_parse_nxc_output_success(self):
        """Test parsing success indicators."""
        stdout = "[+] Authentication successful\n[+] Found 5 shares"
        results = parse_nxc_output(stdout)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], ("success", "Authentication successful"))
        self.assertEqual(results[1], ("success", "Found 5 shares"))

    def test_parse_nxc_output_error(self):
        """Test parsing error indicators."""
        stdout = "[-] Authentication failed\n[-] Access denied"
        results = parse_nxc_output(stdout)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], ("error", "Authentication failed"))
        self.assertEqual(results[1], ("error", "Access denied"))

    def test_parse_nxc_output_info(self):
        """Test parsing info indicators."""
        stdout = "[*] Connecting to 10.0.0.1\n[*] Enumeration complete"
        results = parse_nxc_output(stdout)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], ("info", "Connecting to 10.0.0.1"))
        self.assertEqual(results[1], ("info", "Enumeration complete"))

    def test_parse_nxc_output_filters_noise(self):
        """Test that noise lines are filtered from parsed output."""
        stdout = "[+] Success\nINFO Socket info\n[-] Error\n"
        results = parse_nxc_output(stdout)

        self.assertEqual(len(results), 2)
        self.assertNotIn(("info", "Socket info"), results)

    def test_extract_after_port_found(self):
        """Test extracting content after port number."""
        parts = ["10.0.0.1", "445", "DC01", "[+]", "admin", "has", "access"]
        result = extract_after_port(parts)

        self.assertEqual(result, ["[+]", "admin", "has", "access"])

    def test_extract_after_port_ldap(self):
        """Test extracting content after LDAP port."""
        parts = ["10.0.0.1", "389", "DC01", "[*]", "Domain", "info"]
        result = extract_after_port(parts)

        self.assertEqual(result, ["[*]", "Domain", "info"])

    def test_extract_after_port_not_found(self):
        """Test behavior when port not found."""
        parts = ["10.0.0.1", "8080", "server", "[+]", "data"]
        result = extract_after_port(parts)

        self.assertEqual(result, [])

    def test_extract_after_port_too_short(self):
        """Test behavior when line is too short after port."""
        parts = ["10.0.0.1", "445"]
        result = extract_after_port(parts)

        self.assertEqual(result, [])

    def test_find_port_index_found(self):
        """Test finding port index in parts."""
        parts = ["10.0.0.1", "445", "DC01", "data"]
        idx = find_port_index(parts)

        self.assertEqual(idx, 1)

    def test_find_port_index_not_found(self):
        """Test when port not found."""
        parts = ["10.0.0.1", "8080", "server"]
        idx = find_port_index(parts)

        self.assertEqual(idx, -1)

    def test_extract_status_content_success(self):
        """Test extracting success status."""
        result = extract_status_content("[+] Authentication successful")
        self.assertEqual(result, ("success", "Authentication successful"))

    def test_extract_status_content_error(self):
        """Test extracting error status."""
        result = extract_status_content("[-] Access denied")
        self.assertEqual(result, ("error", "Access denied"))

    def test_extract_status_content_info(self):
        """Test extracting info status."""
        result = extract_status_content("[*] Enumerating shares")
        self.assertEqual(result, ("info", "Enumerating shares"))

    def test_extract_status_content_warning(self):
        """Test extracting warning status."""
        result = extract_status_content("[!] SMB signing disabled")
        self.assertEqual(result, ("warning", "SMB signing disabled"))

    def test_extract_status_content_none(self):
        """Test when no status indicator found."""
        result = extract_status_content("Some plain text")
        self.assertIsNone(result)


class TestClassification(unittest.TestCase):
    """Test user and group classification utilities."""

    def test_safe_int_valid(self):
        """Test safe_int with valid integer string."""
        self.assertEqual(safe_int("123"), 123)
        self.assertEqual(safe_int("0"), 0)

    def test_safe_int_invalid(self):
        """Test safe_int with invalid input."""
        self.assertEqual(safe_int("abc"), 9999)
        self.assertEqual(safe_int(""), 9999)
        self.assertEqual(safe_int(None), 9999)

    def test_safe_int_custom_default(self):
        """Test safe_int with custom default."""
        self.assertEqual(safe_int("abc", default=0), 0)
        self.assertEqual(safe_int("abc", default=-1), -1)

    def test_is_service_account_suffix(self):
        """Test service account detection by suffix."""
        self.assertTrue(is_service_account("backup.svc"))
        self.assertTrue(is_service_account("sql_svc"))
        self.assertTrue(is_service_account("web-svc"))
        self.assertTrue(is_service_account("mailsvc"))

    def test_is_service_account_prefix(self):
        """Test service account detection by prefix."""
        self.assertTrue(is_service_account("svc_backup"))
        self.assertTrue(is_service_account("svc-sql"))
        self.assertTrue(is_service_account("svc.web"))

    def test_is_service_account_regular(self):
        """Test regular accounts are not detected as service."""
        self.assertFalse(is_service_account("admin"))
        self.assertFalse(is_service_account("john.doe"))
        self.assertFalse(is_service_account("service"))  # Just the word

    def test_is_computer_account(self):
        """Test computer account detection."""
        self.assertTrue(is_computer_account("DC01$"))
        self.assertTrue(is_computer_account("WORKSTATION$"))
        self.assertFalse(is_computer_account("admin"))
        self.assertFalse(is_computer_account("user$name"))

    def test_is_builtin_account(self):
        """Test built-in account detection by RID."""
        self.assertTrue(is_builtin_account(500))  # Administrator
        self.assertTrue(is_builtin_account(501))  # Guest
        self.assertTrue(is_builtin_account(999))  # Max builtin
        self.assertFalse(is_builtin_account(1000))  # First regular user
        self.assertFalse(is_builtin_account(1234))

    def test_classify_users(self):
        """Test user classification into categories."""
        users = {
            "Administrator": {"rid": "500"},
            "Guest": {"rid": "501"},
            "svc_backup": {"rid": "1001"},
            "DC01$": {"rid": "1002"},
            "john.doe": {"rid": "1003"},
        }

        result = classify_users(users)

        # Check categorization
        builtin_names = [u[0] for u in result["builtin"]]
        self.assertIn("Administrator", builtin_names)
        self.assertIn("Guest", builtin_names)

        service_names = [u[0] for u in result["service"]]
        self.assertIn("svc_backup", service_names)

        computer_names = [u[0] for u in result["computer"]]
        self.assertIn("DC01$", computer_names)

        domain_names = [u[0] for u in result["domain"]]
        self.assertIn("john.doe", domain_names)

    def test_classify_groups(self):
        """Test group classification into high-value and other."""
        groups = {
            "Domain Admins": {"rid": "512"},
            "Domain Users": {"rid": "513"},
            "Enterprise Admins": {"rid": "519"},
            "IT Support": {"rid": "1001"},
        }

        result = classify_groups(groups)

        high_value_names = [g[0] for g in result["high_value"]]
        self.assertIn("Domain Admins", high_value_names)
        self.assertIn("Enterprise Admins", high_value_names)

        other_names = [g[0] for g in result["other"]]
        self.assertIn("Domain Users", other_names)
        self.assertIn("IT Support", other_names)


class TestModuleArguments(unittest.TestCase):
    """Test module-related command line arguments."""

    def setUp(self):
        """Import parser for each test."""
        from nxc_enum.cli.args import create_parser

        self.parser = create_parser()

    def test_shares_filter_read(self):
        """Test --shares-filter READ argument."""
        args = self.parser.parse_args(["target", "--shares-filter", "READ"])
        self.assertEqual(args.shares_filter, "READ")

    def test_shares_filter_write(self):
        """Test --shares-filter WRITE argument."""
        args = self.parser.parse_args(["target", "--shares-filter", "WRITE"])
        self.assertEqual(args.shares_filter, "WRITE")

    def test_shares_filter_default(self):
        """Test --shares-filter default is None."""
        args = self.parser.parse_args(["target"])
        self.assertIsNone(args.shares_filter)

    def test_active_users_flag(self):
        """Test --active-users flag."""
        args = self.parser.parse_args(["target", "--active-users"])
        self.assertTrue(args.active_users)

    def test_active_users_default(self):
        """Test --active-users default is False."""
        args = self.parser.parse_args(["target"])
        self.assertFalse(args.active_users)

    def test_local_groups_filter(self):
        """Test --local-groups-filter argument."""
        args = self.parser.parse_args(["target", "--local-groups-filter", "Administrators"])
        self.assertEqual(args.local_groups_filter, "Administrators")

    def test_local_groups_filter_default(self):
        """Test --local-groups-filter default is None."""
        args = self.parser.parse_args(["target"])
        self.assertIsNone(args.local_groups_filter)

    def test_query_argument(self):
        """Test --query argument."""
        args = self.parser.parse_args(["target", "--query", "(objectClass=user)"])
        self.assertEqual(args.query, "(objectClass=user)")

    def test_query_attrs_argument(self):
        """Test --query-attrs argument."""
        args = self.parser.parse_args(
            ["target", "--query", "(objectClass=user)", "--query-attrs", "cn,mail"]
        )
        self.assertEqual(args.query_attrs, "cn,mail")

    def test_query_arguments_default(self):
        """Test --query and --query-attrs defaults."""
        args = self.parser.parse_args(["target"])
        self.assertIsNone(args.query)
        self.assertIsNone(args.query_attrs)


class TestNetworkArguments(unittest.TestCase):
    """Test network and protocol-related command line arguments."""

    def setUp(self):
        """Import parser for each test."""
        from nxc_enum.cli.args import create_parser

        self.parser = create_parser()

    def test_port_argument(self):
        """Test --port argument."""
        args = self.parser.parse_args(["target", "--port", "139"])
        self.assertEqual(args.port, 139)

    def test_port_default(self):
        """Test --port default is None."""
        args = self.parser.parse_args(["target"])
        self.assertIsNone(args.port)

    def test_smb_timeout_argument(self):
        """Test --smb-timeout argument."""
        args = self.parser.parse_args(["target", "--smb-timeout", "60"])
        self.assertEqual(args.smb_timeout, 60)

    def test_smb_timeout_default(self):
        """Test --smb-timeout default is None."""
        args = self.parser.parse_args(["target"])
        self.assertIsNone(args.smb_timeout)

    def test_no_smb_flag(self):
        """Test --no-smb flag."""
        args = self.parser.parse_args(["target", "--no-smb"])
        self.assertTrue(args.no_smb)

    def test_no_smb_default(self):
        """Test --no-smb default is False."""
        args = self.parser.parse_args(["target"])
        self.assertFalse(args.no_smb)

    def test_ipv6_short_flag(self):
        """Test -6 short flag."""
        args = self.parser.parse_args(["target", "-6"])
        self.assertTrue(args.ipv6)

    def test_ipv6_long_flag(self):
        """Test --ipv6 long flag."""
        args = self.parser.parse_args(["target", "--ipv6"])
        self.assertTrue(args.ipv6)

    def test_ipv6_default(self):
        """Test IPv6 default is False."""
        args = self.parser.parse_args(["target"])
        self.assertFalse(args.ipv6)

    def test_dns_server_argument(self):
        """Test --dns-server argument."""
        args = self.parser.parse_args(["target", "--dns-server", "8.8.8.8"])
        self.assertEqual(args.dns_server, "8.8.8.8")

    def test_dns_server_default(self):
        """Test --dns-server default is None."""
        args = self.parser.parse_args(["target"])
        self.assertIsNone(args.dns_server)

    def test_dns_tcp_flag(self):
        """Test --dns-tcp flag."""
        args = self.parser.parse_args(["target", "--dns-tcp"])
        self.assertTrue(args.dns_tcp)

    def test_dns_tcp_default(self):
        """Test --dns-tcp default is False."""
        args = self.parser.parse_args(["target"])
        self.assertFalse(args.dns_tcp)

    def test_combined_network_options(self):
        """Test multiple network options combined."""
        args = self.parser.parse_args(
            [
                "target",
                "--port",
                "139",
                "--smb-timeout",
                "45",
                "-6",
                "--dns-server",
                "192.168.1.1",
                "--dns-tcp",
            ]
        )
        self.assertEqual(args.port, 139)
        self.assertEqual(args.smb_timeout, 45)
        self.assertTrue(args.ipv6)
        self.assertEqual(args.dns_server, "192.168.1.1")
        self.assertTrue(args.dns_tcp)


if __name__ == "__main__":
    unittest.main()
