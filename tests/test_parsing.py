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


class TestCustomQueryArguments(unittest.TestCase):
    """Test custom LDAP query command line arguments."""

    def setUp(self):
        """Import parser for each test."""
        from nxc_enum.cli.args import create_parser

        self.parser = create_parser()

    def test_query_simple_filter(self):
        """Test --query with simple LDAP filter."""
        args = self.parser.parse_args(["target", "--query", "(objectClass=user)"])
        self.assertEqual(args.query, "(objectClass=user)")

    def test_query_complex_filter(self):
        """Test --query with complex LDAP filter."""
        filter_str = "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        args = self.parser.parse_args(["target", "--query", filter_str])
        self.assertEqual(args.query, filter_str)

    def test_query_filter_with_spaces(self):
        """Test --query with filter containing spaces in description search."""
        filter_str = "(description=*password*)"
        args = self.parser.parse_args(["target", "--query", filter_str])
        self.assertEqual(args.query, filter_str)

    def test_query_filter_with_wildcards(self):
        """Test --query with wildcard filter."""
        filter_str = "(sAMAccountName=svc_*)"
        args = self.parser.parse_args(["target", "--query", filter_str])
        self.assertEqual(args.query, filter_str)

    def test_query_attrs_comma_separated(self):
        """Test --query-attrs with comma-separated attributes."""
        args = self.parser.parse_args(
            ["target", "--query", "(objectClass=user)", "--query-attrs", "cn,mail,description"]
        )
        self.assertEqual(args.query_attrs, "cn,mail,description")

    def test_query_attrs_single_attribute(self):
        """Test --query-attrs with single attribute."""
        args = self.parser.parse_args(
            ["target", "--query", "(objectClass=user)", "--query-attrs", "sAMAccountName"]
        )
        self.assertEqual(args.query_attrs, "sAMAccountName")

    def test_query_attrs_many_attributes(self):
        """Test --query-attrs with many attributes."""
        attrs = "cn,sAMAccountName,mail,description,memberOf,userAccountControl"
        args = self.parser.parse_args(
            ["target", "--query", "(objectClass=user)", "--query-attrs", attrs]
        )
        self.assertEqual(args.query_attrs, attrs)

    def test_query_default_none(self):
        """Test --query defaults to None when not specified."""
        args = self.parser.parse_args(["target"])
        self.assertIsNone(args.query)

    def test_query_attrs_default_none(self):
        """Test --query-attrs defaults to None when not specified."""
        args = self.parser.parse_args(["target"])
        self.assertIsNone(args.query_attrs)

    def test_query_attrs_without_query(self):
        """Test --query-attrs can be specified without --query (parser allows it)."""
        # Parser allows it, but enum_custom_query will handle the validation
        args = self.parser.parse_args(["target", "--query-attrs", "cn,mail"])
        self.assertEqual(args.query_attrs, "cn,mail")
        self.assertIsNone(args.query)

    def test_query_with_credentials(self):
        """Test --query combined with credential arguments."""
        args = self.parser.parse_args(
            [
                "target",
                "-u",
                "admin",
                "-p",
                "password",
                "-d",
                "CORP",
                "--query",
                "(objectClass=user)",
            ]
        )
        self.assertEqual(args.query, "(objectClass=user)")
        self.assertEqual(args.user, "admin")
        self.assertEqual(args.password, "password")
        self.assertEqual(args.domain, "CORP")


class TestCustomQueryParsing(unittest.TestCase):
    """Test custom LDAP query output parsing."""

    def setUp(self):
        """Import parsing function."""
        from nxc_enum.enums.custom_query import _parse_query_output

        self.parse_query_output = _parse_query_output

    def test_parse_single_object(self):
        """Test parsing a single LDAP object response."""
        stdout = """LDAP 10.0.0.1 389 DC01 Response for object: CN=John Doe,CN=Users,DC=corp,DC=local
LDAP 10.0.0.1 389 DC01 sAMAccountName john.doe
LDAP 10.0.0.1 389 DC01 mail john.doe@corp.local"""

        results = self.parse_query_output(stdout)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["dn"], "CN=John Doe,CN=Users,DC=corp,DC=local")
        self.assertEqual(results[0]["attributes"]["sAMAccountName"], "john.doe")
        self.assertEqual(results[0]["attributes"]["mail"], "john.doe@corp.local")

    def test_parse_multiple_objects(self):
        """Test parsing multiple LDAP objects."""
        stdout = """LDAP 10.0.0.1 389 DC01 Response for object: CN=User1,CN=Users,DC=corp,DC=local
LDAP 10.0.0.1 389 DC01 cn User1
LDAP 10.0.0.1 389 DC01 Response for object: CN=User2,CN=Users,DC=corp,DC=local
LDAP 10.0.0.1 389 DC01 cn User2"""

        results = self.parse_query_output(stdout)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["dn"], "CN=User1,CN=Users,DC=corp,DC=local")
        self.assertEqual(results[0]["attributes"]["cn"], "User1")
        self.assertEqual(results[1]["dn"], "CN=User2,CN=Users,DC=corp,DC=local")
        self.assertEqual(results[1]["attributes"]["cn"], "User2")

    def test_parse_empty_output(self):
        """Test parsing empty output returns empty list."""
        results = self.parse_query_output("")
        self.assertEqual(results, [])

    def test_parse_no_results(self):
        """Test parsing output with no LDAP objects."""
        stdout = """LDAP 10.0.0.1 389 DC01 [*] Searching for objects
LDAP 10.0.0.1 389 DC01 [*] No objects found"""

        results = self.parse_query_output(stdout)
        self.assertEqual(results, [])

    def test_parse_with_attribute_filter(self):
        """Test parsing with attribute filtering."""
        stdout = """LDAP 10.0.0.1 389 DC01 Response for object: CN=User1,CN=Users,DC=corp,DC=local
LDAP 10.0.0.1 389 DC01 cn User1
LDAP 10.0.0.1 389 DC01 mail user1@corp.local
LDAP 10.0.0.1 389 DC01 description Some description"""

        # Request only cn and mail, should filter out description
        results = self.parse_query_output(stdout, requested_attrs=["cn", "mail"])

        self.assertEqual(len(results), 1)
        self.assertIn("cn", results[0]["attributes"])
        self.assertIn("mail", results[0]["attributes"])
        self.assertNotIn("description", results[0]["attributes"])

    def test_parse_case_insensitive_attr_filter(self):
        """Test attribute filtering is case-insensitive."""
        stdout = """LDAP 10.0.0.1 389 DC01 Response for object: CN=User1,CN=Users,DC=corp,DC=local
LDAP 10.0.0.1 389 DC01 sAMAccountName user1"""

        # Request with different case
        results = self.parse_query_output(stdout, requested_attrs=["samaccountname"])

        self.assertEqual(len(results), 1)
        self.assertIn("sAMAccountName", results[0]["attributes"])

    def test_parse_multi_valued_attribute(self):
        """Test parsing multi-valued attributes."""
        stdout = """LDAP 10.0.0.1 389 DC01 Response for object: CN=User1,CN=Users,DC=corp,DC=local
LDAP 10.0.0.1 389 DC01 memberOf CN=Group1,DC=corp,DC=local
LDAP 10.0.0.1 389 DC01 memberOf CN=Group2,DC=corp,DC=local
LDAP 10.0.0.1 389 DC01 memberOf CN=Group3,DC=corp,DC=local"""

        results = self.parse_query_output(stdout)

        self.assertEqual(len(results), 1)
        memberOf = results[0]["attributes"]["memberOf"]
        self.assertIsInstance(memberOf, list)
        self.assertEqual(len(memberOf), 3)
        self.assertIn("CN=Group1,DC=corp,DC=local", memberOf)
        self.assertIn("CN=Group2,DC=corp,DC=local", memberOf)
        self.assertIn("CN=Group3,DC=corp,DC=local", memberOf)

    def test_parse_attribute_with_colon_format(self):
        """Test parsing attributes with colon separator format."""
        stdout = """LDAP 10.0.0.1 389 DC01 Response for object: CN=User1,CN=Users,DC=corp,DC=local
LDAP 10.0.0.1 389 DC01 cn: User1
LDAP 10.0.0.1 389 DC01 mail: user1@corp.local"""

        results = self.parse_query_output(stdout)

        self.assertEqual(len(results), 1)
        # The regex should handle both space and colon separators
        self.assertEqual(results[0]["attributes"]["cn"], "User1")
        self.assertEqual(results[0]["attributes"]["mail"], "user1@corp.local")

    def test_parse_whitespace_handling(self):
        """Test parsing handles extra whitespace correctly."""
        stdout = """
LDAP 10.0.0.1 389 DC01 Response for object: CN=User1,CN=Users,DC=corp,DC=local

LDAP 10.0.0.1 389 DC01 cn User1

"""
        results = self.parse_query_output(stdout)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["attributes"]["cn"], "User1")


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


class TestRunNxcPortParameter(unittest.TestCase):
    """Test that run_nxc correctly handles the port parameter."""

    def test_run_nxc_adds_port_to_command(self):
        """Test that port parameter adds --port to nxc command."""
        from unittest.mock import MagicMock, patch

        with patch("nxc_enum.core.runner.subprocess.run") as mock_run:
            # Create a mock result with required attributes
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            from nxc_enum.core.runner import run_nxc

            run_nxc(["smb", "10.0.0.1"], timeout=30, port=139)

            # Check that subprocess.run was called
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]

            # Verify --port 139 is in the command
            self.assertIn("--port", call_args)
            port_idx = call_args.index("--port")
            self.assertEqual(call_args[port_idx + 1], "139")

    def test_run_nxc_does_not_add_port_when_none(self):
        """Test that no --port is added when port parameter is None."""
        from unittest.mock import MagicMock, patch

        with patch("nxc_enum.core.runner.subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            from nxc_enum.core.runner import run_nxc

            run_nxc(["smb", "10.0.0.1"], timeout=30, port=None)

            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]

            # Verify --port is NOT in the command
            self.assertNotIn("--port", call_args)

    def test_run_nxc_does_not_duplicate_port(self):
        """Test that --port is not added when already present in args."""
        from unittest.mock import MagicMock, patch

        with patch("nxc_enum.core.runner.subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            from nxc_enum.core.runner import run_nxc

            # Pass --port in args, also pass port parameter
            run_nxc(["smb", "10.0.0.1", "--port", "445"], timeout=30, port=139)

            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]

            # Count occurrences of --port
            port_count = call_args.count("--port")
            self.assertEqual(port_count, 1, "Should not duplicate --port in command")


class TestRunNxcSmbTimeout(unittest.TestCase):
    """Test that run_nxc correctly handles the smb_timeout parameter."""

    def test_run_nxc_uses_smb_timeout_when_provided(self):
        """Test that smb_timeout overrides the default timeout."""
        from unittest.mock import MagicMock, patch

        with patch("nxc_enum.core.runner.subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            from nxc_enum.core.runner import run_nxc

            run_nxc(["smb", "10.0.0.1"], timeout=60, smb_timeout=120)

            mock_run.assert_called_once()
            # Check the timeout keyword argument
            call_kwargs = mock_run.call_args[1]
            self.assertEqual(call_kwargs["timeout"], 120, "Should use smb_timeout value")

    def test_run_nxc_uses_general_timeout_when_smb_timeout_none(self):
        """Test that general timeout is used when smb_timeout is None."""
        from unittest.mock import MagicMock, patch

        with patch("nxc_enum.core.runner.subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            from nxc_enum.core.runner import run_nxc

            run_nxc(["smb", "10.0.0.1"], timeout=45, smb_timeout=None)

            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args[1]
            self.assertEqual(call_kwargs["timeout"], 45, "Should use general timeout value")

    def test_run_nxc_smb_timeout_zero_uses_zero(self):
        """Test that smb_timeout=0 is used (not treated as falsy)."""
        from unittest.mock import MagicMock, patch

        with patch("nxc_enum.core.runner.subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            from nxc_enum.core.runner import run_nxc

            # smb_timeout=0 should be used as-is (not default to timeout)
            run_nxc(["smb", "10.0.0.1"], timeout=60, smb_timeout=0)

            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args[1]
            # Note: 0 is falsy but explicit, so smb_timeout should be checked with `is not None`
            self.assertEqual(call_kwargs["timeout"], 0, "Should use smb_timeout=0")


class TestCheckPortIPv6(unittest.TestCase):
    """Test that check_port correctly handles the ipv6 parameter."""

    def test_check_port_uses_af_inet_by_default(self):
        """Test that check_port uses AF_INET (IPv4) by default."""
        import socket
        from unittest.mock import MagicMock, patch

        with patch("nxc_enum.core.runner.socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket.connect_ex.return_value = 0
            mock_socket_class.return_value = mock_socket

            from nxc_enum.core.runner import check_port

            result = check_port("10.0.0.1", 445, timeout=1.0, ipv6=False)

            # Should use AF_INET
            mock_socket_class.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
            self.assertTrue(result)

    def test_check_port_uses_af_inet6_when_ipv6_true(self):
        """Test that check_port uses AF_INET6 when ipv6=True."""
        import socket
        from unittest.mock import MagicMock, patch

        with patch("nxc_enum.core.runner.socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket.connect_ex.return_value = 0
            mock_socket_class.return_value = mock_socket

            from nxc_enum.core.runner import check_port

            result = check_port("::1", 445, timeout=1.0, ipv6=True)

            # Should use AF_INET6
            mock_socket_class.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
            self.assertTrue(result)

    def test_check_port_returns_false_on_connection_failure(self):
        """Test that check_port returns False when connection fails."""
        from unittest.mock import MagicMock, patch

        with patch("nxc_enum.core.runner.socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            # Non-zero return means connection failed
            mock_socket.connect_ex.return_value = 111
            mock_socket_class.return_value = mock_socket

            from nxc_enum.core.runner import check_port

            result = check_port("10.0.0.1", 445, timeout=1.0)

            self.assertFalse(result)

    def test_check_port_returns_false_on_socket_error(self):
        """Test that check_port returns False on socket error."""
        import socket
        from unittest.mock import patch

        with patch("nxc_enum.core.runner.socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = socket.error("Connection error")

            from nxc_enum.core.runner import check_port

            result = check_port("10.0.0.1", 445, timeout=1.0)

            self.assertFalse(result)


class TestEnumCacheGetDnsArgs(unittest.TestCase):
    """Test EnumCache.get_dns_args() method for building DNS arguments."""

    def test_get_dns_args_empty_when_no_options(self):
        """Test that get_dns_args returns empty list when no DNS options set."""
        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()

        result = cache.get_dns_args()

        self.assertEqual(result, [])

    def test_get_dns_args_with_dns_server(self):
        """Test that get_dns_args includes --dns-server when set."""
        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()
        cache.dns_server = "10.0.0.1"

        result = cache.get_dns_args()

        self.assertEqual(result, ["--dns-server", "10.0.0.1"])

    def test_get_dns_args_with_dns_tcp(self):
        """Test that get_dns_args includes --dns-tcp when set."""
        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()
        cache.dns_tcp = True

        result = cache.get_dns_args()

        self.assertEqual(result, ["--dns-tcp"])

    def test_get_dns_args_with_both_options(self):
        """Test that get_dns_args includes both DNS options when set."""
        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()
        cache.dns_server = "8.8.8.8"
        cache.dns_tcp = True

        result = cache.get_dns_args()

        self.assertEqual(result, ["--dns-server", "8.8.8.8", "--dns-tcp"])

    def test_get_dns_args_dns_tcp_false_not_included(self):
        """Test that --dns-tcp is not included when dns_tcp is False."""
        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()
        cache.dns_server = "10.0.0.1"
        cache.dns_tcp = False

        result = cache.get_dns_args()

        self.assertEqual(result, ["--dns-server", "10.0.0.1"])
        self.assertNotIn("--dns-tcp", result)


class TestEnumCacheNetworkOptions(unittest.TestCase):
    """Test EnumCache network option attributes and initialization."""

    def test_cache_port_default_is_none(self):
        """Test that cache.port defaults to None."""
        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()

        self.assertIsNone(cache.port)

    def test_cache_smb_timeout_default_is_none(self):
        """Test that cache.smb_timeout defaults to None."""
        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()

        self.assertIsNone(cache.smb_timeout)

    def test_cache_ipv6_default_is_false(self):
        """Test that cache.ipv6 defaults to False."""
        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()

        self.assertFalse(cache.ipv6)

    def test_cache_dns_server_default_is_none(self):
        """Test that cache.dns_server defaults to None."""
        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()

        self.assertIsNone(cache.dns_server)

    def test_cache_dns_tcp_default_is_false(self):
        """Test that cache.dns_tcp defaults to False."""
        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()

        self.assertFalse(cache.dns_tcp)

    def test_cache_network_options_can_be_set(self):
        """Test that all network options can be set on cache."""
        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()
        cache.port = 139
        cache.smb_timeout = 90
        cache.ipv6 = True
        cache.dns_server = "192.168.1.1"
        cache.dns_tcp = True

        self.assertEqual(cache.port, 139)
        self.assertEqual(cache.smb_timeout, 90)
        self.assertTrue(cache.ipv6)
        self.assertEqual(cache.dns_server, "192.168.1.1")
        self.assertTrue(cache.dns_tcp)


class TestEnumCacheRunNxcCached(unittest.TestCase):
    """Test EnumCache.run_nxc_cached() method for network option application."""

    def test_run_nxc_cached_applies_port(self):
        """Test that run_nxc_cached passes port to run_nxc."""
        from unittest.mock import patch

        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()
        cache.port = 139
        cache.timeout = 30

        with patch("nxc_enum.models.cache.run_nxc") as mock_run_nxc:
            mock_run_nxc.return_value = (0, "", "")

            cache.run_nxc_cached(["smb", "10.0.0.1"])

            mock_run_nxc.assert_called_once()
            call_kwargs = mock_run_nxc.call_args[1]
            self.assertEqual(call_kwargs["port"], 139)

    def test_run_nxc_cached_applies_smb_timeout(self):
        """Test that run_nxc_cached passes smb_timeout to run_nxc."""
        from unittest.mock import patch

        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()
        cache.smb_timeout = 120
        cache.timeout = 30

        with patch("nxc_enum.models.cache.run_nxc") as mock_run_nxc:
            mock_run_nxc.return_value = (0, "", "")

            cache.run_nxc_cached(["smb", "10.0.0.1"])

            mock_run_nxc.assert_called_once()
            call_kwargs = mock_run_nxc.call_args[1]
            self.assertEqual(call_kwargs["smb_timeout"], 120)

    def test_run_nxc_cached_applies_dns_args(self):
        """Test that run_nxc_cached adds DNS args to command."""
        from unittest.mock import patch

        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()
        cache.dns_server = "10.0.0.53"
        cache.dns_tcp = True
        cache.timeout = 30

        with patch("nxc_enum.models.cache.run_nxc") as mock_run_nxc:
            mock_run_nxc.return_value = (0, "", "")

            cache.run_nxc_cached(["smb", "10.0.0.1"])

            mock_run_nxc.assert_called_once()
            call_args = mock_run_nxc.call_args[0][0]
            self.assertIn("--dns-server", call_args)
            self.assertIn("10.0.0.53", call_args)
            self.assertIn("--dns-tcp", call_args)

    def test_run_nxc_cached_stores_result_in_cache_attr(self):
        """Test that run_nxc_cached stores result when cache_attr is provided."""
        from unittest.mock import patch

        from nxc_enum.models.cache import EnumCache

        cache = EnumCache()
        cache.timeout = 30

        with patch("nxc_enum.models.cache.run_nxc") as mock_run_nxc:
            mock_run_nxc.return_value = (0, "output", "")

            cache.run_nxc_cached(["smb", "10.0.0.1"], cache_attr="smb_basic")

            self.assertEqual(cache.smb_basic, (0, "output", ""))


if __name__ == "__main__":
    unittest.main()
