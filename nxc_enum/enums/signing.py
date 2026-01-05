"""SMB signing check with verbose output parsing."""

import re

from ..core.colors import Colors, c
from ..core.constants import RE_HOSTNAME
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

# Regex patterns for parsing verbose SMB signing output
# Matches signing status in parentheses: (signing:True) or (signing:False)
RE_SIGNING_STATUS = re.compile(r"\(signing:(\w+)\)", re.IGNORECASE)

# Matches SMB dialect/version info from verbose output
# Note: Must not match IP addresses - SMB versions are 1, 2, 2.1, 3, 3.0, 3.0.2, 3.1.1
RE_SMB_DIALECT = re.compile(r"(?:SMB|dialect)[:\s]+([123](?:\.[01](?:\.[012])?)?)\b", re.IGNORECASE)
RE_NEGOTIATED_DIALECT = re.compile(
    r"(?:negotiated|selected|using)\s+(?:dialect\s+)?(?:SMB\s*)?([123](?:\.[01](?:\.[012])?)?)\b",
    re.IGNORECASE,
)

# Matches SMBv1 status
RE_SMBV1 = re.compile(r"\(SMBv1:(\w+)\)", re.IGNORECASE)

# Matches host/IP patterns from verbose output
RE_HOST_IP = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
RE_HOST_FQDN = re.compile(r"(?:host|target|server)[:\s]+(\S+)", re.IGNORECASE)

# Matches signing negotiation details from INFO lines
# Format: INFO ... Signing: <status> ... or Message signing: <enabled/disabled>
RE_INFO_SIGNING = re.compile(
    r"(?:INFO|DEBUG|\[\*\]).*?(?:signing|message.?signing)[:\s]+(\w+)", re.IGNORECASE
)

# Matches security mode from verbose output
# Format: "Security mode: ..." or "secmode: ..."
RE_SECURITY_MODE = re.compile(r"(?:security.?mode|secmode)[:\s]+(.+?)(?:\s|$)", re.IGNORECASE)

# Matches SMB capabilities from verbose output
RE_CAPABILITIES = re.compile(r"(?:capabilities|caps)[:\s]+(.+)", re.IGNORECASE)

# Matches encryption support from verbose output
RE_ENCRYPTION = re.compile(r"(?:encryption)[:\s]+(\w+)", re.IGNORECASE)

# Matches connection-specific signing info (per-host status in verbose mode)
# Format: "IP ... signing <status>" or "hostname signing: <status>"
RE_HOST_SIGNING = re.compile(
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\S+?\.(?:local|domain|corp|net|com)\S*)\s+.*?signing[:\s]*(\w+)",
    re.IGNORECASE,
)

# Matches relay list generation messages
RE_RELAY_LIST = re.compile(r"(?:relay|gen-relay|relayable)[:\s]+(.+)", re.IGNORECASE)


def parse_verbose_signing_info(stdout: str, stderr: str) -> dict:
    """Parse verbose SMB --gen-relay-list output for detailed signing info.

    Verbose output may include INFO lines with:
    - Signing negotiation details per host
    - SMB dialect/version info
    - SMB capabilities (encryption, message signing flags)
    - Security mode details
    - Per-host signing status

    Returns dict with parsed verbose signing data.
    """
    verbose_data = {
        "hosts": {},  # Per-host signing info: {host: {signing: bool, dialect: str, ...}}
        "dialect": None,  # Global/first-seen dialect
        "smbv1_enabled": None,  # SMBv1 status if detected
        "security_mode": None,  # Security mode string
        "capabilities": [],  # List of detected capabilities
        "encryption_supported": None,
        "info_messages": [],  # Relevant INFO/verbose messages
        "errors": [],  # Error messages
        "hosts_signing_required": [],  # Hosts with signing required
        "hosts_signing_not_required": [],  # Hosts with signing not required (relayable)
    }

    # Track IP to hostname mappings to avoid duplicates
    ip_to_hostname = {}

    def get_canonical_host(ip_addr, hostname):
        """Get the canonical host key, preferring hostname over IP.

        Also consolidates entries if we later discover an IP maps to a hostname.
        Returns the canonical host key to use.
        """
        # If we have both, prefer hostname and track the mapping
        if hostname and ip_addr:
            # Check if we already have an entry for this IP
            if ip_addr in ip_to_hostname:
                # Already mapped, use the existing hostname
                return ip_to_hostname[ip_addr]

            # Check if IP was already added as a host entry - need to consolidate
            if ip_addr in verbose_data["hosts"] and hostname not in verbose_data["hosts"]:
                # Move the IP entry to the hostname entry
                verbose_data["hosts"][hostname] = verbose_data["hosts"].pop(ip_addr)
                verbose_data["hosts"][hostname]["ip"] = ip_addr

                # Update the signing lists
                if ip_addr in verbose_data["hosts_signing_required"]:
                    verbose_data["hosts_signing_required"].remove(ip_addr)
                    if hostname not in verbose_data["hosts_signing_required"]:
                        verbose_data["hosts_signing_required"].append(hostname)
                if ip_addr in verbose_data["hosts_signing_not_required"]:
                    verbose_data["hosts_signing_not_required"].remove(ip_addr)
                    if hostname not in verbose_data["hosts_signing_not_required"]:
                        verbose_data["hosts_signing_not_required"].append(hostname)

            # Record the mapping
            ip_to_hostname[ip_addr] = hostname
            return hostname

        # If we only have IP, check if it's already mapped to a hostname
        if ip_addr and not hostname:
            if ip_addr in ip_to_hostname:
                return ip_to_hostname[ip_addr]
            return ip_addr

        # If we only have hostname
        if hostname:
            return hostname

        return None

    # Combine stdout and stderr (some verbose info may go to stderr)
    combined_output = stdout + "\n" + stderr

    for line in combined_output.split("\n"):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Parse signing status from standard format (signing:True/False)
        signing_match = RE_SIGNING_STATUS.search(line_stripped)
        if signing_match:
            signing_value = signing_match.group(1).lower()
            signing_required = signing_value == "true"

            # Extract host from this line - prefer hostname over IP to avoid duplicates
            hostname = None
            ip_addr = None
            hostname_match = RE_HOSTNAME.search(line_stripped)
            ip_match = RE_HOST_IP.search(line_stripped)

            if hostname_match:
                hostname = hostname_match.group(1)
            if ip_match:
                ip_addr = ip_match.group(1)

            # Get canonical host key (consolidates IP and hostname as same host)
            primary_host = get_canonical_host(ip_addr, hostname)

            if primary_host:
                if primary_host not in verbose_data["hosts"]:
                    verbose_data["hosts"][primary_host] = {}
                verbose_data["hosts"][primary_host]["signing_required"] = signing_required
                # Store IP if we have it
                if ip_addr:
                    verbose_data["hosts"][primary_host]["ip"] = ip_addr

                # Categorize hosts
                if signing_required:
                    if primary_host not in verbose_data["hosts_signing_required"]:
                        verbose_data["hosts_signing_required"].append(primary_host)
                else:
                    if primary_host not in verbose_data["hosts_signing_not_required"]:
                        verbose_data["hosts_signing_not_required"].append(primary_host)

        # Parse SMBv1 status
        smbv1_match = RE_SMBV1.search(line_stripped)
        if smbv1_match:
            smbv1_value = smbv1_match.group(1).lower()
            verbose_data["smbv1_enabled"] = smbv1_value == "true"

            # Associate with host if possible
            host = None
            hostname_match = RE_HOSTNAME.search(line_stripped)
            if hostname_match:
                host = hostname_match.group(1)
            if host and host in verbose_data["hosts"]:
                verbose_data["hosts"][host]["smbv1"] = verbose_data["smbv1_enabled"]

        # Parse negotiated dialect
        dialect_match = RE_NEGOTIATED_DIALECT.search(line_stripped)
        if dialect_match:
            dialect = dialect_match.group(1)
            if not verbose_data["dialect"]:
                verbose_data["dialect"] = normalize_smb_dialect(dialect)

            # Associate with host if detectable
            host = None
            hostname_match = RE_HOSTNAME.search(line_stripped)
            if hostname_match:
                host = hostname_match.group(1)
            if host and host in verbose_data["hosts"]:
                verbose_data["hosts"][host]["dialect"] = normalize_smb_dialect(dialect)
        elif not verbose_data["dialect"]:
            # Alternative dialect detection
            alt_dialect_match = RE_SMB_DIALECT.search(line_stripped)
            if alt_dialect_match:
                dialect = alt_dialect_match.group(1)
                if dialect not in ("1", "445"):  # Filter port numbers
                    verbose_data["dialect"] = normalize_smb_dialect(dialect)

        # Parse security mode
        secmode_match = RE_SECURITY_MODE.search(line_stripped)
        if secmode_match and not verbose_data["security_mode"]:
            verbose_data["security_mode"] = secmode_match.group(1).strip()

        # Parse capabilities
        caps_match = RE_CAPABILITIES.search(line_stripped)
        if caps_match:
            caps_str = caps_match.group(1)
            caps = [cap.strip() for cap in re.split(r"[,\s|]+", caps_str) if cap.strip()]
            for cap in caps:
                if cap not in verbose_data["capabilities"]:
                    verbose_data["capabilities"].append(cap)

        # Parse encryption support
        enc_match = RE_ENCRYPTION.search(line_stripped)
        if enc_match:
            enc_value = enc_match.group(1).lower()
            verbose_data["encryption_supported"] = enc_value in (
                "true",
                "yes",
                "enabled",
                "supported",
                "1",
            )

        # Parse INFO lines for signing negotiation details
        if "INFO" in line_stripped.upper() or "[*]" in line_stripped:
            # Skip generic nxc verbose lines (connection noise, not signing data)
            noise_keywords = [
                "Socket info:",
                "Creating SMB",
                "Resolved domain",
                "kerberos=",
                "ipv6=",
                "link-local",
                "kdcHost:",
                "hostname=",
                "host=",
            ]
            if any(kw in line_stripped for kw in noise_keywords):
                continue

            info_signing_match = RE_INFO_SIGNING.search(line_stripped)
            if info_signing_match:
                msg = line_stripped
                # Clean up the message
                for marker in ["[*]", "[+]", "[-]", "INFO", "DEBUG"]:
                    msg = msg.replace(marker, "").strip()
                if msg and msg not in verbose_data["info_messages"]:
                    verbose_data["info_messages"].append(msg)

            # Capture host-specific signing details from INFO lines
            host_signing_match = RE_HOST_SIGNING.search(line_stripped)
            if host_signing_match:
                matched_host = host_signing_match.group(1)
                sign_status = host_signing_match.group(2).lower()
                signing_req = sign_status in ("true", "required", "enabled", "yes")

                # Also try to extract both IP and hostname from the full line
                # to properly consolidate duplicates
                hostname = None
                ip_addr = None
                hostname_match = RE_HOSTNAME.search(line_stripped)
                ip_match = RE_HOST_IP.search(line_stripped)

                if hostname_match:
                    hostname = hostname_match.group(1)
                if ip_match:
                    ip_addr = ip_match.group(1)

                # If matched_host looks like an IP but we also have a hostname,
                # use the canonical lookup
                if ip_addr or hostname:
                    primary_host = get_canonical_host(ip_addr, hostname)
                else:
                    # Fallback to what was matched
                    primary_host = matched_host

                if primary_host:
                    if primary_host not in verbose_data["hosts"]:
                        verbose_data["hosts"][primary_host] = {}
                    verbose_data["hosts"][primary_host]["signing_required"] = signing_req
                    if ip_addr:
                        verbose_data["hosts"][primary_host]["ip"] = ip_addr

                    if signing_req:
                        if primary_host not in verbose_data["hosts_signing_required"]:
                            verbose_data["hosts_signing_required"].append(primary_host)
                    else:
                        if primary_host not in verbose_data["hosts_signing_not_required"]:
                            verbose_data["hosts_signing_not_required"].append(primary_host)

        # Parse error messages
        if "[-]" in line_stripped or "ERROR" in line_stripped.upper():
            # Skip noise but capture meaningful errors
            if not is_nxc_noise_line(line_stripped):
                msg = line_stripped
                for marker in ["[-]", "ERROR"]:
                    msg = msg.replace(marker, "").strip()
                if msg and "timeout" not in msg.lower() and msg not in verbose_data["errors"]:
                    verbose_data["errors"].append(msg)

    return verbose_data


def normalize_smb_dialect(dialect: str) -> str:
    """Normalize SMB dialect string to standard format.

    Converts various dialect representations to standard form:
    - '2' or '2.0' -> '2.0'
    - '2.1' -> '2.1'
    - '3' or '3.0' -> '3.0'
    - '3.0.2' or '302' -> '3.0.2'
    - '3.1.1' or '311' -> '3.1.1'
    """
    dialect = dialect.strip()

    # Handle numeric-only formats
    if dialect.isdigit():
        if dialect == "2":
            return "2.0"
        elif dialect == "3":
            return "3.0"
        elif dialect == "21":
            return "2.1"
        elif dialect == "30":
            return "3.0"
        elif dialect == "302":
            return "3.0.2"
        elif dialect == "311":
            return "3.1.1"

    # Handle simple numeric strings
    if dialect == "2":
        return "2.0"
    elif dialect == "3":
        return "3.0"

    return dialect


def _display_verbose_signing_info(verbose_data: dict, args):
    """Display additional signing information from verbose output."""
    has_verbose = any(
        [
            verbose_data.get("dialect"),
            verbose_data.get("security_mode"),
            verbose_data.get("capabilities"),
            verbose_data.get("smbv1_enabled") is not None,
            verbose_data.get("encryption_supported") is not None,
        ]
    )

    if not has_verbose:
        return

    output("")
    output(c("SMB Signing Details:", Colors.CYAN))

    # Display dialect if detected
    if verbose_data.get("dialect"):
        dialect = verbose_data["dialect"]
        dialect_color = Colors.GREEN if dialect in ("3.0.2", "3.1.1") else Colors.YELLOW
        output(f"  Dialect: {c(f'SMB {dialect}', dialect_color)}")

    # Display SMBv1 status
    if verbose_data.get("smbv1_enabled") is not None:
        smbv1 = verbose_data["smbv1_enabled"]
        output(f"  SMBv1: {c('enabled', Colors.RED) if smbv1 else c('disabled', Colors.GREEN)}")

    # Display security mode
    if verbose_data.get("security_mode"):
        output(f"  Security Mode: {verbose_data['security_mode']}")

    # Display encryption support
    if verbose_data.get("encryption_supported") is not None:
        enc = verbose_data["encryption_supported"]
        enc_status = "supported" if enc else "not supported"
        enc_color = Colors.GREEN if enc else Colors.YELLOW
        output(f"  Encryption: {c(enc_status, enc_color)}")

    # Display capabilities
    if verbose_data.get("capabilities"):
        output(f"  Capabilities: {', '.join(sorted(verbose_data['capabilities']))}")


def _display_per_host_info(verbose_data: dict):
    """Display per-host signing information from verbose output."""
    hosts_info = verbose_data.get("hosts", {})
    if not hosts_info or len(hosts_info) <= 1:
        return

    output("")
    output(c("Per-Host Signing Status:", Colors.CYAN))

    for host, info in sorted(hosts_info.items()):
        signing_req = info.get("signing_required")
        dialect = info.get("dialect")
        smbv1 = info.get("smbv1")

        if signing_req is None:
            continue

        # Build status string
        status_parts = []

        if signing_req:
            status_parts.append(c("signing required", Colors.GREEN))
        else:
            status_parts.append(c("signing NOT required", Colors.RED))

        if dialect:
            status_parts.append(f"SMB {dialect}")

        if smbv1 is not None:
            smbv1_str = c("SMBv1", Colors.RED) if smbv1 else "no SMBv1"
            status_parts.append(smbv1_str)

        host_color = Colors.RED if not signing_req else Colors.GREEN
        output(f"  {c(host, host_color)}: {', '.join(status_parts)}")


def enum_signing(args, cache):
    """Check SMB signing requirements with verbose output parsing."""
    print_section("SMB Signing Check", args.target)

    status("Checking SMB signing requirements...")

    signing_args = ["smb", args.target, "--gen-relay-list", "/dev/null"]
    rc, stdout, stderr = run_nxc(signing_args, args.timeout)
    debug_nxc(signing_args, stdout, stderr, "SMB Signing")

    # Parse verbose output for additional details
    verbose_data = parse_verbose_signing_info(stdout, stderr)

    signing_required = True
    hosts_without_signing = []

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        if "(signing:False)" in line or "signing:False" in line:
            signing_required = False
            hostname_match = RE_HOSTNAME.search(line)
            if hostname_match:
                host = hostname_match.group(1)
                if host not in hosts_without_signing:
                    hosts_without_signing.append(host)
            else:
                if args.target not in hosts_without_signing:
                    hosts_without_signing.append(args.target)

    # Merge hosts from verbose parsing
    for host in verbose_data.get("hosts_signing_not_required", []):
        if host not in hosts_without_signing:
            hosts_without_signing.append(host)
            signing_required = False

    cache.smb_signing_disabled = hosts_without_signing

    # Store verbose signing info in cache
    cache.smb_signing_info = {
        "hosts": verbose_data.get("hosts", {}),
        "dialect": verbose_data.get("dialect"),
        "smbv1_enabled": verbose_data.get("smbv1_enabled"),
        "security_mode": verbose_data.get("security_mode"),
        "capabilities": verbose_data.get("capabilities", []),
        "encryption_supported": verbose_data.get("encryption_supported"),
        "hosts_signing_required": verbose_data.get("hosts_signing_required", []),
        "hosts_signing_not_required": hosts_without_signing,
        "info_messages": verbose_data.get("info_messages", []),
        "errors": verbose_data.get("errors", []),
    }

    if not signing_required:
        status(
            f"SMB signing is {c('NOT REQUIRED', Colors.RED)} - vulnerable to relay attacks!",
            "warning",
        )
        for host in hosts_without_signing:
            output(f"  {c(host, Colors.RED)}")

        # Display per-host details if multiple hosts
        _display_per_host_info(verbose_data)

        # Display verbose signing details
        _display_verbose_signing_info(verbose_data, args)

        # Add relay attack recommendation
        cache.add_next_step(
            finding="SMB signing not required",
            command=f"ntlmrelayx.py -t {args.target} -smb2support",
            description="Relay captured NTLM authentication to execute commands",
            priority="high",
        )

        # If SMBv1 is enabled, add EternalBlue recommendation
        if verbose_data.get("smbv1_enabled"):
            cache.add_next_step(
                finding="SMBv1 enabled on target",
                command=f"nmap -p 445 --script smb-vuln-ms17-010 {args.target}",
                description="Check for EternalBlue (MS17-010) vulnerability",
                priority="high",
            )
    else:
        status(f"SMB signing is {c('REQUIRED', Colors.GREEN)} - relay attacks blocked", "success")

        # Display verbose signing details even when signing is required
        _display_verbose_signing_info(verbose_data, args)

        # Display per-host details if multiple hosts
        _display_per_host_info(verbose_data)

    # Display any info messages from verbose output (filter out raw nxc lines)
    if verbose_data.get("info_messages"):
        # Filter out raw nxc protocol output lines
        filtered_msgs = [
            msg for msg in verbose_data["info_messages"]
            if not msg.strip().startswith(("SMB", "LDAP", "RPC"))
            and "445" not in msg[:50]  # Skip lines with port numbers near start
        ]
        if filtered_msgs:
            output("")
            output(c("Signing Negotiation Info:", Colors.CYAN))
            for msg in filtered_msgs[:5]:  # Limit to first 5
                output(f"  {msg}")

    if args.json_output:
        JSON_DATA["smb_signing"] = {
            "required": signing_required,
            "vulnerable_hosts": hosts_without_signing,
            "hosts_signing_required": verbose_data.get("hosts_signing_required", []),
            "dialect": verbose_data.get("dialect"),
            "smbv1_enabled": verbose_data.get("smbv1_enabled"),
            "security_mode": verbose_data.get("security_mode"),
            "capabilities": verbose_data.get("capabilities", []),
            "encryption_supported": verbose_data.get("encryption_supported"),
            "per_host_info": verbose_data.get("hosts", {}),
            "info_messages": verbose_data.get("info_messages", []),
            "errors": verbose_data.get("errors", []),
        }
