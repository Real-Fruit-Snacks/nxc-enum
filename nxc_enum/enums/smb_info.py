"""SMB dialect and signing information."""

import re

from ..core.output import output, status, print_section, JSON_DATA
from ..core.colors import Colors, c
from ..core.constants import RE_SIGNING, RE_SMBV1
from ..parsing.nxc_output import is_nxc_noise_line


# Regex patterns for verbose SMB output parsing
# Note: Must not match IP addresses like 10.0.24.230 - SMB versions are 1, 2, 2.1, 3, 3.0, 3.0.2, 3.1.1
RE_SMB_DIALECT = re.compile(r'(?:SMB|dialect)[:\s]+([123](?:\.[01](?:\.[012])?)?)\b', re.IGNORECASE)
RE_SMB_DIALECT_VERSION = re.compile(r'\bSMB\s*([123](?:\.[01](?:\.[012])?)?)\b', re.IGNORECASE)
RE_NEGOTIATED_DIALECT = re.compile(r'(?:negotiated|selected|using)\s+(?:dialect\s+)?(?:SMB\s*)?(\d+(?:\.\d+)*)', re.IGNORECASE)
RE_SMB_CAPABILITIES = re.compile(r'(?:capabilities|caps)[:\s]+(.+)', re.IGNORECASE)
RE_SMB_ENCRYPTION = re.compile(r'(?:encryption)[:\s]+(\w+)', re.IGNORECASE)
RE_SMB_SECURITY_MODE = re.compile(r'(?:security.?mode|secmode)[:\s]+(.+)', re.IGNORECASE)
RE_MESSAGE_SIGNING = re.compile(r'message.?signing[:\s]+(\w+)', re.IGNORECASE)
RE_MULTI_CHANNEL = re.compile(r'(?:multi.?channel)[:\s]+(\w+)', re.IGNORECASE)
RE_SMB_VERSION_LINE = re.compile(r'\[(?:\*|\+|INFO)\].*(?:SMB|dialect)', re.IGNORECASE)
RE_SMB_MAX_READ = re.compile(r'(?:max.?read|maxread)[:\s]+(\d+)', re.IGNORECASE)
RE_SMB_MAX_WRITE = re.compile(r'(?:max.?write|maxwrite)[:\s]+(\d+)', re.IGNORECASE)
RE_SMB_SERVER_GUID = re.compile(r'(?:server.?guid|guid)[:\s]+([a-f0-9-]+)', re.IGNORECASE)


def parse_verbose_smb_info(stdout: str, stderr: str) -> dict:
    """Parse verbose SMB output for dialect and capability details.

    Verbose output may include INFO lines with:
    - Negotiated SMB dialect (2.0, 2.1, 3.0, 3.0.2, 3.1.1)
    - SMB capabilities (encryption, multi-channel, etc.)
    - Security mode (message signing enabled/required)
    - Server GUID
    - Max read/write sizes

    Returns dict with parsed verbose SMB data.
    """
    verbose_data = {
        'dialect': None,
        'dialects_supported': [],
        'capabilities': [],
        'encryption_supported': None,
        'multi_channel': None,
        'security_mode': None,
        'message_signing': None,
        'max_read_size': None,
        'max_write_size': None,
        'server_guid': None,
        'info_messages': []
    }

    # Combine stdout and stderr for parsing (some verbose info may go to stderr)
    combined_output = stdout + "\n" + stderr

    for line in combined_output.split('\n'):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Skip noise lines but continue looking for verbose data
        if is_nxc_noise_line(line_stripped):
            # Still check for dialect info in noise lines as it may be embedded
            pass

        # Parse negotiated dialect
        dialect_match = RE_NEGOTIATED_DIALECT.search(line_stripped)
        if dialect_match:
            dialect = dialect_match.group(1)
            verbose_data['dialect'] = normalize_dialect(dialect)
            verbose_data['info_messages'].append(f"Negotiated dialect: SMB {verbose_data['dialect']}")
            continue

        # Alternative dialect detection from version lines
        if 'SMB' in line_stripped.upper() and not verbose_data['dialect']:
            version_match = RE_SMB_DIALECT_VERSION.search(line_stripped)
            if version_match:
                dialect = version_match.group(1)
                if dialect and dialect not in ('1', '445'):  # Filter out port numbers
                    verbose_data['dialect'] = normalize_dialect(dialect)

        # Parse capabilities
        caps_match = RE_SMB_CAPABILITIES.search(line_stripped)
        if caps_match:
            caps_str = caps_match.group(1)
            # Parse capability flags (may be comma-separated or space-separated)
            caps = [cap.strip() for cap in re.split(r'[,\s|]+', caps_str) if cap.strip()]
            verbose_data['capabilities'].extend(caps)
            continue

        # Parse encryption support
        enc_match = RE_SMB_ENCRYPTION.search(line_stripped)
        if enc_match:
            enc_value = enc_match.group(1).lower()
            verbose_data['encryption_supported'] = enc_value in ('true', 'yes', 'enabled', 'supported', '1')
            continue

        # Parse multi-channel support
        mc_match = RE_MULTI_CHANNEL.search(line_stripped)
        if mc_match:
            mc_value = mc_match.group(1).lower()
            verbose_data['multi_channel'] = mc_value in ('true', 'yes', 'enabled', 'supported', '1')
            continue

        # Parse security mode
        sec_match = RE_SMB_SECURITY_MODE.search(line_stripped)
        if sec_match:
            verbose_data['security_mode'] = sec_match.group(1).strip()
            continue

        # Parse message signing
        sign_match = RE_MESSAGE_SIGNING.search(line_stripped)
        if sign_match:
            sign_value = sign_match.group(1).lower()
            verbose_data['message_signing'] = sign_value
            continue

        # Parse max read size
        max_read_match = RE_SMB_MAX_READ.search(line_stripped)
        if max_read_match:
            try:
                verbose_data['max_read_size'] = int(max_read_match.group(1))
            except ValueError:
                pass
            continue

        # Parse max write size
        max_write_match = RE_SMB_MAX_WRITE.search(line_stripped)
        if max_write_match:
            try:
                verbose_data['max_write_size'] = int(max_write_match.group(1))
            except ValueError:
                pass
            continue

        # Parse server GUID
        guid_match = RE_SMB_SERVER_GUID.search(line_stripped)
        if guid_match:
            verbose_data['server_guid'] = guid_match.group(1)
            continue

        # Capture relevant INFO/verbose lines about SMB
        if RE_SMB_VERSION_LINE.search(line_stripped):
            if line_stripped not in verbose_data['info_messages']:
                verbose_data['info_messages'].append(line_stripped)

    # Deduplicate capabilities
    verbose_data['capabilities'] = list(set(verbose_data['capabilities']))

    return verbose_data


def normalize_dialect(dialect: str) -> str:
    """Normalize SMB dialect string to standard format.

    Converts various dialect representations to standard form:
    - '2' or '2.0' -> '2.0'
    - '2.1' -> '2.1'
    - '3' or '3.0' -> '3.0'
    - '3.0.2' or '302' -> '3.0.2'
    - '3.1.1' or '311' -> '3.1.1'
    """
    dialect = dialect.strip()

    # Handle numeric-only formats (e.g., '311' -> '3.1.1')
    if dialect.isdigit():
        if dialect == '2':
            return '2.0'
        elif dialect == '3':
            return '3.0'
        elif dialect == '21':
            return '2.1'
        elif dialect == '30':
            return '3.0'
        elif dialect == '302':
            return '3.0.2'
        elif dialect == '311':
            return '3.1.1'

    # Handle standard formats
    if dialect == '2':
        return '2.0'
    elif dialect == '3':
        return '3.0'

    return dialect


def infer_dialect_from_os(os_info: str, build_number: int = 0) -> str:
    """Infer likely SMB dialect from OS information and build number.

    This is used as a fallback when verbose dialect info is unavailable.
    Returns the highest dialect likely supported by the OS.
    """
    os_lower = os_info.lower() if os_info else ''

    # Windows version detection based on build numbers and OS strings
    if 'windows server 2022' in os_lower or build_number >= 20348:
        return '3.1.1'
    elif 'windows 11' in os_lower or build_number >= 22000:
        return '3.1.1'
    elif 'windows 10' in os_lower or (build_number >= 10240 and build_number < 22000):
        return '3.1.1' if build_number >= 14393 else '3.0'
    elif 'windows server 2019' in os_lower or build_number >= 17763:
        return '3.1.1'
    elif 'windows server 2016' in os_lower or build_number >= 14393:
        return '3.1.1'
    elif 'windows 8.1' in os_lower or 'windows server 2012 r2' in os_lower:
        return '3.0.2'
    elif 'windows 8' in os_lower or 'windows server 2012' in os_lower:
        return '3.0'
    elif 'windows 7' in os_lower or 'windows server 2008 r2' in os_lower:
        return '2.1'
    elif 'windows vista' in os_lower or 'windows server 2008' in os_lower:
        return '2.0'
    elif 'samba' in os_lower:
        # Modern Samba typically supports up to 3.1.1
        return '3.1.1'

    # Default for unrecognized systems
    return 'unknown'


def get_dialect_security_notes(dialect: str) -> list:
    """Get security notes for a given SMB dialect."""
    notes = []

    if dialect == '2.0':
        notes.append("SMB 2.0: No encryption support, consider upgrading")
    elif dialect == '2.1':
        notes.append("SMB 2.1: Limited security features, no encryption")
    elif dialect == '3.0':
        notes.append("SMB 3.0: Encryption available but may need explicit enabling")
    elif dialect in ('3.0.2', '3.1.1'):
        notes.append(f"SMB {dialect}: Modern protocol with encryption support")

    return notes


def enum_smb_info(args, cache):
    """Get SMB information including signing, dialect, and capabilities."""
    print_section("SMB Dialect Check", args.target)

    status("Trying on 445/tcp")

    # Use cached SMB connection
    auth = cache.auth_args
    rc, stdout, stderr = cache.get_smb_basic(args.target, auth)

    if rc != 0 and "not found" in stderr:
        status("netexec not found in PATH", "error")
        return

    # Parse verbose SMB info from output
    verbose_info = parse_verbose_smb_info(stdout, stderr)

    # Parse SMB info from output using pre-compiled regex
    signing_match = RE_SIGNING.search(stdout)
    smbv1_match = RE_SMBV1.search(stdout)

    smbv1 = False
    if smbv1_match:
        smbv1 = smbv1_match.group(1).lower() == "true"

    signing = False
    if signing_match:
        signing = signing_match.group(1).lower() == "true"

    # Determine actual dialect - use verbose info or infer from OS
    dialect = verbose_info['dialect']
    dialect_inferred = False

    if not dialect:
        # Try to infer from cached domain info if available
        os_info = cache.domain_info.get('os', '')
        build_number = cache.domain_info.get('build', 0)
        dialect = infer_dialect_from_os(os_info, build_number)
        dialect_inferred = True

    # Display SMB dialect information
    status("SMB dialect information:", "success")

    # Show actual negotiated dialect
    if dialect and dialect != 'unknown':
        dialect_color = Colors.GREEN if dialect in ('3.0.2', '3.1.1') else Colors.YELLOW
        if dialect_inferred:
            output(f"  Dialect: {c(f'SMB {dialect}', dialect_color)} {c('(inferred from OS)', Colors.CYAN)}")
        else:
            output(f"  Dialect: {c(f'SMB {dialect}', dialect_color)}")

        # Show security notes for dialect
        for note in get_dialect_security_notes(dialect):
            note_color = Colors.GREEN if '3.0.2' in note or '3.1.1' in note else Colors.YELLOW
            output(f"    {c(note, note_color)}")

    # Show SMBv1 status
    output(f"  SMB 1.0: {c(str(smbv1).lower(), Colors.RED if smbv1 else Colors.GREEN)}")
    if smbv1:
        output(f"    {c('WARNING: SMBv1 enabled - vulnerable to EternalBlue/WannaCry', Colors.RED)}")
        cache.add_next_step(
            finding="SMBv1 enabled on target",
            command=f"nmap -p 445 --script smb-vuln-ms17-010 {args.target}",
            description="Check for EternalBlue (MS17-010) vulnerability",
            priority="high"
        )

    # Show signing status
    if signing:
        output(f"  Signing: {c('required', Colors.GREEN)} (secure)")
    else:
        output(f"  Signing: {c('not required', Colors.YELLOW)} {c('- Relay attacks possible!', Colors.YELLOW)}")

    # Show capabilities if detected from verbose output
    if verbose_info['capabilities']:
        output("")
        output(c("  SMB Capabilities:", Colors.CYAN))
        # Group and display capabilities
        cap_str = ', '.join(sorted(verbose_info['capabilities']))
        if len(cap_str) > 60:
            # Wrap long capability lists
            caps = sorted(verbose_info['capabilities'])
            for i in range(0, len(caps), 4):
                chunk = caps[i:i+4]
                output(f"    {', '.join(chunk)}")
        else:
            output(f"    {cap_str}")

    # Show encryption support
    if verbose_info['encryption_supported'] is not None:
        enc_status = 'enabled' if verbose_info['encryption_supported'] else 'disabled'
        enc_color = Colors.GREEN if verbose_info['encryption_supported'] else Colors.YELLOW
        output(f"  Encryption: {c(enc_status, enc_color)}")

    # Show multi-channel support
    if verbose_info['multi_channel'] is not None:
        mc_status = 'enabled' if verbose_info['multi_channel'] else 'disabled'
        output(f"  Multi-channel: {mc_status}")

    # Show security mode if available
    if verbose_info['security_mode']:
        output(f"  Security Mode: {verbose_info['security_mode']}")

    # Show server GUID if available
    if verbose_info['server_guid']:
        output(f"  Server GUID: {c(verbose_info['server_guid'], Colors.CYAN)}")

    # Show max read/write sizes if available (useful for tuning)
    if verbose_info['max_read_size'] or verbose_info['max_write_size']:
        output("")
        output(c("  Buffer Sizes:", Colors.CYAN))
        if verbose_info['max_read_size']:
            size_kb = verbose_info['max_read_size'] // 1024
            output(f"    Max Read: {size_kb} KB")
        if verbose_info['max_write_size']:
            size_kb = verbose_info['max_write_size'] // 1024
            output(f"    Max Write: {size_kb} KB")

    # Store comprehensive SMB info in cache
    cache.smb_info = {
        'smbv1': smbv1,
        'signing_required': signing,
        'dialect': dialect,
        'dialect_inferred': dialect_inferred,
        'capabilities': verbose_info['capabilities'],
        'encryption_supported': verbose_info['encryption_supported'],
        'multi_channel': verbose_info['multi_channel'],
        'security_mode': verbose_info['security_mode'],
        'server_guid': verbose_info['server_guid'],
        'max_read_size': verbose_info['max_read_size'],
        'max_write_size': verbose_info['max_write_size']
    }

    if args.json_output:
        JSON_DATA['smb'] = {
            'smbv1': smbv1,
            'signing_required': signing,
            'dialect': dialect,
            'dialect_inferred': dialect_inferred,
            'capabilities': verbose_info['capabilities'],
            'encryption_supported': verbose_info['encryption_supported'],
            'multi_channel': verbose_info['multi_channel'],
            'security_mode': verbose_info['security_mode'],
            'server_guid': verbose_info['server_guid'],
            'max_read_size': verbose_info['max_read_size'],
            'max_write_size': verbose_info['max_write_size']
        }
