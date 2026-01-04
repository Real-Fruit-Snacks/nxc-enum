"""Domain controller and trust enumeration."""

import re
from ..core.runner import run_nxc
from ..core.output import output, status, print_section, debug_nxc, JSON_DATA
from ..core.colors import Colors, c
from ..parsing.nxc_output import is_nxc_noise_line


# Regex patterns for parsing verbose DC and trust output
# DC role patterns (PDC Emulator, GC, RID Master, Schema Master, etc.)
RE_DC_ROLE_PDC = re.compile(r'\b(?:PDC|Primary\s+Domain\s+Controller|PdcRoleOwner)\b', re.IGNORECASE)
RE_DC_ROLE_GC = re.compile(r'\b(?:GC|Global\s+Catalog|isGlobalCatalog(?:Ready)?)\b', re.IGNORECASE)
RE_DC_ROLE_RID = re.compile(r'\b(?:RID\s+Master|RidRoleOwner|RID\s+Pool)\b', re.IGNORECASE)
RE_DC_ROLE_SCHEMA = re.compile(r'\b(?:Schema\s+Master|SchemaMaster|SchemaRoleOwner)\b', re.IGNORECASE)
RE_DC_ROLE_INFRA = re.compile(r'\b(?:Infrastructure\s+Master|InfrastructureRoleOwner)\b', re.IGNORECASE)
RE_DC_ROLE_NAMING = re.compile(r'\b(?:Domain\s+Naming\s+Master|NamingRoleOwner)\b', re.IGNORECASE)
RE_DC_RODC = re.compile(r'\b(?:RODC|Read[- ]?Only\s+Domain\s+Controller)\b', re.IGNORECASE)

# Site information patterns
RE_SITE_NAME = re.compile(r'(?:Site|siteName)[:\s=]+([^\s,\n\r]+)', re.IGNORECASE)
RE_SITE_LINK = re.compile(r'(?:SiteLink|Site\s+Link)[:\s=]+([^\n\r]+)', re.IGNORECASE)
RE_SUBNET = re.compile(r'(?:Subnet)[:\s=]+([^\n\r]+)', re.IGNORECASE)

# Trust relationship patterns
RE_TRUST_DIRECTION = re.compile(
    r'(?:Direction|TrustDirection)[:\s=]*(Bidirectional|Inbound|Outbound|BiDi)',
    re.IGNORECASE
)
RE_TRUST_TYPE = re.compile(
    r'(?:Type|TrustType)[:\s=]*(Forest|External|Parent[- ]?Child|TreeRoot|CrossLink|Kerberos|MIT)',
    re.IGNORECASE
)
RE_TRUST_ATTRIBUTES = re.compile(
    r'(?:Attributes?|TrustAttributes)[:\s=]*(\S+)',
    re.IGNORECASE
)
RE_TRUST_PARTNER = re.compile(
    r'(?:Partner|TrustPartner|TrustedDomain)[:\s=]+([^\s,\n\r]+)',
    re.IGNORECASE
)
RE_TRUST_SID_FILTERING = re.compile(
    r'(?:SID\s*Filtering|SIDFiltering)[:\s=]*(Enabled|Disabled|True|False|Yes|No)',
    re.IGNORECASE
)
RE_TRUST_TRANSITIVE = re.compile(
    r'(?:Transitive|IsTransitive)[:\s=]*(True|False|Yes|No)',
    re.IGNORECASE
)
RE_TRUST_SID_HISTORY = re.compile(
    r'(?:SID\s*History|SIDHistory)[:\s=]*(Enabled|Disabled|True|False|Yes|No)',
    re.IGNORECASE
)

# Domain/forest level from verbose output
RE_FOREST_ROOT = re.compile(r'(?:Forest\s+Root|RootDomain)[:\s=]+([^\s,\n\r]+)', re.IGNORECASE)
RE_FOREST_LEVEL = re.compile(r'(?:Forest\s+)?Functional\s*Level[:\s=]+([^\n\r]+)', re.IGNORECASE)

# DC hostname/IP extraction
RE_DC_ENTRY = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z0-9\.\-]+)\s*[=:]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')


def _parse_dc_roles(line: str) -> list:
    """Parse DC role indicators from a line.

    Returns list of role strings (e.g., ['PDC', 'GC', 'Schema Master']).
    """
    roles = []

    if RE_DC_ROLE_PDC.search(line):
        roles.append('PDC')
    if RE_DC_ROLE_GC.search(line):
        roles.append('GC')
    if RE_DC_ROLE_RID.search(line):
        roles.append('RID Master')
    if RE_DC_ROLE_SCHEMA.search(line):
        roles.append('Schema Master')
    if RE_DC_ROLE_INFRA.search(line):
        roles.append('Infrastructure Master')
    if RE_DC_ROLE_NAMING.search(line):
        roles.append('Naming Master')
    if RE_DC_RODC.search(line):
        roles.append('RODC')

    return roles


def _parse_trust_details(lines: list) -> list:
    """Parse detailed trust information from verbose output.

    Returns list of trust dicts with detailed attributes.
    """
    trusts = []
    current_trust = None

    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Look for trust partner/domain (starts a new trust entry)
        partner_match = RE_TRUST_PARTNER.search(line_stripped)
        if partner_match:
            # Save previous trust if exists
            if current_trust and current_trust.get('partner'):
                trusts.append(current_trust)
            current_trust = {
                'partner': partner_match.group(1).strip(),
                'direction': None,
                'type': None,
                'attributes': None,
                'sid_filtering': None,
                'transitive': None,
                'sid_history': None
            }
            continue

        # Also check for simple "Trust:" lines
        if 'Trust:' in line_stripped or ('trust' in line_stripped.lower() and 'relationship' in line_stripped.lower()):
            # Extract trust name from after colon
            if ':' in line_stripped:
                trust_name = line_stripped.split(':')[-1].strip()
                if trust_name and not current_trust:
                    current_trust = {
                        'partner': trust_name,
                        'direction': None,
                        'type': None,
                        'attributes': None,
                        'sid_filtering': None,
                        'transitive': None,
                        'sid_history': None
                    }
            continue

        if not current_trust:
            continue

        # Parse trust direction
        dir_match = RE_TRUST_DIRECTION.search(line_stripped)
        if dir_match:
            current_trust['direction'] = dir_match.group(1).strip()
            continue

        # Parse trust type
        type_match = RE_TRUST_TYPE.search(line_stripped)
        if type_match:
            current_trust['type'] = type_match.group(1).strip()
            continue

        # Parse trust attributes
        attr_match = RE_TRUST_ATTRIBUTES.search(line_stripped)
        if attr_match:
            current_trust['attributes'] = attr_match.group(1).strip()
            continue

        # Parse SID filtering status
        sid_filter_match = RE_TRUST_SID_FILTERING.search(line_stripped)
        if sid_filter_match:
            val = sid_filter_match.group(1).lower()
            current_trust['sid_filtering'] = val in ('enabled', 'true', 'yes')
            continue

        # Parse transitive flag
        trans_match = RE_TRUST_TRANSITIVE.search(line_stripped)
        if trans_match:
            val = trans_match.group(1).lower()
            current_trust['transitive'] = val in ('true', 'yes')
            continue

        # Parse SID history flag
        sid_hist_match = RE_TRUST_SID_HISTORY.search(line_stripped)
        if sid_hist_match:
            val = sid_hist_match.group(1).lower()
            current_trust['sid_history'] = val in ('enabled', 'true', 'yes')
            continue

    # Save last trust if exists
    if current_trust and current_trust.get('partner'):
        trusts.append(current_trust)

    return trusts


def _parse_site_info(lines: list) -> dict:
    """Parse AD site information from verbose output.

    Returns dict with site details.
    """
    site_info = {
        'sites': [],
        'site_links': [],
        'subnets': []
    }

    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Site name
        site_match = RE_SITE_NAME.search(line_stripped)
        if site_match:
            site_name = site_match.group(1).strip()
            if site_name and site_name not in site_info['sites']:
                site_info['sites'].append(site_name)
            continue

        # Site links
        link_match = RE_SITE_LINK.search(line_stripped)
        if link_match:
            link = link_match.group(1).strip()
            if link and link not in site_info['site_links']:
                site_info['site_links'].append(link)
            continue

        # Subnets
        subnet_match = RE_SUBNET.search(line_stripped)
        if subnet_match:
            subnet = subnet_match.group(1).strip()
            if subnet and subnet not in site_info['subnets']:
                site_info['subnets'].append(subnet)
            continue

    return site_info


def _parse_verbose_dc_info(stdout: str) -> dict:
    """Parse verbose --dc-list output for additional DC and forest metadata.

    Returns dict with:
        - dc_details: list of DC dicts with roles and site info
        - trust_details: list of detailed trust dicts
        - site_info: dict with site/subnet details
        - forest_root: forest root domain if found
        - forest_level: forest functional level if found
        - info_messages: list of relevant INFO lines
    """
    verbose_data = {
        'dc_details': {},  # keyed by DC name/IP
        'trust_details': [],
        'site_info': {'sites': [], 'site_links': [], 'subnets': []},
        'forest_root': None,
        'forest_level': None,
        'info_messages': []
    }

    lines = stdout.split('\n')

    # First pass: extract DC role associations
    # Look for lines that mention DC names/IPs and roles together
    current_dc = None

    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Check for DC entry (hostname = IP format)
        dc_match = RE_DC_ENTRY.search(line_stripped)
        if dc_match:
            dc_name = dc_match.group(1).strip()
            dc_ip = dc_match.group(2).strip()
            current_dc = dc_name

            if dc_name not in verbose_data['dc_details']:
                verbose_data['dc_details'][dc_name] = {
                    'hostname': dc_name,
                    'ip': dc_ip,
                    'roles': [],
                    'site': None,
                    'is_gc': False,
                    'is_rodc': False
                }

            # Check for roles on the same line
            roles = _parse_dc_roles(line_stripped)
            for role in roles:
                if role not in verbose_data['dc_details'][dc_name]['roles']:
                    verbose_data['dc_details'][dc_name]['roles'].append(role)
                if role == 'GC':
                    verbose_data['dc_details'][dc_name]['is_gc'] = True
                if role == 'RODC':
                    verbose_data['dc_details'][dc_name]['is_rodc'] = True

            # Check for site on the same line
            site_match = RE_SITE_NAME.search(line_stripped)
            if site_match:
                verbose_data['dc_details'][dc_name]['site'] = site_match.group(1).strip()

            continue

        # If we have a current DC, check subsequent lines for role info
        if current_dc and current_dc in verbose_data['dc_details']:
            roles = _parse_dc_roles(line_stripped)
            for role in roles:
                if role not in verbose_data['dc_details'][current_dc]['roles']:
                    verbose_data['dc_details'][current_dc]['roles'].append(role)
                if role == 'GC':
                    verbose_data['dc_details'][current_dc]['is_gc'] = True
                if role == 'RODC':
                    verbose_data['dc_details'][current_dc]['is_rodc'] = True

            # Check for site info
            site_match = RE_SITE_NAME.search(line_stripped)
            if site_match:
                verbose_data['dc_details'][current_dc]['site'] = site_match.group(1).strip()

        # Forest root domain
        forest_match = RE_FOREST_ROOT.search(line_stripped)
        if forest_match and not verbose_data['forest_root']:
            verbose_data['forest_root'] = forest_match.group(1).strip()

        # Forest functional level
        level_match = RE_FOREST_LEVEL.search(line_stripped)
        if level_match and not verbose_data['forest_level']:
            verbose_data['forest_level'] = level_match.group(1).strip()

        # Capture INFO lines related to DC/trust enumeration
        if 'INFO' in line_stripped.upper() or '[*]' in line_stripped:
            keywords = ['dc', 'domain controller', 'trust', 'forest', 'site', 'catalog', 'pdc', 'rodc', 'fsmo']
            if any(kw in line_stripped.lower() for kw in keywords):
                verbose_data['info_messages'].append(line_stripped)

    # Parse trust details
    verbose_data['trust_details'] = _parse_trust_details(lines)

    # Parse site information
    verbose_data['site_info'] = _parse_site_info(lines)

    return verbose_data


def enum_dc_list(args, cache):
    """List domain controllers and trusts."""
    print_section("Domain Controllers & Trusts", args.target)

    auth = cache.auth_args
    status("Querying domain controllers and trusts...")

    dc_args = ["ldap", args.target] + auth + ["--dc-list"]
    rc, stdout, stderr = run_nxc(dc_args, args.timeout)
    debug_nxc(dc_args, stdout, stderr, "DC List")

    dcs = []
    trusts = []

    for line in stdout.split('\n'):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue

        if '[*]' in line or '[+]' in line or '[-]' in line:
            continue

        if '=' in line and '.' in line:
            parts = line.split('=')
            if len(parts) >= 2:
                dc_ip = parts[-1].strip()
                pre_equals = parts[0].strip()
                fqdn_parts = pre_equals.split()
                if fqdn_parts:
                    dc_name = fqdn_parts[-1]
                    if dc_name and dc_ip and '.' in dc_name:
                        dcs.append(f"{dc_name} ({dc_ip})")

        if 'Trust:' in line or ('trust' in line.lower() and 'relationship' in line.lower()):
            trust_info = line.split(':')[-1].strip() if ':' in line else line
            if trust_info and trust_info not in trusts:
                trusts.append(trust_info)

    # Parse verbose output for additional DC and trust details
    verbose_info = _parse_verbose_dc_info(stdout)

    cache.domain_controllers = dcs
    cache.domain_trusts = trusts

    # Store verbose DC info in cache
    if not hasattr(cache, 'dc_verbose_info'):
        cache.dc_verbose_info = {}
    cache.dc_verbose_info = verbose_info

    # Update domain_info with forest info if found
    if verbose_info.get('forest_root') and not cache.domain_info.get('forest_root'):
        cache.domain_info['forest_root'] = verbose_info['forest_root']
    if verbose_info.get('forest_level') and not cache.domain_info.get('forest_level'):
        cache.domain_info['forest_level'] = verbose_info['forest_level']

    if dcs:
        status(f"Found {len(dcs)} Domain Controller(s):", "info")
        for dc in dcs:
            output(f"  {c(dc, Colors.CYAN)}")

            # Show DC roles if available from verbose output
            dc_name = dc.split(' (')[0] if ' (' in dc else dc
            if dc_name in verbose_info['dc_details']:
                dc_detail = verbose_info['dc_details'][dc_name]
                if dc_detail.get('roles'):
                    roles_str = ', '.join(dc_detail['roles'])
                    output(f"    Roles: {c(roles_str, Colors.GREEN)}")
                if dc_detail.get('site'):
                    output(f"    Site: {dc_detail['site']}")
                if dc_detail.get('is_rodc'):
                    output(f"    {c('Read-Only Domain Controller', Colors.YELLOW)}")

    # Display site information if available
    _print_site_info(verbose_info['site_info'])

    if trusts:
        status(f"Found {len(trusts)} Trust Relationship(s):", "warning")
        for trust in trusts:
            output(f"  {c(trust, Colors.YELLOW)}")

        # Display detailed trust information if available
        _print_trust_details(verbose_info['trust_details'], cache)
    else:
        status("No trust relationships found", "info")

    # Display forest information if available
    _print_forest_info(verbose_info)

    # Add next steps for interesting findings
    _add_dc_next_steps(dcs, trusts, verbose_info, cache, args)

    if args.json_output:
        JSON_DATA['dc_list'] = {
            'domain_controllers': dcs,
            'trusts': trusts,
            'dc_details': list(verbose_info['dc_details'].values()),
            'trust_details': verbose_info['trust_details'],
            'site_info': verbose_info['site_info'],
            'forest_root': verbose_info['forest_root'],
            'forest_level': verbose_info['forest_level']
        }


def _print_site_info(site_info: dict):
    """Print AD site information if available."""
    if not site_info.get('sites') and not site_info.get('subnets'):
        return

    output("")
    output(c("Site Information:", Colors.CYAN))

    if site_info.get('sites'):
        for site in site_info['sites']:
            output(f"  Site: {site}")

    if site_info.get('subnets'):
        for subnet in site_info['subnets']:
            output(f"  Subnet: {subnet}")

    if site_info.get('site_links'):
        for link in site_info['site_links']:
            output(f"  Site Link: {link}")


def _print_trust_details(trust_details: list, cache):
    """Print detailed trust relationship information."""
    if not trust_details:
        return

    output("")
    output(c("Trust Details (from verbose output):", Colors.CYAN))

    for trust in trust_details:
        partner = trust.get('partner', 'Unknown')
        output(f"  {c(partner, Colors.YELLOW)}:")

        if trust.get('direction'):
            # Highlight bidirectional trusts as they can be more impactful
            direction = trust['direction']
            if 'bidirectional' in direction.lower() or 'bidi' in direction.lower():
                output(f"    Direction: {c(direction, Colors.YELLOW)}")
            else:
                output(f"    Direction: {direction}")

        if trust.get('type'):
            # Highlight forest trusts as they span multiple domains
            trust_type = trust['type']
            if 'forest' in trust_type.lower():
                output(f"    Type: {c(trust_type, Colors.YELLOW)}")
            else:
                output(f"    Type: {trust_type}")

        if trust.get('transitive') is not None:
            trans_str = "Yes" if trust['transitive'] else "No"
            output(f"    Transitive: {trans_str}")

        if trust.get('sid_filtering') is not None:
            # SID filtering disabled is a security concern
            if not trust['sid_filtering']:
                output(f"    SID Filtering: {c('DISABLED', Colors.RED)} {c('(Security Risk)', Colors.RED)}")
            else:
                output(f"    SID Filtering: {c('Enabled', Colors.GREEN)}")

        if trust.get('sid_history') is not None:
            # SID history enabled can be abused
            if trust['sid_history']:
                output(f"    SID History: {c('ENABLED', Colors.YELLOW)} {c('(Potential for abuse)', Colors.YELLOW)}")
            else:
                output(f"    SID History: Disabled")

        if trust.get('attributes'):
            output(f"    Attributes: {trust['attributes']}")


def _print_forest_info(verbose_info: dict):
    """Print forest-level information if available."""
    if not verbose_info.get('forest_root') and not verbose_info.get('forest_level'):
        return

    output("")
    output(c("Forest Information:", Colors.CYAN))

    if verbose_info.get('forest_root'):
        output(f"  Forest Root: {verbose_info['forest_root']}")

    if verbose_info.get('forest_level'):
        level = verbose_info['forest_level']
        # Highlight old functional levels
        old_levels = ['2003', '2008', '2008 R2', '2000']
        if any(old in level for old in old_levels):
            output(f"  Forest Functional Level: {c(level, Colors.YELLOW)} {c('(Legacy)', Colors.YELLOW)}")
        else:
            output(f"  Forest Functional Level: {level}")


def _add_dc_next_steps(dcs: list, trusts: list, verbose_info: dict, cache, args):
    """Add relevant next steps based on DC and trust findings."""

    # Check for FSMO role holders
    fsmo_roles = []
    for dc_name, dc_detail in verbose_info.get('dc_details', {}).items():
        if 'PDC' in dc_detail.get('roles', []):
            fsmo_roles.append(f"PDC: {dc_name}")
        if 'Schema Master' in dc_detail.get('roles', []):
            fsmo_roles.append(f"Schema: {dc_name}")

    if fsmo_roles:
        cache.add_next_step(
            finding=f"FSMO roles identified: {', '.join(fsmo_roles[:2])}",
            command=f"nxc ldap {args.target} -u <user> -p <pass> --get-sid",
            description="Target FSMO role holders for high-value attacks",
            priority="low"
        )

    # Check for trust relationships with security concerns
    for trust in verbose_info.get('trust_details', []):
        partner = trust.get('partner', 'Unknown')

        # SID filtering disabled
        if trust.get('sid_filtering') is False:
            cache.add_next_step(
                finding=f"Trust to {partner} has SID filtering disabled",
                command=f"nxc ldap {partner} -u <user>@<trusted_domain> -p <pass> --users",
                description="SID filtering disabled allows cross-domain privilege escalation",
                priority="high"
            )

        # Bidirectional forest trust
        if trust.get('type') and 'forest' in trust['type'].lower():
            if trust.get('direction') and 'bidirectional' in trust['direction'].lower():
                cache.add_next_step(
                    finding=f"Bidirectional forest trust with {partner}",
                    command=f"nxc ldap {partner} -u <user>@<domain> -p <pass> --trusted-for-delegation",
                    description="Enumerate trusted forest for delegation abuse paths",
                    priority="medium"
                )

    # Check for RODCs
    rodcs = [dc for dc_name, dc in verbose_info.get('dc_details', {}).items() if dc.get('is_rodc')]
    if rodcs:
        rodc_names = [r['hostname'] for r in rodcs]
        cache.add_next_step(
            finding=f"RODC(s) found: {', '.join(rodc_names[:2])}",
            command="nxc ldap <rodc> -u <user> -p <pass> -M laps",
            description="RODCs may have cached credentials for local accounts",
            priority="low"
        )

    # Multiple DCs suggests larger environment - recommend bloodhound
    if len(dcs) >= 3:
        cache.add_next_step(
            finding=f"Large domain with {len(dcs)} DCs",
            command=f"bloodhound-python -u <user> -p <pass> -d <domain> -dc {args.target} -c all",
            description="Collect BloodHound data for attack path analysis",
            priority="medium"
        )
