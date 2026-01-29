"""Domain intelligence gathering."""

import re

from ..core.colors import Colors, c
from ..core.constants import (
    RE_DOMAIN,
    RE_DOMAIN_NAME,
    RE_DOMAIN_SID,
    RE_DOMAIN_SID_FULL,
    RE_HOSTNAME,
    RE_NAME,
)
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc

# Regex patterns for verbose domain output parsing
# Domain functional level (e.g., "domainFunctionality: 7")
RE_DOMAIN_FUNCTIONAL_LEVEL = re.compile(
    r"(?:domain\s*functional(?:ity)?(?:\s*level)?|domainfunctionality)\s*[:=]\s*(.+)",
    re.IGNORECASE,
)
# Forest functional level (e.g., "forestFunctionality: 7")
RE_FOREST_FUNCTIONAL_LEVEL = re.compile(
    r"(?:forest\s*functional(?:ity)?(?:\s*level)?|forestfunctionality)\s*[:=]\s*(.+)",
    re.IGNORECASE,
)
# Domain controller functional level
RE_DC_FUNCTIONAL_LEVEL = re.compile(
    r"(?:domaincontrollerfunctionality|dc\s*functional(?:ity)?(?:\s*level)?)\s*[:=]\s*(.+)",
    re.IGNORECASE,
)
# Schema version (e.g., "schemaVersion: 87" or "Schema Version: 87")
RE_SCHEMA_VERSION = re.compile(r"schema\s*version\s*[:=]\s*(\d+)", re.IGNORECASE)
# Forest name/root domain
RE_FOREST_NAME = re.compile(
    r"(?:forest(?:\s*name)?|root\s*domain(?:\s*naming\s*context)?)\s*[:=]\s*(.+)", re.IGNORECASE
)
# Default naming context (DN of domain)
RE_NAMING_CONTEXT = re.compile(
    r"(?:default\s*naming\s*context|rootdomainnamingcontext)\s*[:=]\s*(.+)", re.IGNORECASE
)
# LDAP server name (DC's FQDN)
RE_LDAP_SERVER = re.compile(
    r"(?:ldap\s*service\s*name|servername|dnsHostName)\s*[:=]\s*(.+)", re.IGNORECASE
)
# Site name
RE_SITE_NAME = re.compile(r"(?:site\s*name|serversite)\s*[:=]\s*(.+)", re.IGNORECASE)
# Domain GUID
RE_DOMAIN_GUID = re.compile(
    r"(?:domain\s*guid|objectguid)\s*[:=]\s*([a-f0-9\-]{36})", re.IGNORECASE
)
# Is Global Catalog
RE_IS_GC = re.compile(
    r"(?:is\s*global\s*catalog|isglobalcatalogready)\s*[:=]\s*(\w+)", re.IGNORECASE
)
# LDAP policies (maxPageSize, etc.)
RE_LDAP_POLICY = re.compile(r"(max\w+|min\w+)\s*[:=]\s*(\d+)", re.IGNORECASE)

# Functional level mappings (numeric value to Windows version)
FUNCTIONAL_LEVEL_MAP = {
    "0": "Windows 2000",
    "1": "Windows Server 2003 Interim",
    "2": "Windows Server 2003",
    "3": "Windows Server 2008",
    "4": "Windows Server 2008 R2",
    "5": "Windows Server 2012",
    "6": "Windows Server 2012 R2",
    "7": "Windows Server 2016",
    "8": "Windows Server 2019",
    "9": "Windows Server 2022",
}

# Schema version mappings
SCHEMA_VERSION_MAP = {
    "13": "Windows 2000",
    "30": "Windows Server 2003",
    "31": "Windows Server 2003 R2",
    "44": "Windows Server 2008",
    "47": "Windows Server 2008 R2",
    "56": "Windows Server 2012",
    "69": "Windows Server 2012 R2",
    "87": "Windows Server 2016",
    "88": "Windows Server 2019/2022",
}


def resolve_functional_level(value: str) -> str:
    """Resolve functional level value to human-readable Windows version.

    Args:
        value: The functional level value (numeric or text)

    Returns:
        Human-readable Windows version string
    """
    value = value.strip()
    # If numeric, map to version name
    if value.isdigit():
        return FUNCTIONAL_LEVEL_MAP.get(value, f"Level {value}")
    # Already text, return cleaned up
    return value


def resolve_schema_version(value: str) -> str:
    """Resolve schema version to Windows version.

    Args:
        value: The schema version number

    Returns:
        Human-readable Windows version string or raw value
    """
    value = value.strip()
    return SCHEMA_VERSION_MAP.get(value, f"Version {value}")


def parse_verbose_domain_output(stdout: str) -> dict:
    """Parse verbose LDAP/SMB output for additional domain information.

    Verbose output may include INFO lines with:
    - Domain functional level
    - Forest functional level
    - DC functional level
    - Schema version
    - Forest name / root domain
    - Naming context
    - LDAP server name
    - Site name
    - Domain GUID
    - Global Catalog status
    - LDAP policies (maxPageSize, etc.)

    Returns dict with parsed verbose domain data.
    """
    verbose_data = {
        "domain_functional_level": None,
        "domain_functional_level_raw": None,
        "forest_functional_level": None,
        "forest_functional_level_raw": None,
        "dc_functional_level": None,
        "schema_version": None,
        "schema_version_raw": None,
        "forest_name": None,
        "naming_context": None,
        "ldap_server": None,
        "site_name": None,
        "domain_guid": None,
        "is_global_catalog": None,
        "ldap_policies": {},
    }

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Domain functional level
        match = RE_DOMAIN_FUNCTIONAL_LEVEL.search(line)
        if match and not verbose_data["domain_functional_level"]:
            raw_value = match.group(1).strip()
            verbose_data["domain_functional_level_raw"] = raw_value
            verbose_data["domain_functional_level"] = resolve_functional_level(raw_value)
            continue

        # Forest functional level
        match = RE_FOREST_FUNCTIONAL_LEVEL.search(line)
        if match and not verbose_data["forest_functional_level"]:
            raw_value = match.group(1).strip()
            verbose_data["forest_functional_level_raw"] = raw_value
            verbose_data["forest_functional_level"] = resolve_functional_level(raw_value)
            continue

        # DC functional level
        match = RE_DC_FUNCTIONAL_LEVEL.search(line)
        if match and not verbose_data["dc_functional_level"]:
            raw_value = match.group(1).strip()
            verbose_data["dc_functional_level"] = resolve_functional_level(raw_value)
            continue

        # Schema version
        match = RE_SCHEMA_VERSION.search(line)
        if match and not verbose_data["schema_version"]:
            raw_value = match.group(1).strip()
            verbose_data["schema_version_raw"] = raw_value
            verbose_data["schema_version"] = resolve_schema_version(raw_value)
            continue

        # Forest name
        match = RE_FOREST_NAME.search(line)
        if match and not verbose_data["forest_name"]:
            verbose_data["forest_name"] = match.group(1).strip()
            continue

        # Naming context
        match = RE_NAMING_CONTEXT.search(line)
        if match and not verbose_data["naming_context"]:
            verbose_data["naming_context"] = match.group(1).strip()
            continue

        # LDAP server name
        match = RE_LDAP_SERVER.search(line)
        if match and not verbose_data["ldap_server"]:
            verbose_data["ldap_server"] = match.group(1).strip()
            continue

        # Site name
        match = RE_SITE_NAME.search(line)
        if match and not verbose_data["site_name"]:
            verbose_data["site_name"] = match.group(1).strip()
            continue

        # Domain GUID
        match = RE_DOMAIN_GUID.search(line)
        if match and not verbose_data["domain_guid"]:
            verbose_data["domain_guid"] = match.group(1).strip()
            continue

        # Global Catalog status
        match = RE_IS_GC.search(line)
        if match and verbose_data["is_global_catalog"] is None:
            gc_value = match.group(1).strip().lower()
            verbose_data["is_global_catalog"] = gc_value in ("true", "yes", "1")
            continue

        # LDAP policies
        match = RE_LDAP_POLICY.search(line)
        if match:
            policy_name = match.group(1).strip()
            policy_value = match.group(2).strip()
            # Only capture interesting policies
            if policy_name.lower() in (
                "maxpagesize",
                "maxquerysize",
                "maxvalrange",
                "maxtempobjects",
                "maxresults",
                "maxbatchreturn",
                "minpwdlength",
                "maxpwdage",
            ):
                verbose_data["ldap_policies"][policy_name] = int(policy_value)

    # Clean up None values from the ldap_policies if empty
    if not verbose_data["ldap_policies"]:
        del verbose_data["ldap_policies"]

    return verbose_data


def enum_domain_intelligence(args, cache, listener_results: dict):
    """Consolidated domain information from LDAP, SMB, and RPC sources."""
    target = cache.target if cache else args.target
    print_section("Domain Intelligence", target, cache=cache)

    auth = cache.auth_args
    domain_info = {
        "domain_sid": None,
        "domain_name": None,
        "dns_domain": None,
        "hostname": None,
        "fqdn": None,
        "is_dc": False,
        "netbios_domain": None,
        # Verbose-specific domain attributes
        "domain_functional_level": None,
        "forest_functional_level": None,
        "dc_functional_level": None,
        "schema_version": None,
        "forest_name": None,
        "naming_context": None,
        "site_name": None,
        "domain_guid": None,
        "is_global_catalog": None,
        "ldap_policies": {},
    }
    # Track raw values separately for JSON output
    verbose_raw = {}

    # --- Collect from LDAP ---
    ldap_info = listener_results.get("LDAP", {})
    if ldap_info.get("open", False):
        status("Gathering from LDAP...")

        # Get domain SID via LDAP
        ldap_sid_args = ["ldap", target] + auth + ["--get-sid"]
        rc, stdout, stderr = run_nxc(ldap_sid_args, args.timeout)
        debug_nxc(ldap_sid_args, stdout, stderr, "LDAP Get-SID")
        for line in stdout.split("\n"):
            sid_match = RE_DOMAIN_SID.search(line)
            if sid_match:
                domain_info["domain_sid"] = sid_match.group(1)
                break

        # Check if it's a DC
        rc2, stdout2, stderr2 = cache.get_ldap_basic(target, auth)
        for line in stdout2.split("\n"):
            if "DC" in line or "Domain Controller" in line:
                domain_info["is_dc"] = True
            domain_match = RE_DOMAIN.search(line)
            if domain_match and not domain_info["dns_domain"]:
                domain_info["dns_domain"] = domain_match.group(1)
            if domain_info["is_dc"] and domain_info["dns_domain"]:
                break

        # Parse verbose output for additional domain attributes
        verbose_data = parse_verbose_domain_output(stdout)
        verbose_data2 = parse_verbose_domain_output(stdout2)

        # Merge verbose data (first source takes precedence for each field)
        for key, value in verbose_data.items():
            if value is not None and (key not in domain_info or domain_info.get(key) is None):
                domain_info[key] = value
                # Store raw values for JSON
                if key.endswith("_raw"):
                    verbose_raw[key] = value

        for key, value in verbose_data2.items():
            if value is not None and (key not in domain_info or domain_info.get(key) is None):
                domain_info[key] = value
                if key.endswith("_raw"):
                    verbose_raw[key] = value

        # Merge ldap_policies dicts
        if verbose_data.get("ldap_policies"):
            domain_info["ldap_policies"].update(verbose_data.get("ldap_policies", {}))
        if verbose_data2.get("ldap_policies"):
            domain_info["ldap_policies"].update(verbose_data2.get("ldap_policies", {}))

    # --- Collect from SMB ---
    status("Gathering from SMB...")
    rc, stdout, stderr = cache.get_smb_basic(target, auth)
    if stdout:
        _name_match = RE_NAME.search(stdout)  # noqa: F841 - parsed but hostname used instead
        domain_match = RE_DOMAIN.search(stdout)
        hostname_match = RE_HOSTNAME.search(stdout)

        if hostname_match:
            domain_info["hostname"] = hostname_match.group(1)
        if domain_match and not domain_info["dns_domain"]:
            domain_info["dns_domain"] = domain_match.group(1)

        # Parse verbose SMB output for additional domain attributes
        smb_verbose = parse_verbose_domain_output(stdout)
        for key, value in smb_verbose.items():
            if value is not None and (key not in domain_info or domain_info.get(key) is None):
                domain_info[key] = value
                if key.endswith("_raw"):
                    verbose_raw[key] = value
        if smb_verbose.get("ldap_policies"):
            domain_info["ldap_policies"].update(smb_verbose.get("ldap_policies", {}))

    # --- Collect from RPC (RID brute) ---
    status("Gathering from RPC...")
    rc, stdout, stderr = cache.get_rid_brute(target, auth)
    for line in stdout.split("\n"):
        if not domain_info["domain_sid"]:
            sid_match = RE_DOMAIN_SID_FULL.search(line)
            if sid_match:
                domain_info["domain_sid"] = sid_match.group(1)
        if not domain_info["domain_name"]:
            domain_match = RE_DOMAIN_NAME.search(line)
            if domain_match:
                domain_info["domain_name"] = domain_match.group(1)
        if domain_info["domain_sid"] and domain_info["domain_name"]:
            break

    # --- Derive missing fields ---
    dns_domain = domain_info.get("dns_domain")
    if dns_domain and not domain_info["domain_name"]:
        domain_info["domain_name"] = dns_domain.split(".")[0].upper()
    if dns_domain and not domain_info["netbios_domain"]:
        domain_info["netbios_domain"] = dns_domain.split(".")[0].upper()
    if domain_info["hostname"] and dns_domain:
        domain_info["fqdn"] = f"{domain_info['hostname']}.{dns_domain}"

    # Validate: if domain_name equals hostname, it's likely the machine name not domain name
    # This happens on member servers where RID brute returns MS01\Administrator
    hostname = domain_info.get("hostname", "").upper()
    if domain_info["domain_name"] and domain_info["domain_name"].upper() == hostname:
        # Clear misleading domain_name - it's just the machine name
        domain_info["domain_name"] = ""
        domain_info["netbios_domain"] = ""

    # --- Display consolidated results ---
    output("")
    if domain_info["is_dc"]:
        status("Target is a Domain Controller", "success")
    if domain_info.get("is_global_catalog"):
        status("Target is a Global Catalog server", "success")

    if domain_info["hostname"]:
        output(f"  Hostname:        {c(domain_info['hostname'], Colors.BOLD)}")
    if domain_info["fqdn"]:
        output(f"  FQDN:            {c(domain_info['fqdn'], Colors.CYAN)}")
    if domain_info["domain_name"]:
        output(f"  NetBIOS Domain:  {c(domain_info['domain_name'], Colors.BOLD)}")
    if domain_info["dns_domain"]:
        output(f"  DNS Domain:      {c(domain_info['dns_domain'], Colors.CYAN)}")
    if domain_info["domain_sid"]:
        output(f"  Domain SID:      {c(domain_info['domain_sid'], Colors.GREEN)}")

    # Display verbose domain attributes if available
    _display_verbose_domain_info(domain_info)

    if args.json_output:
        # Include raw values in JSON for detailed analysis
        json_domain = domain_info.copy()
        json_domain["verbose_raw"] = verbose_raw
        JSON_DATA["domain"] = json_domain

    cache.domain_info = domain_info


def _display_verbose_domain_info(domain_info: dict):
    """Display additional domain information from verbose output.

    Args:
        domain_info: Dictionary containing domain information
    """
    has_verbose = any(
        [
            domain_info.get("domain_functional_level"),
            domain_info.get("forest_functional_level"),
            domain_info.get("schema_version"),
            domain_info.get("forest_name"),
            domain_info.get("site_name"),
            domain_info.get("naming_context"),
        ]
    )

    if not has_verbose:
        return

    output("")
    output(c("Domain Attributes (verbose)", Colors.CYAN))
    output("-" * 50)

    # Functional levels - highlight older versions as potential security concerns
    if domain_info.get("domain_functional_level"):
        level = domain_info["domain_functional_level"]
        # Older functional levels may allow weaker security settings
        level_color = (
            Colors.YELLOW if "2008" in level or "2003" in level or "2000" in level else Colors.WHITE
        )
        output(f"  Domain Func. Level:  {c(level, level_color)}")

    if domain_info.get("forest_functional_level"):
        level = domain_info["forest_functional_level"]
        level_color = (
            Colors.YELLOW if "2008" in level or "2003" in level or "2000" in level else Colors.WHITE
        )
        output(f"  Forest Func. Level:  {c(level, level_color)}")

    if domain_info.get("dc_functional_level"):
        output(f"  DC Func. Level:      {domain_info['dc_functional_level']}")

    if domain_info.get("schema_version"):
        output(f"  Schema Version:      {domain_info['schema_version']}")

    if domain_info.get("forest_name"):
        output(f"  Forest Name:         {c(domain_info['forest_name'], Colors.CYAN)}")

    if domain_info.get("site_name"):
        output(f"  Site Name:           {domain_info['site_name']}")

    if domain_info.get("naming_context"):
        nc = domain_info["naming_context"]
        # Truncate if too long
        if len(nc) > 45:
            nc = nc[:42] + "..."
        output(f"  Naming Context:      {nc}")

    if domain_info.get("domain_guid"):
        output(f"  Domain GUID:         {domain_info['domain_guid']}")

    # Display LDAP policies if available
    if domain_info.get("ldap_policies"):
        output("")
        output(c("LDAP Policies", Colors.CYAN))
        for policy, value in domain_info["ldap_policies"].items():
            output(f"  {policy}: {value}")
