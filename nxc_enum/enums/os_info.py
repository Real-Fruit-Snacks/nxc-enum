"""OS information enumeration."""

import re

from ..core.colors import Colors, c
from ..core.constants import RE_BUILD, RE_OS
from ..core.output import JSON_DATA, output, print_section, status

# Regex patterns for verbose OS output parsing
RE_ARCHITECTURE = re.compile(r"\b(x64|x86|ARM64|amd64|i386)\b", re.IGNORECASE)
RE_SERVICE_PACK = re.compile(r"(?:Service\s*Pack|SP)\s*(\d+)", re.IGNORECASE)
RE_OS_VERSION = re.compile(r"(?:version|ver)[:\s]+([0-9]+(?:\.[0-9]+)*)", re.IGNORECASE)
RE_OS_EDITION = re.compile(
    r"(Standard|Enterprise|Datacenter|Professional|Home|Education|Pro)", re.IGNORECASE
)
RE_WINDOWS_BUILD_DETAIL = re.compile(r"Build\s+(\d+)(?:\.(\d+))?", re.IGNORECASE)
RE_DOMAIN_ROLE = re.compile(r"(?:domain\s*role|role)[:\s]+(.+)", re.IGNORECASE)
RE_SERVER_TYPE = re.compile(r"(?:Windows\s+Server\s+)(\d{4}(?:\s+R2)?)", re.IGNORECASE)
RE_CLIENT_VERSION = re.compile(r"Windows\s+(10|11|7|8(?:\.1)?|Vista|XP)", re.IGNORECASE)
RE_SAMBA_VERSION = re.compile(r"Samba\s+([0-9]+(?:\.[0-9]+)*)", re.IGNORECASE)
RE_KERNEL_VERSION = re.compile(r"(?:kernel|Linux)[:\s]+([0-9]+(?:\.[0-9]+)*)", re.IGNORECASE)
RE_HOTFIX = re.compile(r"(?:hotfix|KB)(\d+)", re.IGNORECASE)


def parse_verbose_os_info(stdout: str, stderr: str) -> dict:
    """Parse verbose SMB output for detailed OS information.

    Verbose output may include INFO lines with:
    - Detailed OS edition (Standard, Enterprise, Datacenter, etc.)
    - Service pack information
    - Architecture details (x64, x86, ARM64)
    - Detailed build numbers (Build 20348.1234)
    - Domain role information
    - Samba version for Linux hosts
    - Installed hotfixes/patches

    Returns dict with parsed verbose OS data.
    """
    verbose_data = {
        "architecture": None,
        "service_pack": None,
        "edition": None,
        "version_detailed": None,
        "build_revision": None,
        "domain_role": None,
        "server_version": None,
        "client_version": None,
        "samba_version": None,
        "kernel_version": None,
        "hotfixes": [],
        "is_server": None,
        "is_domain_controller": None,
        "info_messages": [],
    }

    # Combine stdout and stderr for parsing (some verbose info may go to stderr)
    combined_output = stdout + "\n" + stderr

    for line in combined_output.split("\n"):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Parse architecture
        if not verbose_data["architecture"]:
            arch_match = RE_ARCHITECTURE.search(line_stripped)
            if arch_match:
                arch = arch_match.group(1).lower()
                # Normalize architecture names
                if arch in ("x64", "amd64"):
                    verbose_data["architecture"] = "x64"
                elif arch in ("x86", "i386"):
                    verbose_data["architecture"] = "x86"
                elif arch == "arm64":
                    verbose_data["architecture"] = "ARM64"

        # Parse service pack
        if not verbose_data["service_pack"]:
            sp_match = RE_SERVICE_PACK.search(line_stripped)
            if sp_match:
                verbose_data["service_pack"] = f"SP{sp_match.group(1)}"

        # Parse OS edition
        if not verbose_data["edition"]:
            edition_match = RE_OS_EDITION.search(line_stripped)
            if edition_match:
                verbose_data["edition"] = edition_match.group(1)

        # Parse detailed version
        if not verbose_data["version_detailed"]:
            ver_match = RE_OS_VERSION.search(line_stripped)
            if ver_match:
                verbose_data["version_detailed"] = ver_match.group(1)

        # Parse detailed build number with revision
        build_detail_match = RE_WINDOWS_BUILD_DETAIL.search(line_stripped)
        if build_detail_match:
            if build_detail_match.group(2):
                verbose_data["build_revision"] = build_detail_match.group(2)

        # Parse domain role
        if not verbose_data["domain_role"]:
            role_match = RE_DOMAIN_ROLE.search(line_stripped)
            if role_match:
                role = role_match.group(1).strip()
                verbose_data["domain_role"] = role
                # Detect domain controller
                if "domain controller" in role.lower() or "dc" in role.lower():
                    verbose_data["is_domain_controller"] = True

        # Parse Windows Server version
        if not verbose_data["server_version"]:
            server_match = RE_SERVER_TYPE.search(line_stripped)
            if server_match:
                verbose_data["server_version"] = server_match.group(1)
                verbose_data["is_server"] = True

        # Parse Windows client version
        if not verbose_data["client_version"]:
            client_match = RE_CLIENT_VERSION.search(line_stripped)
            if client_match:
                verbose_data["client_version"] = client_match.group(1)
                verbose_data["is_server"] = False

        # Parse Samba version (for Linux hosts)
        if not verbose_data["samba_version"]:
            samba_match = RE_SAMBA_VERSION.search(line_stripped)
            if samba_match:
                verbose_data["samba_version"] = samba_match.group(1)

        # Parse kernel version (for Linux hosts)
        if not verbose_data["kernel_version"]:
            kernel_match = RE_KERNEL_VERSION.search(line_stripped)
            if kernel_match:
                verbose_data["kernel_version"] = kernel_match.group(1)

        # Parse hotfixes
        for hotfix_match in RE_HOTFIX.finditer(line_stripped):
            kb = f"KB{hotfix_match.group(1)}"
            if kb not in verbose_data["hotfixes"]:
                verbose_data["hotfixes"].append(kb)

        # Capture relevant INFO lines about OS
        if "[INFO]" in line_stripped.upper() or "[*]" in line_stripped:
            if any(
                keyword in line_stripped.lower()
                for keyword in [
                    "os",
                    "version",
                    "build",
                    "windows",
                    "server",
                    "service pack",
                    "edition",
                    "samba",
                    "linux",
                ]
            ):
                if line_stripped not in verbose_data["info_messages"]:
                    verbose_data["info_messages"].append(line_stripped)

    return verbose_data


def get_os_security_notes(os_info: str, build: str, verbose_data: dict) -> list:
    """Generate security notes based on OS information."""
    notes = []
    os_lower = os_info.lower() if os_info else ""
    build_int = int(build) if build and build.isdigit() else 0

    # Check for outdated/vulnerable Windows versions
    if "windows 7" in os_lower or "windows server 2008" in os_lower:
        notes.append(("WARNING: End-of-life OS - no security updates!", "high"))
    elif "windows 8" in os_lower and "windows 8.1" not in os_lower:
        notes.append(("WARNING: End-of-life OS - upgrade recommended", "high"))
    elif "windows xp" in os_lower or "windows vista" in os_lower:
        notes.append(("CRITICAL: Ancient OS - extremely vulnerable!", "critical"))
    elif "windows server 2012" in os_lower and "r2" not in os_lower:
        notes.append(("WARNING: Extended support ended - upgrade recommended", "high"))

    # Check for missing service packs
    if "windows 7" in os_lower or "windows server 2008 r2" in os_lower:
        if not verbose_data.get("service_pack"):
            notes.append(("Missing service pack - may lack critical patches", "medium"))

    # Check for old builds of supported Windows versions
    if "windows 10" in os_lower or "windows 11" in os_lower:
        # Windows 10/11 build thresholds for supported versions
        if build_int > 0 and build_int < 19041:  # Before 20H1
            notes.append(("Outdated Windows 10 build - security updates may be limited", "medium"))

    # Note if it's a domain controller
    if verbose_data.get("is_domain_controller"):
        notes.append(("This is a Domain Controller - high-value target", "info"))

    # Samba-specific notes
    if verbose_data.get("samba_version"):
        samba_ver = verbose_data["samba_version"]
        try:
            major, minor = samba_ver.split(".")[:2]
            if int(major) < 4 or (int(major) == 4 and int(minor) < 13):
                notes.append(("Older Samba version - check for known vulnerabilities", "medium"))
        except (ValueError, IndexError):
            pass

    return notes


def infer_version_from_build(build: str) -> str:
    """Infer Windows version from build number."""
    if not build or not build.isdigit():
        return None

    build_int = int(build)

    # Windows build number to version mapping
    if build_int >= 22621:
        return "10.0 (Windows 11 22H2+)"
    elif build_int >= 22000:
        return "10.0 (Windows 11 21H2)"
    elif build_int >= 20348:
        return "10.0 (Server 2022)"
    elif build_int >= 19045:
        return "10.0 (Windows 10 22H2)"
    elif build_int >= 19044:
        return "10.0 (Windows 10 21H2)"
    elif build_int >= 19043:
        return "10.0 (Windows 10 21H1)"
    elif build_int >= 19042:
        return "10.0 (Windows 10 20H2)"
    elif build_int >= 19041:
        return "10.0 (Windows 10 2004)"
    elif build_int >= 18363:
        return "10.0 (Windows 10 1909)"
    elif build_int >= 17763:
        return "10.0 (Server 2019/Windows 10 1809)"
    elif build_int >= 17134:
        return "10.0 (Windows 10 1803)"
    elif build_int >= 16299:
        return "10.0 (Windows 10 1709)"
    elif build_int >= 15063:
        return "10.0 (Windows 10 1703)"
    elif build_int >= 14393:
        return "10.0 (Server 2016/Windows 10 1607)"
    elif build_int >= 10240:
        return "10.0 (Windows 10 RTM)"
    elif build_int >= 9600:
        return "6.3 (Server 2012 R2/Windows 8.1)"
    elif build_int >= 9200:
        return "6.2 (Server 2012/Windows 8)"
    elif build_int >= 7601:
        return "6.1 (Server 2008 R2 SP1/Windows 7 SP1)"
    elif build_int >= 7600:
        return "6.1 (Server 2008 R2/Windows 7)"
    elif build_int >= 6002:
        return "6.0 (Server 2008 SP2/Vista SP2)"
    elif build_int >= 6001:
        return "6.0 (Server 2008 SP1/Vista SP1)"
    elif build_int >= 6000:
        return "6.0 (Server 2008/Vista)"

    return None


def enum_os_info(args, cache):
    """Get OS information."""
    target = cache.target if cache else args.target
    print_section("OS Information via RPC", target)

    auth = cache.auth_args
    rc, stdout, stderr = cache.get_smb_basic(target, auth)

    if rc != 0 and not stdout:
        status("Could not get OS information", "error")
        return

    status("Enumerating via SMB session on 445/tcp")

    # Parse verbose OS info from output
    verbose_data = parse_verbose_os_info(stdout, stderr)

    # Parse: Windows Server 2022 Build 20348 x64 using pre-compiled regex
    os_match = RE_OS.search(stdout)

    if os_match:
        os_info = os_match.group(1).strip()
        status("Found OS information via SMB", "success")

        build_match = RE_BUILD.search(os_info)
        build = build_match.group(1) if build_match else "Unknown"

        # Infer version from build number
        version_inferred = infer_version_from_build(build)
        version = verbose_data.get("version_detailed") or version_inferred or "10.0"

        output(f"  OS: {os_info}")

        # Display version with inference note if applicable
        if version_inferred and not verbose_data.get("version_detailed"):
            output(f"  OS version: '{version}' {c('(inferred from build)', Colors.CYAN)}")
        else:
            output(f"  OS version: '{version}'")

        # Display architecture if detected
        if verbose_data.get("architecture"):
            output(f"  Architecture: {c(verbose_data['architecture'], Colors.CYAN)}")

        # Display edition if detected
        if verbose_data.get("edition"):
            output(f"  Edition: {verbose_data['edition']}")

        # Display build with revision if available
        if verbose_data.get("build_revision"):
            output(f"  OS build: '{build}.{verbose_data['build_revision']}'")
        else:
            output(f"  OS build: '{build}'")

        # Display service pack if detected
        if verbose_data.get("service_pack"):
            output(f"  Service Pack: {verbose_data['service_pack']}")

        # Display domain role if detected
        if verbose_data.get("domain_role"):
            role_color = Colors.RED if verbose_data.get("is_domain_controller") else Colors.CYAN
            output(f"  Domain Role: {c(verbose_data['domain_role'], role_color)}")

        # Display Samba info for Linux hosts
        if verbose_data.get("samba_version"):
            output(f"  Samba Version: {verbose_data['samba_version']}")
        if verbose_data.get("kernel_version"):
            output(f"  Kernel Version: {verbose_data['kernel_version']}")

        # Display hotfixes if detected
        if verbose_data.get("hotfixes"):
            output(f"  Detected Hotfixes: {', '.join(sorted(verbose_data['hotfixes']))}")

        # Display security notes
        security_notes = get_os_security_notes(os_info, build, verbose_data)
        if security_notes:
            output("")
            for note, severity in security_notes:
                if severity == "critical":
                    output(f"  {c(note, Colors.RED)}")
                elif severity == "high":
                    output(f"  {c(note, Colors.RED)}")
                elif severity == "medium":
                    output(f"  {c(note, Colors.YELLOW)}")
                else:
                    output(f"  {c(note, Colors.CYAN)}")

        # Store OS info in cache for other modules
        cache.domain_info["os"] = os_info
        cache.domain_info["build"] = int(build) if build.isdigit() else 0
        cache.domain_info["architecture"] = verbose_data.get("architecture")
        cache.domain_info["edition"] = verbose_data.get("edition")
        cache.domain_info["service_pack"] = verbose_data.get("service_pack")
        cache.domain_info["is_domain_controller"] = verbose_data.get("is_domain_controller")
        cache.domain_info["samba_version"] = verbose_data.get("samba_version")

        # Add next step recommendations based on findings
        if verbose_data.get("is_domain_controller"):
            cache.add_next_step(
                finding="Domain Controller detected",
                command=f"nxc ldap {target} -u USER -p PASS --trusted-for-delegation",
                description="Enumerate delegation settings on the DC",
                priority="high",
            )

        # Check for vulnerable OS versions
        if any(
            "end-of-life" in note[0].lower() or "ancient" in note[0].lower()
            for note in security_notes
        ):
            cache.add_next_step(
                finding="Outdated/vulnerable OS detected",
                command=f"nmap -sV --script vuln {target}",
                description="Scan for known vulnerabilities on legacy OS",
                priority="high",
            )

        if args.json_output:
            JSON_DATA["os"] = {
                "name": os_info,
                "version": version,
                "build": build,
                "build_revision": verbose_data.get("build_revision"),
                "architecture": verbose_data.get("architecture"),
                "edition": verbose_data.get("edition"),
                "service_pack": verbose_data.get("service_pack"),
                "domain_role": verbose_data.get("domain_role"),
                "is_domain_controller": verbose_data.get("is_domain_controller"),
                "is_server": verbose_data.get("is_server"),
                "samba_version": verbose_data.get("samba_version"),
                "kernel_version": verbose_data.get("kernel_version"),
                "hotfixes": verbose_data.get("hotfixes", []),
            }
    else:
        status("Could not parse OS information", "error")
