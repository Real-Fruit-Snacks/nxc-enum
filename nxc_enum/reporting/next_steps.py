"""Next steps / recommended commands section."""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, output, print_section

# Auto-exploit modules that automatically exploit vulnerabilities rather than just detecting them
# User should be warned when these are suggested as they may have unintended consequences
AUTO_EXPLOIT_MODULES = {
    # NetExec/CrackMapExec auto-exploit modules
    "-M printnightmare": "PrintNightmare (CVE-2021-34527) - auto-exploits print spooler",
    "-M zerologon": "ZeroLogon (CVE-2020-1472) - auto-exploits Netlogon",
    "-M petitpotam": "PetitPotam - coerces authentication (may trigger auto-relay)",
    "-M nopac": "noPac/sAMAccountName - auto-exploits CVE-2021-42278/CVE-2021-42287",
    "-M smbghost": "SMBGhost (CVE-2020-0796) - auto-exploits SMBv3",
    "-M ms17-010": "EternalBlue (MS17-010) - auto-exploits SMBv1",
    "-M dfscoerce": "DFSCoerce - coerces authentication",
    "-M shadowcoerce": "ShadowCoerce - coerces authentication",
    "-M drop-sc": "Drops malicious scheduled task",
    "-M handlekatz": "Dumps credentials via handle duplication",
    "-M nanodump": "Dumps LSASS memory",
    "-M procdump": "Dumps LSASS via procdump",
    "-M lsassy": "Dumps credentials from LSASS",
    "-M mimikatz": "Runs Mimikatz for credential extraction",
    "-M met_inject": "Injects Meterpreter shellcode",
    "-M shellcode_inject": "Injects arbitrary shellcode",
    "-M empire_exec": "Executes Empire stager",
    # Impacket auto-exploit tools
    "secretsdump": "Dumps secrets/hashes from SAM/NTDS",
    "ntlmrelayx": "Auto-relays NTLM authentication",
    "getST.py": "Requests service tickets (may auto-exploit)",
}

# Modules that CHECK for vulnerabilities but don't auto-exploit (generally OK)
VULN_CHECK_MODULES = {
    "-M webdav": "Checks if WebDAV is enabled",
    "-M spooler": "Checks if Print Spooler is running",
    "-M coerce_plus": "Checks for coercion vulnerabilities (detection only)",
}


def get_external_tool_auth(
    args,
    cache,
    tool: str = "impacket",
    include_domain: bool = True,
) -> dict:
    """Generate authentication arguments for external tools based on credential type.

    Returns a dict with different authentication string variants that can be used
    by different external tools. The caller can pick the appropriate format.

    Args:
        args: Parsed command-line arguments
        cache: EnumCache with credential/domain info
        tool: Tool family - "impacket", "certipy", "adidnsdump", "rusthound", "nxc"
        include_domain: Whether to include domain in the auth string

    Returns:
        dict with keys:
            - auth_string: Primary auth string for the tool (e.g., "-u user -p pass")
            - credential_format: Impacket format "domain/user:pass" or "domain/user" for kcache
            - kerberos_hint: Additional hint text for Kerberos users
            - auth_type: "password", "hash", "kerberos", "certificate", or "none"
            - is_kerberos: True if using Kerberos (kcache or aesKey)
    """
    # Get credentials from args or cache.primary_credential
    user = args.user if hasattr(args, "user") and args.user else None
    password = args.password if hasattr(args, "password") and args.password else None
    ntlm_hash = args.hash if hasattr(args, "hash") and args.hash else None
    domain = args.domain if hasattr(args, "domain") and args.domain else None
    use_kcache = getattr(args, "use_kcache", False)
    aes_key = getattr(args, "aes_key", None)
    kerberos = getattr(args, "kerberos", False)
    pfx_cert = getattr(args, "pfx_cert", None)
    pem_cert = getattr(args, "pem_cert", None)

    # Fall back to primary_credential from cache (for -C multi-cred mode)
    if not user and cache and cache.primary_credential:
        cred = cache.primary_credential
        user = cred.user
        password = cred.password
        ntlm_hash = cred.hash if not password else None
        domain = cred.domain if cred.domain else domain
        use_kcache = cred.use_kcache
        aes_key = cred.aes_key
        kerberos = cred.kerberos
        pfx_cert = cred.pfx_cert
        pem_cert = cred.pem_cert

    # Get domain from cache if not in args
    if not domain and cache and cache.domain_info:
        domain = cache.domain_info.get("dns_domain") or cache.domain_info.get("netbios_domain")

    # Default placeholders
    if not user:
        user = "<user>"
    if not domain:
        domain = "<domain>"

    # Determine auth type
    is_kerberos = use_kcache or bool(aes_key) or kerberos
    is_certificate = bool(pfx_cert) or bool(pem_cert)

    if is_certificate:
        auth_type = "certificate"
    elif is_kerberos:
        auth_type = "kerberos"
    elif password is not None:
        auth_type = "password"
    elif ntlm_hash:
        auth_type = "hash"
    else:
        auth_type = "none"

    result = {
        "auth_string": "",
        "credential_format": "",
        "kerberos_hint": "",
        "alt_auth_hint": "",
        "auth_type": auth_type,
        "is_kerberos": is_kerberos,
        "user": user,
        "domain": domain,
    }

    # Build tool-specific auth strings
    if tool == "impacket":
        # Impacket tools use: domain/user:password or domain/user with -k for kerberos
        if is_kerberos:
            if use_kcache:
                result["auth_string"] = "-k -no-pass"
                result["credential_format"] = f"'{domain}/{user}'"
                result["kerberos_hint"] = "  # Uses KRB5CCNAME environment variable"
            elif aes_key:
                result["auth_string"] = f"-aesKey '{aes_key}'"
                result["credential_format"] = f"'{domain}/{user}'"
                result["kerberos_hint"] = ""
            else:
                # Kerberos flag set but no kcache/aesKey - assume password with -k
                if password:
                    result["credential_format"] = f"'{domain}/{user}:{password}'"
                else:
                    result["credential_format"] = f"'{domain}/{user}:<pass>'"
                result["auth_string"] = "-k"
        elif is_certificate:
            result["credential_format"] = f"'{domain}/{user}'"
            if pfx_cert:
                result["auth_string"] = f"-pfx '{pfx_cert}'"
            else:
                result["auth_string"] = f"-cert-pfx '{pem_cert}'"
            result["alt_auth_hint"] = "  # Use -k for Kerberos auth with certificate"
        elif ntlm_hash:
            result["credential_format"] = f"'{domain}/{user}'"
            result["auth_string"] = f"-hashes ':{ntlm_hash}'"
            result["alt_auth_hint"] = "  # Or use -k with KRB5CCNAME for Kerberos"
        elif password is not None:
            result["credential_format"] = f"'{domain}/{user}:{password}'"
            result["auth_string"] = ""
            result["alt_auth_hint"] = "  # Or use -k with KRB5CCNAME for Kerberos"
        else:
            result["credential_format"] = f"'{domain}/{user}:<pass>'"
            result["auth_string"] = ""
            result["alt_auth_hint"] = "  # Or: -k -no-pass (with KRB5CCNAME), -hashes ':NTLM'"

    elif tool == "certipy":
        # Certipy: -u user@domain -p password / -hashes :hash / -pfx cert.pfx
        user_part = f"'{user}@{domain}'" if include_domain else f"'{user}'"
        if is_kerberos:
            if use_kcache:
                result["auth_string"] = f"-u {user_part} -k -no-pass"
                result["kerberos_hint"] = "  # Uses KRB5CCNAME environment variable"
            elif aes_key:
                # Certipy doesn't have direct aesKey, use Kerberos ticket
                result["auth_string"] = f"-u {user_part} -k -no-pass"
                result["kerberos_hint"] = "  # Obtain ticket first: getTGT.py with -aesKey"
            else:
                if password:
                    result["auth_string"] = f"-u {user_part} -p '{password}' -k"
                else:
                    result["auth_string"] = f"-u {user_part} -p '<pass>' -k"
        elif is_certificate:
            if pfx_cert:
                result["auth_string"] = f"-u {user_part} -pfx '{pfx_cert}'"
            else:
                result["auth_string"] = f"-u {user_part} -cert '{pem_cert}'"
            result["alt_auth_hint"] = ""
        elif ntlm_hash:
            result["auth_string"] = f"-u {user_part} -hashes ':{ntlm_hash}'"
            result["alt_auth_hint"] = "  # Or: -k -no-pass (with KRB5CCNAME)"
        elif password is not None:
            result["auth_string"] = f"-u {user_part} -p '{password}'"
            result["alt_auth_hint"] = "  # Or: -hashes ':NTLM', -k -no-pass (Kerberos)"
        else:
            result["auth_string"] = f"-u {user_part} -p '<pass>'"
            result["alt_auth_hint"] = "  # Or: -hashes ':NTLM', -k -no-pass (Kerberos)"

    elif tool == "adidnsdump":
        # adidnsdump: -u domain\\user -p password / --hashes :hash / -k
        user_part = f"'{domain}\\\\{user}'" if include_domain else f"'{user}'"
        if is_kerberos:
            if use_kcache:
                result["auth_string"] = f"-u {user_part} -k"
                result["kerberos_hint"] = "  # Uses KRB5CCNAME environment variable"
            elif aes_key:
                result["auth_string"] = f"-u {user_part} -k"
                result["kerberos_hint"] = "  # Obtain ticket first: getTGT.py with -aesKey"
            else:
                if password:
                    result["auth_string"] = f"-u {user_part} -p '{password}'"
                else:
                    result["auth_string"] = f"-u {user_part} -p '<password>'"
        elif ntlm_hash:
            result["auth_string"] = f"-u {user_part} --hashes ':{ntlm_hash}'"
            result["alt_auth_hint"] = "  # Or: -k (with KRB5CCNAME)"
        elif password is not None:
            result["auth_string"] = f"-u {user_part} -p '{password}'"
            result["alt_auth_hint"] = "  # Or: --hashes ':NTLM', -k (Kerberos)"
        else:
            result["auth_string"] = f"-u {user_part} -p '<password>'"
            result["alt_auth_hint"] = "  # Or: --hashes ':NTLM', -k (Kerberos)"

    elif tool == "rusthound":
        # rusthound-ce: -u user@domain -p password / --ldaps / -k
        user_part = f"'{user}@{domain}'" if include_domain else f"'{user}'"
        if is_kerberos:
            if use_kcache or aes_key:
                result["auth_string"] = f"-u {user_part} -k"
                result["kerberos_hint"] = "  # Uses KRB5CCNAME environment variable"
            else:
                if password:
                    result["auth_string"] = f"-u {user_part} -p '{password}'"
                else:
                    result["auth_string"] = f"-u {user_part} -p '<pass>'"
        elif ntlm_hash:
            # rusthound doesn't support hashes directly, note this
            result["auth_string"] = f"-u {user_part} -p '<pass>'"
            result["alt_auth_hint"] = "  # rusthound needs password; use PTH to get ticket first"
        elif password is not None:
            result["auth_string"] = f"-u {user_part} -p '{password}'"
            result["alt_auth_hint"] = "  # Or: -k (with KRB5CCNAME for Kerberos)"
        else:
            result["auth_string"] = f"-u {user_part} -p '<pass>'"
            result["alt_auth_hint"] = "  # Or: -k (with KRB5CCNAME for Kerberos)"

    elif tool == "nxc":
        # NetExec: -u user -p password / -H hash / -k / --use-kcache / --aesKey
        if is_kerberos:
            if use_kcache:
                result["auth_string"] = f"-u '{user}' --use-kcache"
                result["kerberos_hint"] = "  # Uses KRB5CCNAME environment variable"
            elif aes_key:
                result["auth_string"] = f"-u '{user}' --aesKey '{aes_key}'"
            else:
                if password:
                    result["auth_string"] = f"-u '{user}' -p '{password}' -k"
                else:
                    result["auth_string"] = f"-u '{user}' -p '<pass>' -k"
        elif is_certificate:
            if pfx_cert:
                result["auth_string"] = f"-u '{user}' --pfx-cert '{pfx_cert}'"
            else:
                result["auth_string"] = f"-u '{user}' --pem-cert '{pem_cert}'"
        elif ntlm_hash:
            result["auth_string"] = f"-u '{user}' -H '{ntlm_hash}'"
            result["alt_auth_hint"] = "  # Or: --use-kcache, --aesKey"
        elif password is not None:
            result["auth_string"] = f"-u '{user}' -p '{password}'"
            result["alt_auth_hint"] = "  # Or: -H 'NTLM', --use-kcache, --aesKey"
        else:
            result["auth_string"] = f"-u '{user}' -p '<pass>'"
            result["alt_auth_hint"] = "  # Or: -H 'NTLM', --use-kcache, --aesKey"

        # Add domain if available
        if include_domain and domain and domain != "<domain>":
            result["auth_string"] += f" -d '{domain}'"

    else:
        # Generic fallback
        if password is not None:
            result["auth_string"] = f"-u '{user}' -p '{password}'"
        elif ntlm_hash:
            result["auth_string"] = f"-u '{user}' -H '{ntlm_hash}'"
        else:
            result["auth_string"] = f"-u '{user}' -p '<pass>'"

    return result


def _substitute_credentials(command: str, args, cache) -> str:
    """Substitute credential placeholders with actual values.

    Replaces patterns like <user>, <pass>, '<user>', '<pass>' with actual credentials.
    Also handles domain-specific formats like DOMAIN\\<user> and <user>@domain.
    """
    # Try to get credentials from args first, then fall back to cache.primary_credential
    user = args.user if hasattr(args, "user") and args.user else None
    password = args.password if hasattr(args, "password") and args.password else None
    ntlm_hash = args.hash if hasattr(args, "hash") and args.hash else None
    domain = args.domain if hasattr(args, "domain") and args.domain else None

    # Fall back to primary_credential from cache (for -C multi-cred mode)
    if not user and cache.primary_credential:
        cred = cache.primary_credential
        user = cred.user
        password = cred.password
        ntlm_hash = cred.hash if not password else None
        domain = cred.domain if cred.domain else domain

    # If still no credentials available, return command as-is
    if not user:
        return command

    result = command

    # Get domain from cache if not in args
    if not domain and cache.domain_info:
        domain = cache.domain_info.get("dns_domain") or cache.domain_info.get("netbios_domain")

    # Handle domain-qualified patterns FIRST (before replacing standalone <user>)
    # Pattern: 'DOMAIN\<user>' or DOMAIN\\<user> or "DOMAIN\<user>"
    if domain:
        # Handle 'domain\<user>' format (with quotes around whole thing)
        result = re.sub(r"'[A-Za-z0-9._-]+\\\\?<user>'", f"'{domain}\\\\{user}'", result)
        # Handle domain\<user> format (without quotes)
        result = re.sub(r"([A-Za-z0-9._-]+)\\\\?<user>", f"{domain}\\\\{user}", result)
        # Handle -u <user>@<domain> format (both placeholders)
        # Must come before other @domain patterns
        result = re.sub(r"-u\s+<user>@<domain>", f"-u '{user}@{domain}'", result)
        # Handle standalone <user>@<domain> format (both placeholders)
        result = re.sub(r"<user>@<domain>", f"{user}@{domain}", result)
        # Handle '<user>@domain.local' format
        result = re.sub(r"'<user>@[A-Za-z0-9._-]+'", f"'{user}@{domain}'", result)
        # Handle <user>@domain format without quotes
        result = re.sub(r"<user>@[A-Za-z0-9._-]+", f"{user}@{domain}", result)

    # Substitute password patterns (before user, to handle -p '<pass>' correctly)
    if password:
        # Escape special regex characters in password for safe substitution
        safe_password = password.replace("\\", "\\\\").replace("'", "'\"'\"'")
        # Handle -p '<pass>' (quotes around placeholder)
        result = re.sub(r"-p\s+'<pass(?:word)?>'", f"-p '{safe_password}'", result)
        # Handle -p "<pass>"
        result = re.sub(r'-p\s+"<pass(?:word)?>"', f"-p '{safe_password}'", result)
        # Handle -p <pass> (no quotes)
        result = re.sub(r"-p\s+<pass(?:word)?>", f"-p '{safe_password}'", result)
        # Handle standalone '<pass>' or "<pass>"
        result = re.sub(r"'<pass(?:word)?>'", f"'{safe_password}'", result)
        result = re.sub(r'"<pass(?:word)?>"', f"'{safe_password}'", result)
        # Handle standalone <pass> (no quotes) - be careful not to break other things
        result = re.sub(r"(?<!['\"]):<pass(?:word)?>(?!['\"])", f":{safe_password}", result)
        # Handle impacket format inside quotes: 'domain/user:<pass>' -> 'domain/user:password'
        # This matches :<pass> when followed by a closing single quote
        result = re.sub(r":<pass(?:word)?>(?=')", f":{safe_password}", result)
        # Handle smbclient format: -U 'user%<password>' or -U user%<password>
        result = re.sub(r"%<pass(?:word)?>", f"%{safe_password}", result)
    elif ntlm_hash:
        # Replace password auth with hash auth
        result = re.sub(r"-p\s+'<pass(?:word)?>'", f"-H '{ntlm_hash}'", result)
        result = re.sub(r'-p\s+"<pass(?:word)?>"', f"-H '{ntlm_hash}'", result)
        result = re.sub(r"-p\s+<pass(?:word)?>", f"-H '{ntlm_hash}'", result)

    # Substitute username patterns LAST
    # Handle -u '<user>' (quotes around placeholder)
    result = re.sub(r"-u\s+'<user>'", f"-u '{user}'", result)
    # Handle -u "<user>"
    result = re.sub(r'-u\s+"<user>"', f"-u '{user}'", result)
    # Handle -u <user> (no quotes)
    result = re.sub(r"-u\s+<user>(?!['\"])", f"-u '{user}'", result)
    # Handle standalone '<user>' in other contexts (like impacket tools)
    result = re.sub(r"'<user>'", f"'{user}'", result)
    # Handle standalone <user> that's not part of domain\user or user@domain
    result = re.sub(r"(?<![\\@])<user>(?!@)", user, result)

    # Handle generic placeholders
    if domain:
        result = re.sub(r"<domain>", domain, result)

    # Handle USER/PASS uppercase placeholders (like in os_info.py)
    if password:
        result = re.sub(r"-p\s+PASS\b", f"-p '{password}'", result)
    elif ntlm_hash:
        result = re.sub(r"-p\s+PASS\b", f"-H '{ntlm_hash}'", result)
    result = re.sub(r"-u\s+USER\b", f"-u '{user}'", result)

    return result


def print_next_steps(args, cache):
    """Print collected next steps and recommended commands.

    This aggregates all actionable recommendations discovered during
    enumeration into a single section at the end of the output.
    """
    if not cache.next_steps:
        return

    # Filter out invalid steps (must have finding and command)
    valid_steps = [s for s in cache.next_steps if s.get("finding") and s.get("command")]

    if not valid_steps:
        return

    target = cache.target if cache else args.target
    print_section("Recommended Next Steps", target)

    # Group by priority (default to 'medium' consistently)
    high_priority = [s for s in valid_steps if s.get("priority", "medium") == "high"]
    medium_priority = [s for s in valid_steps if s.get("priority", "medium") == "medium"]
    low_priority = [s for s in valid_steps if s.get("priority", "medium") == "low"]

    if high_priority:
        output(c(f"HIGH PRIORITY ({len(high_priority)})", Colors.RED + Colors.BOLD))
        output(c("-" * 60, Colors.RED))
        for step in high_priority:
            _print_step(step, args, cache, Colors.RED)

    if medium_priority:
        output(c(f"MEDIUM PRIORITY ({len(medium_priority)})", Colors.YELLOW + Colors.BOLD))
        output(c("-" * 60, Colors.YELLOW))
        for step in medium_priority:
            _print_step(step, args, cache, Colors.YELLOW)

    if low_priority:
        output(c(f"LOW PRIORITY ({len(low_priority)})", Colors.CYAN + Colors.BOLD))
        output(c("-" * 60, Colors.CYAN))
        for step in low_priority:
            _print_step(step, args, cache, Colors.CYAN)

    # Add to JSON output if requested (with substituted credentials)
    if args.json_output:

        def _step_to_json(s):
            """Convert a step to JSON format with auto-exploit check."""
            cmd = _substitute_credentials(s["command"], args, cache)
            auto_exploit = _check_auto_exploit(cmd)
            return {
                "finding": s["finding"],
                "command": cmd,
                "description": s.get("description", ""),
                "auto_exploit": bool(auto_exploit),
                "auto_exploit_details": [desc for _, desc in auto_exploit] if auto_exploit else [],
            }

        JSON_DATA["next_steps"] = {
            "high": [_step_to_json(s) for s in high_priority],
            "medium": [_step_to_json(s) for s in medium_priority],
            "low": [_step_to_json(s) for s in low_priority],
        }


def _check_auto_exploit(command: str) -> list[tuple[str, str]]:
    """Check if a command contains auto-exploit modules.

    Returns list of (pattern, description) tuples for any matches found.
    """
    matches = []
    command_lower = command.lower()

    for pattern, description in AUTO_EXPLOIT_MODULES.items():
        # Check for pattern match (case-insensitive)
        pattern_lower = pattern.lower()
        if pattern_lower in command_lower:
            matches.append((pattern, description))

    return matches


def _print_step(step: dict, args, cache, accent_color: str = Colors.CYAN):
    """Print a single next step recommendation with credential substitution."""
    finding = step.get("finding", "")
    command = step.get("command", "")
    description = step.get("description", "")

    # Substitute placeholders with actual credentials
    command = _substitute_credentials(command, args, cache)

    output(f"  {c('→', accent_color)} {c(finding, Colors.BOLD)}")
    if description:
        output(f"    {description}")
    if command:
        output(f"    {c('$', Colors.GREEN)} {c(command, Colors.WHITE)}")

        # Check for auto-exploit modules and warn user
        auto_exploit_matches = _check_auto_exploit(command)
        if auto_exploit_matches:
            for pattern, exploit_desc in auto_exploit_matches:
                output(
                    f"    {c('!!! AUTO-EXPLOIT:', Colors.RED + Colors.BOLD)} "
                    f"{c(exploit_desc, Colors.RED)}"
                )
    output("")
