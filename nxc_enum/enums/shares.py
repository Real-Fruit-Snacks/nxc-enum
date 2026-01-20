"""Share enumeration (single credential)."""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line
from ..reporting.next_steps import get_external_tool_auth

# Patterns for verbose output parsing
RE_SHARE_CHECK = re.compile(r"Checking share[:\s]+(\S+)", re.IGNORECASE)
RE_ACCESS_DENIED = re.compile(
    r"(Access denied|STATUS_ACCESS_DENIED|NT_STATUS_ACCESS_DENIED)[:\s]*(.+)?", re.IGNORECASE
)
RE_SHARE_TYPE = re.compile(
    r"(STYPE_DISKTREE|STYPE_PRINTQ|STYPE_IPC|STYPE_DEVICE|STYPE_SPECIAL|Disk|Printer|IPC)",
    re.IGNORECASE,
)
RE_MAX_USERS = re.compile(r"max_users[:\s]+(\d+|-?\d+)", re.IGNORECASE)
RE_SHARE_INFO = re.compile(r"\[INFO\].*?(share|permission|access)", re.IGNORECASE)


def parse_verbose_share_info(stdout: str) -> dict:
    """Parse verbose output for additional share metadata.

    Returns dict with:
        - permission_checks: list of (share_name, result) tuples
        - access_errors: list of (share_name, error_detail) tuples
        - share_types: dict mapping share_name to type
        - max_users: dict mapping share_name to max user count
        - info_messages: list of relevant INFO lines
    """
    verbose_data = {
        "permission_checks": [],
        "access_errors": [],
        "share_types": {},
        "max_users": {},
        "info_messages": [],
    }

    current_share = None

    for line in stdout.split("\n"):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Track which share is being checked
        check_match = RE_SHARE_CHECK.search(line_stripped)
        if check_match:
            current_share = check_match.group(1)
            verbose_data["permission_checks"].append((current_share, "checking"))
            continue

        # Capture access denied details
        denied_match = RE_ACCESS_DENIED.search(line_stripped)
        if denied_match:
            detail = denied_match.group(2) if denied_match.group(2) else "Access denied"
            share = current_share or "unknown"
            verbose_data["access_errors"].append((share, detail.strip()))
            continue

        # Capture share type from verbose output
        type_match = RE_SHARE_TYPE.search(line_stripped)
        if type_match and current_share:
            share_type = type_match.group(1).upper()
            # Normalize type names
            if "DISK" in share_type:
                share_type = "DISK"
            elif "PRINT" in share_type:
                share_type = "PRINTER"
            elif "IPC" in share_type:
                share_type = "IPC"
            verbose_data["share_types"][current_share] = share_type
            continue

        # Capture max users if present
        max_match = RE_MAX_USERS.search(line_stripped)
        if max_match and current_share:
            try:
                max_users = int(max_match.group(1))
                verbose_data["max_users"][current_share] = max_users
            except ValueError:
                pass
            continue

        # Capture relevant INFO messages
        if RE_SHARE_INFO.search(line_stripped) or "[INFO]" in line_stripped.upper():
            # Filter out noise, keep share-related info
            if any(
                kw in line_stripped.lower()
                for kw in ["share", "permission", "access", "denied", "granted"]
            ):
                verbose_data["info_messages"].append(line_stripped)

    return verbose_data


def enum_shares(args, cache):
    """Enumerate SMB shares."""
    target = cache.target if cache else args.target
    print_section("Shares via RPC", target)

    auth = cache.auth_args
    shares_args = ["smb", target] + auth + ["--shares"]
    rc, stdout, stderr = run_nxc(shares_args, args.timeout)
    debug_nxc(shares_args, stdout, stderr, "Shares")

    if rc != 0 and not stdout:
        status("Could not enumerate shares", "error")
        return

    status("Enumerating shares")

    # Parse verbose output for additional metadata
    verbose_info = parse_verbose_share_info(stdout)

    shares = []
    in_share_table = False

    for line in stdout.split("\n"):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        if "Share" in line and "Permissions" in line and "Remark" in line:
            in_share_table = True
            continue
        if "-----" in line and in_share_table:
            continue

        if is_nxc_noise_line(line_stripped):
            continue
        if "[*]" in line and "Enumerated" in line:
            continue

        if in_share_table or line_stripped.startswith("SMB"):
            parts = line.split()

            if "[*]" in line and "Windows" in line:
                continue
            if "[+]" in line and "\\" in line and ":" in line:
                continue

            share_name = None
            perms = "NO ACCESS"
            remark = ""

            if line_stripped.startswith("SMB"):
                try:
                    port_idx = -1
                    for i, p in enumerate(parts):
                        if p == "445":
                            port_idx = i
                            break
                    if port_idx >= 0 and port_idx + 2 < len(parts):
                        remaining_parts = parts[port_idx + 2 :]
                        if remaining_parts and not remaining_parts[0].startswith("["):
                            # Find permission keyword to determine where share name ends
                            perm_idx = -1
                            for i, p in enumerate(remaining_parts):
                                if p in ["READ", "WRITE", "READ,WRITE"]:
                                    perm_idx = i
                                    perms = p
                                    remark = " ".join(remaining_parts[i + 1 :])
                                    break
                                elif (
                                    p == "NO"
                                    and i + 1 < len(remaining_parts)
                                    and remaining_parts[i + 1] == "ACCESS"
                                ):
                                    perm_idx = i
                                    perms = "NO ACCESS"
                                    remark = " ".join(remaining_parts[i + 2 :])
                                    break

                            if perm_idx > 0:
                                # Share name is everything before the permission keyword
                                share_name = " ".join(remaining_parts[:perm_idx])
                            elif perm_idx == 0:
                                # Permission at start means no share name parsed (skip)
                                share_name = None
                            else:
                                # No permission found - first part is share name, rest is remark
                                share_name = remaining_parts[0]
                                if len(remaining_parts) > 1:
                                    remark = " ".join(remaining_parts[1:])
                except (ValueError, IndexError):
                    pass
            else:
                if parts:
                    # Find permission keyword to determine where share name ends
                    perm_idx = -1
                    for i, p in enumerate(parts):
                        if p in ["READ", "WRITE", "READ,WRITE"]:
                            perm_idx = i
                            perms = p
                            remark = " ".join(parts[i + 1 :])
                            break
                        elif p == "NO" and i + 1 < len(parts) and parts[i + 1] == "ACCESS":
                            perm_idx = i
                            perms = "NO ACCESS"
                            remark = " ".join(parts[i + 2 :])
                            break

                    if perm_idx > 0:
                        # Share name is everything before the permission keyword
                        share_name = " ".join(parts[:perm_idx])
                    elif perm_idx == 0:
                        # Permission at start means no share name parsed (skip)
                        share_name = None
                    else:
                        # No permission found - first part is share name, rest is remark
                        share_name = parts[0]
                        if len(parts) > 1:
                            remark = " ".join(parts[1:])

            if share_name and share_name not in [s[0] for s in shares]:
                if share_name not in ("Share", "-----", "[*]", "[+]"):
                    # Enrich with verbose data
                    share_type = verbose_info["share_types"].get(share_name, "")
                    max_users = verbose_info["max_users"].get(share_name)
                    shares.append((share_name, perms, remark, share_type, max_users))

    if shares:
        cache.share_count = len(shares)

        # Store verbose info in cache for potential use by other modules
        cache.share_verbose_info = verbose_info

        # Apply shares filter if specified
        shares_filter = getattr(args, "shares_filter", None)
        if shares_filter:
            if shares_filter == "READ":
                # Show shares where user has at least READ access (includes READ,WRITE)
                filtered_shares = [(n, p, r, t, m) for n, p, r, t, m in shares if "READ" in p]
            else:  # WRITE
                # Show shares where user has WRITE access (includes READ,WRITE)
                filtered_shares = [(n, p, r, t, m) for n, p, r, t, m in shares if "WRITE" in p]

            status(f"Found {len(shares)} share(s)", "success")
            status(f"Filtered to {len(filtered_shares)} shares with {shares_filter} access", "info")

            # When filtering, all filtered shares are "accessible" by definition
            accessible = filtered_shares
            no_access = []
        else:
            # No filter - separate accessible vs no-access shares (handle 5-tuple format)
            accessible = [
                (n, p, r, t, m) for n, p, r, t, m in shares if "READ" in p or "WRITE" in p
            ]
            no_access = [
                (n, p, r, t, m) for n, p, r, t, m in shares if "READ" not in p and "WRITE" not in p
            ]

            status(f"Found {len(shares)} share(s)", "success")
        output("")

        # Show verbose access errors if any were captured
        if verbose_info["access_errors"]:
            unique_errors = {}
            for share, error in verbose_info["access_errors"]:
                if share not in unique_errors:
                    unique_errors[share] = error
            if unique_errors:
                output(c("ACCESS DENIED DETAILS:", Colors.YELLOW))
                for share, error in unique_errors.items():
                    output(f"  {share}: {error}")
                output("")

        if accessible:
            output(c(f"ACCESSIBLE SHARES ({len(accessible)})", Colors.GREEN))
            # Include Type column if any types were detected
            has_types = any(t for _, _, _, t, _ in accessible)
            if has_types:
                output(f"{'Share':<15} {'Access':<12} {'Type':<8} {'Comment'}")
                output(f"{'-'*15} {'-'*12} {'-'*8} {'-'*25}")
            else:
                output(f"{'Share':<15} {'Access':<12} {'Comment'}")
                output(f"{'-'*15} {'-'*12} {'-'*30}")

            # Track admin share access for potential elevated privileges detection
            has_admin_share_write = False
            has_c_dollar_write = False

            for share_name, perms, remark, share_type, max_users in accessible:
                # Check for admin share access indicators
                if share_name.upper() == "ADMIN$" and "WRITE" in perms:
                    has_admin_share_write = True
                if share_name.upper() == "C$" and "WRITE" in perms:
                    has_c_dollar_write = True

                if "READ" in perms and "WRITE" in perms:
                    # READ+WRITE is highest risk - can read and write data
                    access_padded = "READ,WRITE".ljust(12)
                    access_str = c(access_padded, Colors.RED + Colors.BOLD)
                elif "WRITE" in perms:
                    # WRITE-only is high risk - can write malicious files
                    access_padded = "WRITE".ljust(12)
                    access_str = c(access_padded, Colors.RED)
                else:
                    # READ-only is lower risk but still interesting
                    access_padded = "READ".ljust(12)
                    access_str = c(access_padded, Colors.GREEN)

                comment = remark if remark else ""
                max_comment_len = 25 if has_types else 30
                if len(comment) > max_comment_len:
                    comment = comment[: max_comment_len - 3] + "..."

                if has_types:
                    type_str = (share_type or "-").ljust(8)
                    output(f"{share_name:<15} {access_str} {type_str} {comment}")
                else:
                    output(f"{share_name:<15} {access_str} {comment}")
            output("")

            # Warn about potential elevated privileges if admin shares are writable
            # but we didn't detect admin via Pwn3d! marker
            primary_cred = cache.primary_credential
            is_detected_admin = primary_cred.is_admin if primary_cred else False
            if (has_admin_share_write or has_c_dollar_write) and not is_detected_admin:
                output(c("=" * 60, Colors.YELLOW + Colors.BOLD))
                output(
                    c(
                        "  POTENTIAL ELEVATED PRIVILEGES DETECTED",
                        Colors.YELLOW + Colors.BOLD,
                    )
                )
                if has_admin_share_write:
                    output(c("  ADMIN$ is writable - likely local admin!", Colors.YELLOW))
                if has_c_dollar_write:
                    output(c("  C$ is writable - likely local admin!", Colors.YELLOW))
                output(
                    c(
                        "  NetExec didn't show Pwn3d! - verify manually with:",
                        Colors.YELLOW,
                    )
                )
                output(c(f"    nxc smb {target} <auth> --local-auth", Colors.CYAN))
                output(c("=" * 60, Colors.YELLOW + Colors.BOLD))
                output("")
                # Store in cache for summary
                cache.potential_admin_access = True

        if no_access:
            output(c(f"NO ACCESS ({len(no_access)})", Colors.RED))
            has_types = any(t for _, _, _, t, _ in no_access)
            if has_types:
                output(f"{'Share':<15} {'Type':<8} {'Comment'}")
                output(f"{'-'*15} {'-'*8} {'-'*25}")
            else:
                output(f"{'Share':<15} {'Comment'}")
                output(f"{'-'*15} {'-'*30}")

            for share_name, perms, remark, share_type, max_users in no_access:
                comment = remark if remark else ""
                max_comment_len = 25 if has_types else 30
                if len(comment) > max_comment_len:
                    comment = comment[: max_comment_len - 3] + "..."
                share_padded = share_name.ljust(15)
                if has_types:
                    type_str = (share_type or "-").ljust(8)
                    output(f"{c(share_padded, Colors.RED)} {type_str} {comment}")
                else:
                    output(f"{c(share_padded, Colors.RED)} {comment}")

        # Display relevant verbose INFO messages if any
        if verbose_info["info_messages"]:
            output("")
            output(c("VERBOSE INFO:", Colors.CYAN))
            for msg in verbose_info["info_messages"][:5]:  # Limit to first 5
                # Clean up the message for display
                clean_msg = msg.replace("[INFO]", "").strip()
                if clean_msg:
                    output(f"  {clean_msg}")

        if args.json_output:
            # Include verbose data in JSON output
            JSON_DATA["shares"] = [
                {
                    "name": s[0],
                    "permissions": s[1],
                    "comment": s[2],
                    "type": s[3] if s[3] else None,
                    "max_users": s[4],
                }
                for s in shares
            ]
            # Add verbose metadata to JSON
            if verbose_info["access_errors"]:
                JSON_DATA["share_access_errors"] = [
                    {"share": share, "error": error}
                    for share, error in verbose_info["access_errors"]
                ]

        # Add spider recommendation if we have readable shares
        if accessible:
            # Filter out IPC$ and PRINT$ shares - only suggest spidering file shares
            file_shares = [
                name
                for name, perms, _, stype, _ in accessible
                if "READ" in perms
                and name.upper() not in ("IPC$", "PRINT$")
                and (not stype or "IPC" not in stype.upper())
            ]

            # Cache readable shares for spider module
            cache.readable_shares = file_shares

            if file_shares:
                share_list = ", ".join(file_shares[:3])
                if len(file_shares) > 3:
                    share_list += f" (+{len(file_shares) - 3} more)"

                # Get auth string for external tool commands
                auth_info = get_external_tool_auth(args, cache, tool="nxc")
                auth_hint = auth_info["auth_string"]

                # Enumerate and download files from shares
                # MAX_FILE_SIZE=10485760 (10MB) - default 50KB is too small
                # DOWNLOAD_FLAG=True enables file download (default is JSON listing only)
                spider_cmd = (
                    f"nxc smb {target} {auth_hint} "
                    "-M spider_plus -o OUTPUT_FOLDER=. MAX_FILE_SIZE=10485760 DOWNLOAD_FLAG=True"
                )
                cache.add_next_step(
                    finding=f"Readable shares: {share_list}",
                    command=spider_cmd,
                    description="Spider and download files from shares (outputs to OUTPUT_FOLDER)",
                    priority="low",
                )

                # Add smbclient command for manual browsing
                first_share = file_shares[0]
                smb_auth_info = get_external_tool_auth(args, cache, tool="smbclient")
                smb_auth_hint = smb_auth_info["auth_string"]
                smbclient_cmd = f"smbclient //{target}/{first_share} {smb_auth_hint}"
                cache.add_next_step(
                    finding=f"Readable share: {first_share}",
                    command=smbclient_cmd,
                    description="Browse share manually with smbclient",
                    priority="low",
                )

        # Store share names for aggregated copy-paste section
        # When filter is applied, only store filtered shares (accessible ones)
        shares_for_copy = accessible if shares_filter else shares
        cache.copy_paste_data["share_names"].update(s[0] for s in shares_for_copy)
        # Store UNC paths for multi-target aggregation (includes target IP)
        cache.copy_paste_data["share_unc_paths"].update(
            f"\\\\{target}\\{s[0]}" for s in shares_for_copy
        )
    else:
        # No shares parsed - check for access denied or other errors
        combined = stdout + stderr
        if "STATUS_ACCESS_DENIED" in combined.upper():
            status("Access denied - cannot enumerate shares", "error")
        elif "STATUS_LOGON_FAILURE" in combined.upper():
            status("Authentication failed - cannot enumerate shares", "error")
        else:
            status("No shares found or unable to enumerate", "warning")
