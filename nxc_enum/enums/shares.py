"""Share enumeration (single credential)."""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

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
    print_section("Shares via RPC", args.target)

    auth = cache.auth_args
    shares_args = ["smb", args.target] + auth + ["--shares"]
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

        # Separate accessible vs no-access shares (handle 5-tuple format)
        accessible = [(n, p, r, t, m) for n, p, r, t, m in shares if "READ" in p or "WRITE" in p]
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

            for share_name, perms, remark, share_type, max_users in accessible:
                if "READ" in perms and "WRITE" in perms:
                    access_padded = "READ,WRITE".ljust(12)
                    access_str = c(access_padded, Colors.GREEN)
                elif "WRITE" in perms:
                    access_padded = "WRITE".ljust(12)
                    access_str = c(access_padded, Colors.GREEN)
                else:
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
            if file_shares:
                share_list = ", ".join(file_shares[:3])
                if len(file_shares) > 3:
                    share_list += f" (+{len(file_shares) - 3} more)"
                # Enumerate shares (JSON metadata)
                # MAX_FILE_SIZE=10485760 (10MB) - default 50KB is too small
                spider_cmd = (
                    f"nxc smb {args.target} -u <user> -p <pass> "
                    "-M spider_plus -o OUTPUT_FOLDER=. MAX_FILE_SIZE=10485760"
                )
                cache.add_next_step(
                    finding=f"Readable shares: {share_list}",
                    command=spider_cmd,
                    description="Enumerate share contents (creates JSON metadata)",
                    priority="low",
                )
                # Download files from shares
                download_cmd = (
                    f"nxc smb {args.target} -u <user> -p <pass> "
                    "-M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=. MAX_FILE_SIZE=10485760"
                )
                cache.add_next_step(
                    finding=f"Readable shares: {share_list}",
                    command=download_cmd,
                    description="Download files from shares (up to 10MB each)",
                    priority="low",
                )

        # Store share names for aggregated copy-paste section
        cache.copy_paste_data["share_names"].update(s[0] for s in shares)
    else:
        # No shares parsed - check for access denied or other errors
        combined = stdout + stderr
        if "STATUS_ACCESS_DENIED" in combined.upper():
            status("Access denied - cannot enumerate shares", "error")
        elif "STATUS_LOGON_FAILURE" in combined.upper():
            status("Authentication failed - cannot enumerate shares", "error")
        else:
            status("No shares found or unable to enumerate", "warning")
