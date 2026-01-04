"""Share output parsing."""

from .nxc_output import is_nxc_noise_line


def parse_shares_from_output(stdout: str) -> list[tuple[str, str, str]]:
    """Parse shares from nxc --shares output. Returns [(name, perms, comment), ...]"""
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
                            share_name = remaining_parts[0]
                            # Iterate with absolute indices to avoid off-by-one errors
                            for idx in range(1, len(remaining_parts)):
                                p = remaining_parts[idx]
                                if p in ["READ", "WRITE", "READ,WRITE"]:
                                    perms = p
                                    remark = " ".join(remaining_parts[idx + 1 :])
                                    break
                                elif (
                                    p == "NO"
                                    and idx + 1 < len(remaining_parts)
                                    and remaining_parts[idx + 1] == "ACCESS"
                                ):
                                    perms = "NO ACCESS"
                                    remark = " ".join(remaining_parts[idx + 2 :])
                                    break
                            else:
                                if len(remaining_parts) > 1:
                                    remark = " ".join(remaining_parts[1:])
                except (ValueError, IndexError):
                    pass
            else:
                if parts:
                    share_name = parts[0]
                    # Iterate with absolute indices to avoid off-by-one errors
                    for idx in range(1, len(parts)):
                        p = parts[idx]
                        if p in ["READ", "WRITE", "READ,WRITE"]:
                            perms = p
                            remark = " ".join(parts[idx + 1 :])
                            break
                        elif p == "NO" and idx + 1 < len(parts) and parts[idx + 1] == "ACCESS":
                            perms = "NO ACCESS"
                            remark = " ".join(parts[idx + 2 :])
                            break
                    else:
                        if len(parts) > 1:
                            remark = " ".join(parts[1:])

            if share_name and share_name not in [s[0] for s in shares]:
                if share_name not in ("Share", "-----", "[*]", "[+]"):
                    shares.append((share_name, perms, remark))

    return shares
