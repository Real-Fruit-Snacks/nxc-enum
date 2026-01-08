"""Share file spider/listing enumeration.

This module uses spider_plus to recursively list files on accessible
SMB shares. It does NOT download files - only lists metadata.

This is pure SMB directory listing - uses listPath() for enumeration.
No file downloads or command execution on the target.

Pentest value: Discovers sensitive files (configs, backups, scripts, docs).
"""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line

# High-value file patterns for pentesters
INTERESTING_EXTENSIONS = {
    # Credentials/configs
    ".conf",
    ".config",
    ".ini",
    ".xml",
    ".json",
    ".yaml",
    ".yml",
    ".env",
    ".properties",
    # Scripts (may contain creds)
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".sh",
    ".py",
    # Databases
    ".sql",
    ".sqlite",
    ".db",
    ".mdb",
    ".accdb",
    # Backups
    ".bak",
    ".backup",
    ".old",
    ".orig",
    # Keys/certs
    ".key",
    ".pem",
    ".pfx",
    ".p12",
    ".crt",
    ".cer",
    ".ppk",
    # Office (may contain sensitive data)
    ".xlsx",
    ".docx",
    ".doc",
    ".xls",
    # Archives
    ".zip",
    ".7z",
    ".tar",
    ".gz",
    # SAM/SYSTEM
    ".sam",
    ".system",
    ".ntds",
}

# High-value filenames
INTERESTING_FILENAMES = {
    "web.config",
    "appsettings.json",
    "database.yml",
    "secrets.json",
    ".env",
    "credentials.xml",
    "password",
    "passwords.txt",
    "creds.txt",
    "unattend.xml",
    "sysprep.xml",
    "groups.xml",
    "services.xml",
    "scheduledtasks.xml",
    "datasources.xml",
    "drives.xml",
    "printers.xml",
    "ntds.dit",
    "sam",
    "system",
    "security",
}


def enum_spider(args, cache):
    """Spider accessible shares for interesting files.

    Uses spider_plus module to recursively list files on shares.
    By default, only enumerates metadata (no downloads).

    CLI Options:
        --spider-download: Enable file download
        --spider-max-size: Max file size in bytes (default: 10MB)
        --spider-output: Output directory for downloads

    Identifies files that may contain credentials, configs, or sensitive data.
    """
    target = cache.target if cache else args.target
    print_section("Share File Discovery (Spider)", target)

    # Check if we have readable shares from prior enumeration
    readable_shares = getattr(cache, "readable_shares", None)
    if readable_shares is not None and not readable_shares:
        status("No readable shares found - skipping spider", "info")
        output("")
        return

    auth = cache.auth_args

    # Build spider_plus options based on CLI args
    spider_options = []
    download_enabled = getattr(args, "spider_download", False)
    max_size = getattr(args, "spider_max_size", 10485760)  # 10MB default
    output_dir = getattr(args, "spider_output", None)

    if download_enabled:
        spider_options.append("DOWNLOAD_FLAG=True")
        spider_options.append(f"MAX_FILE_SIZE={max_size}")
        if output_dir:
            spider_options.append(f"OUTPUT_FOLDER={output_dir}")
        else:
            spider_options.append("OUTPUT_FOLDER=.")
        status(f"Spidering shares with downloads enabled (max: {max_size // 1024 // 1024}MB)...")
    else:
        status("Spidering accessible shares (listing only, no downloads)...")

    # Build command
    spider_args = ["smb", target] + auth + ["-M", "spider_plus"]
    if spider_options:
        spider_args.extend(["-o", " ".join(spider_options)])

    rc, stdout, stderr = run_nxc(spider_args, args.timeout * 2)  # Double timeout for spidering
    debug_nxc(spider_args, stdout, stderr, "Spider Plus")

    files_found = []
    interesting_files = []
    total_files = 0
    shares_spidered = set()

    # Parse output
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        if is_nxc_noise_line(line):
            continue

        # Look for share names
        if "Spidering" in line or "spider_plus" in line.lower():
            # Extract share name
            share_match = re.search(r"share:\s*(\S+)", line, re.IGNORECASE)
            if share_match:
                shares_spidered.add(share_match.group(1))

        # Look for file listings
        # Format varies but typically includes path and size
        if "/" in line or "\\" in line:
            # Extract filename
            path_match = re.search(r"[/\\]([^/\\]+\.\w+)", line)
            if path_match:
                filename = path_match.group(1).lower()
                total_files += 1

                file_info = {
                    "path": line.split()[-1] if line.split() else line,
                    "filename": filename,
                }

                # Check if file is interesting
                ext = "." + filename.split(".")[-1] if "." in filename else ""

                is_interesting = (
                    ext.lower() in INTERESTING_EXTENSIONS
                    or filename in INTERESTING_FILENAMES
                    or any(fn in filename for fn in INTERESTING_FILENAMES)
                )

                if is_interesting:
                    interesting_files.append(file_info)

                files_found.append(file_info)

        # Alternative: count from summary
        count_match = re.search(r"(\d+)\s+file", line, re.IGNORECASE)
        if count_match:
            total_files = max(total_files, int(count_match.group(1)))

    # Check for access/error conditions
    combined = stdout + stderr
    access_denied = "STATUS_ACCESS_DENIED" in combined.upper()
    no_files = "0 file" in combined.lower() or "No files" in combined

    # Store in cache
    cache.spider_files = files_found
    cache.spider_interesting = interesting_files
    cache.spider_total = total_files

    if files_found or total_files > 0:
        status(
            f"Found {total_files} file(s) across {len(shares_spidered) or '?'} share(s)",
            "success",
        )
        output("")

        if interesting_files:
            output(
                c(
                    f"INTERESTING FILES ({len(interesting_files)})",
                    Colors.YELLOW + Colors.BOLD,
                )
            )
            output(f"{'-'*60}")

            # Group by type
            shown = 0
            max_show = 20  # Limit output

            for file_info in sorted(interesting_files, key=lambda x: x["filename"]):
                if shown >= max_show:
                    remaining = len(interesting_files) - max_show
                    output(c(f"  ... and {remaining} more", Colors.BLUE))
                    break

                filename = file_info["filename"]
                path = file_info.get("path", "")

                # Color based on type
                if any(kw in filename for kw in ["password", "cred", "secret"]):
                    output(f"  {c('[!]', Colors.RED)} {c(path, Colors.RED)}")
                elif filename in INTERESTING_FILENAMES:
                    output(f"  {c('[!]', Colors.YELLOW)} {c(path, Colors.YELLOW)}")
                else:
                    output(f"  {c('[*]', Colors.CYAN)} {path}")

                shown += 1

            output("")

            # Advice
            output(c("[*] Review files for credentials, configs, and sensitive data", Colors.BLUE))
            output(
                c(
                    f"    Full results saved to: ~/.nxc/modules/nxc_spider_plus/{target}.json",
                    Colors.BLUE,
                )
            )
            output("")

            # Store for copy-paste
            cache.copy_paste_data["interesting_files"] = {
                f["filename"] for f in interesting_files[:50]  # Limit
            }

        else:
            output(c(f"[*] {total_files} files found, none match patterns", Colors.BLUE))
            output(
                c(
                    f"    Full listing: ~/.nxc/modules/nxc_spider_plus/{target}.json",
                    Colors.BLUE,
                )
            )
            output("")

    elif access_denied:
        status("Access denied to shares for spidering", "warning")
    elif no_files:
        status("No files found in accessible shares", "info")
    else:
        if not stdout.strip() or rc != 0:
            status("Could not spider shares", "error")
        else:
            status("No files discovered during spidering", "info")

    if args.json_output:
        JSON_DATA["spider"] = {
            "total_files": total_files,
            "interesting_files": [f["path"] for f in interesting_files],
            "interesting_count": len(interesting_files),
        }
