"""NFS share enumeration.

This module enumerates NFS exports and their access permissions.

This is pure enumeration - lists exported shares without mounting.
"""

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line


def enum_nfs(args, cache):
    """Enumerate NFS exports and permissions.

    Lists exported NFS shares and their access controls.
    """
    print_section("NFS Share Enumeration", args.target)

    status("Checking NFS exports...")

    # Query NFS shares
    nfs_args = ["nfs", args.target, "--shares"]
    rc, stdout, stderr = run_nxc(nfs_args, args.timeout)
    debug_nxc(nfs_args, stdout, stderr, "NFS Shares")

    nfs_info = {
        "accessible": False,
        "exports": [],
    }

    combined = stdout + stderr

    # Check if NFS is available
    if (
        "Connection refused" in combined
        or "port" in combined.lower()
        and "closed" in combined.lower()
    ):
        status("NFS port (2049) not open", "info")
        if args.json_output:
            JSON_DATA["nfs"] = nfs_info
        return

    if "timed out" in combined.lower():
        status("NFS connection timed out", "error")
        if args.json_output:
            JSON_DATA["nfs"] = nfs_info
        return

    # Check if NFS responded
    if "NFS" in stdout:
        nfs_info["accessible"] = True

    exports = []

    # Parse NFS exports
    for line in stdout.split("\n"):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue

        # Look for export lines
        # Format: "NFS IP PORT HOST /export *" or "/export (host access)"
        if line.startswith("NFS"):
            parts = line.split()
            if len(parts) >= 5:
                # Find path (starts with /)
                for i, part in enumerate(parts):
                    if part.startswith("/"):
                        export_path = part
                        # Access list is everything after
                        access = " ".join(parts[i + 1 :]) if i + 1 < len(parts) else "*"
                        exports.append(
                            {
                                "path": export_path,
                                "access": access,
                            }
                        )
                        break
        elif line.startswith("/"):
            # Raw export line
            parts = line.split()
            export_path = parts[0]
            access = " ".join(parts[1:]) if len(parts) > 1 else "*"
            exports.append(
                {
                    "path": export_path,
                    "access": access,
                }
            )

    nfs_info["exports"] = exports

    # Store results
    cache.nfs_info = nfs_info
    cache.nfs_exports = exports

    # Display results
    if exports:
        status(f"Found {len(exports)} NFS export(s)", "success")
        output("")

        output(c("NFS EXPORTS", Colors.CYAN))
        output(f"{'Export Path':<30} {'Access'}")
        output(f"{'-'*30} {'-'*40}")

        world_readable = []
        for export in exports:
            path = export["path"]
            access = export["access"]

            # Check for world-readable exports
            if access == "*" or "everyone" in access.lower() or "(rw)" in access:
                icon = c("[!]", Colors.RED)
                world_readable.append(path)
            else:
                icon = c("[*]", Colors.CYAN)

            output(f"{icon} {path:<28} {access}")

        output("")

        # Security warning for world-readable exports
        if world_readable:
            output(
                c(
                    "[!] World-readable NFS exports found!",
                    Colors.RED + Colors.BOLD,
                )
            )
            output(
                c(
                    "    These exports may be mounted without authentication",
                    Colors.RED,
                )
            )
            output("")

            # Add next step
            nfs_cmd = (
                f"showmount -e {args.target} && mkdir /tmp/nfs && "
                f"mount -t nfs {args.target}:{world_readable[0]} /tmp/nfs"
            )
            cache.add_next_step(
                finding=f"{len(world_readable)} world-accessible NFS exports",
                command=nfs_cmd,
                description="Mount NFS export to browse files",
                priority="high",
            )

        # Store copy-paste data
        cache.copy_paste_data["nfs_exports"] = set(e["path"] for e in exports)

    else:
        if nfs_info["accessible"]:
            status("NFS available but no exports found", "info")
        else:
            status("NFS not available or no exports", "info")

    if args.json_output:
        JSON_DATA["nfs"] = nfs_info
