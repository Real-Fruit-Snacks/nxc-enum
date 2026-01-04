"""Machine Account Quota enumeration."""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, print_section, status
from ..core.runner import run_nxc
from ..parsing.nxc_output import is_nxc_noise_line


def enum_maq(args, cache):
    """Check machine account quota."""
    print_section("Machine Account Quota", args.target)

    auth = cache.auth_args
    status("Querying machine account quota...")

    maq_args = ["ldap", args.target] + auth + ["-M", "maq"]
    rc, stdout, stderr = run_nxc(maq_args, args.timeout)
    debug_nxc(maq_args, stdout, stderr, "Machine Account Quota")

    quota = None
    for line in stdout.split("\n"):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue

        # Handle both module output format and LDAP query format:
        # Module: "MachineAccountQuota: 10"
        # Query:  "ms-DS-MachineAccountQuota 10"

        # Module output format (with colon)
        if "MachineAccountQuota:" in line:
            parts = line.split("MachineAccountQuota:", 1)
            if len(parts) > 1:
                numbers = re.findall(r"\d+", parts[1])
                if numbers:
                    quota = int(numbers[0])
                    break

        # LDAP query output format (ms-DS prefix, space-separated)
        if "ms-DS-MachineAccountQuota" in line:
            parts = line.split("ms-DS-MachineAccountQuota", 1)
            if len(parts) > 1:
                numbers = re.findall(r"\d+", parts[1])
                if numbers:
                    quota = int(numbers[0])
                    break

    cache.machine_account_quota = quota

    if quota is not None:
        if quota > 0:
            status(
                f"Machine Account Quota: {c(str(quota), Colors.YELLOW)} (users can add computers)",
                "warning",
            )

            # Add machine account abuse recommendation
            domain = cache.domain_info.get("dns_domain", "<domain>")
            cache.add_next_step(
                finding=f"Machine Account Quota is {quota}",
                command=f"addcomputer.py -computer-name 'YOURPC$' -computer-pass 'Password123!' '{domain}/<user>:<pass>'",
                description="Add a machine account for RBCD or other attacks",
                priority="medium",
            )
        else:
            status(f"Machine Account Quota: {quota} (users cannot add computers)", "success")
    else:
        status("Could not determine machine account quota", "info")

    if args.json_output:
        JSON_DATA["machine_account_quota"] = quota
