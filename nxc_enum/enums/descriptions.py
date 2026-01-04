"""User descriptions enumeration."""

from ..core.runner import run_nxc
from ..core.output import output, status, print_section, debug_nxc, JSON_DATA
from ..core.colors import Colors, c
from ..parsing.nxc_output import is_nxc_noise_line


def enum_descriptions(args, cache):
    """Extract user description fields."""
    print_section("User Descriptions", args.target)

    auth = cache.auth_args
    status("Querying user descriptions...")

    desc_args = ["ldap", args.target] + auth + ["-M", "get-desc-users"]
    rc, stdout, stderr = run_nxc(desc_args, args.timeout)
    debug_nxc(desc_args, stdout, stderr, "User Descriptions")

    descriptions = []
    for line in stdout.split('\n'):
        line = line.strip()
        if not line or is_nxc_noise_line(line):
            continue

        if 'User:' in line and 'description:' in line:
            user_part = line.split('User:', 1)[-1]
            if 'description:' in user_part:
                username, desc = user_part.split('description:', 1)
                descriptions.append({
                    'user': username.strip(),
                    'description': desc.strip()
                })

    cache.user_descriptions = descriptions

    if descriptions:
        status(f"Found {len(descriptions)} user description(s):", "info")
        output("")
        for d in descriptions:
            if d['description']:
                desc_lower = d['description'].lower()
                is_sensitive = any(kw in desc_lower for kw in ['pass', 'pwd', 'cred', 'secret', 'key'])
                desc_color = Colors.RED if is_sensitive else Colors.CYAN
                output(f"  {d['user']}: {c(d['description'], desc_color)}")
    else:
        status("No user descriptions found", "info")

    if args.json_output:
        JSON_DATA['user_descriptions'] = descriptions
