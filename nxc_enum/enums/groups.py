"""Group enumeration."""

from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.runner import run_nxc
from ..core.output import output, status, print_section, debug_nxc, JSON_DATA
from ..core.colors import Colors, c
from ..core.constants import (
    RE_GROUP, RE_RID_GROUP, RE_RID_ALIAS,
    RE_GROUP_DESC, RE_GROUP_TYPE, RE_GROUP_SCOPE, RE_GROUP_DN, RE_GROUP_SAM,
    BUILTIN_GROUP_RID_MIN, BUILTIN_GROUP_RID_MAX, DOMAIN_GROUP_RID_MIN, DOMAIN_GROUP_RID_MAX
)
from ..parsing.classify import classify_groups, safe_int
from ..parsing.nxc_output import is_nxc_noise_line


def parse_verbose_group_output(stdout: str) -> dict:
    """Parse verbose LDAP --groups output for additional group details.

    Verbose output may include INFO lines with:
    - description: Group purpose/description
    - groupType: Security or Distribution group type
    - groupScope: Global, Universal, or Domain Local scope
    - distinguishedName: Full DN path
    - sAMAccountName: Group's SAM account name

    Returns dict mapping group names to their verbose details.
    """
    verbose_data = {}
    current_group = None

    for line in stdout.split('\n'):
        line = line.strip()
        if not line:
            continue

        # Match standard group line to track current group context
        group_match = RE_GROUP.search(line)
        if group_match:
            current_group = group_match.group(1).strip()
            if current_group not in verbose_data:
                verbose_data[current_group] = {}
            continue

        # Skip noise lines but continue parsing verbose data
        if is_nxc_noise_line(line):
            continue

        # Parse verbose INFO lines (typically start with protocol or contain verbose attrs)
        # Look for description
        desc_match = RE_GROUP_DESC.search(line)
        if desc_match and current_group:
            desc_value = desc_match.group(1).strip()
            if desc_value and desc_value.lower() != '(null)':
                verbose_data[current_group]['description'] = desc_value
            continue

        # Look for group type (Security/Distribution)
        type_match = RE_GROUP_TYPE.search(line)
        if type_match and current_group:
            type_value = type_match.group(1).strip()
            if type_value:
                verbose_data[current_group]['group_type'] = type_value
            continue

        # Look for group scope (Global/Universal/DomainLocal)
        scope_match = RE_GROUP_SCOPE.search(line)
        if scope_match and current_group:
            scope_value = scope_match.group(1).strip()
            if scope_value:
                verbose_data[current_group]['scope'] = scope_value
            continue

        # Look for distinguished name
        dn_match = RE_GROUP_DN.search(line)
        if dn_match and current_group:
            dn_value = dn_match.group(1).strip()
            if dn_value:
                verbose_data[current_group]['dn'] = dn_value
            continue

        # Look for sAMAccountName (useful when display name differs)
        sam_match = RE_GROUP_SAM.search(line)
        if sam_match and current_group:
            sam_value = sam_match.group(1).strip()
            if sam_value:
                verbose_data[current_group]['sam_account_name'] = sam_value
            continue

    return verbose_data


def get_group_members(target: str, auth: list, group_name: str, timeout: int) -> list:
    """Query members of a specific group via LDAP."""
    group_members_args = ["ldap", target] + auth + ["--groups", group_name]
    rc, stdout, stderr = run_nxc(group_members_args, timeout)
    debug_nxc(group_members_args, stdout, stderr, f"Group Members ({group_name})")

    members = []
    for line in stdout.split('\n'):
        line = line.strip()
        if not line:
            continue
        if '[*]' in line or '[+]' in line or '[-]' in line:
            continue
        if is_nxc_noise_line(line):
            continue

        if line.startswith('LDAP') or line.startswith('SMB'):
            parts = line.split()
            if len(parts) >= 5:
                try:
                    port_idx = -1
                    for i, p in enumerate(parts):
                        if p in ('389', '636', '445', '139'):
                            port_idx = i
                            break
                    if port_idx >= 0 and port_idx + 2 < len(parts):
                        member_name = ' '.join(parts[port_idx + 2:])
                        if member_name and member_name not in members:
                            members.append(member_name)
                except (ValueError, IndexError):
                    pass

    return members


def enum_groups(args, cache):
    """Enumerate domain groups."""
    print_section("Groups via RPC", args.target)

    auth = cache.auth_args
    groups = {}

    # Get groups via --groups (LDAP protocol - SMB --groups is deprecated)
    status("Enumerating domain groups")
    groups_args = ["ldap", args.target] + auth + ["--groups"]
    rc, stdout, stderr = run_nxc(groups_args, args.timeout)
    debug_nxc(groups_args, stdout, stderr, "Groups")

    # Parse: Group: Domain Admins membercount: 2
    for line in stdout.split('\n'):
        group_match = RE_GROUP.search(line)
        if group_match:
            groupname = group_match.group(1).strip()
            membercount = group_match.group(2)
            groups[groupname] = {'type': 'domain', 'membercount': membercount}

    # Parse verbose output for additional group details (descriptions, types, scopes)
    verbose_data = parse_verbose_group_output(stdout)

    # Merge verbose data into groups dict
    for groupname, verbose_info in verbose_data.items():
        if groupname in groups:
            groups[groupname].update(verbose_info)

    # Track groups with descriptions for cache
    groups_with_descriptions = []
    for groupname, info in groups.items():
        if info.get('description'):
            groups_with_descriptions.append({
                'group': groupname,
                'description': info['description'],
                'group_type': info.get('group_type', ''),
                'scope': info.get('scope', '')
            })

    cache.group_descriptions = groups_with_descriptions

    # Use cached RID brute results
    status("Enumerating builtin groups")
    rc2, stdout2, stderr2 = cache.get_rid_brute(args.target, auth)

    # Parse group RIDs
    for line in stdout2.split('\n'):
        rid_match = RE_RID_GROUP.search(line)
        if rid_match:
            rid = rid_match.group(1)
            groupname = rid_match.group(2).strip()
            rid_int = safe_int(rid, 0)

            if BUILTIN_GROUP_RID_MIN <= rid_int <= BUILTIN_GROUP_RID_MAX:  # Windows built-in group RIDs
                gtype = 'builtin'
            elif DOMAIN_GROUP_RID_MIN <= rid_int <= DOMAIN_GROUP_RID_MAX:  # Domain-managed group RIDs
                gtype = 'domain'
            else:
                gtype = 'local'

            if groupname not in groups:
                groups[groupname] = {'type': gtype}
            groups[groupname]['rid'] = rid

        alias_match = RE_RID_ALIAS.search(line)
        if alias_match:
            rid = alias_match.group(1)
            groupname = alias_match.group(2).strip()
            rid_int = safe_int(rid, 0)
            gtype = 'builtin' if BUILTIN_GROUP_RID_MIN <= rid_int <= BUILTIN_GROUP_RID_MAX else 'local'

            if groupname not in groups:
                groups[groupname] = {'type': gtype}
            groups[groupname]['rid'] = rid

    if groups:
        cache.group_count = len(groups)

        local_count = sum(1 for g in groups.values() if g.get('type') == 'local')
        builtin_count = sum(1 for g in groups.values() if g.get('type') == 'builtin')
        domain_count = sum(1 for g in groups.values() if g.get('type') == 'domain')

        status(f"Found {len(groups)} group(s) total ({domain_count} domain, {builtin_count} builtin, {local_count} local)", "success")

        categories = classify_groups(groups)

        # Query members of high-value groups in parallel
        group_members = {}
        privileged_users = set()
        if categories['high_value']:
            status("Enumerating high-value group members...")

            def fetch_members(group_name):
                members = get_group_members(args.target, cache.auth_args, group_name, args.timeout)
                return group_name, members

            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(fetch_members, gname) for gname, _ in categories['high_value']]
                for future in as_completed(futures):
                    try:
                        gname, members = future.result()
                        group_members[gname] = members
                        for member in members:
                            privileged_users.add(member)
                    except Exception as e:
                        status(f"Error fetching group members: {e}", "error")

        cache.privileged_users = list(privileged_users)

        # Print High-Value Groups
        if categories['high_value']:
            groups_with_members = []
            groups_without_members = []

            for groupname, info in categories['high_value']:
                members = group_members.get(groupname, [])
                if members:
                    groups_with_members.append((groupname, info, members))
                else:
                    groups_without_members.append((groupname, info))

            output("")
            output(c(f"HIGH-VALUE GROUPS ({len(categories['high_value'])})", Colors.RED + Colors.BOLD))
            output(c("=" * 70, Colors.RED))

            if groups_with_members:
                output(f"{'Group':<32} {'Members'}")
                output(f"{'-'*32} {'-'*38}")

                for groupname, info, members in groups_with_members:
                    display_name = groupname[:30] + '..' if len(groupname) > 32 else groupname
                    padded_name = display_name.ljust(32)
                    members_str = ', '.join(members[:5])
                    if len(members) > 5:
                        members_str += f" (+{len(members) - 5})"
                    output(f"{c(padded_name, Colors.RED)} {c(members_str, Colors.YELLOW)}")
                    # Show description if available from verbose output
                    if info.get('description'):
                        desc = info['description']
                        if len(desc) > 66:
                            desc = desc[:63] + '...'
                        output(f"  {c('Desc:', Colors.CYAN)} {desc}")

            if groups_without_members:
                output("")
                empty_names = [g[0] for g in groups_without_members]
                output(f"{c('Empty/Inaccessible:', Colors.CYAN)} {', '.join(empty_names)}")

        # Print Other Groups
        if categories['other']:
            output("")
            output(c(f"OTHER GROUPS ({len(categories['other'])})", Colors.CYAN))
            output("-" * 70)

            by_type = {'domain': [], 'builtin': [], 'local': []}
            for groupname, info in categories['other']:
                gtype = info.get('type', 'local')
                by_type.get(gtype, by_type['local']).append(groupname)

            for gtype, names in by_type.items():
                if names:
                    names_str = ', '.join(names)
                    if len(names_str) > 65:
                        shown = []
                        length = 0
                        for name in names:
                            if length + len(name) + 2 > 50:
                                break
                            shown.append(name)
                            length += len(name) + 2
                        names_str = ', '.join(shown) + f" (+{len(names) - len(shown)} more)"
                    output(f"  {c(gtype.capitalize() + ':', Colors.BOLD)} {names_str}")

        # Print Group Descriptions section if any were found from verbose output
        if cache.group_descriptions:
            output("")
            output(c(f"GROUP DESCRIPTIONS ({len(cache.group_descriptions)})", Colors.CYAN))
            output("-" * 70)

            for gd in cache.group_descriptions:
                groupname = gd['group']
                desc = gd['description']
                # Highlight potentially sensitive descriptions
                desc_lower = desc.lower()
                is_sensitive = any(kw in desc_lower for kw in [
                    'pass', 'pwd', 'cred', 'secret', 'key', 'admin', 'temp', 'test'
                ])
                desc_color = Colors.RED if is_sensitive else Colors.WHITE

                # Truncate long descriptions
                if len(desc) > 55:
                    desc = desc[:52] + '...'

                display_name = groupname[:25] + '..' if len(groupname) > 27 else groupname
                padded_name = display_name.ljust(27)

                # Show group type/scope if available
                type_scope = []
                if gd.get('group_type'):
                    type_scope.append(gd['group_type'])
                if gd.get('scope'):
                    type_scope.append(gd['scope'])
                type_info = f" [{'/'.join(type_scope)}]" if type_scope else ""

                output(f"  {c(padded_name, Colors.BOLD)}{type_info}")
                output(f"    {c(desc, desc_color)}")

        if args.json_output:
            sorted_groups = sorted(groups.items(), key=lambda x: safe_int(x[1].get('rid', '9999')))
            JSON_DATA['groups'] = {g: v for g, v in sorted_groups}
            if cache.group_descriptions:
                JSON_DATA['group_descriptions'] = cache.group_descriptions
    else:
        status("No groups found or unable to parse output", "warning")
