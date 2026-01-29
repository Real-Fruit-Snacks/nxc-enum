"""Custom LDAP query enumeration."""

import re

from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc

# Regex to parse LDAP query response objects
# Format: "Response for object: CN=ObjectName,..."
RE_RESPONSE_OBJECT = re.compile(r"Response for object:\s*(.+)", re.IGNORECASE)

# Regex to parse attribute values from nxc --query output
# Format: "LDAP   IP   PORT   HOSTNAME   attribute_name   value" or
#         "LDAP   IP   PORT   HOSTNAME   attribute_name: value"
RE_ATTRIBUTE_LINE = re.compile(r"LDAP\s+\S+\s+\d+\s+\S+\s+(\w+)[\s:]+(.+)$", re.IGNORECASE)


def _parse_query_output(stdout: str, requested_attrs: list | None = None) -> list[dict]:
    """Parse nxc --query output into a list of result objects.

    Args:
        stdout: Raw nxc output from --query command
        requested_attrs: List of attributes that were requested (for filtering)

    Returns:
        List of dicts, each representing an LDAP object with its attributes
    """
    results = []
    current_object = None
    current_dn = None

    for line in stdout.split("\n"):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Check for new object header
        obj_match = RE_RESPONSE_OBJECT.search(line_stripped)
        if obj_match:
            # Save previous object if exists
            if current_object:
                results.append(current_object)

            # Start new object
            current_dn = obj_match.group(1).strip()
            current_object = {"dn": current_dn, "attributes": {}}
            continue

        # Parse attribute lines
        if current_object:
            attr_match = RE_ATTRIBUTE_LINE.search(line_stripped)
            if attr_match:
                attr_name = attr_match.group(1).strip()
                attr_value = attr_match.group(2).strip()

                # Filter to requested attributes if specified
                if requested_attrs:
                    # Case-insensitive match
                    if not any(attr_name.lower() == req.lower() for req in requested_attrs):
                        continue

                # Handle multi-valued attributes
                if attr_name in current_object["attributes"]:
                    existing = current_object["attributes"][attr_name]
                    if isinstance(existing, list):
                        existing.append(attr_value)
                    else:
                        current_object["attributes"][attr_name] = [existing, attr_value]
                else:
                    current_object["attributes"][attr_name] = attr_value

    # Don't forget the last object
    if current_object:
        results.append(current_object)

    return results


def _display_results_table(results: list[dict], attrs: list[str] | None = None) -> None:
    """Display query results in a formatted table.

    Args:
        results: List of parsed result objects
        attrs: List of attributes to display (uses all found if None)
    """
    if not results:
        return

    # Collect all attribute names found if not specified
    if attrs:
        display_attrs = attrs
    else:
        display_attrs = set()
        for obj in results:
            display_attrs.update(obj.get("attributes", {}).keys())
        display_attrs = sorted(display_attrs)

    # Calculate column widths
    col_widths = {}
    for attr in display_attrs:
        max_width = len(attr)
        for obj in results:
            val = obj.get("attributes", {}).get(attr, "")
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            max_width = max(max_width, len(str(val)))
        col_widths[attr] = min(max_width, 50)  # Cap at 50 chars

    # Print header
    header_parts = []
    for attr in display_attrs:
        header_parts.append(attr.ljust(col_widths[attr]))
    output("")
    output(c("  " + "  ".join(header_parts), Colors.BOLD))
    output("  " + "  ".join("-" * col_widths[attr] for attr in display_attrs))

    # Print rows
    for obj in results:
        row_parts = []
        for attr in display_attrs:
            val = obj.get("attributes", {}).get(attr, "")
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            val_str = str(val)[: col_widths[attr]]
            row_parts.append(val_str.ljust(col_widths[attr]))
        output("  " + "  ".join(row_parts))


def enum_custom_query(args, cache):
    """Execute a custom LDAP query and display results.

    This module allows users to run arbitrary LDAP queries using nxc's
    --query option. Results are parsed and displayed in a table format.

    Args:
        args: Parsed command-line arguments (must have args.query set)
        cache: EnumCache instance with target and auth information
    """
    target = cache.target if cache else args.target
    print_section("Custom LDAP Query", target, cache=cache)

    # Validate that query is provided
    if not args.query:
        status("No query filter specified (use --query)", "error")
        return

    # Check LDAP availability
    if not cache.ldap_available:
        status("LDAP unavailable - cannot execute custom query", "error")
        return

    auth = cache.auth_args
    query_filter = args.query

    # Parse requested attributes
    requested_attrs = None
    attrs_str = ""
    if args.query_attrs:
        # Accept comma-separated or space-separated attributes
        if "," in args.query_attrs:
            requested_attrs = [a.strip() for a in args.query_attrs.split(",") if a.strip()]
        else:
            requested_attrs = args.query_attrs.split()
        attrs_str = " ".join(requested_attrs)

    # Display query info
    status(f"Filter: {c(query_filter, Colors.CYAN)}")
    if requested_attrs:
        status(f"Attributes: {c(', '.join(requested_attrs), Colors.CYAN)}")
    else:
        status("Attributes: (all)")

    # Build nxc command
    # nxc ldap --query format: --query "FILTER" "ATTRS" (space-separated attrs)
    cmd_args = ["ldap", target] + auth + ["--query", query_filter]
    if attrs_str:
        cmd_args.append(attrs_str)

    status("Executing LDAP query...")
    rc, stdout, stderr = run_nxc(cmd_args, args.timeout)
    debug_nxc(cmd_args, stdout, stderr, "Custom LDAP Query")

    # Check for errors
    combined = (stdout + stderr).lower()
    error_indicators = [
        "invalid filter",
        "bad search filter",
        "filter error",
        "ldap error",
        "failed to connect",
        "connection refused",
        "timed out",
        "ldap ping failed",
        "status_logon_failure",
        "status_access_denied",
        "failed to create connection",
        "kerberos sessionerror",
    ]

    if any(ind in combined for ind in error_indicators) or rc != 0:
        # Try to extract specific error message
        if "invalid filter" in combined or "bad search filter" in combined:
            status(f"Invalid LDAP filter syntax: {query_filter}", "error")
            output("  Hint: Ensure proper LDAP filter syntax, e.g., '(objectClass=user)'")
        elif "status_access_denied" in combined or "status_logon_failure" in combined:
            status("Access denied - insufficient permissions for this query", "error")
        elif "timed out" in combined:
            status("Query timed out - try increasing timeout with -t", "error")
        else:
            status("LDAP query failed", "error")
            if stderr.strip():
                output(f"  Error: {stderr.strip()[:200]}")
        return

    # Parse results
    results = _parse_query_output(stdout, requested_attrs)

    if results:
        status(f"Found {len(results)} result(s)", "success")

        # Display in table format
        _display_results_table(results, requested_attrs)

        output("")

        # Show DN for each result (helpful for understanding context)
        output(c("Distinguished Names:", Colors.CYAN))
        for i, obj in enumerate(results[:10], 1):  # Limit to first 10 DNs
            dn = obj.get("dn", "Unknown")
            output(f"  {i}. {dn}")
        if len(results) > 10:
            output(f"  ... and {len(results) - 10} more")

        # Store sAMAccountNames in copy-paste data if present
        for obj in results:
            attrs = obj.get("attributes", {})
            sam_name = attrs.get("sAMAccountName") or attrs.get("samaccountname")
            if sam_name:
                cache.copy_paste_data["custom_query_names"].add(
                    sam_name if isinstance(sam_name, str) else sam_name[0]
                )
    else:
        status("No results found for query", "info")
        output(f"  Filter: {query_filter}")
        if requested_attrs:
            output(f"  Attributes: {', '.join(requested_attrs)}")

    # JSON export
    if args.json_output:
        JSON_DATA["custom_query"] = {
            "filter": query_filter,
            "attributes_requested": requested_attrs,
            "result_count": len(results),
            "results": results,
        }
