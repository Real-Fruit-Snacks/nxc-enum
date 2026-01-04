"""User and group classification utilities."""

from ..core.constants import SERVICE_ACCOUNT_SUFFIXES, SERVICE_ACCOUNT_PREFIXES, HIGH_VALUE_GROUPS


def safe_int(value: str, default: int = 9999) -> int:
    """Safely convert string to int with fallback."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def is_service_account(username: str) -> bool:
    """Check if username appears to be a service account."""
    username_lower = username.lower()
    for suffix in SERVICE_ACCOUNT_SUFFIXES:
        if username_lower.endswith(suffix):
            return True
    for prefix in SERVICE_ACCOUNT_PREFIXES:
        if username_lower.startswith(prefix):
            return True
    return False


def is_computer_account(username: str) -> bool:
    """Check if username is a computer account (ends with $)."""
    return username.endswith('$')


def is_builtin_account(rid: int) -> bool:
    """Check if RID indicates a built-in account."""
    return rid < 1000


def classify_users(users: dict) -> dict:
    """Classify users into categories for display."""
    categories = {
        'builtin': [],
        'service': [],
        'computer': [],
        'domain': []
    }

    sorted_users = sorted(users.items(), key=lambda x: safe_int(x[1].get('rid', '9999')))

    for username, info in sorted_users:
        rid = safe_int(info.get('rid', '9999'))

        if is_builtin_account(rid):
            categories['builtin'].append((username, info))
        elif is_service_account(username):
            categories['service'].append((username, info))
        elif is_computer_account(username):
            categories['computer'].append((username, info))
        else:
            categories['domain'].append((username, info))

    return categories


def classify_groups(groups: dict) -> dict:
    """Classify groups into high-value and other."""
    categories = {
        'high_value': [],
        'other': []
    }

    sorted_groups = sorted(groups.items(), key=lambda x: safe_int(x[1].get('rid', '9999')))

    for groupname, info in sorted_groups:
        if groupname in HIGH_VALUE_GROUPS:
            categories['high_value'].append((groupname, info))
        else:
            categories['other'].append((groupname, info))

    return categories
