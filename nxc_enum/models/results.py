"""Multi-user results container."""


class MultiUserResults:
    """Store results from per-user commands for multi-credential mode."""

    def __init__(self):
        # Share access matrix: {share_name: {user: permission}}
        self.shares: dict[str, dict[str, str]] = {}
        self.share_comments: dict[str, str] = {}

        # Session results: {user: (success, sessions_list_or_error)}
        self.sessions: dict[str, tuple[bool, list | str]] = {}

        # Logged on results: {user: (success, logged_on_list_or_error)}
        self.loggedon: dict[str, tuple[bool, list | str]] = {}

        # Printers: {user: (success, spooler_running)}
        self.printers: dict[str, tuple[bool, bool]] = {}

        # AV detection: {product: [users_who_detected]}
        self.av_products: dict[str, list[str]] = {}
        # Track users skipped for AV (non-admin)
        self.av_skipped: list[str] = []
