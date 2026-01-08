"""Multi-target scan result aggregation."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .cache import EnumCache


@dataclass
class TargetResult:
    """Result from scanning a single target.

    Attributes:
        target: IP or hostname that was scanned
        status: "success", "failed", or "skipped"
        error: Error message if status is "failed"
        cache: EnumCache with findings (if successful)
        elapsed_time: Time taken to scan this target
        json_data: Per-target JSON data snapshot (for per-target file output)
        output_lines: Per-target output buffer snapshot (for per-target file output)
    """

    target: str
    status: str = "pending"  # "success", "failed", "skipped"
    error: Optional[str] = None
    cache: Optional[EnumCache] = None
    elapsed_time: float = 0.0
    json_data: Optional[Dict[str, Any]] = None
    output_lines: Optional[List[str]] = None


@dataclass
class MultiTargetResults:
    """Aggregated results from multi-target scan.

    Collects results from each target and provides methods to
    aggregate findings across all successful targets.
    """

    results: Dict[str, TargetResult] = field(default_factory=dict)
    total_elapsed: float = 0.0

    def add_result(self, target: str, result: TargetResult) -> None:
        """Add a target's result to the collection."""
        self.results[target] = result

    @property
    def successful_targets(self) -> List[str]:
        """List of targets that completed successfully."""
        return [t for t, r in self.results.items() if r.status == "success"]

    @property
    def failed_targets(self) -> List[str]:
        """List of targets that failed."""
        return [t for t, r in self.results.items() if r.status == "failed"]

    @property
    def success_count(self) -> int:
        """Number of successful scans."""
        return len(self.successful_targets)

    @property
    def fail_count(self) -> int:
        """Number of failed scans."""
        return len(self.failed_targets)

    def get_aggregate_findings(self) -> Dict[str, Any]:
        """Aggregate key findings across all successful targets.

        Returns dict with:
        - smb_signing_disabled: List of targets with SMB signing disabled
        - kerberoastable_count: Total kerberoastable accounts found
        - asreproastable_count: Total AS-REP roastable accounts found
        - total_users: Total unique users across all targets
        - total_shares: Total shares found
        - anonymous_access: Targets allowing anonymous access
        - delegation_accounts: Delegation accounts found
        - outdated_os: Targets with outdated OS
        """
        findings = {
            "smb_signing_disabled": [],
            "kerberoastable_count": 0,
            "kerberoastable_accounts": [],
            "asreproastable_count": 0,
            "asreproastable_accounts": [],
            "total_users": 0,
            "total_shares": 0,
            "anonymous_access": [],
            "delegation_accounts": [],
            "outdated_os": [],
            "pwd_not_required": [],
            "admin_count_accounts": [],
            "webdav_enabled": [],
            "domain_info": {},  # Map of target -> domain info
        }

        for target, result in self.results.items():
            if result.status != "success" or not result.cache:
                continue

            cache = result.cache

            # SMB Signing
            if cache.smb_signing_disabled:
                findings["smb_signing_disabled"].append(target)

            # Kerberoastable
            if cache.kerberoastable:
                findings["kerberoastable_count"] += len(cache.kerberoastable)
                findings["kerberoastable_accounts"].extend(cache.kerberoastable)

            # AS-REP Roastable
            if cache.asreproastable:
                findings["asreproastable_count"] += len(cache.asreproastable)
                findings["asreproastable_accounts"].extend(cache.asreproastable)

            # User/Share counts
            findings["total_users"] += cache.user_count
            findings["total_shares"] += cache.share_count

            # Anonymous access
            anon = cache.anonymous_access
            if anon.get("null_available") or anon.get("guest_available"):
                findings["anonymous_access"].append(target)

            # Delegation
            if cache.delegation_accounts:
                findings["delegation_accounts"].extend(cache.delegation_accounts)

            # Outdated OS
            if cache.outdated_os_computers:
                findings["outdated_os"].extend([(target, c) for c in cache.outdated_os_computers])

            # PASSWD_NOTREQD
            if cache.pwd_not_required:
                findings["pwd_not_required"].extend(cache.pwd_not_required)

            # AdminCount
            if cache.admin_count_accounts:
                findings["admin_count_accounts"].extend(cache.admin_count_accounts)

            # WebDAV
            if cache.webdav_enabled:
                findings["webdav_enabled"].append(target)

            # Domain info
            if cache.domain_info:
                findings["domain_info"][target] = cache.domain_info

        return findings

    def to_json(self) -> Dict[str, Any]:
        """Export results as JSON-serializable dict."""
        aggregate = self.get_aggregate_findings()

        return {
            "scan_info": {
                "total_targets": len(self.results),
                "successful": self.success_count,
                "failed": self.fail_count,
                "total_elapsed": self.total_elapsed,
            },
            "targets": {
                target: {
                    "status": result.status,
                    "error": result.error,
                    "elapsed_time": result.elapsed_time,
                }
                for target, result in self.results.items()
            },
            "aggregate": {
                "smb_signing_disabled": aggregate["smb_signing_disabled"],
                "kerberoastable_count": aggregate["kerberoastable_count"],
                "asreproastable_count": aggregate["asreproastable_count"],
                "total_users": aggregate["total_users"],
                "total_shares": aggregate["total_shares"],
                "anonymous_access": aggregate["anonymous_access"],
                "webdav_enabled": aggregate["webdav_enabled"],
            },
        }
