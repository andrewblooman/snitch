"""Policy evaluation service.

Maps policy scan type labels to Finding model fields:
  sast      → finding_type="SAST",      scanner="semgrep"
  sca       → finding_type="SCA",       scanner="trivy"
  container → finding_type="container", scanner="grype"
  secrets   → finding_type="secrets",   scanner="gitleaks"
  iac       → finding_type="IaC",       scanner="checkov"
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.policy import Policy

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Maps policy scan-type label → (finding_type value, scanner value)
SCAN_TYPE_MAP: dict[str, tuple[str, str]] = {
    "sast": ("SAST", "semgrep"),
    "sca": ("SCA", "trivy"),
    "container": ("container", "grype"),
    "secrets": ("secrets", "gitleaks"),
    "iac": ("IaC", "checkov"),
}


def _severity_index(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity.lower())
    except ValueError:
        return 0


def _finding_scan_type(finding: "Finding") -> str | None:
    """Return the policy scan-type label for a finding, or None if unknown."""
    for label, (ftype, scanner) in SCAN_TYPE_MAP.items():
        if finding.finding_type == ftype or finding.scanner == scanner:
            return label
    return None


def evaluate_policy(policy: "Policy", findings: list["Finding"]) -> dict:
    """Evaluate a list of findings against a single policy.

    Returns a dict matching PolicyEvaluationResult schema.
    """
    from app.schemas.policy import PolicyEvaluationResult, PolicyViolation

    min_idx = _severity_index(policy.min_severity)
    enabled_types: set[str] = set(policy.enabled_scan_types) if policy.enabled_scan_types else set()
    blocklist: set[str] = {r.lower() for r in (policy.rule_blocklist or [])}
    allowlist: set[str] = {r.lower() for r in (policy.rule_allowlist or [])}

    violations: list[PolicyViolation] = []

    for finding in findings:
        if finding.status != "open":
            continue

        # Allowlist overrides everything — skip this finding
        rule_key = (finding.rule_id or "").lower()
        cve_key = (finding.cve_id or "").lower()
        if (rule_key and rule_key in allowlist) or (cve_key and cve_key in allowlist):
            continue

        # Filter by enabled scan types (empty = all types)
        if enabled_types:
            scan_type_label = _finding_scan_type(finding)
            if scan_type_label not in enabled_types:
                continue

        # Check blocklist (always flagged regardless of severity)
        if (rule_key and rule_key in blocklist) or (cve_key and cve_key in blocklist):
            violations.append(
                PolicyViolation(
                    finding_id=finding.id,
                    finding_title=finding.title,
                    severity=finding.severity,
                    scanner=finding.scanner,
                    finding_type=finding.finding_type,
                    rule_id=finding.rule_id,
                    cve_id=finding.cve_id,
                    reason="blocklisted_rule",
                )
            )
            continue

        # Check severity threshold
        if _severity_index(finding.severity) >= min_idx:
            violations.append(
                PolicyViolation(
                    finding_id=finding.id,
                    finding_title=finding.title,
                    severity=finding.severity,
                    scanner=finding.scanner,
                    finding_type=finding.finding_type,
                    rule_id=finding.rule_id,
                    cve_id=finding.cve_id,
                    reason="severity_threshold",
                )
            )

    blocked = len(violations) > 0 and policy.action in ("block", "both")

    return PolicyEvaluationResult(
        policy_id=policy.id,
        policy_name=policy.name,
        is_active=policy.is_active,
        action=policy.action,
        total_violations=len(violations),
        blocked=blocked,
        violations=violations,
    ).model_dump()


def evaluate_all_active_policies(
    db,  # SQLAlchemy Session (sync or async caller passes findings directly)
    findings: list["Finding"],
    policies: list["Policy"],
) -> list[dict]:
    """Evaluate all provided active policies against the given findings."""
    return [evaluate_policy(p, findings) for p in policies]
