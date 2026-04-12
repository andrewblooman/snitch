from typing import List, Tuple

from app.models.finding import Finding


def calculate_risk_score(findings: List[Finding]) -> Tuple[float, str]:
    """
    Calculate risk score from a list of open findings.
    Returns (score 0-100, risk_level string).
    """
    open_findings = [f for f in findings if f.status == "open"]

    critical = sum(1 for f in open_findings if f.severity == "critical")
    high = sum(1 for f in open_findings if f.severity == "high")
    medium = sum(1 for f in open_findings if f.severity == "medium")
    low = sum(1 for f in open_findings if f.severity == "low")

    score = (critical * 25) + (high * 10) + (medium * 3) + (low * 1)
    score = min(score, 100.0)

    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "info"

    return float(score), level
