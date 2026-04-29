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

    # Weighted scoring: critical=25, high=10, medium=3, low=1
    # Rationale: critical findings represent active exploit risk (CVSS 9+),
    # high represent significant risk (CVSS 7-9), medium are moderate issues,
    # and low are informational/best-practice. Scores are capped at 100.
    score = (critical * 25) + (high * 10) + (medium * 3) + (low * 1)
    
    # EPSS Boost: If a highly exploitable CVE (top 15%) is present and open, boost the score.
    epss_boost = 0
    for f in open_findings:
        if f.epss_percentile and f.epss_percentile > 0.85:
            epss_boost += 15
        elif f.epss_percentile and f.epss_percentile > 0.50:
            epss_boost += 5
            
    score += epss_boost
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
