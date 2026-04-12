from datetime import date
from typing import Dict, List, Optional

from pydantic import BaseModel


class OverviewStats(BaseModel):
    total_apps: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    open_findings: int
    fixed_findings: int
    avg_risk_score: float
    apps_by_risk_level: Dict[str, int]
    mttr_days: Optional[float] = None  # Mean time to remediate


class LeaderboardEntry(BaseModel):
    rank: int
    team_name: str
    app_count: int
    total_findings: int
    critical_findings: int
    high_findings: int
    avg_risk_score: float
    risk_level: str


class TrendDataPoint(BaseModel):
    date: date
    critical: int
    high: int
    medium: int
    low: int
    total: int


class VulnerabilityTrend(BaseModel):
    data_points: List[TrendDataPoint]
    period_days: int


class PRRecord(BaseModel):
    remediation_id: str
    title: str
    application_name: str
    team_name: str
    pr_url: Optional[str]
    pr_number: Optional[int]
    pr_status: Optional[str]
    status: str
    created_at: str


class TopVulnerability(BaseModel):
    identifier: str  # CVE ID or rule ID
    title: str
    finding_type: str
    severity: str
    affected_apps: int
    total_occurrences: int
    cvss_score: Optional[float] = None
