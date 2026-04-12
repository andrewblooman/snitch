from datetime import date, datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.application import Application
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.schemas.report import (
    LeaderboardEntry,
    OverviewStats,
    PRRecord,
    TopVulnerability,
    TrendDataPoint,
    VulnerabilityTrend,
)

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/overview", response_model=OverviewStats)
async def get_overview(db: AsyncSession = Depends(get_db)):
    apps_result = await db.execute(select(Application))
    apps = apps_result.scalars().all()

    findings_result = await db.execute(select(Finding))
    findings = findings_result.scalars().all()

    risk_level_counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for app in apps:
        risk_level_counts[app.risk_level] = risk_level_counts.get(app.risk_level, 0) + 1

    # MTTR: average days between first_seen_at and fixed_at for fixed findings
    fixed = [f for f in findings if f.status == "fixed" and f.fixed_at and f.first_seen_at]
    mttr = None
    if fixed:
        total_days = sum((f.fixed_at - f.first_seen_at).days for f in fixed)
        mttr = total_days / len(fixed)

    avg_risk = sum(a.risk_score for a in apps) / len(apps) if apps else 0.0

    return OverviewStats(
        total_apps=len(apps),
        total_findings=len(findings),
        critical_findings=sum(1 for f in findings if f.severity == "critical"),
        high_findings=sum(1 for f in findings if f.severity == "high"),
        medium_findings=sum(1 for f in findings if f.severity == "medium"),
        low_findings=sum(1 for f in findings if f.severity == "low"),
        open_findings=sum(1 for f in findings if f.status == "open"),
        fixed_findings=sum(1 for f in findings if f.status == "fixed"),
        avg_risk_score=round(avg_risk, 2),
        apps_by_risk_level=risk_level_counts,
        mttr_days=round(mttr, 1) if mttr is not None else None,
    )


@router.get("/leaderboard", response_model=List[LeaderboardEntry])
async def get_leaderboard(db: AsyncSession = Depends(get_db)):
    apps_result = await db.execute(select(Application))
    apps = apps_result.scalars().all()

    findings_result = await db.execute(select(Finding))
    all_findings = findings_result.scalars().all()

    # Group by team
    teams: dict = {}
    for app in apps:
        t = app.team_name
        if t not in teams:
            teams[t] = {"apps": [], "risk_scores": []}
        teams[t]["apps"].append(app)
        teams[t]["risk_scores"].append(app.risk_score)

    findings_by_app: dict = {}
    for f in all_findings:
        if f.application_id not in findings_by_app:
            findings_by_app[f.application_id] = []
        findings_by_app[f.application_id].append(f)

    entries = []
    for team_name, data in teams.items():
        team_findings = []
        for app in data["apps"]:
            team_findings.extend(findings_by_app.get(app.id, []))

        avg_risk = sum(data["risk_scores"]) / len(data["risk_scores"])
        open_findings = [f for f in team_findings if f.status == "open"]

        if avg_risk >= 75:
            risk_level = "critical"
        elif avg_risk >= 50:
            risk_level = "high"
        elif avg_risk >= 25:
            risk_level = "medium"
        elif avg_risk > 0:
            risk_level = "low"
        else:
            risk_level = "info"

        entries.append(
            LeaderboardEntry(
                rank=0,
                team_name=team_name,
                app_count=len(data["apps"]),
                total_findings=len(open_findings),
                critical_findings=sum(1 for f in open_findings if f.severity == "critical"),
                high_findings=sum(1 for f in open_findings if f.severity == "high"),
                avg_risk_score=round(avg_risk, 2),
                risk_level=risk_level,
            )
        )

    entries.sort(key=lambda e: e.avg_risk_score)
    for i, entry in enumerate(entries, 1):
        entry.rank = i

    return entries


@router.get("/trend", response_model=VulnerabilityTrend)
async def get_trend(
    days: int = Query(90, ge=7, le=365),
    db: AsyncSession = Depends(get_db),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    findings_result = await db.execute(
        select(Finding).where(Finding.first_seen_at >= cutoff)
    )
    findings = findings_result.scalars().all()

    # Build cumulative daily counts
    daily: dict[date, dict] = {}
    today = datetime.now(timezone.utc).date()
    for i in range(days):
        d = today - timedelta(days=days - 1 - i)
        daily[d] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in findings:
        d = f.first_seen_at.date()
        if d in daily:
            sev = f.severity if f.severity in daily[d] else "low"
            daily[d][sev] = daily[d].get(sev, 0) + 1

    data_points = []
    running = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for d in sorted(daily.keys()):
        for sev in running:
            running[sev] += daily[d].get(sev, 0)
        data_points.append(
            TrendDataPoint(
                date=d,
                critical=running["critical"],
                high=running["high"],
                medium=running["medium"],
                low=running["low"],
                total=sum(running.values()),
            )
        )

    return VulnerabilityTrend(data_points=data_points, period_days=days)


@router.get("/pull-requests", response_model=List[PRRecord])
async def get_pull_requests(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Remediation))
    remediations = result.scalars().all()

    app_ids = list({r.application_id for r in remediations})
    if not app_ids:
        return []

    apps_result = await db.execute(select(Application).where(Application.id.in_(app_ids)))
    apps = {a.id: a for a in apps_result.scalars().all()}

    return [
        PRRecord(
            remediation_id=str(r.id),
            title=r.title,
            application_name=apps[r.application_id].name if r.application_id in apps else "Unknown",
            team_name=apps[r.application_id].team_name if r.application_id in apps else "Unknown",
            pr_url=r.pr_url,
            pr_number=r.pr_number,
            pr_status=r.pr_status,
            status=r.status,
            created_at=r.created_at.isoformat(),
        )
        for r in remediations
    ]


@router.get("/top-vulnerabilities", response_model=List[TopVulnerability])
async def get_top_vulnerabilities(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    findings_result = await db.execute(select(Finding).where(Finding.status == "open"))
    findings = findings_result.scalars().all()

    vuln_map: dict = {}
    for f in findings:
        key = f.cve_id or f.rule_id or f.title
        if not key:
            continue
        if key not in vuln_map:
            vuln_map[key] = {
                "identifier": key,
                "title": f.title,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "affected_apps": set(),
                "total_occurrences": 0,
                "cvss_score": f.cvss_score,
            }
        vuln_map[key]["affected_apps"].add(str(f.application_id))
        vuln_map[key]["total_occurrences"] += 1

    results = []
    for v in vuln_map.values():
        results.append(
            TopVulnerability(
                identifier=v["identifier"],
                title=v["title"],
                finding_type=v["finding_type"],
                severity=v["severity"],
                affected_apps=len(v["affected_apps"]),
                total_occurrences=v["total_occurrences"],
                cvss_score=v["cvss_score"],
            )
        )

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results.sort(key=lambda v: (sev_order.get(v.severity, 5), -v.total_occurrences))
    return results[:limit]
