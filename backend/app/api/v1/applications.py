import math
import uuid
from datetime import datetime, timezone
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.application import Application
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.application import (
    ApplicationCreate,
    ApplicationDetail,
    ApplicationListResponse,
    ApplicationResponse,
    ApplicationUpdate,
    PaginatedApplications,
)
from app.schemas.finding import PaginatedFindings
from app.schemas.scan import PaginatedScans, ScanResponse
from app.services.scoring import calculate_risk_score

router = APIRouter(prefix="/applications", tags=["applications"])


def _finding_counts(findings: List[Finding]) -> dict:
    open_findings = [f for f in findings if f.status == "open"]
    return {
        "critical_count": sum(1 for f in open_findings if f.severity == "critical"),
        "high_count": sum(1 for f in open_findings if f.severity == "high"),
        "medium_count": sum(1 for f in open_findings if f.severity == "medium"),
        "low_count": sum(1 for f in open_findings if f.severity == "low"),
        "total_findings": len(findings),
        "open_findings": len(open_findings),
    }


@router.get("", response_model=PaginatedApplications)
async def list_applications(
    team: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    q = select(Application)
    if team:
        q = q.where(Application.team_name == team)
    if risk_level:
        q = q.where(Application.risk_level == risk_level)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(Application.risk_score.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    apps = result.scalars().all()

    app_ids = [app.id for app in apps]
    counts_by_app = {
        app_id: {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "total_findings": 0,
            "open_findings": 0,
        }
        for app_id in app_ids
    }

    if app_ids:
        findings_result = await db.execute(
            select(
                Finding.application_id,
                Finding.status,
                Finding.severity,
                func.count().label("finding_count"),
            )
            .where(Finding.application_id.in_(app_ids))
            .group_by(Finding.application_id, Finding.status, Finding.severity)
        )

        for application_id, finding_status, finding_severity, finding_count in findings_result.all():
            counts = counts_by_app[application_id]
            counts["total_findings"] += finding_count
            if finding_status == "open":
                counts["open_findings"] += finding_count
                if finding_severity == "critical":
                    counts["critical_count"] += finding_count
                elif finding_severity == "high":
                    counts["high_count"] += finding_count
                elif finding_severity == "medium":
                    counts["medium_count"] += finding_count
                elif finding_severity == "low":
                    counts["low_count"] += finding_count

    items = []
    for app in apps:
        counts = counts_by_app.get(
            app.id,
            {
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "total_findings": 0,
                "open_findings": 0,
            },
        )
        items.append(ApplicationListResponse(**app.__dict__, **counts))

    return PaginatedApplications(
        items=items, total=total, page=page, page_size=page_size,
        pages=max(1, math.ceil(total / page_size))
    )


@router.post("", response_model=ApplicationResponse, status_code=status.HTTP_201_CREATED)
async def create_application(payload: ApplicationCreate, db: AsyncSession = Depends(get_db)):
    app = Application(**payload.model_dump())
    db.add(app)
    await db.flush()
    await db.refresh(app)
    return app


@router.get("/{app_id}", response_model=ApplicationDetail)
async def get_application(app_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    findings_result = await db.execute(
        select(Finding).where(Finding.application_id == app_id)
    )
    findings = findings_result.scalars().all()

    scan_result = await db.execute(
        select(func.count()).where(Scan.application_id == app_id)
    )
    scan_count = scan_result.scalar_one()

    counts = _finding_counts(findings)
    counts["scan_count"] = scan_count
    return ApplicationDetail(**app.__dict__, **counts)


@router.put("/{app_id}", response_model=ApplicationResponse)
async def update_application(
    app_id: uuid.UUID, payload: ApplicationUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(app, field, value)
    await db.flush()
    await db.refresh(app)
    return app


@router.delete("/{app_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_application(app_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    await db.delete(app)


@router.post("/{app_id}/scan", response_model=ScanResponse)
async def trigger_scan(
    app_id: uuid.UUID,
    scan_type: Literal["semgrep", "trivy", "all"] = Query("all"),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    scan = Scan(
        application_id=app_id,
        scan_type=scan_type,
        status="queued",
        trigger="manual",
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Dispatch to Celery worker (non-blocking)
    from app.worker.tasks import scan_application_task
    scan_application_task.delay(str(app_id), scan_type)

    return scan


@router.get("/{app_id}/findings", response_model=PaginatedFindings)
async def get_application_findings(
    app_id: uuid.UUID,
    severity: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    scanner: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Application).where(Application.id == app_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Application not found")

    q = select(Finding).where(Finding.application_id == app_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if finding_type:
        q = q.where(Finding.finding_type == finding_type)
    if scanner:
        q = q.where(Finding.scanner == scanner)
    if status:
        q = q.where(Finding.status == status)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(Finding.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    findings_result = await db.execute(q)
    findings = findings_result.scalars().all()

    return PaginatedFindings(
        items=findings, total=total, page=page, page_size=page_size,
        pages=max(1, math.ceil(total / page_size))
    )


@router.get("/{app_id}/scans", response_model=PaginatedScans)
async def get_application_scans(
    app_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Application).where(Application.id == app_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Application not found")

    q = select(Scan).where(Scan.application_id == app_id)
    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    scans_result = await db.execute(q)
    scans = scans_result.scalars().all()

    return PaginatedScans(
        items=scans, total=total, page=page, page_size=page_size,
        pages=max(1, math.ceil(total / page_size))
    )


@router.post("/{app_id}/sync-github")
async def sync_github(
    app_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    from app.core.config import settings
    from app.services.github_service import sync_github_security_alerts

    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    if not settings.GITHUB_TOKEN:
        raise HTTPException(status_code=400, detail="GITHUB_TOKEN not configured")

    raw_findings = sync_github_security_alerts(app, settings.GITHUB_TOKEN)

    scan = Scan(
        application_id=app_id,
        scan_type="semgrep",
        status="completed",
        trigger="webhook",
        findings_count=len(raw_findings),
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.flush()

    for raw in raw_findings:
        finding = Finding(application_id=app_id, scan_id=scan.id, **raw)
        db.add(finding)

    await db.flush()
    return {"synced": len(raw_findings), "scan_id": str(scan.id)}
