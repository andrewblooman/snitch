import math
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, cast, func, or_, select, String
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.finding import Finding
from app.schemas.finding import FindingResponse, FindingStats, FindingUpdate, PaginatedFindings

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/stats", response_model=FindingStats)
async def get_finding_stats(
    application_id: Optional[uuid.UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(Finding)
    if application_id:
        q = q.where(Finding.application_id == application_id)

    result = await db.execute(q)
    findings = result.scalars().all()

    by_scanner: dict = {}
    by_type: dict = {}
    for f in findings:
        by_scanner[f.scanner] = by_scanner.get(f.scanner, 0) + 1
        by_type[f.finding_type] = by_type.get(f.finding_type, 0) + 1

    return FindingStats(
        total=len(findings),
        critical=sum(1 for f in findings if f.severity == "critical"),
        high=sum(1 for f in findings if f.severity == "high"),
        medium=sum(1 for f in findings if f.severity == "medium"),
        low=sum(1 for f in findings if f.severity == "low"),
        info=sum(1 for f in findings if f.severity == "info"),
        open=sum(1 for f in findings if f.status == "open"),
        fixed=sum(1 for f in findings if f.status == "fixed"),
        accepted=sum(1 for f in findings if f.status == "accepted"),
        false_positive=sum(1 for f in findings if f.status == "false_positive"),
        by_scanner=by_scanner,
        by_type=by_type,
    )


@router.get("", response_model=PaginatedFindings)
async def list_findings(
    application_id: Optional[uuid.UUID] = Query(None),
    severity: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    scanner: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    identifier: Optional[str] = Query(None),
    compliance_tag: Optional[str] = Query(None),
    sort_by: Optional[str] = Query("severity", pattern="^(severity|created_at)$"),
    sort_dir: Optional[str] = Query("asc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    q = select(Finding)
    if application_id:
        q = q.where(Finding.application_id == application_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if finding_type:
        q = q.where(func.lower(Finding.finding_type) == finding_type.lower())
    if scanner:
        q = q.where(Finding.scanner == scanner)
    if status:
        q = q.where(Finding.status == status)
    if identifier:
        q = q.where(or_(
            Finding.cve_id == identifier,
            Finding.rule_id == identifier,
            Finding.title == identifier,
        ))
    if compliance_tag:
        q = q.where(cast(Finding.compliance_tags, String).contains(compliance_tag))

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    sev_order = case(
        (Finding.severity == "critical", 0),
        (Finding.severity == "high", 1),
        (Finding.severity == "medium", 2),
        (Finding.severity == "low", 3),
        else_=4,
    )
    if sort_by == "severity":
        primary = sev_order if sort_dir == "asc" else sev_order.desc()
        secondary = Finding.created_at.desc()
    else:
        primary = Finding.created_at.asc() if sort_dir == "asc" else Finding.created_at.desc()
        secondary = sev_order

    q = (
        q.options(selectinload(Finding.application))
        .order_by(primary, secondary)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(q)
    findings = result.scalars().all()

    return PaginatedFindings(
        items=findings, total=total, page=page, page_size=page_size,
        pages=max(1, math.ceil(total / page_size))
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).options(selectinload(Finding.application)).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: uuid.UUID, payload: FindingUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(finding, field, value)

    if payload.status == "fixed":
        from datetime import datetime, timezone
        finding.fixed_at = datetime.now(timezone.utc)

    await db.flush()
    result = await db.execute(
        select(Finding).options(selectinload(Finding.application)).where(Finding.id == finding_id)
    )
    return result.scalar_one()
