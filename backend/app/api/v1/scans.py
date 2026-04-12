import math
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.finding import PaginatedFindings
from app.schemas.scan import PaginatedScans, ScanResponse

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=PaginatedScans)
async def list_scans(
    application_id: Optional[uuid.UUID] = Query(None),
    status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    q = select(Scan)
    if application_id:
        q = q.where(Scan.application_id == application_id)
    if status:
        q = q.where(Scan.status == status)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    scans = result.scalars().all()

    return PaginatedScans(
        items=scans, total=total, page=page, page_size=page_size,
        pages=max(1, math.ceil(total / page_size))
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/findings", response_model=PaginatedFindings)
async def get_scan_findings(
    scan_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")

    q = select(Finding).where(Finding.scan_id == scan_id)
    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(Finding.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    findings_result = await db.execute(q)
    findings = findings_result.scalars().all()

    return PaginatedFindings(
        items=findings, total=total, page=page, page_size=page_size,
        pages=max(1, math.ceil(total / page_size))
    )
