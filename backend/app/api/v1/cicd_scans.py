import math
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_service_account
from app.db.session import get_db
from app.models.application import Application
from app.models.cicd_scan import CiCdScan
from app.models.finding import Finding
from app.models.service_account import ServiceAccount
from app.schemas.cicd_scan import CiCdScanResponse, PaginatedCiCdScans
from app.schemas.finding import PaginatedFindings
from app.services.cicd_normaliser import normalise
from app.services.deduplication import upsert_findings

router = APIRouter(tags=["cicd-scans"])


@router.post("/cicd-scans/push", response_model=CiCdScanResponse, status_code=201)
async def push_cicd_scan(
    payload: Any = Body(...),
    application_id: uuid.UUID = Query(..., description="UUID of the Snitch application"),
    commit_sha: Optional[str] = Query(None),
    branch: Optional[str] = Query(None),
    workflow_run_id: Optional[str] = Query(None),
    ci_provider: Optional[str] = Query("github-actions"),
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    """
    Stage 2 — Ingest scanner JSON output directly from a CI/CD pipeline.

    Requires a valid Bearer token (service account). Accepts raw Semgrep, Grype, or Checkov
    JSON output; format is auto-detected. Findings are deduplicated automatically.
    """
    app_result = await db.execute(select(Application).where(Application.id == application_id))
    app = app_result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found.")

    try:
        raw_findings, detected_scan_type = normalise(payload)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Could not parse scanner output: {exc}. Supported formats: semgrep, grype, checkov.",
        )

    scan = CiCdScan(
        id=uuid.uuid4(),
        application_id=application_id,
        scan_type=detected_scan_type,
        status="processing",
        commit_sha=commit_sha,
        branch=branch,
        workflow_run_id=workflow_run_id,
        ci_provider=ci_provider,
    )
    db.add(scan)
    await db.flush()

    try:
        findings, created, updated = await upsert_findings(db, application_id, scan.id, raw_findings)
        scan.findings_count = len(raw_findings)
        scan.critical_count = sum(1 for f in raw_findings if f.get("severity") == "critical")
        scan.high_count = sum(1 for f in raw_findings if f.get("severity") == "high")
        scan.medium_count = sum(1 for f in raw_findings if f.get("severity") == "medium")
        scan.low_count = sum(1 for f in raw_findings if f.get("severity") == "low")
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
    except Exception as exc:
        scan.status = "failed"
        scan.error_message = str(exc)

    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("/cicd-scans", response_model=PaginatedCiCdScans)
async def list_cicd_scans(
    application_id: Optional[uuid.UUID] = Query(None),
    scan_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    q = select(CiCdScan)
    if application_id:
        q = q.where(CiCdScan.application_id == application_id)
    if scan_type:
        q = q.where(CiCdScan.scan_type == scan_type)
    if status:
        q = q.where(CiCdScan.status == status)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(CiCdScan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    scans = result.scalars().all()

    return PaginatedCiCdScans(
        items=scans, total=total, page=page, page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.get("/cicd-scans/{scan_id}", response_model=CiCdScanResponse)
async def get_cicd_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CiCdScan).where(CiCdScan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="CI/CD scan not found")
    return scan


@router.get("/cicd-scans/{scan_id}/findings", response_model=PaginatedFindings)
async def get_cicd_scan_findings(
    scan_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(CiCdScan).where(CiCdScan.id == scan_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="CI/CD scan not found")

    q = select(Finding).where(Finding.cicd_scan_id == scan_id)
    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(Finding.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    findings_result = await db.execute(q)
    findings = findings_result.scalars().all()

    return PaginatedFindings(
        items=findings, total=total, page=page, page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.get("/applications/{app_id}/cicd-scans", response_model=PaginatedCiCdScans)
async def get_application_cicd_scans(
    app_id: uuid.UUID,
    scan_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Application).where(Application.id == app_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Application not found")

    q = select(CiCdScan).where(CiCdScan.application_id == app_id)
    if scan_type:
        q = q.where(CiCdScan.scan_type == scan_type)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(CiCdScan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    scans_result = await db.execute(q)
    scans = scans_result.scalars().all()

    return PaginatedCiCdScans(
        items=scans, total=total, page=page, page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.get("/applications/{app_id}/cicd-findings", response_model=PaginatedFindings)
async def get_application_cicd_findings(
    app_id: uuid.UUID,
    severity: Optional[str] = Query(None),
    scanner: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Application).where(Application.id == app_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Application not found")

    q = select(Finding).where(
        Finding.application_id == app_id,
        Finding.cicd_scan_id.isnot(None),
    )
    if severity:
        q = q.where(Finding.severity == severity)
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
        pages=max(1, math.ceil(total / page_size)),
    )
