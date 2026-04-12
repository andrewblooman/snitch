import math
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.application import Application
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.schemas.remediation import (
    PaginatedRemediations,
    RemediationPlanRequest,
    RemediationResponse,
    RemediationUpdate,
)
from app.services.ai_remediation import generate_remediation_plan

router = APIRouter(prefix="/remediation", tags=["remediation"])


@router.get("", response_model=PaginatedRemediations)
async def list_remediations(
    application_id: Optional[uuid.UUID] = Query(None),
    status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    q = select(Remediation)
    if application_id:
        q = q.where(Remediation.application_id == application_id)
    if status:
        q = q.where(Remediation.status == status)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(Remediation.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    items = result.scalars().all()

    return PaginatedRemediations(
        items=items, total=total, page=page, page_size=page_size,
        pages=max(1, math.ceil(total / page_size))
    )


@router.post("/plan", response_model=RemediationResponse, status_code=201)
async def generate_plan(
    payload: RemediationPlanRequest,
    db: AsyncSession = Depends(get_db),
):
    app_result = await db.execute(
        select(Application).where(Application.id == payload.application_id)
    )
    app = app_result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    if payload.finding_ids:
        finding_uuids = [uuid.UUID(fid) for fid in payload.finding_ids]
        findings_result = await db.execute(
            select(Finding).where(
                Finding.application_id == payload.application_id,
                Finding.id.in_(finding_uuids),
            )
        )
    else:
        findings_result = await db.execute(
            select(Finding).where(
                Finding.application_id == payload.application_id,
                Finding.status == "open",
            )
        )
    findings = findings_result.scalars().all()

    if not findings:
        raise HTTPException(status_code=400, detail="No open findings found for remediation")

    plan_text, model_used = await generate_remediation_plan(app, list(findings))

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    top = min(findings, key=lambda f: sev_order.get(f.severity, 4))

    remediation = Remediation(
        application_id=payload.application_id,
        title=f"Remediation plan for {app.name}: {len(findings)} findings",
        status="planned",
        finding_ids=[str(f.id) for f in findings],
        ai_plan=plan_text,
        ai_model=model_used,
    )
    db.add(remediation)
    await db.flush()
    await db.refresh(remediation)
    return remediation


@router.get("/{remediation_id}", response_model=RemediationResponse)
async def get_remediation(remediation_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")
    return rem


@router.patch("/{remediation_id}", response_model=RemediationResponse)
async def update_remediation(
    remediation_id: uuid.UUID, payload: RemediationUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(rem, field, value)
    await db.flush()
    await db.refresh(rem)
    return rem


@router.post("/{remediation_id}/execute", response_model=RemediationResponse)
async def execute_remediation(
    remediation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    from app.core.config import settings
    from app.services.github_service import create_branch, create_pull_request

    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")

    app_result = await db.execute(select(Application).where(Application.id == rem.application_id))
    app = app_result.scalar_one_or_none()
    if not app:
        rem.status = "failed"
        await db.flush()
        raise HTTPException(status_code=404, detail="Associated application not found")

    if not settings.GITHUB_TOKEN:
        raise HTTPException(status_code=400, detail="GITHUB_TOKEN not configured")

    repo_full_name = f"{app.github_org}/{app.github_repo}"
    branch_name = f"snitch/remediation-{str(rem.id)[:8]}"

    branch_ok = create_branch(repo_full_name, branch_name, settings.GITHUB_TOKEN)
    if not branch_ok:
        rem.status = "failed"
        await db.flush()
        raise HTTPException(status_code=500, detail="Failed to create branch")

    pr_result = create_pull_request(
        repo_full_name=repo_full_name,
        branch=branch_name,
        title=rem.title,
        body=rem.ai_plan or "Automated security remediation by Snitch",
        token=settings.GITHUB_TOKEN,
    )

    if pr_result:
        rem.branch_name = branch_name
        rem.pr_url = pr_result["pr_url"]
        rem.pr_number = pr_result["pr_number"]
        rem.pr_status = "open"
        rem.status = "pr_created"
    else:
        rem.status = "failed"

    await db.flush()
    await db.refresh(rem)
    return rem


@router.get("/{remediation_id}/status", response_model=RemediationResponse)
async def check_pr_status(
    remediation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    from app.core.config import settings

    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")

    if rem.pr_number and settings.GITHUB_TOKEN:
        try:
            from github import Github

            app_result = await db.execute(
                select(Application).where(Application.id == rem.application_id)
            )
            app = app_result.scalar_one_or_none()
            if not app:
                raise HTTPException(status_code=404, detail="Associated application not found")
            g = Github(settings.GITHUB_TOKEN)
            repo = g.get_repo(f"{app.github_org}/{app.github_repo}")
            pr = repo.get_pull(rem.pr_number)
            rem.pr_status = pr.state
            if pr.merged:
                rem.pr_status = "merged"
                rem.status = "completed"
            await db.flush()
        except Exception:
            pass

    return rem
