import math
import re
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.finding import Finding
from app.models.secret_pattern import SecretPattern
from app.schemas.finding import FindingResponse, FindingUpdate, PaginatedFindings
from app.schemas.secret_pattern import (
    PaginatedSecretPatterns,
    SecretPatternCreate,
    SecretPatternResponse,
    SecretPatternTest,
    SecretPatternTestResult,
    SecretPatternUpdate,
)

router = APIRouter(prefix="/secrets", tags=["secrets"])


# ---------------------------------------------------------------------------
# Findings routes (secrets-specific view over the Finding model)
# ---------------------------------------------------------------------------

@router.get("/findings", response_model=PaginatedFindings)
async def list_secret_findings(
    application_id: Optional[uuid.UUID] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    q = select(Finding).where(Finding.finding_type == "secrets")
    if application_id:
        q = q.where(Finding.application_id == application_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if status:
        q = q.where(Finding.status == status)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(Finding.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    findings = result.scalars().all()

    return PaginatedFindings(
        items=findings,
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.get("/findings/stats")
async def get_secret_finding_stats(
    application_id: Optional[uuid.UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(Finding).where(Finding.finding_type == "secrets")
    if application_id:
        q = q.where(Finding.application_id == application_id)

    result = await db.execute(q)
    findings = result.scalars().all()

    by_rule: dict = {}
    for f in findings:
        rule = f.rule_id or "unknown"
        by_rule[rule] = by_rule.get(rule, 0) + 1

    return {
        "total": len(findings),
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
        "medium": sum(1 for f in findings if f.severity == "medium"),
        "low": sum(1 for f in findings if f.severity == "low"),
        "open": sum(1 for f in findings if f.status == "open"),
        "accepted": sum(1 for f in findings if f.status == "accepted"),
        "false_positive": sum(1 for f in findings if f.status == "false_positive"),
        "by_rule": by_rule,
    }


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_secret_finding(finding_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.finding_type == "secrets")
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Secret finding not found")
    return finding


@router.patch("/findings/{finding_id}", response_model=FindingResponse)
async def update_secret_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.finding_type == "secrets")
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Secret finding not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(finding, field, value)

    if payload.status == "fixed":
        from datetime import datetime, timezone
        finding.fixed_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(finding)
    return finding


# ---------------------------------------------------------------------------
# Custom pattern CRUD
# ---------------------------------------------------------------------------

@router.get("/patterns", response_model=PaginatedSecretPatterns)
async def list_patterns(
    is_active: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    q = select(SecretPattern)
    if is_active is not None:
        q = q.where(SecretPattern.is_active == is_active)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(SecretPattern.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    patterns = result.scalars().all()

    return PaginatedSecretPatterns(
        items=patterns,
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.post("/patterns", response_model=SecretPatternResponse, status_code=201)
async def create_pattern(payload: SecretPatternCreate, db: AsyncSession = Depends(get_db)):
    try:
        re.compile(payload.pattern)
    except re.error as e:
        raise HTTPException(status_code=422, detail=f"Invalid regex pattern: {e}")

    pattern = SecretPattern(**payload.model_dump())
    db.add(pattern)
    await db.flush()
    await db.refresh(pattern)
    return pattern


@router.get("/patterns/{pattern_id}", response_model=SecretPatternResponse)
async def get_pattern(pattern_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SecretPattern).where(SecretPattern.id == pattern_id))
    pattern = result.scalar_one_or_none()
    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")
    return pattern


@router.put("/patterns/{pattern_id}", response_model=SecretPatternResponse)
async def update_pattern(
    pattern_id: uuid.UUID,
    payload: SecretPatternUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(SecretPattern).where(SecretPattern.id == pattern_id))
    pattern = result.scalar_one_or_none()
    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")

    if payload.pattern is not None:
        try:
            re.compile(payload.pattern)
        except re.error as e:
            raise HTTPException(status_code=422, detail=f"Invalid regex pattern: {e}")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(pattern, field, value)

    await db.flush()
    await db.refresh(pattern)
    return pattern


@router.delete("/patterns/{pattern_id}", status_code=204)
async def delete_pattern(pattern_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SecretPattern).where(SecretPattern.id == pattern_id))
    pattern = result.scalar_one_or_none()
    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")
    await db.delete(pattern)
    await db.flush()


@router.post("/patterns/test", response_model=SecretPatternTestResult)
async def test_pattern(payload: SecretPatternTest):
    try:
        compiled = re.compile(payload.pattern)
    except re.error as e:
        return SecretPatternTestResult(matches=[], match_count=0, valid=False, error=str(e))

    matches = compiled.findall(payload.sample_text)
    str_matches = [m if isinstance(m, str) else str(m) for m in matches]
    return SecretPatternTestResult(matches=str_matches, match_count=len(str_matches), valid=True)
