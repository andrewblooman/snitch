import asyncio
import math
import re
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
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
    filters = [Finding.finding_type == "secrets"]
    if application_id:
        filters.append(Finding.application_id == application_id)

    total = (await db.execute(select(func.count()).select_from(Finding).where(*filters))).scalar_one()

    sev_rows = (await db.execute(
        select(Finding.severity, func.count()).where(*filters).group_by(Finding.severity)
    )).all()
    severity_counts = {s: c for s, c in sev_rows}

    status_rows = (await db.execute(
        select(Finding.status, func.count()).where(*filters).group_by(Finding.status)
    )).all()
    status_counts = {s: c for s, c in status_rows}

    rule_rows = (await db.execute(
        select(Finding.rule_id, func.count()).where(*filters).group_by(Finding.rule_id)
    )).all()
    by_rule = {(r or "unknown"): c for r, c in rule_rows}

    return {
        "total": total,
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
        "low": severity_counts.get("low", 0),
        "open": status_counts.get("open", 0),
        "accepted": status_counts.get("accepted", 0),
        "false_positive": status_counts.get("false_positive", 0),
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
    err = await asyncio.get_running_loop().run_in_executor(
        None, _validate_pattern_safe, payload.pattern
    )
    if err:
        raise HTTPException(status_code=422, detail=err)

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
        err = await asyncio.get_running_loop().run_in_executor(
            None, _validate_pattern_safe, payload.pattern
        )
        if err:
            raise HTTPException(status_code=422, detail=err)

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


def _compile_and_match(pattern: str, sample_text: str) -> list:
    compiled = re.compile(pattern)
    return compiled.findall(sample_text)


_REDOS_PROBE = "a" * 20 + "!"  # triggers catastrophic backtracking on vulnerable patterns
_VALIDATION_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="regex-validate")


def _validate_pattern_safe(pattern: str) -> str | None:
    """
    Compile and execute a user-supplied pattern against a ReDoS probe string
    in a thread with a hard timeout.  Returns an error string on failure or None if safe.
    """
    def _run() -> None:
        compiled = re.compile(pattern)
        compiled.search(_REDOS_PROBE)

    future = _VALIDATION_EXECUTOR.submit(_run)
    try:
        future.result(timeout=2.0)
    except re.error as exc:
        return f"Invalid regex pattern: {exc}"
    except FuturesTimeoutError:
        return "Pattern evaluation timed out — the pattern may cause catastrophic backtracking"
    except Exception as exc:
        return f"Pattern validation error: {exc}"
    return None


@router.post("/patterns/test", response_model=SecretPatternTestResult)
async def test_pattern(payload: SecretPatternTest):
    loop = asyncio.get_running_loop()
    try:
        matches = await asyncio.wait_for(
            loop.run_in_executor(None, _compile_and_match, payload.pattern, payload.sample_text),
            timeout=5.0,
        )
    except re.error as e:
        return SecretPatternTestResult(matches=[], match_count=0, valid=False, error=str(e))
    except asyncio.TimeoutError:
        return SecretPatternTestResult(
            matches=[], match_count=0, valid=False,
            error="Pattern evaluation timed out — the pattern may cause catastrophic backtracking",
        )

    str_matches = [m if isinstance(m, str) else str(m) for m in matches]
    return SecretPatternTestResult(matches=str_matches, match_count=len(str_matches), valid=True)
