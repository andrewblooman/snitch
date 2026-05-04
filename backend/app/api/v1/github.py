import asyncio
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.models.application import Application
from app.models.finding import Finding
from app.services.github_service import fetch_pull_requests, list_accessible_repos, lookup_public_repo

router = APIRouter(prefix="/github", tags=["github"])


class RepoInfo(BaseModel):
    github_org: str
    github_repo: str
    full_name: str
    description: Optional[str]
    language: Optional[str]
    repo_url: str
    private: bool
    archived: bool
    default_branch: str
    updated_at: Optional[str]
    tracked: bool
    application_id: Optional[uuid.UUID]


@router.get("/repos", response_model=List[RepoInfo])
async def list_github_repos(
    include_archived: bool = Query(False),
    db: AsyncSession = Depends(get_db),
):
    """List all GitHub repos accessible to the configured token, with tracking status."""
    if not settings.GITHUB_TOKEN:
        raise HTTPException(status_code=400, detail="GITHUB_TOKEN not configured")

    raw_repos = await asyncio.to_thread(list_accessible_repos, settings.GITHUB_TOKEN)

    # Fetch all tracked applications keyed by (org, repo)
    result = await db.execute(select(Application.id, Application.github_org, Application.github_repo))
    tracked: dict[tuple[str, str], uuid.UUID] = {
        (row.github_org, row.github_repo): row.id for row in result.all()
    }

    repos = []
    for r in raw_repos:
        if r["archived"] and not include_archived:
            continue
        key = (r["github_org"], r["github_repo"])
        app_id = tracked.get(key)
        repos.append(RepoInfo(
            **r,
            tracked=app_id is not None,
            application_id=app_id,
        ))

    return repos


class RepoLookupInfo(BaseModel):
    github_org: str
    github_repo: str
    full_name: str
    description: Optional[str]
    language: Optional[str]
    repo_url: str
    private: bool
    archived: bool
    default_branch: str
    updated_at: Optional[str]


@router.get("/repos/lookup", response_model=RepoLookupInfo)
async def lookup_github_repo(
    owner: str = Query(..., description="GitHub organisation or username"),
    repo: str = Query(..., description="Repository name"),
):
    """Look up metadata for any public GitHub repository (no token required for public repos)."""
    token = settings.GITHUB_TOKEN or None
    info = await asyncio.to_thread(lookup_public_repo, owner, repo, token)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Repository {owner}/{repo} not found or not accessible")
    return RepoLookupInfo(**info)


@router.post("/apps/{app_id}/sync-alerts", status_code=202)
async def sync_github_alerts(app_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Trigger an immediate GitHub security alert sync for a single application."""
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    if not app.github_org or not app.github_repo:
        raise HTTPException(status_code=400, detail="Application has no GitHub repository configured")

    from app.worker.github_tasks import poll_github_security_task
    task = poll_github_security_task.delay(str(app_id))
    return {"task_id": task.id, "status": "queued", "app_id": str(app_id)}


class PRFinding(BaseModel):
    id: uuid.UUID
    title: str
    severity: str
    finding_type: str
    scanner: str
    status: str
    file_path: Optional[str]
    line_number: Optional[int]
    rule_id: Optional[str]
    cve_id: Optional[str]
    github_alert_url: Optional[str]
    created_at: Optional[str]

    model_config = {"from_attributes": True}


class PRReview(BaseModel):
    pr_number: int
    title: str
    state: str
    author: Optional[str]
    author_url: Optional[str]
    pr_url: str
    base_branch: Optional[str]
    head_branch: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]
    merged_at: Optional[str]
    closed_at: Optional[str]
    draft: bool
    merged: bool
    findings_introduced: List[PRFinding]
    findings_addressed: List[PRFinding]


class PRReviewsResponse(BaseModel):
    application_id: uuid.UUID
    application_name: str
    github_org: str
    github_repo: str
    total_prs: int
    prs: List[PRReview]


@router.get("/apps/{app_id}/pr-reviews", response_model=PRReviewsResponse)
async def get_pr_reviews(
    app_id: uuid.UUID,
    limit: int = Query(20, ge=1, le=100, description="Number of recent PRs to fetch"),
    db: AsyncSession = Depends(get_db),
):
    """
    Return recent pull requests for an application's GitHub repo, annotated with
    security findings introduced (open findings linked to the PR) and findings
    addressed (fixed findings linked to the PR).
    """
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    if not app.github_org or not app.github_repo:
        raise HTTPException(status_code=400, detail="Application has no GitHub repository configured")

    token = settings.GITHUB_TOKEN or None

    # Fetch PRs from GitHub
    pull_requests = await fetch_pull_requests(app.github_org, app.github_repo, token, limit=limit)

    if not pull_requests:
        return PRReviewsResponse(
            application_id=app.id,
            application_name=app.name,
            github_org=app.github_org,
            github_repo=app.github_repo,
            total_prs=0,
            prs=[],
        )

    pr_numbers = [pr["pr_number"] for pr in pull_requests if pr["pr_number"]]

    # Fetch all findings linked to these PR numbers
    findings_result = await db.execute(
        select(Finding).where(
            Finding.application_id == app_id,
            Finding.pr_number.in_(pr_numbers),
        )
    )
    all_findings: list[Finding] = list(findings_result.scalars().all())

    # Group findings by PR number
    findings_by_pr: Dict[int, Dict[str, list]] = {}
    for pr_num in pr_numbers:
        findings_by_pr[pr_num] = {"introduced": [], "addressed": []}

    for f in all_findings:
        if f.pr_number not in findings_by_pr:
            continue
        finding_dict: Dict[str, Any] = {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "finding_type": f.finding_type,
            "scanner": f.scanner,
            "status": f.status,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "rule_id": f.rule_id,
            "cve_id": f.cve_id,
            "github_alert_url": f.github_alert_url,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        if f.status in ("open", "accepted", "false_positive"):
            findings_by_pr[f.pr_number]["introduced"].append(finding_dict)
        else:
            findings_by_pr[f.pr_number]["addressed"].append(finding_dict)

    prs: list[PRReview] = []
    for pr in pull_requests:
        pr_num = pr["pr_number"]
        if pr_num is None:
            continue
        pr_findings = findings_by_pr.get(pr_num, {"introduced": [], "addressed": []})
        prs.append(PRReview(
            **pr,
            findings_introduced=[PRFinding(**f) for f in pr_findings["introduced"]],
            findings_addressed=[PRFinding(**f) for f in pr_findings["addressed"]],
        ))

    return PRReviewsResponse(
        application_id=app.id,
        application_name=app.name,
        github_org=app.github_org,
        github_repo=app.github_repo,
        total_prs=len(prs),
        prs=prs,
    )
