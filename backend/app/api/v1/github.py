import asyncio
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.models.application import Application
from app.services.github_service import list_accessible_repos, lookup_public_repo

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
