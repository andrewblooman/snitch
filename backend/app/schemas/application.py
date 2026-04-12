import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class ApplicationBase(BaseModel):
    name: str
    description: Optional[str] = None
    github_org: str
    github_repo: str
    repo_url: str
    team_name: str
    language: Optional[str] = None
    scan_schedule: str = "none"


class ApplicationCreate(ApplicationBase):
    pass


class ApplicationUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    team_name: Optional[str] = None
    language: Optional[str] = None
    repo_url: Optional[str] = None
    scan_schedule: Optional[str] = None


class ApplicationResponse(ApplicationBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    risk_score: float
    risk_level: str
    scan_schedule: str
    last_scan_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class ApplicationListResponse(ApplicationResponse):
    model_config = ConfigDict(from_attributes=True)

    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_findings: int = 0


class ApplicationDetail(ApplicationResponse):
    model_config = ConfigDict(from_attributes=True)

    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_findings: int = 0
    open_findings: int = 0
    scan_count: int = 0


class PaginatedApplications(BaseModel):
    items: List[ApplicationListResponse]
    total: int
    page: int
    page_size: int
    pages: int
