import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class CiCdScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    application_id: uuid.UUID
    scan_type: str
    status: str
    commit_sha: Optional[str] = None
    branch: Optional[str] = None
    workflow_run_id: Optional[str] = None
    ci_provider: Optional[str] = None
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    error_message: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    created_at: datetime


class PaginatedCiCdScans(BaseModel):
    items: List[CiCdScanResponse]
    total: int
    page: int
    page_size: int
    pages: int
