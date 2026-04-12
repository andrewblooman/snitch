import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class ScanBase(BaseModel):
    scan_type: str
    trigger: str = "manual"


class ScanCreate(ScanBase):
    application_id: uuid.UUID


class ScanResponse(ScanBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    application_id: uuid.UUID
    status: str
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: datetime


class PaginatedScans(BaseModel):
    items: List[ScanResponse]
    total: int
    page: int
    page_size: int
    pages: int
