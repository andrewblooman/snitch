import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class FindingBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str
    finding_type: str
    scanner: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    rule_id: Optional[str] = None
    cve_id: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fixed_version: Optional[str] = None
    cvss_score: Optional[float] = None


class FindingCreate(FindingBase):
    application_id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    description: Optional[str] = None


class FindingResponse(FindingBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    application_id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    fixed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class FindingStats(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    open: int
    fixed: int
    accepted: int
    false_positive: int
    by_scanner: dict
    by_type: dict


class PaginatedFindings(BaseModel):
    items: List[FindingResponse]
    total: int
    page: int
    page_size: int
    pages: int
