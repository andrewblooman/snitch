import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class RemediationBase(BaseModel):
    title: str
    finding_ids: List[str] = []


class RemediationCreate(RemediationBase):
    application_id: uuid.UUID


class RemediationPlanRequest(BaseModel):
    application_id: uuid.UUID
    finding_ids: Optional[List[str]] = None


class RemediationUpdate(BaseModel):
    status: Optional[str] = None
    branch_name: Optional[str] = None
    pr_url: Optional[str] = None
    pr_number: Optional[int] = None
    pr_status: Optional[str] = None


class RemediationResponse(RemediationBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    application_id: uuid.UUID
    status: str
    ai_plan: Optional[str] = None
    ai_model: Optional[str] = None
    branch_name: Optional[str] = None
    pr_url: Optional[str] = None
    pr_number: Optional[int] = None
    pr_status: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class PaginatedRemediations(BaseModel):
    items: List[RemediationResponse]
    total: int
    page: int
    page_size: int
    pages: int
