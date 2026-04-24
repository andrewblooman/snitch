import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ServiceAccountCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    team_name: str = Field(..., min_length=1, max_length=255)


class ServiceAccountResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    team_name: str
    token_prefix: str
    is_active: bool
    created_at: datetime
    last_used_at: Optional[datetime]

    model_config = {"from_attributes": True}


class ServiceAccountCreated(ServiceAccountResponse):
    """Returned only on create/rotate — includes the raw token (shown once, never stored)."""
    token: str
