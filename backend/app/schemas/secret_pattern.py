import uuid
from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class SecretPatternBase(BaseModel):
    name: str
    description: Optional[str] = None
    pattern: str
    severity: Literal["critical", "high", "medium", "low"] = "high"
    is_active: bool = True


class SecretPatternCreate(SecretPatternBase):
    pass


class SecretPatternUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    pattern: Optional[str] = None
    severity: Optional[Literal["critical", "high", "medium", "low"]] = None
    is_active: Optional[bool] = None


class SecretPatternResponse(SecretPatternBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class SecretPatternTest(BaseModel):
    pattern: str = Field(..., max_length=500)
    sample_text: str = Field(..., max_length=100_000)


class SecretPatternTestResult(BaseModel):
    matches: List[str]
    match_count: int
    valid: bool
    error: Optional[str] = None


class PaginatedSecretPatterns(BaseModel):
    items: List[SecretPatternResponse]
    total: int
    page: int
    page_size: int
    pages: int
