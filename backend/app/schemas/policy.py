import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, field_validator


VALID_SCAN_TYPES = {"sast", "sca", "container", "secrets", "iac"}
VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"]
VALID_ACTIONS = {"block", "inform", "both"}


class PolicyBase(BaseModel):
    name: str
    description: Optional[str] = None
    is_active: bool = False
    action: str = "inform"
    min_severity: str = "medium"
    enabled_scan_types: List[str] = []
    rule_blocklist: List[str] = []
    rule_allowlist: List[str] = []

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in VALID_ACTIONS:
            raise ValueError(f"action must be one of {sorted(VALID_ACTIONS)}")
        return v

    @field_validator("min_severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        if v not in VALID_SEVERITIES:
            raise ValueError(f"min_severity must be one of {VALID_SEVERITIES}")
        return v

    @field_validator("enabled_scan_types")
    @classmethod
    def validate_scan_types(cls, v: List[str]) -> List[str]:
        invalid = set(v) - VALID_SCAN_TYPES
        if invalid:
            raise ValueError(f"Invalid scan types: {invalid}. Valid: {sorted(VALID_SCAN_TYPES)}")
        return v


class PolicyCreate(PolicyBase):
    pass


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    action: Optional[str] = None
    min_severity: Optional[str] = None
    enabled_scan_types: Optional[List[str]] = None
    rule_blocklist: Optional[List[str]] = None
    rule_allowlist: Optional[List[str]] = None

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_ACTIONS:
            raise ValueError(f"action must be one of {sorted(VALID_ACTIONS)}")
        return v

    @field_validator("min_severity")
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_SEVERITIES:
            raise ValueError(f"min_severity must be one of {VALID_SEVERITIES}")
        return v

    @field_validator("enabled_scan_types")
    @classmethod
    def validate_scan_types(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is not None:
            invalid = set(v) - VALID_SCAN_TYPES
            if invalid:
                raise ValueError(f"Invalid scan types: {invalid}. Valid: {sorted(VALID_SCAN_TYPES)}")
        return v


class PolicyResponse(PolicyBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class PaginatedPolicies(BaseModel):
    items: List[PolicyResponse]
    total: int
    page: int
    page_size: int
    pages: int


class PolicyViolation(BaseModel):
    finding_id: uuid.UUID
    finding_title: str
    severity: str
    scanner: str
    finding_type: str
    rule_id: Optional[str] = None
    cve_id: Optional[str] = None
    reason: str  # "severity_threshold" | "blocklisted_rule"


class PolicyEvaluationResult(BaseModel):
    policy_id: uuid.UUID
    policy_name: str
    is_active: bool
    action: str
    total_violations: int
    blocked: bool
    violations: List[PolicyViolation]
