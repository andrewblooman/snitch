import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------

class IntegrationCreate(BaseModel):
    type: str = Field(..., pattern="^(slack|jira)$")
    name: str = Field(..., min_length=1, max_length=255)
    config: dict[str, Any] = Field(...)


class IntegrationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    config: Optional[dict[str, Any]] = None
    is_active: Optional[bool] = None


_SENSITIVE_KEYS = {"api_token", "webhook_url", "password", "secret"}


def _mask_config(config: dict) -> dict:
    return {k: ("***" if k in _SENSITIVE_KEYS else v) for k, v in config.items()}


class IntegrationResponse(BaseModel):
    id: uuid.UUID
    type: str
    name: str
    config_summary: dict[str, Any]
    is_active: bool
    last_tested_at: Optional[datetime]
    last_test_status: Optional[str]
    last_test_message: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_masked(cls, obj: Any) -> "IntegrationResponse":
        import json
        raw_config = obj.config if isinstance(obj.config, dict) else json.loads(obj.config or "{}")
        return cls(
            id=obj.id,
            type=obj.type,
            name=obj.name,
            config_summary=_mask_config(raw_config),
            is_active=obj.is_active,
            last_tested_at=obj.last_tested_at,
            last_test_status=obj.last_test_status,
            last_test_message=obj.last_test_message,
            created_at=obj.created_at,
            updated_at=obj.updated_at,
        )


class IntegrationCreated(IntegrationResponse):
    """Returned only on POST — includes the full config (shown once)."""
    config_full: dict[str, Any]


# ---------------------------------------------------------------------------
# Notification Rule
# ---------------------------------------------------------------------------

class NotificationRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    event_type: str = Field(..., pattern="^(new_finding|scan_complete|risk_spike|policy_violation)$")
    min_severity: str = Field("high", pattern="^(critical|high|medium|low)$")
    finding_types: list[str] = Field(default_factory=list)
    application_ids: list[uuid.UUID] = Field(default_factory=list)
    is_active: bool = True


class NotificationRuleUpdate(BaseModel):
    name: Optional[str] = None
    event_type: Optional[str] = None
    min_severity: Optional[str] = None
    finding_types: Optional[list[str]] = None
    application_ids: Optional[list[uuid.UUID]] = None
    is_active: Optional[bool] = None


class NotificationRuleResponse(BaseModel):
    id: uuid.UUID
    integration_id: uuid.UUID
    name: str
    event_type: str
    min_severity: str
    finding_types: list[str]
    application_ids: list[uuid.UUID]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Jira-specific
# ---------------------------------------------------------------------------

class CreateJiraIssueRequest(BaseModel):
    finding_id: uuid.UUID


class JiraCrawlRequest(BaseModel):
    epic_keys: list[str] = Field(..., min_length=1)
    application_id: Optional[uuid.UUID] = None


class JiraIssueLinkResponse(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    integration_id: uuid.UUID
    jira_issue_key: str
    jira_issue_url: str
    jira_status: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CrawlCoveredItem(BaseModel):
    finding_id: str
    title: str
    severity: str


class CrawlUncoveredItem(BaseModel):
    finding_id: str
    title: str
    severity: str
    cve_id: Optional[str]
    package_name: Optional[str]


class CrawlExternalItem(BaseModel):
    key: str
    summary: str
    status: str
    url: str


class JiraCrawlResponse(BaseModel):
    epic_keys: list[str]
    covered: list[CrawlCoveredItem]
    uncovered: list[CrawlUncoveredItem]
    external: list[CrawlExternalItem]
    remediation_plan: str
    total_findings_checked: int


# ---------------------------------------------------------------------------
# Test result
# ---------------------------------------------------------------------------

class IntegrationTestResponse(BaseModel):
    success: bool
    message: str
