import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.auth import get_service_account
from app.db.session import get_db
from app.models.application import Application
from app.models.finding import Finding
from app.models.integration import Integration
from app.models.jira_issue_link import JiraIssueLink
from app.models.notification_rule import NotificationRule
from app.models.service_account import ServiceAccount
from app.schemas.integration import (
    CreateJiraIssueRequest,
    CrawlCoveredItem,
    CrawlExternalItem,
    CrawlUncoveredItem,
    IntegrationCreate,
    IntegrationCreated,
    IntegrationResponse,
    IntegrationTestResponse,
    IntegrationUpdate,
    JiraCrawlRequest,
    JiraCrawlResponse,
    JiraIssueLinkResponse,
    NotificationRuleCreate,
    NotificationRuleResponse,
    NotificationRuleUpdate,
    _mask_config,
)

router = APIRouter(tags=["integrations"])


def _parse_config(integration: Integration) -> dict:
    if isinstance(integration.config, dict):
        return integration.config
    return json.loads(integration.config or "{}")


# ---------------------------------------------------------------------------
# Integration CRUD
# ---------------------------------------------------------------------------

@router.get("/integrations", response_model=list[IntegrationResponse])
async def list_integrations(
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Integration).order_by(Integration.created_at.desc()))
    integrations = result.scalars().all()
    return [IntegrationResponse.from_orm_masked(i) for i in integrations]


@router.post("/integrations", response_model=IntegrationCreated, status_code=201)
async def create_integration(
    body: IntegrationCreate,
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    integration = Integration(
        id=uuid.uuid4(),
        type=body.type,
        name=body.name,
        config=json.dumps(body.config),
    )
    db.add(integration)
    await db.commit()
    await db.refresh(integration)

    base = IntegrationResponse.from_orm_masked(integration)
    return IntegrationCreated(**base.model_dump(), config_full=body.config)


@router.get("/integrations/{integration_id}", response_model=IntegrationResponse)
async def get_integration(
    integration_id: uuid.UUID,
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    integration = await _get_or_404(db, integration_id)
    return IntegrationResponse.from_orm_masked(integration)


@router.put("/integrations/{integration_id}", response_model=IntegrationResponse)
async def update_integration(
    integration_id: uuid.UUID,
    body: IntegrationUpdate,
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    integration = await _get_or_404(db, integration_id)
    if body.name is not None:
        integration.name = body.name
    if body.is_active is not None:
        integration.is_active = body.is_active
    if body.config is not None:
        existing = _parse_config(integration)
        # Merge: preserve existing sensitive fields if caller sends "***"
        merged = {**existing}
        for k, v in body.config.items():
            if v != "***":
                merged[k] = v
        integration.config = json.dumps(merged)
    await db.commit()
    await db.refresh(integration)
    return IntegrationResponse.from_orm_masked(integration)


@router.delete("/integrations/{integration_id}", status_code=204)
async def delete_integration(
    integration_id: uuid.UUID,
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    integration = await _get_or_404(db, integration_id)
    await db.delete(integration)
    await db.commit()


@router.post("/integrations/{integration_id}/test", response_model=IntegrationTestResponse)
async def test_integration(
    integration_id: uuid.UUID,
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    integration = await _get_or_404(db, integration_id)
    config = _parse_config(integration)

    if integration.type == "slack":
        from app.services.slack_service import test_webhook
        success, message = test_webhook(config.get("webhook_url", ""))
    elif integration.type == "jira":
        from app.services.jira_service import test_connection
        success, message = test_connection(config)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown integration type: {integration.type}")

    integration.last_tested_at = datetime.now(timezone.utc)
    integration.last_test_status = "ok" if success else "error"
    integration.last_test_message = message
    await db.commit()

    return IntegrationTestResponse(success=success, message=message)


# ---------------------------------------------------------------------------
# Notification Rules
# ---------------------------------------------------------------------------

@router.get("/integrations/{integration_id}/rules", response_model=list[NotificationRuleResponse])
async def list_rules(
    integration_id: uuid.UUID,
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    await _get_or_404(db, integration_id)
    result = await db.execute(
        select(NotificationRule)
        .where(NotificationRule.integration_id == integration_id)
        .order_by(NotificationRule.created_at)
    )
    return result.scalars().all()


@router.post("/integrations/{integration_id}/rules", response_model=NotificationRuleResponse, status_code=201)
async def create_rule(
    integration_id: uuid.UUID,
    body: NotificationRuleCreate,
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    await _get_or_404(db, integration_id)
    rule = NotificationRule(
        id=uuid.uuid4(),
        integration_id=integration_id,
        name=body.name,
        event_type=body.event_type,
        min_severity=body.min_severity,
        finding_types=body.finding_types,
        application_ids=[str(aid) for aid in body.application_ids],
        is_active=body.is_active,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


@router.put("/integrations/{integration_id}/rules/{rule_id}", response_model=NotificationRuleResponse)
async def update_rule(
    integration_id: uuid.UUID,
    rule_id: uuid.UUID,
    body: NotificationRuleUpdate,
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    rule = await _get_rule_or_404(db, integration_id, rule_id)
    if body.name is not None:
        rule.name = body.name
    if body.event_type is not None:
        rule.event_type = body.event_type
    if body.min_severity is not None:
        rule.min_severity = body.min_severity
    if body.finding_types is not None:
        rule.finding_types = body.finding_types
    if body.application_ids is not None:
        rule.application_ids = [str(aid) for aid in body.application_ids]
    if body.is_active is not None:
        rule.is_active = body.is_active
    await db.commit()
    await db.refresh(rule)
    return rule


@router.delete("/integrations/{integration_id}/rules/{rule_id}", status_code=204)
async def delete_rule(
    integration_id: uuid.UUID,
    rule_id: uuid.UUID,
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    rule = await _get_rule_or_404(db, integration_id, rule_id)
    await db.delete(rule)
    await db.commit()


# ---------------------------------------------------------------------------
# Jira-specific endpoints
# ---------------------------------------------------------------------------

@router.post("/integrations/jira/{integration_id}/create-issue", response_model=JiraIssueLinkResponse, status_code=201)
async def create_jira_issue(
    integration_id: uuid.UUID,
    body: CreateJiraIssueRequest,
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    integration = await _get_or_404(db, integration_id)
    if integration.type != "jira":
        raise HTTPException(status_code=400, detail="Integration is not a Jira integration")

    finding_result = await db.execute(select(Finding).where(Finding.id == body.finding_id))
    finding = finding_result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Dedup check
    existing = await db.execute(
        select(JiraIssueLink).where(
            JiraIssueLink.finding_id == finding.id,
            JiraIssueLink.integration_id == integration_id,
        )
    )
    existing_link = existing.scalar_one_or_none()
    if existing_link:
        raise HTTPException(
            status_code=409,
            detail=f"Jira issue already exists: {existing_link.jira_issue_key}",
        )

    app_result = await db.execute(select(Application).where(Application.id == finding.application_id))
    app = app_result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    config = _parse_config(integration)
    try:
        from app.services.jira_service import create_issue
        result = create_issue(config, finding, app)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Jira API error: {exc}")

    link = JiraIssueLink(
        finding_id=finding.id,
        integration_id=integration_id,
        jira_issue_key=result["issue_key"],
        jira_issue_url=result["issue_url"],
        jira_status="To Do",
    )
    db.add(link)
    await db.commit()
    await db.refresh(link)
    return link


@router.get("/integrations/jira/{integration_id}/issues", response_model=list[JiraIssueLinkResponse])
async def list_jira_issues(
    integration_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    await _get_or_404(db, integration_id)
    result = await db.execute(
        select(JiraIssueLink)
        .where(JiraIssueLink.integration_id == integration_id)
        .order_by(JiraIssueLink.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return result.scalars().all()


@router.post("/integrations/jira/{integration_id}/crawl-epic", response_model=JiraCrawlResponse)
async def crawl_epic(
    integration_id: uuid.UUID,
    body: JiraCrawlRequest,
    sa: ServiceAccount = Depends(get_service_account),
    db: AsyncSession = Depends(get_db),
):
    integration = await _get_or_404(db, integration_id)
    if integration.type != "jira":
        raise HTTPException(status_code=400, detail="Integration is not a Jira integration")

    config = _parse_config(integration)

    # Fetch findings to match against (scoped to app if provided)
    findings_q = select(Finding).where(Finding.status == "open")
    if body.application_id:
        findings_q = findings_q.where(Finding.application_id == body.application_id)
    findings_result = await db.execute(findings_q)
    all_findings = findings_result.scalars().all()

    # Crawl the epics
    try:
        from app.services.jira_service import crawl_epic as jira_crawl_epic, match_findings_to_issues
        epic_results = jira_crawl_epic(config, body.epic_keys)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Jira API error: {exc}")

    # Match findings
    match_result = match_findings_to_issues(epic_results, list(all_findings))

    finding_by_id = {str(f.id): f for f in all_findings}

    covered_items = [
        CrawlCoveredItem(
            finding_id=fid,
            title=finding_by_id[fid].title if fid in finding_by_id else "—",
            severity=finding_by_id[fid].severity if fid in finding_by_id else "—",
        )
        for fid in match_result["covered"]
        if fid in finding_by_id
    ]

    uncovered_findings_objs = [
        finding_by_id[fid] for fid in match_result["uncovered"] if fid in finding_by_id
    ]
    uncovered_items = [
        CrawlUncoveredItem(
            finding_id=str(f.id),
            title=f.title,
            severity=f.severity,
            cve_id=f.cve_id,
            package_name=f.package_name,
        )
        for f in uncovered_findings_objs
    ]

    external_items = [
        CrawlExternalItem(
            key=e["key"],
            summary=e["summary"],
            status=e["status"],
            url=e["url"],
        )
        for e in match_result["external"]
    ]

    # Generate remediation plan
    app_name = "Unknown"
    if body.application_id:
        app_result = await db.execute(select(Application).where(Application.id == body.application_id))
        app_obj = app_result.scalar_one_or_none()
        if app_obj:
            app_name = app_obj.name

    from app.services.epic_remediation import generate_epic_remediation_plan
    remediation_plan = generate_epic_remediation_plan(uncovered_findings_objs, epic_results, app_name)

    return JiraCrawlResponse(
        epic_keys=body.epic_keys,
        covered=covered_items,
        uncovered=uncovered_items,
        external=external_items,
        remediation_plan=remediation_plan,
        total_findings_checked=len(all_findings),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_or_404(db: AsyncSession, integration_id: uuid.UUID) -> Integration:
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    return integration


async def _get_rule_or_404(db: AsyncSession, integration_id: uuid.UUID, rule_id: uuid.UUID) -> NotificationRule:
    result = await db.execute(
        select(NotificationRule).where(
            NotificationRule.id == rule_id,
            NotificationRule.integration_id == integration_id,
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Notification rule not found")
    return rule
