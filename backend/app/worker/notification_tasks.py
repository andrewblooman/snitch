"""Celery tasks for dispatching Slack and Jira notifications after scans."""
from __future__ import annotations

import json
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.integration import Integration
from app.models.jira_issue_link import JiraIssueLink
from app.models.notification_rule import NotificationRule
from app.models.scan import Scan
from app.models.cicd_scan import CiCdScan
from app.models.application import Application
from app.worker.celery_app import celery_app

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _meets_severity(finding_severity: str, min_severity: str) -> bool:
    return _SEVERITY_ORDER.get(finding_severity, 4) <= _SEVERITY_ORDER.get(min_severity, 4)


def _get_config(integration: Integration) -> dict:
    if isinstance(integration.config, dict):
        return integration.config
    return json.loads(integration.config or "{}")


@celery_app.task(
    bind=True,
    name="app.worker.notification_tasks.dispatch_finding_notifications",
    max_retries=3,
    default_retry_delay=60,
)
def dispatch_finding_notifications(self, scan_id: str, is_cicd: bool = False) -> dict:
    """Evaluate notification rules and send Slack/Jira notifications for a completed scan."""
    from app.worker.tasks import _get_sync_session

    stats = {"slack_sent": 0, "jira_created": 0, "jira_commented": 0, "errors": 0}

    try:
        with _get_sync_session() as db:
            _run_notifications(db, scan_id, is_cicd, stats)
    except Exception as exc:
        logger.error("Notification dispatch failed for scan %s: %s", scan_id, exc)
        raise self.retry(exc=exc)

    logger.info("Notifications dispatched for scan %s: %s", scan_id, stats)
    return stats


def _run_notifications(db: Session, scan_id: str, is_cicd: bool, stats: dict) -> None:
    from app.services import slack_service, jira_service

    # Resolve the scan and its application
    scan_uuid = uuid.UUID(scan_id)
    if is_cicd:
        scan_row = db.execute(select(CiCdScan).where(CiCdScan.id == scan_uuid)).scalar_one_or_none()
        if not scan_row:
            return
        application_id = scan_row.application_id
        scan_type = scan_row.scan_type
    else:
        scan_row = db.execute(select(Scan).where(Scan.id == scan_uuid)).scalar_one_or_none()
        if not scan_row:
            return
        application_id = scan_row.application_id
        scan_type = scan_row.scan_type

    app = db.execute(select(Application).where(Application.id == application_id)).scalar_one_or_none()
    if not app:
        return

    # Load all new findings from this scan
    if is_cicd:
        findings_q = select(Finding).where(Finding.cicd_scan_id == scan_uuid, Finding.status == "open")
    else:
        findings_q = select(Finding).where(Finding.scan_id == scan_uuid, Finding.status == "open")
    findings = db.execute(findings_q).scalars().all()

    if not findings:
        return

    # Load active notification rules with their integrations
    rules = db.execute(
        select(NotificationRule)
        .join(Integration, NotificationRule.integration_id == Integration.id)
        .where(NotificationRule.is_active.is_(True), Integration.is_active.is_(True))
    ).scalars().all()

    integration_cache: dict[uuid.UUID, Integration] = {}

    for rule in rules:
        # Filter: app scope
        rule_app_ids = rule.application_ids or []
        if rule_app_ids and str(application_id) not in [str(aid) for aid in rule_app_ids]:
            continue

        # Filter: finding types
        rule_finding_types = rule.finding_types or []

        # Filter findings for this rule
        matching = [
            f for f in findings
            if _meets_severity(f.severity or "info", rule.min_severity)
            and (not rule_finding_types or f.finding_type in rule_finding_types)
        ]
        if not matching:
            continue

        # Get integration
        if rule.integration_id not in integration_cache:
            integration = db.execute(
                select(Integration).where(Integration.id == rule.integration_id)
            ).scalar_one_or_none()
            if not integration:
                continue
            integration_cache[rule.integration_id] = integration
        integration = integration_cache[rule.integration_id]
        config = _get_config(integration)

        if integration.type == "slack":
            _dispatch_slack(config, rule, matching, app, scan_type, stats)
        elif integration.type == "jira":
            _dispatch_jira(db, config, integration, rule, matching, app, stats)


def _dispatch_slack(config: dict, rule: NotificationRule, findings: list, app: "Application", scan_type: str, stats: dict) -> None:
    from app.services import slack_service

    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return

    if rule.event_type == "scan_complete":
        counts = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        ok = slack_service.send_scan_summary(webhook_url, scan_type, app.name, counts)
        if ok:
            stats["slack_sent"] += 1
        else:
            stats["errors"] += 1
    else:
        # new_finding — send per finding (cap at 5 to avoid flooding)
        for finding in findings[:5]:
            ok = slack_service.send_finding_notification(webhook_url, finding, app)
            if ok:
                stats["slack_sent"] += 1
            else:
                stats["errors"] += 1


def _dispatch_jira(db: Session, config: dict, integration: Integration, rule: NotificationRule, findings: list, app: "Application", stats: dict) -> None:
    from app.services import jira_service

    for finding in findings:
        # Dedup check
        existing = db.execute(
            select(JiraIssueLink).where(
                JiraIssueLink.finding_id == finding.id,
                JiraIssueLink.integration_id == integration.id,
            )
        ).scalar_one_or_none()

        if existing:
            # Add a comment noting it was seen again
            jira_service.add_comment(
                config,
                existing.jira_issue_key,
                f"Snitch re-detected this finding on latest scan. Current status in Snitch: {finding.status}.",
            )
            stats["jira_commented"] += 1
        else:
            try:
                result = jira_service.create_issue(config, finding, app)
                link = JiraIssueLink(
                    finding_id=finding.id,
                    integration_id=integration.id,
                    jira_issue_key=result["issue_key"],
                    jira_issue_url=result["issue_url"],
                    jira_status="To Do",
                )
                db.add(link)
                db.commit()
                stats["jira_created"] += 1
            except Exception as exc:
                logger.error("Failed to create Jira issue for finding %s: %s", finding.id, exc)
                stats["errors"] += 1
