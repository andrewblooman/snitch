"""Celery tasks for dispatching Slack and Jira notifications after scans."""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime

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

# Event types supported by scan-triggered dispatch (risk_spike/policy_violation are
# not scan events — they require separate dispatch hooks not yet implemented).
_SCAN_EVENT_TYPES = {"new_finding", "scan_complete"}


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
    scan_uuid = uuid.UUID(scan_id)
    if is_cicd:
        scan_row = db.execute(select(CiCdScan).where(CiCdScan.id == scan_uuid)).scalar_one_or_none()
        if not scan_row:
            return
        application_id = scan_row.application_id
        scan_type = scan_row.scan_type
        scan_started_at: datetime | None = scan_row.started_at
    else:
        scan_row = db.execute(select(Scan).where(Scan.id == scan_uuid)).scalar_one_or_none()
        if not scan_row:
            return
        application_id = scan_row.application_id
        scan_type = scan_row.scan_type
        scan_started_at = scan_row.started_at

    app = db.execute(select(Application).where(Application.id == application_id)).scalar_one_or_none()
    if not app:
        return

    # All open findings linked to this scan (covers both new and re-detected).
    if is_cicd:
        base_q = select(Finding).where(Finding.cicd_scan_id == scan_uuid, Finding.status == "open")
    else:
        base_q = select(Finding).where(Finding.scan_id == scan_uuid, Finding.status == "open")

    all_scan_findings = db.execute(base_q).scalars().all()
    if not all_scan_findings:
        return

    # Findings first seen in THIS scan (for new_finding rules).
    if scan_started_at:
        new_findings = [
            f for f in all_scan_findings
            if f.first_seen_at and f.first_seen_at >= scan_started_at
        ]
    else:
        new_findings = all_scan_findings

    # Load active notification rules — only event types this scan trigger can satisfy.
    rules = db.execute(
        select(NotificationRule)
        .join(Integration, NotificationRule.integration_id == Integration.id)
        .where(
            NotificationRule.is_active.is_(True),
            Integration.is_active.is_(True),
            NotificationRule.event_type.in_(_SCAN_EVENT_TYPES),
        )
    ).scalars().all()

    integration_cache: dict[uuid.UUID, Integration] = {}

    for rule in rules:
        # Filter: app scope
        rule_app_ids = rule.application_ids or []
        if rule_app_ids and str(application_id) not in [str(aid) for aid in rule_app_ids]:
            continue

        rule_finding_types = rule.finding_types or []

        # Choose finding set based on event type.
        candidate_findings = new_findings if rule.event_type == "new_finding" else all_scan_findings

        matching = [
            f for f in candidate_findings
            if _meets_severity(f.severity or "info", rule.min_severity)
            and (not rule_finding_types or f.finding_type in rule_finding_types)
        ]
        if not matching:
            continue

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
            # Jira issues are only created for genuinely new findings to avoid ticket churn.
            jira_findings = new_findings if rule.event_type == "new_finding" else new_findings
            jira_matching = [
                f for f in jira_findings
                if _meets_severity(f.severity or "info", rule.min_severity)
                and (not rule_finding_types or f.finding_type in rule_finding_types)
            ]
            if jira_matching:
                _dispatch_jira(db, config, integration, jira_matching, app, stats)


def _dispatch_slack(config: dict, rule: NotificationRule, findings: list, app: "Application", scan_type: str, stats: dict) -> None:
    from app.services import slack_service

    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return

    if rule.event_type == "scan_complete":
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        ok = slack_service.send_scan_summary(webhook_url, scan_type, app.name, counts)
        stats["slack_sent" if ok else "errors"] += 1
    else:
        # new_finding: send per finding, capped at 5 per rule per scan to avoid flooding.
        for finding in findings[:5]:
            ok = slack_service.send_finding_notification(webhook_url, finding, app)
            stats["slack_sent" if ok else "errors"] += 1


def _dispatch_jira(db: Session, config: dict, integration: Integration, findings: list, app: "Application", stats: dict) -> None:
    from app.services import jira_service

    for finding in findings:
        existing = db.execute(
            select(JiraIssueLink).where(
                JiraIssueLink.finding_id == finding.id,
                JiraIssueLink.integration_id == integration.id,
            )
        ).scalar_one_or_none()

        if existing:
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
