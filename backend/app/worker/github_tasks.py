"""
Celery tasks for polling GitHub Advanced Security alerts.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import and_, select

from app.core.config import settings
from app.models.application import Application
from app.models.finding import Finding
from app.worker.celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_sync_session():
    """Reuse the sync session helper from tasks.py to avoid duplication."""
    from app.worker.tasks import _get_sync_session as _base
    return _base()


def _recalculate_risk(db, app: Application) -> None:
    from app.worker.tasks import _recalculate_risk as _base
    _base(db, app)


@celery_app.task(name="app.worker.github_tasks.poll_github_security_task", bind=True, max_retries=2)
def poll_github_security_task(self, app_id: str | None = None):
    """
    Poll GitHub GHAS APIs (code scanning, Dependabot, secret scanning) for all
    tracked applications (or a single app if app_id is provided).
    Upserts findings; dedup key = (application_id, scanner, github_alert_number).
    """
    token = settings.GITHUB_TOKEN
    if not token:
        logger.warning("GITHUB_TOKEN not set — skipping GitHub security poll")
        return {"skipped": True, "reason": "no GITHUB_TOKEN"}

    from app.services.github_service import fetch_github_security_alerts

    db = _get_sync_session()
    try:
        if app_id:
            apps = db.execute(
                select(Application).where(Application.id == uuid.UUID(app_id))
            ).scalars().all()
        else:
            apps = db.execute(
                select(Application).where(
                    Application.github_org.isnot(None),
                    Application.github_repo.isnot(None),
                )
            ).scalars().all()

        summary = {"apps_polled": 0, "created": 0, "updated": 0, "errors": 0}

        for app in apps:
            if not app.github_org or not app.github_repo:
                continue
            try:
                alert_findings = asyncio.run(
                    fetch_github_security_alerts(app.github_org, app.github_repo, token)
                )
                created, updated = _upsert_ghas_findings(db, app, alert_findings)
                _recalculate_risk(db, app)
                app.last_github_sync_at = datetime.now(timezone.utc)
                db.commit()
                summary["apps_polled"] += 1
                summary["created"] += created
                summary["updated"] += updated
                logger.info(
                    "GHAS poll %s/%s — %d created, %d updated",
                    app.github_org, app.github_repo, created, updated,
                )
            except Exception as e:
                logger.error("GHAS poll failed for app %s: %s", app.id, e)
                db.rollback()
                summary["errors"] += 1

        return summary
    finally:
        db.close()


def _has_native_duplicate(db, app_id, finding: dict) -> bool:
    """Return True if a native (non-GHAS) scanner already tracks an equivalent finding.

    Uses github_alert_number IS NULL as the native-finding discriminator — all GHAS
    findings have a non-null alert number; native scanner findings never do.
    Uses .scalars().first() to safely handle multiple matching rows.
    """
    scanner = finding.get("scanner", "")
    finding_type = (finding.get("finding_type") or "").lower()

    if scanner == "github_secret_scanning":
        return False

    if scanner == "dependabot":
        cve_id = finding.get("cve_id")
        package_name = finding.get("package_name")
        if not cve_id or not package_name:
            return False
        existing = db.execute(
            select(Finding).where(
                and_(
                    Finding.application_id == app_id,
                    Finding.cve_id == cve_id,
                    Finding.package_name == package_name,
                    Finding.github_alert_number.is_(None),
                )
            )
        ).scalars().first()
        return existing is not None

    if finding_type == "sast":
        rule_id = finding.get("rule_id")
        file_path = finding.get("file_path")
        if not rule_id or not file_path:
            return False
        existing = db.execute(
            select(Finding).where(
                and_(
                    Finding.application_id == app_id,
                    Finding.rule_id == rule_id,
                    Finding.file_path == file_path,
                    Finding.github_alert_number.is_(None),
                )
            )
        ).scalars().first()
        return existing is not None

    return False


def _upsert_ghas_findings(db, app: Application, alert_findings: list[dict]) -> tuple[int, int]:
    """
    Upsert GHAS findings for an application.
    Dedup key: (application_id, scanner, github_alert_number).
    Returns (created_count, updated_count).
    """
    created = updated = 0
    now = datetime.now(timezone.utc)

    for fd in alert_findings:
        alert_num = fd.get("github_alert_number")
        scanner = fd.get("scanner", "unknown")
        if alert_num is None:
            continue

        existing = db.execute(
            select(Finding).where(
                Finding.application_id == app.id,
                Finding.scanner == scanner,
                Finding.github_alert_number == alert_num,
            )
        ).scalar_one_or_none()

        if existing:
            # Update mutable fields on re-poll
            existing.severity = fd.get("severity", existing.severity)
            existing.title = fd.get("title", existing.title)
            existing.description = fd.get("description", existing.description)
            existing.file_path = fd.get("file_path", existing.file_path)
            existing.line_number = fd.get("line_number", existing.line_number)
            existing.commit_sha = fd.get("commit_sha") or existing.commit_sha
            existing.introduced_by = fd.get("introduced_by") or existing.introduced_by
            existing.pr_number = fd.get("pr_number") or existing.pr_number
            existing.pr_url = fd.get("pr_url") or existing.pr_url
            existing.github_alert_url = fd.get("github_alert_url") or existing.github_alert_url
            existing.last_seen_at = now
            updated += 1
        else:
            if _has_native_duplicate(db, app.id, fd):
                logger.debug(
                    "Skipping GHAS finding — native duplicate exists: scanner=%s title=%s",
                    scanner, fd.get("title"),
                )
                continue

            finding = Finding(
                id=uuid.uuid4(),
                application_id=app.id,
                title=fd.get("title", ""),
                description=fd.get("description"),
                severity=fd.get("severity", "medium"),
                finding_type=fd.get("finding_type", "sast"),
                scanner=scanner,
                rule_id=fd.get("rule_id"),
                cve_id=fd.get("cve_id"),
                package_name=fd.get("package_name"),
                package_version=fd.get("package_version"),
                fixed_version=fd.get("fixed_version"),
                cvss_score=fd.get("cvss_score"),
                file_path=fd.get("file_path"),
                line_number=fd.get("line_number"),
                status="open",
                commit_sha=fd.get("commit_sha"),
                introduced_by=fd.get("introduced_by"),
                pr_number=fd.get("pr_number"),
                pr_url=fd.get("pr_url"),
                github_alert_url=fd.get("github_alert_url"),
                github_alert_number=alert_num,
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(finding)
            created += 1

    db.flush()
    return created, updated
