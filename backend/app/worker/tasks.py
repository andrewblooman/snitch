"""
Celery tasks for asynchronous and scheduled repository scanning.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.models.application import Application
from app.models.finding import Finding
from app.models.scan import Scan
from app.worker.celery_app import celery_app

logger = logging.getLogger(__name__)

# Celery workers are synchronous — use a regular (sync) SQLAlchemy engine.
# Engine is created lazily so tests that don't execute tasks don't require psycopg2.
_SYNC_DB_URL = settings.DATABASE_URL.replace(
    "postgresql+asyncpg://", "postgresql+psycopg2://"
).replace(
    "sqlite+aiosqlite://", "sqlite://"
)

_sync_engine = None
_SyncSession = None


def _get_sync_session() -> Session:
    global _sync_engine, _SyncSession
    if _sync_engine is None:
        _sync_engine = create_engine(_SYNC_DB_URL, pool_pre_ping=True)
        _SyncSession = sessionmaker(_sync_engine, expire_on_commit=False)
    return _SyncSession()


def _recalculate_risk(db: Session, app: Application) -> None:
    from app.services.scoring import calculate_risk_score

    findings = db.execute(
        select(Finding).where(Finding.application_id == app.id)
    ).scalars().all()
    score, level = calculate_risk_score(list(findings))
    app.risk_score = score
    app.risk_level = level
    app.last_scan_at = datetime.now(timezone.utc)


def _upsert_findings_sync(
    db: Session,
    application_id: uuid.UUID,
    scan_id: uuid.UUID,
    raw_findings: list[dict],
) -> tuple[int, int]:
    """Synchronous version of upsert_findings for use in Celery tasks."""
    from app.models.finding import Finding

    existing = db.execute(
        select(Finding).where(Finding.application_id == application_id)
    ).scalars().all()

    def _key(f_dict: dict | Finding) -> tuple:
        if isinstance(f_dict, Finding):
            return _raw_key(f_dict.rule_id, f_dict.file_path, f_dict.cve_id, f_dict.package_name, f_dict.scanner, f_dict.title)
        return _raw_key(f_dict.get("rule_id"), f_dict.get("file_path"), f_dict.get("cve_id"), f_dict.get("package_name"), f_dict.get("scanner", ""), f_dict.get("title", ""))

    def _raw_key(rule_id, file_path, cve_id, package_name, scanner, title):
        if rule_id and file_path:
            return ("sast", rule_id, file_path)
        if cve_id and package_name:
            return ("sca", cve_id, package_name)
        return ("generic", scanner, str(title)[:255])

    existing_by_key = {_key(f): f for f in existing}
    now = datetime.now(timezone.utc)
    seen_ids: set[uuid.UUID] = set()
    created = 0
    updated = 0

    for raw in raw_findings:
        raw.pop("id", None)
        raw.pop("first_seen_at", None)
        raw.pop("last_seen_at", None)
        key = _key(raw)

        if key in existing_by_key:
            match = existing_by_key[key]
            match.last_seen_at = now
            match.scan_id = scan_id
            match.severity = raw.get("severity", match.severity)
            match.package_version = raw.get("package_version", match.package_version)
            match.fixed_version = raw.get("fixed_version", match.fixed_version)
            match.cvss_score = raw.get("cvss_score", match.cvss_score)
            if match.status == "fixed":
                match.status = "open"
                match.fixed_at = None
            seen_ids.add(match.id)
            updated += 1
        else:
            finding = Finding(application_id=application_id, scan_id=scan_id, **raw)
            db.add(finding)
            db.flush()
            seen_ids.add(finding.id)
            existing_by_key[key] = finding
            created += 1

    # Mark disappeared open findings as fixed
    for f in existing:
        if f.id not in seen_ids and f.status == "open":
            f.status = "fixed"
            f.fixed_at = now

    db.flush()
    return created, updated


@celery_app.task(bind=True, name="app.worker.tasks.scan_application_task", max_retries=2)
def scan_application_task(self, app_id: str, scan_type: str = "all") -> dict:
    """Run a real Semgrep + Trivy scan for a single application."""
    from app.services.scanner import RealScannerService

    application_id = uuid.UUID(app_id)

    with _get_sync_session() as db:
        app = db.get(Application, application_id)
        if not app:
            return {"error": f"Application {app_id} not found"}

        scan = db.execute(
            select(Scan).where(
                Scan.application_id == application_id,
                Scan.status == "queued",
            ).order_by(Scan.created_at.desc())
        ).scalars().first()

        if not scan:
            scan = Scan(
                application_id=application_id,
                scan_type=scan_type,
                status="running",
                trigger="scheduled",
                started_at=datetime.now(timezone.utc),
            )
            db.add(scan)
            db.flush()
        else:
            scan.status = "running"
            scan.started_at = datetime.now(timezone.utc)
            db.flush()

        scan_id = scan.id

        try:
            svc = RealScannerService()
            raw_findings = svc.run_scan(app, scan_type)

            created, updated = _upsert_findings_sync(db, application_id, scan_id, raw_findings)

            scan.findings_count = len(raw_findings)
            scan.critical_count = sum(1 for f in raw_findings if f.get("severity") == "critical")
            scan.high_count = sum(1 for f in raw_findings if f.get("severity") == "high")
            scan.medium_count = sum(1 for f in raw_findings if f.get("severity") == "medium")
            scan.low_count = sum(1 for f in raw_findings if f.get("severity") == "low")
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)

            _recalculate_risk(db, app)
            db.commit()

            return {
                "scan_id": str(scan_id),
                "status": "completed",
                "findings": len(raw_findings),
                "created": created,
                "updated": updated,
            }

        except Exception as exc:
            scan.status = "failed"
            scan.error_message = str(exc)
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            logger.error("Scan failed for app %s: %s", app_id, exc)
            raise self.retry(exc=exc, countdown=60)


@celery_app.task(name="app.worker.tasks.weekly_scan_all")
def weekly_scan_all() -> dict:
    """Dispatch scan tasks for all applications with scan_schedule='weekly'."""
    with _get_sync_session() as db:
        apps = db.execute(
            select(Application).where(Application.scan_schedule == "weekly")
        ).scalars().all()

        dispatched = []
        for app in apps:
            scan_application_task.delay(str(app.id), "all")
            dispatched.append(str(app.id))
            logger.info("Dispatched weekly scan for app %s (%s)", app.id, app.name)

    return {"dispatched": len(dispatched), "app_ids": dispatched}
