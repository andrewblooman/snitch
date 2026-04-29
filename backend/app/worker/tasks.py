"""
Celery tasks for asynchronous and scheduled repository scanning,
and CI/CD scan ingestion via SQS + S3.
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
from app.models.secret_pattern import SecretPattern
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
            return _raw_key(f_dict.rule_id, f_dict.file_path, f_dict.cve_id, f_dict.package_name, f_dict.scanner, f_dict.title, f_dict.finding_type)
        return _raw_key(f_dict.get("rule_id"), f_dict.get("file_path"), f_dict.get("cve_id"), f_dict.get("package_name"), f_dict.get("scanner", ""), f_dict.get("title", ""), f_dict.get("finding_type", ""))

    def _raw_key(rule_id, file_path, cve_id, package_name, scanner, title, finding_type=""):
        ftype = (finding_type or "").lower()
        if ftype == "secrets" and rule_id and file_path:
            return ("secrets", rule_id, file_path)
        if rule_id and file_path:
            return ("sast", rule_id, file_path)
        if cve_id and package_name:
            # Distinguish container (grype) from SCA (trivy/govulncheck) to prevent overwrites
            key_prefix = "container" if ftype == "container" else "sca"
            return (key_prefix, cve_id, package_name)
        return ("generic", scanner, str(title)[:255])

    existing_by_key = {_key(f): f for f in existing}
    now = datetime.now(timezone.utc)
    seen_ids: set[uuid.UUID] = set()
    created = 0
    updated = 0

    # Track which scanners actually produced findings in this run so that
    # the "disappeared → fixed" step only applies to those scanners.
    # This prevents partial scans (e.g. checkov-only) from incorrectly
    # auto-fixing findings from scanners that didn't run.
    scanners_run: set[str] = {r.get("scanner", "") for r in raw_findings if r.get("scanner")}

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

    # Mark disappeared open findings as fixed — only for scanners that ran in this scan.
    # Findings from scanners that didn't run are left untouched.
    for f in existing:
        if f.id not in seen_ids and f.status == "open" and f.scanner in scanners_run:
            f.status = "fixed"
            f.fixed_at = now

    # Apply compliance tags to all findings touched in this upsert run
    from app.services.compliance import apply_compliance_tags
    apply_compliance_tags(db, list(existing_by_key.values()))

    db.flush()
    return created, updated


def _evaluate_policies_sync(db: Session, application_id: uuid.UUID) -> dict:
    """Evaluate all active policies against open findings for this application."""
    from app.models.finding import Finding
    from app.models.policy import Policy
    from app.services.policy_evaluator import evaluate_policy

    active_policies = db.execute(
        select(Policy).where(Policy.is_active == True)  # noqa: E712
    ).scalars().all()

    if not active_policies:
        return {"evaluated": 0, "blocked": False, "total_violations": 0}

    findings = db.execute(
        select(Finding).where(
            Finding.application_id == application_id,
            Finding.status == "open",
        )
    ).scalars().all()

    results = [evaluate_policy(p, list(findings)) for p in active_policies]
    blocked = any(r["blocked"] for r in results)
    total_violations = sum(r["total_violations"] for r in results)

    if blocked:
        logger.warning(
            "Policy violation: %d violations across %d policies for app %s",
            total_violations, len(active_policies), application_id,
        )

    return {
        "evaluated": len(active_policies),
        "blocked": blocked,
        "total_violations": total_violations,
        "policies": [{"name": r["policy_name"], "violations": r["total_violations"], "blocked": r["blocked"]} for r in results],
    }


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
            active_patterns = db.execute(
                select(SecretPattern).where(SecretPattern.is_active == True)  # noqa: E712
            ).scalars().all()
            custom_secret_patterns = [
                {"id": str(p.id), "name": p.name, "pattern": p.pattern, "severity": p.severity}
                for p in active_patterns
            ]

            svc = RealScannerService()
            raw_findings = svc.run_scan(
                app,
                scan_type,
                custom_secret_patterns=custom_secret_patterns,
                container_image=getattr(app, "container_image", None),
            )

            created, updated = _upsert_findings_sync(db, application_id, scan_id, raw_findings)

            scan.findings_count = len(raw_findings)
            scan.critical_count = sum(1 for f in raw_findings if f.get("severity") == "critical")
            scan.high_count = sum(1 for f in raw_findings if f.get("severity") == "high")
            scan.medium_count = sum(1 for f in raw_findings if f.get("severity") == "medium")
            scan.low_count = sum(1 for f in raw_findings if f.get("severity") == "low")
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)

            _recalculate_risk(db, app)

            # Evaluate policies after every complete or targeted scan.
            # "all" → all 5 scanner types; "checkov"/"grype" → single full IaC/container scan.
            # Partial runs (e.g. "semgrep" or "trivy" alone) are skipped to avoid false
            # negatives from incomplete finding sets.
            _FULL_SCAN_TYPES = {"all", "checkov", "grype"}
            if scan_type in _FULL_SCAN_TYPES:
                policy_summary = _evaluate_policies_sync(db, application_id)
            else:
                policy_summary = {"skipped": True, "reason": f"partial scan ({scan_type})"}

            db.commit()
            
            # Fetch EPSS scores for any new CVEs
            cve_ids = list(set(f.get("cve_id") for f in raw_findings if f.get("cve_id")))
            if cve_ids:
                fetch_epss_scores_task.delay(str(application_id), cve_ids)

            return {
                "scan_id": str(scan_id),
                "status": "completed",
                "findings": len(raw_findings),
                "created": created,
                "updated": updated,
                "policy_evaluation": policy_summary,
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


@celery_app.task(name="app.worker.tasks.fetch_epss_scores_task", max_retries=3)
def fetch_epss_scores_task(app_id_str: str, cve_ids: list[str]) -> dict:
    import asyncio
    from app.services.epss import fetch_epss_scores
    
    if not cve_ids:
        return {"fetched": 0}
        
    application_id = uuid.UUID(app_id_str)
    
    # Run the async fetch in a synchronous wrapper
    scores = asyncio.run(fetch_epss_scores(cve_ids))
    if not scores:
        return {"fetched": 0, "error": "No scores returned or API failed"}
        
    with _get_sync_session() as db:
        findings = db.execute(
            select(Finding).where(
                Finding.application_id == application_id,
                Finding.cve_id.in_(scores.keys())
            )
        ).scalars().all()
        
        updated = 0
        for finding in findings:
            cve = finding.cve_id
            if cve in scores:
                finding.epss_score = scores[cve]["epss"]
                finding.epss_percentile = scores[cve]["percentile"]
                updated += 1
                
        if updated > 0:
            app = db.get(Application, application_id)
            if app:
                _recalculate_risk(db, app)
            db.commit()
            
    return {"fetched": len(scores), "updated": updated}
