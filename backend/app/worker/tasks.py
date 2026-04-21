"""
Celery tasks for asynchronous and scheduled repository scanning,
and CI/CD scan ingestion via SQS + S3.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.models.application import Application
from app.models.cicd_scan import CiCdScan
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
            raw_findings = svc.run_scan(app, scan_type, custom_secret_patterns=custom_secret_patterns)

            created, updated = _upsert_findings_sync(db, application_id, scan_id, raw_findings)

            scan.findings_count = len(raw_findings)
            scan.critical_count = sum(1 for f in raw_findings if f.get("severity") == "critical")
            scan.high_count = sum(1 for f in raw_findings if f.get("severity") == "high")
            scan.medium_count = sum(1 for f in raw_findings if f.get("severity") == "medium")
            scan.low_count = sum(1 for f in raw_findings if f.get("severity") == "low")
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)

            _recalculate_risk(db, app)

            # Evaluate all active policies against the updated findings
            policy_summary = _evaluate_policies_sync(db, application_id)

            db.commit()

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


def _upsert_cicd_findings_sync(
    db: Session,
    application_id: uuid.UUID,
    cicd_scan_id: uuid.UUID,
    raw_findings: list[dict],
) -> tuple[int, int]:
    """Upsert CI/CD findings — uses a separate dedup pool from repository findings."""
    existing = db.execute(
        select(Finding).where(
            Finding.application_id == application_id,
            Finding.cicd_scan_id.isnot(None),
        )
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
            match.cicd_scan_id = cicd_scan_id
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
            finding = Finding(application_id=application_id, cicd_scan_id=cicd_scan_id, **raw)
            db.add(finding)
            db.flush()
            seen_ids.add(finding.id)
            existing_by_key[key] = finding
            created += 1

    # Mark disappeared open CI/CD findings as fixed
    for f in existing:
        if f.id not in seen_ids and f.status == "open":
            f.status = "fixed"
            f.fixed_at = now

    db.flush()
    return created, updated


@celery_app.task(name="app.worker.tasks.poll_sqs_task")
def poll_sqs_task() -> dict:
    """Poll SQS for CI/CD scan result notifications and dispatch processing tasks."""
    if not settings.SQS_CICD_QUEUE_URL:
        logger.debug("SQS_CICD_QUEUE_URL not configured — skipping CI/CD scan poll")
        return {"skipped": True}

    import boto3

    sqs = boto3.client(
        "sqs",
        region_name=settings.AWS_REGION,
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    )

    response = sqs.receive_message(
        QueueUrl=settings.SQS_CICD_QUEUE_URL,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=5,
    )

    messages = response.get("Messages", [])
    dispatched = 0

    for message in messages:
        receipt_handle = message["ReceiptHandle"]
        try:
            body = json.loads(message["Body"])
            # S3 event notification wraps in {"Records": [...]}
            records = body.get("Records", [])
            for record in records:
                s3_info = record.get("s3", {})
                bucket = s3_info.get("bucket", {}).get("name")
                key = s3_info.get("object", {}).get("key")
                if bucket and key:
                    process_cicd_scan_task.delay(bucket, key, receipt_handle)
                    dispatched += 1
        except Exception as exc:
            logger.error("Failed to parse SQS message %s: %s", message.get("MessageId"), exc)

    logger.info("CI/CD SQS poll: %d messages, %d tasks dispatched", len(messages), dispatched)
    return {"messages": len(messages), "dispatched": dispatched}


@celery_app.task(bind=True, name="app.worker.tasks.process_cicd_scan_task", max_retries=2)
def process_cicd_scan_task(self, bucket: str, key: str, receipt_handle: str) -> dict:
    """
    Download a CI/CD scan result from S3, normalise it, and store findings.

    S3 key format: {org}/{repo}/{scan_type}/{yymmdd}-{run_id}.json
    """
    import boto3
    from app.services.cicd_normaliser import normalise

    # Parse key: org/repo/scan_type/filename
    parts = key.strip("/").split("/")
    if len(parts) < 4:
        logger.error("Cannot parse S3 key '%s' — expected org/repo/scan_type/file", key)
        return {"error": f"Unparseable S3 key: {key}"}

    github_org = parts[0]
    github_repo = parts[1]
    # scan_type from key is informational; normaliser auto-detects from JSON content

    with _get_sync_session() as db:
        app = db.execute(
            select(Application).where(
                Application.github_org == github_org,
                Application.github_repo == github_repo,
            )
        ).scalars().first()

        if not app:
            logger.warning(
                "No application found for %s/%s — dropping S3 key %s",
                github_org, github_repo, key,
            )
            # Delete message to avoid infinite re-delivery
            _delete_sqs_message(receipt_handle)
            return {"error": f"Application not found: {github_org}/{github_repo}"}

        # Download from S3
        s3 = boto3.client(
            "s3",
            region_name=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        )
        s3_obj = s3.get_object(Bucket=bucket, Key=key)
        raw_data = json.loads(s3_obj["Body"].read())

        # Extract optional CI context from S3 object metadata
        metadata = s3_obj.get("Metadata", {})
        commit_sha = metadata.get("commit-sha")
        branch = metadata.get("branch")
        workflow_run_id = metadata.get("workflow-run-id")
        ci_provider = metadata.get("ci-provider", "github-actions")

        # Normalise findings
        try:
            raw_findings, detected_scan_type = normalise(raw_data)
        except ValueError as exc:
            logger.error("Failed to normalise scan result from %s/%s: %s", bucket, key, exc)
            _delete_sqs_message(receipt_handle)
            return {"error": str(exc)}

        # Create CiCdScan record
        cicd_scan = CiCdScan(
            application_id=app.id,
            scan_type=detected_scan_type,
            status="processing",
            s3_bucket=bucket,
            s3_key=key,
            commit_sha=commit_sha,
            branch=branch,
            workflow_run_id=workflow_run_id,
            ci_provider=ci_provider,
            started_at=datetime.now(timezone.utc),
        )
        db.add(cicd_scan)
        db.flush()

        try:
            created, updated = _upsert_cicd_findings_sync(db, app.id, cicd_scan.id, raw_findings)

            cicd_scan.findings_count = len(raw_findings)
            cicd_scan.critical_count = sum(1 for f in raw_findings if f.get("severity") == "critical")
            cicd_scan.high_count = sum(1 for f in raw_findings if f.get("severity") == "high")
            cicd_scan.medium_count = sum(1 for f in raw_findings if f.get("severity") == "medium")
            cicd_scan.low_count = sum(1 for f in raw_findings if f.get("severity") == "low")
            cicd_scan.status = "completed"
            cicd_scan.completed_at = datetime.now(timezone.utc)
            db.commit()

        except Exception as exc:
            cicd_scan.status = "failed"
            cicd_scan.error_message = str(exc)
            cicd_scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            logger.error("CI/CD scan processing failed for %s/%s: %s", bucket, key, exc)
            raise self.retry(exc=exc, countdown=60)

    _delete_sqs_message(receipt_handle)

    return {
        "cicd_scan_id": str(cicd_scan.id),
        "application": f"{github_org}/{github_repo}",
        "scan_type": detected_scan_type,
        "findings": len(raw_findings),
        "created": created,
        "updated": updated,
    }


def _delete_sqs_message(receipt_handle: str) -> None:
    """Delete an SQS message after successful processing."""
    if not settings.SQS_CICD_QUEUE_URL:
        return
    try:
        import boto3
        sqs = boto3.client(
            "sqs",
            region_name=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        )
        sqs.delete_message(QueueUrl=settings.SQS_CICD_QUEUE_URL, ReceiptHandle=receipt_handle)
    except Exception as exc:
        logger.warning("Failed to delete SQS message: %s", exc)


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
