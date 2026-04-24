"""
Finding deduplication: upsert findings from a scan against existing records.

Matching keys:
  SAST      → rule_id  + file_path  + application_id
  SCA       → cve_id   + package_name + application_id
  fallback  → title    + scanner    + application_id
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def _match_key(raw: dict) -> tuple:
    """Return a tuple that uniquely identifies a finding for deduplication."""
    ftype = (raw.get("finding_type") or "").lower()
    if ftype == "secrets" and raw.get("rule_id") and raw.get("file_path"):
        return ("secrets", raw["rule_id"], raw["file_path"])
    if raw.get("rule_id") and raw.get("file_path"):
        return ("sast", raw["rule_id"], raw["file_path"])
    if raw.get("cve_id") and raw.get("package_name"):
        # Distinguish container (grype) from SCA (trivy/govulncheck) to prevent overwrites
        key_prefix = "container" if ftype == "container" else "sca"
        return (key_prefix, raw["cve_id"], raw["package_name"])
    return ("generic", raw.get("scanner", ""), raw.get("title", "")[:255])


async def upsert_findings(
    db: AsyncSession,
    application_id,
    scan_id,
    raw_findings: list[dict],
) -> tuple[list[Finding], int, int]:
    """
    Upsert findings for an application scan.

    Returns:
        (all_findings_after_upsert, created_count, updated_count)

    Side effects:
        - Creates new Finding rows for genuinely new findings
        - Updates last_seen_at (and scan_id) for existing matches
        - Marks open findings NOT seen in this scan as 'fixed'
    """
    result = await db.execute(
        select(Finding).where(Finding.application_id == application_id)
    )
    existing: list[Finding] = list(result.scalars().all())

    existing_by_key: dict[tuple, Finding] = {}
    for f in existing:
        key = _match_key({
            "rule_id": f.rule_id,
            "file_path": f.file_path,
            "cve_id": f.cve_id,
            "package_name": f.package_name,
            "scanner": f.scanner,
            "title": f.title,
        })
        existing_by_key[key] = f

    now = datetime.now(timezone.utc)
    seen_ids: set = set()
    created = 0
    updated = 0

    for raw in raw_findings:
        key = _match_key(raw)
        if key in existing_by_key:
            match = existing_by_key[key]
            match.last_seen_at = now
            match.scan_id = scan_id
            # Refresh volatile fields that may change between scans
            match.severity = raw.get("severity", match.severity)
            match.package_version = raw.get("package_version", match.package_version)
            match.fixed_version = raw.get("fixed_version", match.fixed_version)
            match.cvss_score = raw.get("cvss_score", match.cvss_score)
            if match.status == "fixed":
                # Re-opened: mark open again
                match.status = "open"
                match.fixed_at = None
            seen_ids.add(match.id)
            updated += 1
        else:
            finding = Finding(
                application_id=application_id,
                scan_id=scan_id,
                **raw,
            )
            db.add(finding)
            seen_ids.add(id(finding))  # placeholder; real id after flush
            existing_by_key[key] = finding
            created += 1

    await db.flush()

    # Mark previously-open findings that disappeared as fixed
    for f in existing:
        if f.id not in seen_ids and f.status == "open":
            f.status = "fixed"
            f.fixed_at = now

    await db.flush()

    all_result = await db.execute(
        select(Finding).where(Finding.application_id == application_id)
    )
    all_findings = list(all_result.scalars().all())

    logger.info(
        "upsert_findings: %d created, %d updated, %d total for app %s",
        created, updated, len(all_findings), application_id,
    )
    return all_findings, created, updated
