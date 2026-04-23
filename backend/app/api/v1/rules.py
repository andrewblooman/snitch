"""Rules library API — merges the static catalog with rules discovered from scan findings."""

import math
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.finding import Finding
from app.models.policy import Policy
from app.services.rule_catalog import CATALOG_BY_ID, RULE_CATALOG

router = APIRouter(prefix="/rules", tags=["rules"])

# Severity ordering for sorting
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _build_policy_memberships(rule_id: str, policies: list) -> list[dict]:
    """Return which policies include rule_id and whether it's blocklisted/allowlisted."""
    rid = rule_id.lower()
    memberships = []
    for p in policies:
        list_type = None
        if rid in [r.lower() for r in (p.rule_allowlist or [])]:
            list_type = "allowlist"
        elif rid in [r.lower() for r in (p.rule_blocklist or [])]:
            list_type = "blocklist"
        if list_type:
            memberships.append(
                {"policy_id": str(p.id), "policy_name": p.name, "list_type": list_type}
            )
    return memberships


@router.get("")
async def list_rules(
    scan_type: Optional[str] = Query(None, description="Filter by scan type: sast|sca|container|secrets|iac"),
    scanner: Optional[str] = Query(None, description="Filter by scanner: semgrep|checkov|gitleaks|trivy|grype"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    search: Optional[str] = Query(None, description="Search rule ID, name, or description"),
    source: Optional[str] = Query(None, description="catalog | discovered"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return a merged list of catalog rules + dynamically discovered rules from findings."""

    # Fetch all policies to compute memberships
    policies_result = await db.execute(select(Policy))
    all_policies = list(policies_result.scalars().all())

    # Build base catalog list
    catalog_items: list[dict] = [
        {**r, "source": "catalog"} for r in RULE_CATALOG
    ]

    # Discover rule IDs from findings that are not in the catalog.
    # Group by rule_id so each rule produces exactly one row (deterministic).
    discovered_result = await db.execute(
        select(
            Finding.rule_id,
            func.max(Finding.scanner).label("scanner"),
            func.max(Finding.finding_type).label("finding_type"),
            func.min(Finding.severity).label("severity"),
        )
        .where(Finding.rule_id.isnot(None))
        .where(Finding.rule_id != "")
        .group_by(Finding.rule_id)
    )
    discovered_rows = discovered_result.all()

    discovered_items: list[dict] = []
    for row in discovered_rows:
        rid, scanner_name, ftype, sev = row
        if rid in CATALOG_BY_ID:
            continue
        discovered_items.append(
            {
                "id": rid,
                "name": rid,
                "description": f"Rule discovered from scan findings (scanner: {scanner_name}).",
                "severity": sev or "info",
                "scanner": scanner_name or "unknown",
                "scan_type": ftype.lower() if ftype else "unknown",
                "category": "Discovered",
                "remediation": "Review the original scanner output for remediation guidance.",
                "reference_url": "",
                "source": "discovered",
            }
        )

    all_items = catalog_items + discovered_items

    # Apply filters
    if source:
        all_items = [r for r in all_items if r["source"] == source]
    if scan_type:
        all_items = [r for r in all_items if r["scan_type"] == scan_type]
    if scanner:
        all_items = [r for r in all_items if r["scanner"] == scanner]
    if severity:
        all_items = [r for r in all_items if r["severity"] == severity]
    if search:
        q = search.lower()
        all_items = [
            r for r in all_items
            if q in r["id"].lower() or q in r["name"].lower() or q in r["description"].lower()
        ]

    # Sort: catalog first, then by severity
    all_items.sort(key=lambda r: (0 if r["source"] == "catalog" else 1, _SEV_ORDER.get(r["severity"], 99)))

    total = len(all_items)
    pages = max(1, math.ceil(total / page_size))
    offset = (page - 1) * page_size
    page_items = all_items[offset: offset + page_size]

    # Attach policy memberships
    for item in page_items:
        item["policy_memberships"] = _build_policy_memberships(item["id"], all_policies)

    return {
        "items": page_items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
        "catalog_count": len(catalog_items),
        "discovered_count": len(discovered_items),
    }
