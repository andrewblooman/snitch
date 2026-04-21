import math
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.finding import Finding
from app.models.policy import Policy
from app.schemas.policy import (
    PaginatedPolicies,
    PolicyCreate,
    PolicyEvaluationResult,
    PolicyResponse,
    PolicyUpdate,
)
from app.services.policy_evaluator import evaluate_policy

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("", response_model=PaginatedPolicies)
async def list_policies(
    is_active: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    q = select(Policy)
    if is_active is not None:
        q = q.where(Policy.is_active == is_active)

    from sqlalchemy import func
    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(Policy.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    policies = result.scalars().all()

    return PaginatedPolicies(
        items=policies,
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.post("", response_model=PolicyResponse, status_code=201)
async def create_policy(payload: PolicyCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(Policy).where(Policy.name == payload.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A policy with this name already exists")

    policy = Policy(**payload.model_dump())
    db.add(policy)
    await db.flush()
    await db.refresh(policy)
    return policy


@router.get("/evaluate/all", response_model=List[PolicyEvaluationResult])
async def evaluate_all_active(
    application_id: Optional[uuid.UUID] = Query(None, description="Filter findings by application"),
    db: AsyncSession = Depends(get_db),
):
    """Evaluate all active policies against current open findings."""
    policies_result = await db.execute(select(Policy).where(Policy.is_active == True))  # noqa: E712
    policies = policies_result.scalars().all()

    findings_q = select(Finding).where(Finding.status == "open")
    if application_id:
        findings_q = findings_q.where(Finding.application_id == application_id)
    findings_result = await db.execute(findings_q)
    findings = findings_result.scalars().all()

    return [evaluate_policy(p, list(findings)) for p in policies]


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(policy_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.patch("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: uuid.UUID, payload: PolicyUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    if payload.name is not None and payload.name != policy.name:
        existing = await db.execute(select(Policy).where(Policy.name == payload.name))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="A policy with this name already exists")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(policy, field, value)

    await db.flush()
    await db.refresh(policy)
    return policy


@router.post("/seed", status_code=201)
async def seed_default_policies(db: AsyncSession = Depends(get_db)):
    """Create default security policies if none exist. Idempotent."""
    existing = await db.execute(select(Policy))
    if existing.scalars().first():
        return {"message": "Policies already exist — seed skipped", "policies_created": 0}

    DEFAULT_POLICIES = [
        {
            "name": "Baseline SAST Policy",
            "description": "Flag SAST findings at medium severity or above. Intended to inform developers without blocking pipelines.",
            "is_active": True,
            "action": "inform",
            "min_severity": "medium",
            "enabled_scan_types": ["sast"],
            "rule_blocklist": [],
            "rule_allowlist": [],
        },
        {
            "name": "Critical Vulnerability Block",
            "description": "Block deployment when critical CVEs are found in SCA or container scans. CIS L1-aligned.",
            "is_active": True,
            "action": "block",
            "min_severity": "critical",
            "enabled_scan_types": ["sca", "container"],
            "rule_blocklist": [],
            "rule_allowlist": [],
        },
        {
            "name": "High Vulnerability Watch",
            "description": "Track high-severity CVEs across dependency and container scans. Inform only — escalate to block after triage.",
            "is_active": True,
            "action": "inform",
            "min_severity": "high",
            "enabled_scan_types": ["sca", "container"],
            "rule_blocklist": [],
            "rule_allowlist": [],
        },
        {
            "name": "Secrets Detection",
            "description": "Block on any hardcoded secrets or credentials regardless of severity. Any matched rule immediately blocks.",
            "is_active": True,
            "action": "block",
            "min_severity": "info",
            "enabled_scan_types": ["secrets"],
            "rule_blocklist": [
                "generic.secrets.security.detected-generic-secret",
                "python.django.security.audit.django-secret-key",
                "javascript.lang.security.audit.hardcoded-credentials",
                "generic.github.security.github-personal-access-token",
                "generic.aws.security.aws-secret-access-key",
            ],
            "rule_allowlist": [],
        },
        {
            "name": "IaC Security (CIS Level 1)",
            "description": (
                "Block IaC findings that violate CIS AWS Foundations Benchmark Level 1 controls. "
                "Covers IAM least-privilege, S3 public access, unrestricted SSH/RDP, "
                "CloudTrail integrity, RDS encryption, KMS rotation, and EC2 IMDSv2."
            ),
            "is_active": True,
            "action": "block",
            "min_severity": "medium",
            "enabled_scan_types": ["iac"],
            "rule_blocklist": [
                # IAM
                "CKV_AWS_1",   # No IAM policy with full admin privileges (*:*)
                # Security Groups
                "CKV_AWS_24",  # No unrestricted SSH (port 22) ingress from 0.0.0.0/0
                "CKV_AWS_25",  # No unrestricted RDP (port 3389) ingress from 0.0.0.0/0
                # S3
                "CKV_AWS_18",  # S3 access logging enabled
                "CKV_AWS_19",  # S3 server-side encryption enabled
                "CKV_AWS_20",  # S3 not publicly accessible via ACL
                "CKV_AWS_53",  # S3 BlockPublicAcls
                "CKV_AWS_54",  # S3 BlockPublicPolicy
                "CKV_AWS_55",  # S3 IgnorePublicAcls
                "CKV_AWS_56",  # S3 RestrictPublicBuckets
                # CloudTrail
                "CKV_AWS_36",  # CloudTrail log file validation enabled
                "CKV_AWS_67",  # CloudTrail enabled in all regions
                # RDS
                "CKV_AWS_16",  # RDS storage encrypted at rest
                "CKV_AWS_17",  # RDS instance not publicly accessible
                # KMS
                "CKV_AWS_7",   # KMS key rotation enabled
                # EC2
                "CKV_AWS_79",  # EC2 IMDSv2 required (disables IMDSv1)
            ],
            "rule_allowlist": [],
        },
    ]

    count = 0
    for policy_data in DEFAULT_POLICIES:
        policy = Policy(**policy_data)
        db.add(policy)
        count += 1

    await db.flush()
    return {"message": f"Created {count} default policies", "policies_created": count}


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(policy_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    await db.delete(policy)
    await db.flush()


@router.post("/{policy_id}/evaluate", response_model=PolicyEvaluationResult)
async def evaluate_policy_endpoint(
    policy_id: uuid.UUID,
    application_id: Optional[uuid.UUID] = Query(None, description="Filter findings by application"),
    db: AsyncSession = Depends(get_db),
):
    """Evaluate a specific policy against current open findings."""
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    findings_q = select(Finding).where(Finding.status == "open")
    if application_id:
        findings_q = findings_q.where(Finding.application_id == application_id)
    findings_result = await db.execute(findings_q)
    findings = findings_result.scalars().all()

    return evaluate_policy(policy, list(findings))
