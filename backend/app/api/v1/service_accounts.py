import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import generate_token, hash_token, token_prefix_display
from app.db.session import get_db
from app.models.service_account import ServiceAccount
from app.schemas.service_account import (
    ServiceAccountCreate,
    ServiceAccountCreated,
    ServiceAccountResponse,
)

router = APIRouter(prefix="/service-accounts", tags=["service-accounts"])


@router.post("", response_model=ServiceAccountCreated, status_code=201)
async def create_service_account(
    payload: ServiceAccountCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a service account. Returns the plain token **once** — it cannot be retrieved again."""
    existing = await db.execute(
        select(ServiceAccount).where(ServiceAccount.name == payload.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A service account with this name already exists.")

    token = generate_token()
    sa = ServiceAccount(
        id=uuid.uuid4(),
        name=payload.name,
        description=payload.description,
        team_name=payload.team_name,
        token_hash=hash_token(token),
        token_prefix=token_prefix_display(token),
    )
    db.add(sa)
    await db.commit()
    await db.refresh(sa)

    return ServiceAccountCreated(
        id=sa.id,
        name=sa.name,
        description=sa.description,
        team_name=sa.team_name,
        token_prefix=sa.token_prefix,
        is_active=sa.is_active,
        created_at=sa.created_at,
        last_used_at=sa.last_used_at,
        token=token,
    )


@router.get("", response_model=list[ServiceAccountResponse])
async def list_service_accounts(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ServiceAccount).order_by(ServiceAccount.created_at.desc())
    )
    return result.scalars().all()


@router.delete("/{sa_id}", status_code=204)
async def revoke_service_account(sa_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ServiceAccount).where(ServiceAccount.id == sa_id))
    sa = result.scalar_one_or_none()
    if not sa:
        raise HTTPException(status_code=404, detail="Service account not found.")
    sa.is_active = False
    await db.commit()


@router.post("/{sa_id}/rotate", response_model=ServiceAccountCreated)
async def rotate_token(sa_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Rotate the token for a service account. Returns the new plain token **once**."""
    result = await db.execute(select(ServiceAccount).where(ServiceAccount.id == sa_id))
    sa = result.scalar_one_or_none()
    if not sa:
        raise HTTPException(status_code=404, detail="Service account not found.")
    if not sa.is_active:
        raise HTTPException(status_code=400, detail="Cannot rotate token for a revoked service account.")

    token = generate_token()
    sa.token_hash = hash_token(token)
    sa.token_prefix = token_prefix_display(token)
    await db.commit()
    await db.refresh(sa)

    return ServiceAccountCreated(
        id=sa.id,
        name=sa.name,
        description=sa.description,
        team_name=sa.team_name,
        token_prefix=sa.token_prefix,
        is_active=sa.is_active,
        created_at=sa.created_at,
        last_used_at=sa.last_used_at,
        token=token,
    )
