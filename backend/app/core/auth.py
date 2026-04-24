"""
Service account token authentication dependency.

Tokens are formatted as  snitch_<32 random URL-safe chars>.
Only the SHA-256 hex digest is stored in the database — the plaintext token
is returned once on creation and never persisted.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.service_account import ServiceAccount

_bearer_scheme = HTTPBearer(auto_error=False)

TOKEN_PREFIX = "snitch_"
TOKEN_RANDOM_BYTES = 24  # 24 random bytes → 32 URL-safe base64 chars


def generate_token() -> str:
    """Generate a new plain-text service account token."""
    return TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_RANDOM_BYTES)


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a token."""
    return hashlib.sha256(token.encode()).hexdigest()


def token_prefix_display(token: str) -> str:
    """Return the first 12 characters for display (e.g. 'snitch_abc12')."""
    return token[:12]


async def get_service_account(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> ServiceAccount:
    """
    FastAPI dependency that validates a Bearer token and returns the ServiceAccount.
    Raises HTTP 401 if the token is missing, invalid, or belongs to a revoked account.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token. Create a service account to obtain a token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_hash = hash_token(credentials.credentials)
    result = await db.execute(
        select(ServiceAccount).where(ServiceAccount.token_hash == token_hash)
    )
    sa = result.scalar_one_or_none()

    if sa is None or not sa.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked service account token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Update last_used_at without a separate DB round-trip on every call
    sa.last_used_at = datetime.now(timezone.utc)

    return sa
