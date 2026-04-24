from fastapi import APIRouter, Depends

from app.core.auth import get_service_account
from app.models.service_account import ServiceAccount
from app.schemas.service_account import ServiceAccountResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/verify", response_model=dict)
async def verify_token(sa: ServiceAccount = Depends(get_service_account)):
    """
    Stage 1 auth check — validates a Bearer token and returns the service account info.
    Use this as the first step in CI/CD pipelines to confirm credentials are correct
    before running scanners.
    """
    return {
        "authenticated": True,
        "service_account": ServiceAccountResponse.model_validate(sa).model_dump(),
    }
