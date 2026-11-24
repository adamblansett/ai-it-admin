from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.core.auth import (
    Actor,
    ActorRole,
    create_access_token,
    get_current_actor,
    resolve_settings,
)

router = APIRouter(prefix="/auth", tags=["auth"])


class TokenIssueRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    role: ActorRole = "operator"
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)


class TokenIssueResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    actor: Actor


@router.get("/me", response_model=Actor)
async def get_me(actor: Actor = Depends(get_current_actor)) -> Actor:
    """Return the resolved actor context for the current request."""
    return actor


@router.post("/token", response_model=TokenIssueResponse)
async def issue_token(
    payload: TokenIssueRequest,
    request: Request,
) -> TokenIssueResponse:
    """Issue a signed HMAC-SHA256 bearer token (requires admin when strict auth is active)."""
    settings = resolve_settings(request)
    is_prod = settings.app_env.strip().lower() == "production"
    if is_prod or settings.auth_require_token:
        actor = await get_current_actor(request)
        if actor.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role is required to issue bearer tokens.",
            )

    clean_email = payload.email.strip()
    token = create_access_token(
        email=clean_email,
        role=payload.role,
        secret_key=settings.auth_secret_key,
        ttl_seconds=payload.ttl_seconds,
    )
    return TokenIssueResponse(
        access_token=token,
        expires_in=payload.ttl_seconds,
        actor=Actor(email=clean_email, role=payload.role, auth_method="bearer_token"),
    )
