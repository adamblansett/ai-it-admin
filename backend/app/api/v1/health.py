from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.core.auth import resolve_settings
from app.core.config import Settings, get_settings
from app.db.session import check_db_ready, ensure_db_initialized

router = APIRouter(prefix="/health", tags=["health"])


class HealthResponse(BaseModel):
    status: str
    service: str
    app_name: str
    version: str
    environment: str
    llm_provider: str
    db_ready: bool = True


def _build_payload(settings: Settings, db_ready: bool = True) -> HealthResponse:
    return HealthResponse(
        status="ok" if db_ready else "degraded",
        service=settings.app_slug,
        app_name=settings.app_name,
        version="0.1.0",
        environment=settings.app_env,
        llm_provider=settings.llm_default_provider,
        db_ready=db_ready,
    )


@router.get("", response_model=HealthResponse)
@router.get("/live", response_model=HealthResponse)
async def health_check(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """Return service liveness and runtime configuration summary."""
    return _build_payload(settings, db_ready=True)


@router.get("/ready", response_model=HealthResponse)
async def readiness_check(request: Request) -> HealthResponse | JSONResponse:
    """Verify database readiness and return service readiness state."""
    settings = resolve_settings(request)
    await ensure_db_initialized(request.app)
    db_ready = await check_db_ready(request.app.state.db_engine)
    payload = _build_payload(settings, db_ready=db_ready)
    if not db_ready:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=payload.model_dump(),
        )
    return payload
