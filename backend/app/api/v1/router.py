from fastapi import APIRouter

from app.access_audit.router import router as access_audit_router
from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.api.v1.overview import router as overview_router
from app.core.metrics import router as metrics_router
from app.governance.router import router as governance_router
from app.identity.router import router as identity_router
from app.integrations.router import router as integrations_router
from app.runbooks.router import router as runbooks_router
from app.seed.router import router as seed_router
from app.telemetry.router import router as telemetry_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(metrics_router)
api_v1_router.include_router(overview_router)
api_v1_router.include_router(identity_router)
api_v1_router.include_router(telemetry_router)
api_v1_router.include_router(access_audit_router)
api_v1_router.include_router(runbooks_router)
api_v1_router.include_router(integrations_router)
api_v1_router.include_router(governance_router)
api_v1_router.include_router(seed_router)
