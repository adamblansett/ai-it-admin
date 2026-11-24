from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.access_audit.schemas import (
    AccessAuditRunOut,
    AccessFindingOut,
    AccessScanIn,
    EntitlementCreateIn,
    SaaSEntitlementOut,
)
from app.access_audit.service import (
    create_entitlement,
    request_finding_remediation,
    run_access_audit_scan,
)
from app.core.auth import Actor, get_current_actor, require_roles
from app.core.config import Settings, get_settings
from app.db.models import AccessAuditRun, AccessFinding, SaaSEntitlement
from app.db.session import get_db
from app.llm.router import LLMRouter, get_llm_router

router = APIRouter(prefix="/access-audit", tags=["access-audit"])


@router.get("/entitlements", response_model=list[SaaSEntitlementOut])
async def list_entitlements(
    app_name: str | None = Query(default=None),
    account_status: str | None = Query(default=None),
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> list[SaaSEntitlementOut]:
    """List SaaS application entitlements."""
    stmt = select(SaaSEntitlement).order_by(
        SaaSEntitlement.app_name.asc(), SaaSEntitlement.user_email.asc()
    )
    if app_name:
        stmt = stmt.where(SaaSEntitlement.app_name == app_name)
    if account_status:
        stmt = stmt.where(SaaSEntitlement.account_status == account_status)
    rows = list((await db.execute(stmt)).scalars().all())
    return [SaaSEntitlementOut.model_validate(row) for row in rows]


@router.post("/entitlements", response_model=SaaSEntitlementOut)
async def post_entitlement(
    payload: EntitlementCreateIn,
    actor: Actor = Depends(require_roles("operator", "it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
) -> SaaSEntitlementOut:
    """Import or create a SaaS entitlement record."""
    ent = await create_entitlement(db, payload=payload, actor=actor)
    return SaaSEntitlementOut.model_validate(ent)


@router.post("/scans", response_model=AccessAuditRunOut)
async def post_run_access_scan(
    payload: AccessScanIn | None = None,
    actor: Actor = Depends(require_roles("operator", "it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    settings: Settings = Depends(get_settings),
) -> AccessAuditRunOut:
    """Execute a full SaaS entitlement scan for orphaned accounts, stale tokens, and drift."""
    scope = payload.scope if payload is not None else "all_saas"
    run = await run_access_audit_scan(
        db,
        llm_router=llm_router,
        settings=settings,
        scope=scope,
        actor=actor,
    )
    return AccessAuditRunOut.model_validate(run)


@router.get("/scans", response_model=list[AccessAuditRunOut])
async def list_access_scans(
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> list[AccessAuditRunOut]:
    """List historical access control audit runs."""
    rows = list(
        (await db.execute(select(AccessAuditRun).order_by(AccessAuditRun.created_at.desc())))
        .scalars()
        .all()
    )
    return [AccessAuditRunOut.model_validate(row) for row in rows]


@router.get("/findings", response_model=list[AccessFindingOut])
async def list_access_findings(
    finding_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> list[AccessFindingOut]:
    """List detected access audit findings."""
    stmt = select(AccessFinding).order_by(AccessFinding.created_at.desc())
    if finding_type:
        stmt = stmt.where(AccessFinding.finding_type == finding_type)
    if severity:
        stmt = stmt.where(AccessFinding.severity == severity)
    if status_filter:
        stmt = stmt.where(AccessFinding.status == status_filter)
    rows = list((await db.execute(stmt)).scalars().all())
    return [AccessFindingOut.model_validate(row) for row in rows]


@router.post("/findings/{finding_id}/request-remediation", response_model=AccessFindingOut)
async def post_request_remediation(
    finding_id: str,
    actor: Actor = Depends(require_roles("operator", "it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
) -> AccessFindingOut:
    """Queue an access finding for human-in-the-loop remediation approval."""
    finding = await request_finding_remediation(db, finding_id=finding_id, actor=actor)
    return AccessFindingOut.model_validate(finding)
