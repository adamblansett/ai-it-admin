from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor, get_current_actor, require_roles
from app.db.models import DirectoryUser, ProvisioningPlan, RoleTemplate, SaaSEntitlement
from app.db.session import get_db
from app.identity.schemas import (
    DirectoryUserOut,
    ProvisioningPlanOut,
    ProvisioningPreviewIn,
    RoleTemplateCreateIn,
    RoleTemplateOut,
)
from app.identity.service import create_role_template, preview_provisioning_plan
from app.llm.router import LLMRouter, get_llm_router

router = APIRouter(prefix="/identity", tags=["identity"])


@router.get("/templates", response_model=list[RoleTemplateOut])
async def list_role_templates(
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> list[RoleTemplateOut]:
    """List least-privilege SCIM/RBAC role templates."""
    rows = list(
        (await db.execute(select(RoleTemplate).order_by(RoleTemplate.code.asc())))
        .scalars()
        .all()
    )
    return [RoleTemplateOut.model_validate(row) for row in rows]


@router.post("/templates", response_model=RoleTemplateOut)
async def post_role_template(
    payload: RoleTemplateCreateIn,
    actor: Actor = Depends(require_roles("it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
) -> RoleTemplateOut:
    """Create a new least-privilege role template."""
    tmpl = await create_role_template(db, payload=payload, actor=actor)
    return RoleTemplateOut.model_validate(tmpl)


@router.get("/users", response_model=list[DirectoryUserOut])
async def list_directory_users(
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> list[DirectoryUserOut]:
    """List directory users along with their active SaaS entitlement counts."""
    users = list(
        (await db.execute(select(DirectoryUser).order_by(DirectoryUser.full_name.asc())))
        .scalars()
        .all()
    )
    counts_rows = (
        await db.execute(
            select(SaaSEntitlement.user_email, func.count(SaaSEntitlement.id))
            .where(SaaSEntitlement.account_status == "active")
            .group_by(SaaSEntitlement.user_email)
        )
    ).all()
    counts_map = {str(email).lower(): int(cnt) for email, cnt in counts_rows}

    result: list[DirectoryUserOut] = []
    for u in users:
        out = DirectoryUserOut.model_validate(u)
        out.active_entitlements_count = counts_map.get(u.email.lower(), 0)
        result.append(out)
    return result


@router.get("/plans", response_model=list[ProvisioningPlanOut])
async def list_provisioning_plans(
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> list[ProvisioningPlanOut]:
    """List Joiner/Mover/Leaver SCIM change plans ordered by newest first."""
    rows = list(
        (await db.execute(select(ProvisioningPlan).order_by(ProvisioningPlan.created_at.desc())))
        .scalars()
        .all()
    )
    return [ProvisioningPlanOut.model_validate(row) for row in rows]


@router.post("/plans/preview", response_model=ProvisioningPlanOut)
async def post_preview_provisioning_plan(
    payload: ProvisioningPreviewIn,
    actor: Actor = Depends(require_roles("operator", "it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
) -> ProvisioningPlanOut:
    """Create a dry-run Joiner/Mover/Leaver SCIM plan gated by HITL approval."""
    plan = await preview_provisioning_plan(
        db,
        llm_router=llm_router,
        payload=payload,
        actor=actor,
    )
    return ProvisioningPlanOut.model_validate(plan)
