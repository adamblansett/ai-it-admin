from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor
from app.db.models import DirectoryUser, ProvisioningPlan, RoleTemplate, SaaSEntitlement
from app.governance.service import create_approval_request, record_audit_event
from app.identity.schemas import (
    ProvisioningPreviewIn,
    RoleTemplateCreateIn,
    ScimBulkOperation,
    ScimBulkRequestOut,
)
from app.llm.router import LLMRouter


async def create_role_template(
    db: AsyncSession,
    *,
    payload: RoleTemplateCreateIn,
    actor: Actor,
) -> RoleTemplate:
    """Create a least-privilege RBAC/SCIM role template."""
    clean_code = payload.code.strip().lower()
    existing = (
        await db.execute(select(RoleTemplate).where(RoleTemplate.code == clean_code))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Role template '{clean_code}' already exists.",
        )

    tmpl = RoleTemplate(
        code=clean_code,
        name=payload.name.strip(),
        department=payload.department.strip(),
        description=payload.description.strip(),
        allowed_groups_json=[g.strip() for g in payload.allowed_groups if g.strip()],
        allowed_apps_json=[a.model_dump() for a in payload.allowed_apps],
        requires_mfa=payload.requires_mfa,
    )
    db.add(tmpl)
    await db.flush()

    await record_audit_event(
        db,
        event_type="identity.role_template_created",
        actor=actor,
        entity_type="role_template",
        entity_id=tmpl.id,
        action="created",
        details={"code": tmpl.code, "department": tmpl.department},
    )
    await db.commit()
    await db.refresh(tmpl)
    return tmpl


async def _load_template(db: AsyncSession, code: str) -> RoleTemplate:
    tmpl = (
        await db.execute(select(RoleTemplate).where(RoleTemplate.code == code.strip().lower()))
    ).scalar_one_or_none()
    if tmpl is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role template '{code}' not found.",
        )
    return tmpl


async def preview_provisioning_plan(
    db: AsyncSession,
    *,
    llm_router: LLMRouter,
    payload: ProvisioningPreviewIn,
    actor: Actor,
) -> ProvisioningPlan:
    """Compute a dry-run Joiner/Mover/Leaver SCIM diff without mutating directory state."""
    target_email = payload.target_email.strip().lower()
    existing_user = (
        await db.execute(select(DirectoryUser).where(DirectoryUser.email == target_email))
    ).scalar_one_or_none()
    active_entitlements = list(
        (
            await db.execute(
                select(SaaSEntitlement).where(
                    SaaSEntitlement.user_email == target_email,
                    SaaSEntitlement.account_status == "active",
                )
            )
        )
        .scalars()
        .all()
    )

    scim_diff: list[dict[str, Any]] = []
    warnings: list[str] = []
    has_privileged_grant = False
    has_extra_app = False
    has_extra_privileged = False
    has_privileged_revoke = False

    resolved_name = payload.target_name.strip() or (
        existing_user.full_name
        if existing_user is not None
        else target_email.split("@")[0].replace(".", " ").title()
    )
    resolved_dept = payload.department.strip() or (
        existing_user.department if existing_user is not None else "General"
    )
    from_role = payload.from_role_code.strip().lower() if payload.from_role_code else (
        existing_user.role_template_code if existing_user is not None else None
    )
    to_role = payload.to_role_code.strip().lower() if payload.to_role_code else None

    if payload.plan_type == "joiner":
        if not to_role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="to_role_code is required for a joiner provisioning plan.",
            )
        to_tmpl = await _load_template(db, to_role)
        resolved_dept = payload.department.strip() or to_tmpl.department

        scim_diff.append(
            {
                "action": "create_user",
                "resource_type": "User",
                "target": target_email,
                "details": {
                    "full_name": resolved_name,
                    "department": resolved_dept,
                    "role_template": to_tmpl.code,
                },
                "privileged": False,
            }
        )
        if to_tmpl.requires_mfa:
            scim_diff.append(
                {
                    "action": "require_mfa",
                    "resource_type": "Policy",
                    "target": target_email,
                    "details": {"policy": "hardware_or_totp_mfa"},
                    "privileged": False,
                }
            )
        for grp in to_tmpl.allowed_groups_json:
            scim_diff.append(
                {
                    "action": "add_group",
                    "resource_type": "Group",
                    "target": grp,
                    "details": {"member": target_email},
                    "privileged": False,
                }
            )
        template_apps: dict[str, dict[str, Any]] = {}
        for app_cfg in to_tmpl.allowed_apps_json:
            app_name = str(app_cfg.get("app", ""))
            app_role = str(app_cfg.get("role", "member"))
            priv = bool(app_cfg.get("privileged", False))
            template_apps[app_name.lower()] = app_cfg
            if priv:
                has_privileged_grant = True
                warnings.append(
                    f"Template '{to_tmpl.code}' includes privileged role "
                    f"'{app_role}' on '{app_name}'."
                )
            scim_diff.append(
                {
                    "action": "grant_app",
                    "resource_type": "Application",
                    "target": app_name,
                    "details": {"role": app_role, "extra_request": False},
                    "privileged": priv,
                }
            )

        for extra in payload.requested_extra_apps:
            if extra.app.strip().lower() not in template_apps:
                has_extra_app = True
                if extra.privileged:
                    has_extra_privileged = True
                    warnings.append(
                        f"Privileged access outside role template '{to_tmpl.code}': "
                        f"'{extra.app}' ({extra.role}) requires explicit IT Approver justification."
                    )
                else:
                    warnings.append(
                        f"Least-privilege deviation: extra app '{extra.app}' ({extra.role}) "
                        f"is outside template '{to_tmpl.code}'."
                    )
                scim_diff.append(
                    {
                        "action": "grant_app",
                        "resource_type": "Application",
                        "target": extra.app.strip(),
                        "details": {"role": extra.role.strip(), "extra_request": True},
                        "privileged": extra.privileged,
                    }
                )

    elif payload.plan_type == "mover":
        if not to_role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="to_role_code is required for a mover provisioning plan.",
            )
        to_tmpl = await _load_template(db, to_role)
        resolved_dept = payload.department.strip() or to_tmpl.department
        from_tmpl: RoleTemplate | None = None
        if from_role:
            from_tmpl = (
                await db.execute(select(RoleTemplate).where(RoleTemplate.code == from_role))
            ).scalar_one_or_none()

        scim_diff.append(
            {
                "action": "update_user",
                "resource_type": "User",
                "target": target_email,
                "details": {
                    "from_role": from_role,
                    "to_role": to_tmpl.code,
                    "department": resolved_dept,
                },
                "privileged": False,
            }
        )

        old_groups = set(from_tmpl.allowed_groups_json) if from_tmpl is not None else set()
        new_groups = set(to_tmpl.allowed_groups_json)
        for grp in sorted(old_groups - new_groups):
            scim_diff.append(
                {
                    "action": "remove_group",
                    "resource_type": "Group",
                    "target": grp,
                    "details": {"member": target_email},
                    "privileged": False,
                }
            )
        for grp in sorted(new_groups - old_groups):
            scim_diff.append(
                {
                    "action": "add_group",
                    "resource_type": "Group",
                    "target": grp,
                    "details": {"member": target_email},
                    "privileged": False,
                }
            )

        current_apps: dict[str, tuple[str, bool]] = {
            e.app_name.lower(): (e.assigned_role, e.is_privileged) for e in active_entitlements
        }
        if not current_apps and from_tmpl is not None:
            for app_cfg in from_tmpl.allowed_apps_json:
                current_apps[str(app_cfg["app"]).lower()] = (
                    str(app_cfg.get("role", "member")),
                    bool(app_cfg.get("privileged", False)),
                )

        desired_apps: dict[str, dict[str, Any]] = {
            str(a["app"]).lower(): a for a in to_tmpl.allowed_apps_json
        }

        for app_key, (old_role_name, old_priv) in sorted(current_apps.items()):
            display_name = next(
                (e.app_name for e in active_entitlements if e.app_name.lower() == app_key),
                app_key,
            )
            if app_key not in desired_apps:
                if old_priv:
                    has_privileged_revoke = True
                scim_diff.append(
                    {
                        "action": "revoke_app",
                        "resource_type": "Application",
                        "target": display_name,
                        "details": {"previous_role": old_role_name},
                        "privileged": old_priv,
                    }
                )

        for app_key, app_cfg in sorted(desired_apps.items()):
            app_name = str(app_cfg["app"])
            new_role_name = str(app_cfg.get("role", "member"))
            priv = bool(app_cfg.get("privileged", False))
            if app_key not in current_apps or current_apps[app_key][0] != new_role_name:
                if priv:
                    has_privileged_grant = True
                    warnings.append(
                        f"Mover target template '{to_tmpl.code}' grants privileged role "
                        f"'{new_role_name}' on '{app_name}'."
                    )
                scim_diff.append(
                    {
                        "action": "grant_app",
                        "resource_type": "Application",
                        "target": app_name,
                        "details": {"role": new_role_name, "extra_request": False},
                        "privileged": priv,
                    }
                )

        for extra in payload.requested_extra_apps:
            if extra.app.strip().lower() not in desired_apps:
                has_extra_app = True
                if extra.privileged:
                    has_extra_privileged = True
                    warnings.append(
                        f"Privileged access outside role template '{to_tmpl.code}': "
                        f"'{extra.app}' ({extra.role}) requires explicit IT Approver justification."
                    )
                else:
                    warnings.append(
                        f"Least-privilege deviation: extra app '{extra.app}' ({extra.role}) "
                        f"is outside template '{to_tmpl.code}'."
                    )
                scim_diff.append(
                    {
                        "action": "grant_app",
                        "resource_type": "Application",
                        "target": extra.app.strip(),
                        "details": {"role": extra.role.strip(), "extra_request": True},
                        "privileged": extra.privileged,
                    }
                )

    else:  # leaver
        if existing_user is None and not active_entitlements:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No directory user or active entitlements found for '{target_email}'.",
            )
        scim_diff.extend(
            [
                {
                    "action": "suspend_user",
                    "resource_type": "User",
                    "target": target_email,
                    "details": {"employment_status": "terminated"},
                    "privileged": False,
                },
                {
                    "action": "revoke_sessions",
                    "resource_type": "Session",
                    "target": target_email,
                    "details": {"provider": payload.scim_provider},
                    "privileged": False,
                },
                {
                    "action": "revoke_tokens",
                    "resource_type": "OAuthToken",
                    "target": target_email,
                    "details": {"scope": "all_pat_and_oauth"},
                    "privileged": False,
                },
            ]
        )
        for ent in active_entitlements:
            if ent.is_privileged:
                has_privileged_revoke = True
            scim_diff.append(
                {
                    "action": "revoke_app",
                    "resource_type": "Application",
                    "target": ent.app_name,
                    "details": {"previous_role": ent.assigned_role},
                    "privileged": ent.is_privileged,
                }
            )
        if has_privileged_revoke:
            warnings.append(
                "Leaver holds privileged SaaS roles; verify SSH/cloud break-glass keys are rotated."
            )

    if has_extra_privileged or (payload.plan_type == "leaver" and has_privileged_revoke):
        risk_level = "critical"
    elif has_extra_app or has_privileged_grant:
        risk_level = "high"
    elif payload.plan_type in ("mover", "leaver"):
        risk_level = "medium"
    else:
        risk_level = "low"

    prompt = (
        f"Plan Type: {payload.plan_type}\nTarget: {target_email}\n"
        f"Provider: {payload.scim_provider}\nRole: {from_role} -> {to_role}\n"
        f"Operations: {len(scim_diff)}\nWarnings: {'; '.join(warnings) or 'none'}"
    )
    llm_resp = await llm_router.generate(
        prompt=prompt,
        system_prompt=(
            "You are an IAM governance architect evaluating SCIM provisioning plans for "
            "least-privilege compliance."
        ),
        task_type="provisioning_plan",
    )

    plan = ProvisioningPlan(
        plan_type=payload.plan_type,
        target_email=target_email,
        target_name=resolved_name,
        department=resolved_dept,
        from_role_code=from_role,
        to_role_code=to_role,
        scim_provider=payload.scim_provider,
        scim_diff_json=scim_diff,
        least_privilege_warnings_json=warnings,
        risk_level=risk_level,
        llm_rationale=llm_resp.content,
        llm_provider=llm_resp.provider,
        status="pending_approval",
        requested_by=actor.email,
    )
    db.add(plan)
    await db.flush()

    approval = await create_approval_request(
        db,
        entity_type="provisioning_plan",
        entity_id=plan.id,
        action_requested=f"scim_{payload.plan_type}_provisioning",
        summary=(
            f"{payload.plan_type.title()} SCIM plan for {target_email} "
            f"({len(scim_diff)} operations via {payload.scim_provider})"
        ),
        diff_preview=scim_diff,
        risk_level=risk_level,
        requested_by=actor.email,
    )
    plan.approval_id = approval.id

    await record_audit_event(
        db,
        event_type="identity.plan_previewed",
        actor=actor,
        entity_type="provisioning_plan",
        entity_id=plan.id,
        action="previewed",
        details={
            "plan_type": plan.plan_type,
            "target_email": plan.target_email,
            "risk_level": risk_level,
            "operations_count": len(scim_diff),
            "warnings_count": len(warnings),
            "approval_id": approval.id,
        },
    )
    await db.commit()
    await db.refresh(plan)
    return plan


async def export_plan_scim_bulk_payload(
    db: AsyncSession,
    *,
    plan_id: str,
) -> ScimBulkRequestOut:
    """Transform a ProvisioningPlan into an RFC 7644 SCIM 2.0 BulkRequest payload."""
    plan = await db.get(ProvisioningPlan, plan_id)
    if plan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provisioning plan '{plan_id}' not found.",
        )

    operations: list[ScimBulkOperation] = []
    for idx, op in enumerate(plan.scim_diff_json, start=1):
        action = str(op.get("action", ""))
        target = str(op.get("target", ""))
        details = dict(op.get("details") or {})
        privileged = bool(op.get("privileged", False))
        bulk_id = f"op-{idx}"

        if action == "create_user":
            operations.append(
                ScimBulkOperation(
                    method="POST",
                    path="/Users",
                    bulkId=bulk_id,
                    data={
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                        "userName": target,
                        "displayName": details.get("full_name", plan.target_name),
                        "active": True,
                        "title": details.get("role_template", plan.to_role_code),
                        "emails": [{"value": target, "primary": True}],
                    },
                )
            )
        elif action == "update_user":
            operations.append(
                ScimBulkOperation(
                    method="PATCH",
                    path=f"/Users/{target}",
                    bulkId=bulk_id,
                    data={
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                        "Operations": [{"op": "replace", "value": details}],
                    },
                )
            )
        elif action == "suspend_user":
            operations.append(
                ScimBulkOperation(
                    method="PATCH",
                    path=f"/Users/{target}",
                    bulkId=bulk_id,
                    data={
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                        "Operations": [{"op": "replace", "path": "active", "value": False}],
                    },
                )
            )
        elif action in ("add_group", "remove_group"):
            operations.append(
                ScimBulkOperation(
                    method="PATCH",
                    path=f"/Groups/{target}",
                    bulkId=bulk_id,
                    data={
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                        "Operations": [
                            {
                                "op": "add" if action == "add_group" else "remove",
                                "path": "members",
                                "value": [{"value": details.get("member", plan.target_email)}],
                            }
                        ],
                    },
                )
            )
        elif action == "grant_app":
            operations.append(
                ScimBulkOperation(
                    method="POST",
                    path="/Entitlements",
                    bulkId=bulk_id,
                    data={
                        "application": target,
                        "user": plan.target_email,
                        "privileged": privileged,
                        **details,
                    },
                )
            )
        elif action == "revoke_app":
            operations.append(
                ScimBulkOperation(
                    method="DELETE",
                    path=f"/Entitlements/{target}",
                    bulkId=bulk_id,
                    data={"user": plan.target_email, **details},
                )
            )
        else:
            operations.append(
                ScimBulkOperation(
                    method="DELETE" if action.startswith("revoke") else "POST",
                    path="/Policies",
                    bulkId=bulk_id,
                    data={"action": action, "target": target, **details},
                )
            )

    return ScimBulkRequestOut(
        schemas=["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        failOnErrors=1,
        plan_id=plan.id,
        plan_type=plan.plan_type,
        scim_provider=plan.scim_provider,
        Operations=operations,
    )
