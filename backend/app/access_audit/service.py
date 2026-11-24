from dataclasses import dataclass

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.access_audit.schemas import EntitlementCreateIn
from app.core.auth import Actor
from app.core.config import Settings
from app.db.base import ensure_utc, utcnow
from app.db.models import (
    AccessAuditRun,
    AccessFinding,
    DirectoryUser,
    RoleTemplate,
    SaaSEntitlement,
)
from app.governance.service import create_approval_request, record_audit_event
from app.llm.router import LLMRouter


@dataclass
class _DetectedIssue:
    entitlement: SaaSEntitlement
    finding_type: str
    severity: str
    detail: str
    recommended_action: str


async def create_entitlement(
    db: AsyncSession,
    *,
    payload: EntitlementCreateIn,
    actor: Actor,
) -> SaaSEntitlement:
    """Register or import a SaaS application entitlement record."""
    ent = SaaSEntitlement(
        app_name=payload.app_name.strip(),
        user_email=payload.user_email.strip().lower(),
        account_status=payload.account_status,
        assigned_role=payload.assigned_role.strip(),
        is_privileged=payload.is_privileged,
        mfa_enabled=payload.mfa_enabled,
        token_created_at=ensure_utc(payload.token_created_at),
        token_last_used_at=ensure_utc(payload.token_last_used_at),
        last_login_at=ensure_utc(payload.last_login_at),
        expected_by_role=payload.expected_by_role,
    )
    db.add(ent)
    await db.flush()

    await record_audit_event(
        db,
        event_type="access_audit.entitlement_imported",
        actor=actor,
        entity_type="saas_entitlement",
        entity_id=ent.id,
        action="created",
        details={
            "app_name": ent.app_name,
            "user_email": ent.user_email,
            "assigned_role": ent.assigned_role,
            "is_privileged": ent.is_privileged,
        },
    )
    await db.commit()
    await db.refresh(ent)
    return ent


async def run_access_audit_scan(
    db: AsyncSession,
    *,
    llm_router: LLMRouter,
    settings: Settings,
    scope: str,
    actor: Actor,
) -> AccessAuditRun:
    """Scan all SaaS entitlements for orphaned accounts, stale tokens, drift, and missing MFA."""
    entitlements = list((await db.execute(select(SaaSEntitlement))).scalars().all())
    users_by_email = {
        u.email.lower(): u for u in (await db.execute(select(DirectoryUser))).scalars().all()
    }
    templates_by_code = {
        t.code.lower(): t for t in (await db.execute(select(RoleTemplate))).scalars().all()
    }
    existing_open_rows = (
        await db.execute(
            select(AccessFinding.entitlement_id, AccessFinding.finding_type).where(
                AccessFinding.status.in_(["open", "pending_approval"])
            )
        )
    ).all()
    existing_open_pairs: set[tuple[str, str]] = {
        (str(eid), str(ft)) for eid, ft in existing_open_rows
    }

    now = utcnow()
    detected: list[_DetectedIssue] = []

    for ent in entitlements:
        email = ent.user_email.lower()
        user = users_by_email.get(email)

        if ent.account_status == "suspended":
            continue

        # 1. Orphaned Account Detection
        is_orphaned = (
            ent.account_status == "orphaned"
            or user is None
            or user.employment_status == "terminated"
        )
        if is_orphaned:
            reason = (
                "account marked orphaned"
                if ent.account_status == "orphaned"
                else (
                    "no matching active directory identity"
                    if user is None
                    else "directory user status is terminated"
                )
            )
            detected.append(
                _DetectedIssue(
                    entitlement=ent,
                    finding_type="orphaned_account",
                    severity="critical",
                    detail=(
                        f"Active {ent.app_name} entitlement ({ent.assigned_role}) for {email} "
                        f"is orphaned ({reason})."
                    ),
                    recommended_action=f"Suspend {ent.app_name} account and revoke API tokens.",
                )
            )

        if ent.account_status != "active":
            continue

        # 2. Stale Token / Dormant Credential Detection
        token_ts = ensure_utc(ent.token_last_used_at)
        login_ts = ensure_utc(ent.last_login_at)
        stale_token_age = (now - token_ts).days if token_ts is not None else None
        dormant_login_age = (now - login_ts).days if login_ts is not None else None
        if (stale_token_age is not None and stale_token_age >= settings.stale_token_days) or (
            dormant_login_age is not None and dormant_login_age >= settings.dormant_account_days
        ):
            age_desc = (
                f"API token unused for {stale_token_age}d"
                if stale_token_age is not None and stale_token_age >= settings.stale_token_days
                else f"no login activity for {dormant_login_age}d"
            )
            detected.append(
                _DetectedIssue(
                    entitlement=ent,
                    finding_type="stale_token",
                    severity="high" if ent.is_privileged else "medium",
                    detail=(
                        f"{ent.app_name} credential for {email} ({ent.assigned_role}) "
                        f"has {age_desc}."
                    ),
                    recommended_action=f"Rotate or revoke stale token on {ent.app_name}.",
                )
            )

        # 3. Privilege Drift Detection
        if user is not None and user.employment_status != "terminated":
            drift_reason: str | None = None
            if not ent.expected_by_role:
                drift_reason = "entitlement flagged outside assigned RBAC template"
            elif user.role_template_code:
                tmpl = templates_by_code.get(user.role_template_code.lower())
                if tmpl is not None:
                    allowed_map = {str(a["app"]).lower(): a for a in tmpl.allowed_apps_json}
                    app_cfg = allowed_map.get(ent.app_name.lower())
                    if app_cfg is None:
                        drift_reason = (
                            f"{ent.app_name} is not included in role template "
                            f"'{tmpl.code}'"
                        )
                    else:
                        expected_role = str(app_cfg.get("role", "")).lower()
                        expected_priv = bool(app_cfg.get("privileged", False))
                        if (ent.is_privileged and not expected_priv) or (
                            expected_role and ent.assigned_role.lower() != expected_role
                        ):
                            drift_reason = (
                                f"assigned role '{ent.assigned_role}' differs from "
                                f"template '{tmpl.code}' expected role '{expected_role}'"
                            )
            if drift_reason is not None:
                detected.append(
                    _DetectedIssue(
                        entitlement=ent,
                        finding_type="privilege_drift",
                        severity="critical" if ent.is_privileged else "high",
                        detail=(
                            f"Privilege drift for {email} on {ent.app_name} "
                            f"({ent.assigned_role}): {drift_reason}."
                        ),
                        recommended_action=(
                            f"Downgrade {ent.app_name} role to least-privilege viewer or revoke."
                        ),
                    )
                )

        # 4. Missing MFA Detection
        if not ent.mfa_enabled:
            detected.append(
                _DetectedIssue(
                    entitlement=ent,
                    finding_type="missing_mfa",
                    severity="high" if ent.is_privileged else "medium",
                    detail=f"MFA is disabled on {ent.app_name} account for {email}.",
                    recommended_action=f"Enforce hardware/TOTP MFA policy on {ent.app_name}.",
                )
            )

    critical_cnt = sum(1 for d in detected if d.severity == "critical")
    high_cnt = sum(1 for d in detected if d.severity == "high")
    medium_cnt = sum(1 for d in detected if d.severity == "medium")
    stale_cnt = sum(1 for d in detected if d.finding_type == "stale_token")
    orphaned_cnt = sum(1 for d in detected if d.finding_type == "orphaned_account")
    drift_cnt = sum(1 for d in detected if d.finding_type == "privilege_drift")

    prompt = (
        f"Scope: {scope}\nScanned: {len(entitlements)} entitlements\n"
        f"Findings: {len(detected)} total (critical={critical_cnt}, high={high_cnt}, "
        f"orphaned={orphaned_cnt}, stale_tokens={stale_cnt}, privilege_drift={drift_cnt})"
    )
    llm_resp = await llm_router.generate(
        prompt=prompt,
        system_prompt=(
            "You are an identity security auditor summarizing SaaS entitlement risks "
            "and least-privilege remediation priorities."
        ),
        task_type="access_audit",
    )

    audit_run = AccessAuditRun(
        scope=scope.strip() or "all_saas",
        total_entitlements_scanned=len(entitlements),
        findings_count=len(detected),
        critical_count=critical_cnt,
        high_count=high_cnt,
        medium_count=medium_cnt,
        stale_tokens_count=stale_cnt,
        orphaned_accounts_count=orphaned_cnt,
        privilege_drift_count=drift_cnt,
        llm_summary=llm_resp.content,
        llm_provider=llm_resp.provider,
        run_by=actor.email,
    )
    db.add(audit_run)
    await db.flush()

    created_count = 0
    for issue in detected:
        pair = (issue.entitlement.id, issue.finding_type)
        if pair in existing_open_pairs:
            continue
        existing_open_pairs.add(pair)
        db.add(
            AccessFinding(
                audit_run_id=audit_run.id,
                entitlement_id=issue.entitlement.id,
                finding_type=issue.finding_type,
                severity=issue.severity,
                app_name=issue.entitlement.app_name,
                user_email=issue.entitlement.user_email,
                detail=issue.detail,
                recommended_action=issue.recommended_action,
                status="open",
            )
        )
        created_count += 1

    await record_audit_event(
        db,
        event_type="access_audit.scan_completed",
        actor=actor,
        entity_type="access_audit_run",
        entity_id=audit_run.id,
        action="scanned",
        details={
            "scope": audit_run.scope,
            "total_entitlements": len(entitlements),
            "detected_findings": len(detected),
            "newly_recorded_findings": created_count,
        },
    )
    await db.commit()
    await db.refresh(audit_run)
    return audit_run


async def request_finding_remediation(
    db: AsyncSession,
    *,
    finding_id: str,
    actor: Actor,
) -> AccessFinding:
    """Create a pending HITL approval gate to remediate an open access finding."""
    finding = await db.get(AccessFinding, finding_id)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Access finding '{finding_id}' not found.",
        )
    if finding.status != "open":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Access finding '{finding_id}' is already '{finding.status}'.",
        )

    risk_level = (
        finding.severity if finding.severity in ("critical", "high", "medium", "low") else "medium"
    )
    action_map = {
        "orphaned_account": "suspend_orphaned_account",
        "stale_token": "rotate_stale_token",
        "privilege_drift": "downgrade_excess_privilege",
        "missing_mfa": "enforce_mfa_policy",
    }
    action_name = action_map.get(finding.finding_type, "remediate_access_finding")

    approval = await create_approval_request(
        db,
        entity_type="access_finding",
        entity_id=finding.id,
        action_requested=action_name,
        summary=f"[{finding.app_name}] {finding.recommended_action} ({finding.user_email})",
        diff_preview={
            "finding_type": finding.finding_type,
            "app_name": finding.app_name,
            "user_email": finding.user_email,
            "recommended_action": finding.recommended_action,
            "detail": finding.detail,
        },
        risk_level=risk_level,
        requested_by=actor.email,
    )

    finding.status = "pending_approval"
    finding.approval_id = approval.id

    await record_audit_event(
        db,
        event_type="access_audit.remediation_requested",
        actor=actor,
        entity_type="access_finding",
        entity_id=finding.id,
        action="requested_approval",
        details={
            "finding_type": finding.finding_type,
            "app_name": finding.app_name,
            "user_email": finding.user_email,
            "approval_id": approval.id,
        },
    )
    await db.commit()
    await db.refresh(finding)
    return finding
