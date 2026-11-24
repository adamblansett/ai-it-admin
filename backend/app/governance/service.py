import hashlib
import json
from typing import Any, Literal

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor
from app.db.base import utcnow
from app.db.models import (
    AccessFinding,
    ApprovalRequest,
    AuditEvent,
    DirectoryUser,
    ProvisioningPlan,
    RemediationDraft,
    SaaSEntitlement,
)
from app.governance.schemas import AuditChainVerifyOut


def compute_event_hash(
    *,
    sequence_no: int,
    event_type: str,
    actor_email: str,
    actor_role: str,
    entity_type: str,
    entity_id: str,
    action: str,
    details: dict[str, Any],
    prev_hash: str,
) -> str:
    """Compute a deterministic SHA-256 hash chaining an audit event to prev_hash."""
    canonical = json.dumps(
        {
            "sequence_no": sequence_no,
            "event_type": event_type,
            "actor_email": actor_email,
            "actor_role": actor_role,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "action": action,
            "details": details,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def record_audit_event(
    db: AsyncSession,
    *,
    event_type: str,
    actor: Actor,
    entity_type: str,
    entity_id: str,
    action: str,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Append an immutable SHA-256 hash-chained event to the operational audit log."""
    stmt = select(AuditEvent).order_by(AuditEvent.sequence_no.desc()).limit(1)
    latest = (await db.execute(stmt)).scalar_one_or_none()

    next_seq = (latest.sequence_no + 1) if latest is not None else 1
    prev_hash = latest.event_hash if latest is not None else "GENESIS"
    clean_details = details or {}

    event_hash = compute_event_hash(
        sequence_no=next_seq,
        event_type=event_type,
        actor_email=actor.email,
        actor_role=actor.role,
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        details=clean_details,
        prev_hash=prev_hash,
    )
    event = AuditEvent(
        sequence_no=next_seq,
        event_type=event_type,
        actor_email=actor.email,
        actor_role=actor.role,
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        details_json=clean_details,
        prev_hash=prev_hash,
        event_hash=event_hash,
    )
    db.add(event)
    await db.flush()
    return event


async def verify_audit_chain(db: AsyncSession) -> AuditChainVerifyOut:
    """Recompute every SHA-256 link in audit_events and report integrity status."""
    stmt = select(AuditEvent).order_by(AuditEvent.sequence_no.asc())
    events = list((await db.execute(stmt)).scalars().all())
    if not events:
        return AuditChainVerifyOut(
            valid=True,
            total_events=0,
            head_hash="GENESIS",
            broken_sequence_no=None,
            message="Audit trail is empty (GENESIS state verified).",
        )

    expected_prev = "GENESIS"
    expected_seq = 1
    for ev in events:
        if ev.sequence_no != expected_seq or ev.prev_hash != expected_prev:
            return AuditChainVerifyOut(
                valid=False,
                total_events=len(events),
                head_hash=events[-1].event_hash,
                broken_sequence_no=ev.sequence_no,
                message=(
                    f"Chain linkage mismatch at sequence #{ev.sequence_no}: "
                    f"expected prev_hash={expected_prev[:12]}..."
                ),
            )
        recomputed = compute_event_hash(
            sequence_no=ev.sequence_no,
            event_type=ev.event_type,
            actor_email=ev.actor_email,
            actor_role=ev.actor_role,
            entity_type=ev.entity_type,
            entity_id=ev.entity_id,
            action=ev.action,
            details=ev.details_json,
            prev_hash=ev.prev_hash,
        )
        if ev.event_hash != recomputed:
            return AuditChainVerifyOut(
                valid=False,
                total_events=len(events),
                head_hash=events[-1].event_hash,
                broken_sequence_no=ev.sequence_no,
                message=f"Hash tamper detected at sequence #{ev.sequence_no}.",
            )
        expected_prev = ev.event_hash
        expected_seq += 1

    return AuditChainVerifyOut(
        valid=True,
        total_events=len(events),
        head_hash=events[-1].event_hash,
        broken_sequence_no=None,
        message=f"All {len(events)} audit events verified intact.",
    )


async def create_approval_request(
    db: AsyncSession,
    *,
    entity_type: str,
    entity_id: str,
    action_requested: str,
    summary: str,
    diff_preview: Any,
    risk_level: str,
    requested_by: str,
) -> ApprovalRequest:
    """Create a pending human-in-the-loop approval request."""
    approval = ApprovalRequest(
        entity_type=entity_type,
        entity_id=entity_id,
        action_requested=action_requested,
        summary=summary,
        diff_preview_json=diff_preview,
        risk_level=risk_level,
        status="pending",
        requested_by=requested_by,
    )
    db.add(approval)
    await db.flush()
    return approval


async def _upsert_entitlement(
    db: AsyncSession,
    *,
    user_email: str,
    app_name: str,
    assigned_role: str,
    is_privileged: bool,
    expected_by_role: bool,
) -> None:
    now = utcnow()
    existing = (
        await db.execute(
            select(SaaSEntitlement).where(
                SaaSEntitlement.user_email == user_email,
                SaaSEntitlement.app_name == app_name,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.account_status = "active"
        existing.assigned_role = assigned_role
        existing.is_privileged = is_privileged
        existing.mfa_enabled = True
        existing.expected_by_role = expected_by_role
        existing.last_login_at = now
        existing.token_created_at = existing.token_created_at or now
        existing.token_last_used_at = now
        return

    db.add(
        SaaSEntitlement(
            app_name=app_name,
            user_email=user_email,
            account_status="active",
            assigned_role=assigned_role,
            is_privileged=is_privileged,
            mfa_enabled=True,
            token_created_at=now,
            token_last_used_at=now,
            last_login_at=now,
            expected_by_role=expected_by_role,
        )
    )


async def _apply_provisioning_plan(
    db: AsyncSession,
    plan: ProvisioningPlan,
    decision: Literal["approved", "rejected"],
) -> None:
    if decision == "rejected":
        plan.status = "rejected"
        return

    now = utcnow()
    plan.status = "applied"
    plan.applied_at = now

    user = (
        await db.execute(select(DirectoryUser).where(DirectoryUser.email == plan.target_email))
    ).scalar_one_or_none()

    if plan.plan_type == "joiner":
        if user is None:
            emp_suffix = plan.id.replace("-", "")[:8].upper()
            user = DirectoryUser(
                employee_id=f"EMP-{emp_suffix}",
                email=plan.target_email,
                full_name=plan.target_name,
                department=plan.department,
                title=plan.to_role_code or "Staff Member",
                role_template_code=plan.to_role_code,
                employment_status="active",
                manager_email=plan.requested_by,
                last_login_at=now,
                mfa_enrolled=True,
                created_at=now,
                updated_at=now,
            )
            db.add(user)
        else:
            user.full_name = plan.target_name
            user.department = plan.department
            user.role_template_code = plan.to_role_code
            user.employment_status = "active"
            user.mfa_enrolled = True
            user.updated_at = now

        for op in plan.scim_diff_json:
            if op.get("action") == "grant_app":
                details = op.get("details") or {}
                await _upsert_entitlement(
                    db,
                    user_email=plan.target_email,
                    app_name=str(op.get("target", "")),
                    assigned_role=str(details.get("role", "member")),
                    is_privileged=bool(op.get("privileged", False)),
                    expected_by_role=not bool(details.get("extra_request", False)),
                )

    elif plan.plan_type == "mover":
        if user is not None:
            user.department = plan.department
            user.role_template_code = plan.to_role_code
            user.employment_status = "active"
            user.updated_at = now

        for op in plan.scim_diff_json:
            action = op.get("action")
            target = str(op.get("target", ""))
            details = op.get("details") or {}
            if action == "revoke_app":
                ents = list(
                    (
                        await db.execute(
                            select(SaaSEntitlement).where(
                                SaaSEntitlement.user_email == plan.target_email,
                                SaaSEntitlement.app_name == target,
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                for ent in ents:
                    ent.account_status = "suspended"
            elif action == "grant_app":
                await _upsert_entitlement(
                    db,
                    user_email=plan.target_email,
                    app_name=target,
                    assigned_role=str(details.get("role", "member")),
                    is_privileged=bool(op.get("privileged", False)),
                    expected_by_role=not bool(details.get("extra_request", False)),
                )

    elif plan.plan_type == "leaver":
        if user is not None:
            user.employment_status = "terminated"
            user.updated_at = now

        ents = list(
            (
                await db.execute(
                    select(SaaSEntitlement).where(SaaSEntitlement.user_email == plan.target_email)
                )
            )
            .scalars()
            .all()
        )
        for ent in ents:
            ent.account_status = "suspended"


async def _apply_access_finding_remediation(
    db: AsyncSession,
    finding: AccessFinding,
    decision: Literal["approved", "rejected"],
) -> None:
    if decision == "rejected":
        finding.status = "dismissed"
        return

    finding.status = "remediated"
    entitlement = await db.get(SaaSEntitlement, finding.entitlement_id)
    if entitlement is None:
        return

    now = utcnow()
    if finding.finding_type == "orphaned_account":
        entitlement.account_status = "suspended"
    elif finding.finding_type == "stale_token":
        entitlement.token_created_at = now
        entitlement.token_last_used_at = now
    elif finding.finding_type == "privilege_drift":
        entitlement.assigned_role = "viewer"
        entitlement.is_privileged = False
        entitlement.expected_by_role = True
    elif finding.finding_type == "missing_mfa":
        entitlement.mfa_enabled = True


async def decide_approval(
    db: AsyncSession,
    *,
    approval_id: str,
    decision: Literal["approved", "rejected"],
    notes: str,
    actor: Actor,
) -> ApprovalRequest:
    """Approve or reject a pending HITL gate and apply domain mutations atomically."""
    approval = await db.get(ApprovalRequest, approval_id)
    if approval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval request '{approval_id}' not found.",
        )
    if approval.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Approval request '{approval_id}' is already '{approval.status}'.",
        )

    approval.status = decision
    approval.decided_by = actor.email
    approval.decision_notes = notes.strip() or f"{decision} by {actor.email}"
    approval.decided_at = utcnow()

    extra_details: dict[str, Any] = {}

    if approval.entity_type == "provisioning_plan":
        plan = await db.get(ProvisioningPlan, approval.entity_id)
        if plan is None:
            plan = (
                await db.execute(
                    select(ProvisioningPlan).where(ProvisioningPlan.approval_id == approval.id)
                )
            ).scalar_one_or_none()
        if plan is not None:
            await _apply_provisioning_plan(db, plan, decision)
            extra_details["plan_status"] = plan.status
            extra_details["plan_type"] = plan.plan_type
            extra_details["target_email"] = plan.target_email

    elif approval.entity_type == "access_finding":
        finding = await db.get(AccessFinding, approval.entity_id)
        if finding is None:
            finding = (
                await db.execute(
                    select(AccessFinding).where(AccessFinding.approval_id == approval.id)
                )
            ).scalar_one_or_none()
        if finding is not None:
            await _apply_access_finding_remediation(db, finding, decision)
            extra_details["finding_type"] = finding.finding_type
            extra_details["finding_status"] = finding.status

    elif approval.entity_type == "remediation_draft":
        draft = await db.get(RemediationDraft, approval.entity_id)
        if draft is None:
            draft = (
                await db.execute(
                    select(RemediationDraft).where(RemediationDraft.approval_id == approval.id)
                )
            ).scalar_one_or_none()
        if draft is not None:
            draft.status = decision
            draft.execution_mode = "advisory_only"
            extra_details["execution_mode"] = "advisory_only"
            extra_details["draft_status"] = draft.status

    await record_audit_event(
        db,
        event_type="approval.decided",
        actor=actor,
        entity_type=approval.entity_type,
        entity_id=approval.entity_id,
        action=decision,
        details={
            "approval_id": approval.id,
            "decision": decision,
            "notes": approval.decision_notes,
            "risk_level": approval.risk_level,
            **extra_details,
        },
    )
    await db.commit()
    await db.refresh(approval)
    return approval
