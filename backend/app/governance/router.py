from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor, get_current_actor, require_roles
from app.db.models import ApprovalRequest, AuditEvent
from app.db.session import get_db
from app.governance.schemas import (
    ApprovalDecisionIn,
    ApprovalRequestOut,
    AuditChainVerifyOut,
    AuditEventOut,
    PiiRedactIn,
    PiiRedactOut,
)
from app.governance.service import decide_approval, verify_audit_chain
from app.llm.pii import redact_pii

router = APIRouter(prefix="/governance", tags=["governance"])


@router.get("/approvals", response_model=list[ApprovalRequestOut])
async def list_approvals(
    status_filter: str | None = Query(default=None, alias="status"),
    entity_type: str | None = Query(default=None),
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> list[ApprovalRequestOut]:
    """List human-in-the-loop approval requests ordered by newest first."""
    stmt = select(ApprovalRequest).order_by(ApprovalRequest.created_at.desc())
    if status_filter:
        stmt = stmt.where(ApprovalRequest.status == status_filter)
    if entity_type:
        stmt = stmt.where(ApprovalRequest.entity_type == entity_type)
    rows = list((await db.execute(stmt)).scalars().all())
    return [ApprovalRequestOut.model_validate(row) for row in rows]


@router.post("/approvals/{approval_id}/decide", response_model=ApprovalRequestOut)
async def post_approval_decision(
    approval_id: str,
    payload: ApprovalDecisionIn,
    actor: Actor = Depends(require_roles("it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
) -> ApprovalRequestOut:
    """Approve or reject a pending HITL gate (restricted to it_approver/admin)."""
    approval = await decide_approval(
        db,
        approval_id=approval_id,
        decision=payload.decision,
        notes=payload.notes,
        actor=actor,
    )
    return ApprovalRequestOut.model_validate(approval)


@router.get("/audit/events", response_model=list[AuditEventOut])
async def list_audit_events(
    entity_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> list[AuditEventOut]:
    """Return tamper-evident operational audit trail events in reverse sequence order."""
    stmt = select(AuditEvent).order_by(AuditEvent.sequence_no.desc()).limit(limit)
    if entity_type:
        stmt = stmt.where(AuditEvent.entity_type == entity_type)
    rows = list((await db.execute(stmt)).scalars().all())
    return [AuditEventOut.model_validate(row) for row in rows]


@router.get("/audit/events/verify", response_model=AuditChainVerifyOut)
async def get_audit_chain_verification(
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> AuditChainVerifyOut:
    """Verify the cryptographic SHA-256 hash chain across all audit events."""
    return await verify_audit_chain(db)


@router.post("/pii/redact", response_model=PiiRedactOut)
async def test_pii_redaction(
    payload: PiiRedactIn,
    _: Actor = Depends(get_current_actor),
) -> PiiRedactOut:
    """Preview outbound cloud PII and credential scrubbing on arbitrary text."""
    result = redact_pii(payload.text)
    return PiiRedactOut(
        redacted_text=result.redacted_text,
        findings=result.findings,
        total_redactions=result.total_redactions,
    )
