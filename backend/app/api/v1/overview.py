from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor, get_current_actor
from app.core.config import Settings, get_settings
from app.db.models import (
    AccessFinding,
    ApprovalRequest,
    AuditEvent,
    DirectoryUser,
    Incident,
    ProvisioningPlan,
    Runbook,
    ServiceCheck,
    TelemetryAlert,
)
from app.db.session import get_db
from app.governance.service import verify_audit_chain
from app.telemetry.service import enrich_service_check

router = APIRouter(prefix="/overview", tags=["overview"])


class OverviewSummaryOut(BaseModel):
    active_users: int
    pending_provisioning_plans: int
    services_total: int
    services_unhealthy: int
    expiring_certs_count: int
    quota_warnings_count: int
    firing_alerts_count: int
    open_incidents_count: int
    open_access_findings: int
    critical_findings_count: int
    stale_tokens_count: int
    orphaned_accounts_count: int
    privilege_drift_count: int
    runbooks_count: int
    pending_approvals_count: int
    audit_events_count: int
    audit_chain_valid: bool
    llm_provider: str


@router.get("", response_model=OverviewSummaryOut)
async def get_overview(
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> OverviewSummaryOut:
    """Aggregate IT administration KPIs across Identity, Telemetry, Access Audits, and Runbooks."""
    active_users = int(
        (
            await db.execute(
                select(func.count(DirectoryUser.id)).where(
                    DirectoryUser.employment_status == "active"
                )
            )
        ).scalar_one()
        or 0
    )
    pending_plans = int(
        (
            await db.execute(
                select(func.count(ProvisioningPlan.id)).where(
                    ProvisioningPlan.status == "pending_approval"
                )
            )
        ).scalar_one()
        or 0
    )

    services = list((await db.execute(select(ServiceCheck))).scalars().all())
    enriched_svcs = [enrich_service_check(s, settings) for s in services]
    services_total = len(enriched_svcs)
    services_unhealthy = sum(1 for s in enriched_svcs if s.status != "healthy")
    expiring_certs = sum(1 for s in enriched_svcs if s.cert_expiring_soon)
    quota_warnings = sum(1 for s in enriched_svcs if s.quota_warning)

    firing_alerts = int(
        (
            await db.execute(
                select(func.count(TelemetryAlert.id)).where(TelemetryAlert.status == "firing")
            )
        ).scalar_one()
        or 0
    )
    open_incidents = int(
        (
            await db.execute(
                select(func.count(Incident.id)).where(Incident.status != "resolved")
            )
        ).scalar_one()
        or 0
    )

    open_findings = list(
        (
            await db.execute(
                select(AccessFinding).where(AccessFinding.status.in_(["open", "pending_approval"]))
            )
        )
        .scalars()
        .all()
    )
    open_access_findings = len(open_findings)
    critical_findings = sum(1 for f in open_findings if f.severity == "critical")
    stale_tokens = sum(1 for f in open_findings if f.finding_type == "stale_token")
    orphaned_accounts = sum(1 for f in open_findings if f.finding_type == "orphaned_account")
    privilege_drift = sum(1 for f in open_findings if f.finding_type == "privilege_drift")

    runbooks_count = int((await db.execute(select(func.count(Runbook.id)))).scalar_one() or 0)
    pending_approvals = int(
        (
            await db.execute(
                select(func.count(ApprovalRequest.id)).where(ApprovalRequest.status == "pending")
            )
        ).scalar_one()
        or 0
    )
    audit_events_count = int(
        (await db.execute(select(func.count(AuditEvent.id)))).scalar_one() or 0
    )
    chain_status = await verify_audit_chain(db)

    return OverviewSummaryOut(
        active_users=active_users,
        pending_provisioning_plans=pending_plans,
        services_total=services_total,
        services_unhealthy=services_unhealthy,
        expiring_certs_count=expiring_certs,
        quota_warnings_count=quota_warnings,
        firing_alerts_count=firing_alerts,
        open_incidents_count=open_incidents,
        open_access_findings=open_access_findings,
        critical_findings_count=critical_findings,
        stale_tokens_count=stale_tokens,
        orphaned_accounts_count=orphaned_accounts,
        privilege_drift_count=privilege_drift,
        runbooks_count=runbooks_count,
        pending_approvals_count=pending_approvals,
        audit_events_count=audit_events_count,
        audit_chain_valid=chain_status.valid,
        llm_provider=settings.llm_default_provider,
    )
