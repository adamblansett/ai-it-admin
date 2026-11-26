from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor, get_current_actor, require_roles, resolve_settings
from app.core.config import Settings, get_settings
from app.db.models import Incident, ServiceCheck, TelemetryAlert
from app.db.session import get_db
from app.llm.router import LLMRouter, get_llm_router
from app.telemetry.schemas import (
    AlertIngestIn,
    AlertIngestOut,
    AlertmanagerWebhookIn,
    AlertmanagerWebhookOut,
    IncidentOut,
    IncidentStatusUpdateIn,
    IncidentTriageIn,
    ServiceCheckIn,
    ServiceCheckOut,
    TelemetryAlertOut,
)
from app.telemetry.service import (
    enrich_service_check,
    ingest_alert,
    ingest_service_check,
    process_alertmanager_webhook,
    triage_incident,
    update_incident_status,
    verify_alertmanager_signature,
)

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


@router.get("/services", response_model=list[ServiceCheckOut])
async def list_services(
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> list[ServiceCheckOut]:
    """List monitored infrastructure services with cert-expiry and quota indicators."""
    rows = list(
        (await db.execute(select(ServiceCheck).order_by(ServiceCheck.service_name.asc())))
        .scalars()
        .all()
    )
    return [enrich_service_check(row, settings) for row in rows]


@router.post("/services/ingest", response_model=ServiceCheckOut)
async def post_ingest_service_check(
    payload: ServiceCheckIn,
    actor: Actor = Depends(require_roles("operator", "it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ServiceCheckOut:
    """Ingest a service telemetry snapshot and auto-generate deduplicated alerts."""
    return await ingest_service_check(db, payload=payload, settings=settings, actor=actor)


@router.get("/alerts", response_model=list[TelemetryAlertOut])
async def list_alerts(
    status_filter: str | None = Query(default=None, alias="status"),
    service_name: str | None = Query(default=None),
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> list[TelemetryAlertOut]:
    """List deduplicated infrastructure alerts ordered by most recently seen."""
    stmt = select(TelemetryAlert).order_by(TelemetryAlert.last_seen_at.desc())
    if status_filter:
        stmt = stmt.where(TelemetryAlert.status == status_filter)
    if service_name:
        stmt = stmt.where(TelemetryAlert.service_name == service_name)
    rows = list((await db.execute(stmt)).scalars().all())
    return [TelemetryAlertOut.model_validate(row) for row in rows]


@router.post("/alerts/ingest", response_model=AlertIngestOut)
async def post_ingest_alert(
    payload: AlertIngestIn,
    actor: Actor = Depends(require_roles("operator", "it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
) -> AlertIngestOut:
    """Ingest an alert and deduplicate matching active alert fingerprints."""
    alert, deduplicated = await ingest_alert(db, payload=payload, actor=actor)
    return AlertIngestOut(alert=TelemetryAlertOut.model_validate(alert), deduplicated=deduplicated)


@router.get("/incidents", response_model=list[IncidentOut])
async def list_incidents(
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> list[IncidentOut]:
    """List triaged incidents ordered by newest first."""
    rows = list(
        (await db.execute(select(Incident).order_by(Incident.created_at.desc())))
        .scalars()
        .all()
    )
    return [IncidentOut.model_validate(row) for row in rows]


@router.post("/incidents/triage", response_model=IncidentOut)
async def post_triage_incident(
    payload: IncidentTriageIn,
    actor: Actor = Depends(require_roles("operator", "it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    settings: Settings = Depends(get_settings),
) -> IncidentOut:
    """Correlate firing alerts into a classified Incident with cited runbooks."""
    incident = await triage_incident(
        db,
        llm_router=llm_router,
        settings=settings,
        payload=payload,
        actor=actor,
    )
    return IncidentOut.model_validate(incident)


@router.patch("/incidents/{incident_id}/status", response_model=IncidentOut)
async def patch_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdateIn,
    actor: Actor = Depends(require_roles("operator", "it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    """Update incident lifecycle status (resolving linked alerts on resolve)."""
    incident = await update_incident_status(
        db,
        incident_id=incident_id,
        payload=payload,
        actor=actor,
    )
    return IncidentOut.model_validate(incident)


@router.post("/webhooks/alertmanager", response_model=AlertmanagerWebhookOut)
async def post_alertmanager_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AlertmanagerWebhookOut:
    """Receive HMAC-signed Prometheus Alertmanager webhook events."""
    settings = resolve_settings(request)
    raw_body = await request.body()
    sig_header = request.headers.get("x-webhook-signature", "")
    verify_alertmanager_signature(raw_body, sig_header, settings)
    try:
        payload = AlertmanagerWebhookIn.model_validate_json(raw_body)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid Alertmanager webhook payload: {exc}",
        ) from exc
    return await process_alertmanager_webhook(db, payload=payload)
