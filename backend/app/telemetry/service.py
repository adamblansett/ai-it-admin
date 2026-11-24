import hashlib

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor
from app.core.config import Settings
from app.db.base import ensure_utc, utcnow
from app.db.models import Incident, ServiceCheck, TelemetryAlert
from app.governance.service import record_audit_event
from app.llm.router import LLMRouter
from app.runbooks.service import hybrid_search_runbooks
from app.telemetry.schemas import (
    AlertIngestIn,
    IncidentStatusUpdateIn,
    IncidentTriageIn,
    ServiceCheckIn,
    ServiceCheckOut,
)

_SEVERITY_RANK: dict[str, int] = {"sev1": 1, "sev2": 2, "sev3": 3, "sev4": 4}


def compute_alert_fingerprint(service_name: str, alert_name: str, source: str) -> str:
    """Compute a deterministic fingerprint for alert deduplication."""
    raw = f"{service_name.strip().lower()}|{alert_name.strip().lower()}|{source.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def enrich_service_check(svc: ServiceCheck, settings: Settings) -> ServiceCheckOut:
    """Attach computed cert-expiry and quota-warning indicators to a ServiceCheck."""
    now = utcnow()
    cert_utc = ensure_utc(svc.cert_expires_at)
    cert_days: int | None = None
    if cert_utc is not None:
        cert_days = int((cert_utc - now).total_seconds() // 86400)
    cert_expiring_soon = cert_days is not None and cert_days <= settings.cert_expiry_warning_days
    quota_warning = svc.quota_used_pct >= settings.quota_warning_pct
    needs_attention = svc.status != "healthy" or cert_expiring_soon or quota_warning

    out = ServiceCheckOut.model_validate(svc)
    out.cert_days_remaining = cert_days
    out.cert_expiring_soon = cert_expiring_soon
    out.quota_warning = quota_warning
    out.needs_attention = needs_attention
    return out


async def _upsert_alert_record(
    db: AsyncSession,
    *,
    service_name: str,
    alert_name: str,
    source: str,
    severity: str,
    metric_value: float,
    threshold_value: float,
    summary: str,
) -> tuple[TelemetryAlert, bool]:
    fingerprint = compute_alert_fingerprint(service_name, alert_name, source)
    now = utcnow()
    existing = (
        await db.execute(
            select(TelemetryAlert).where(
                TelemetryAlert.fingerprint == fingerprint,
                TelemetryAlert.status.in_(["firing", "acknowledged"]),
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.occurrence_count += 1
        existing.last_seen_at = now
        existing.metric_value = metric_value
        existing.threshold_value = threshold_value
        existing.summary = summary
        if _SEVERITY_RANK.get(severity, 4) < _SEVERITY_RANK.get(existing.severity, 4):
            existing.severity = severity
        await db.flush()
        return existing, True

    alert = TelemetryAlert(
        fingerprint=fingerprint,
        service_name=service_name.strip(),
        alert_name=alert_name.strip(),
        source=source.strip(),
        severity=severity,
        metric_value=metric_value,
        threshold_value=threshold_value,
        summary=summary.strip(),
        occurrence_count=1,
        first_seen_at=now,
        last_seen_at=now,
        status="firing",
    )
    db.add(alert)
    await db.flush()
    return alert, False


async def ingest_alert(
    db: AsyncSession,
    *,
    payload: AlertIngestIn,
    actor: Actor,
) -> tuple[TelemetryAlert, bool]:
    """Ingest and fingerprint-deduplicate a telemetry alert."""
    alert, deduplicated = await _upsert_alert_record(
        db,
        service_name=payload.service_name,
        alert_name=payload.alert_name,
        source=payload.source,
        severity=payload.severity,
        metric_value=payload.metric_value,
        threshold_value=payload.threshold_value,
        summary=payload.summary,
    )
    await record_audit_event(
        db,
        event_type="telemetry.alert_ingested",
        actor=actor,
        entity_type="telemetry_alert",
        entity_id=alert.id,
        action="deduplicated" if deduplicated else "created",
        details={
            "fingerprint": alert.fingerprint,
            "service_name": alert.service_name,
            "occurrence_count": alert.occurrence_count,
            "severity": alert.severity,
        },
    )
    await db.commit()
    await db.refresh(alert)
    return alert, deduplicated


async def ingest_service_check(
    db: AsyncSession,
    *,
    payload: ServiceCheckIn,
    settings: Settings,
    actor: Actor,
) -> ServiceCheckOut:
    """Upsert a service telemetry check and emit deduplicated cert/quota/health alerts."""
    clean_name = payload.service_name.strip()
    now = utcnow()
    svc = (
        await db.execute(select(ServiceCheck).where(ServiceCheck.service_name == clean_name))
    ).scalar_one_or_none()

    if svc is None:
        svc = ServiceCheck(
            service_name=clean_name,
            environment=payload.environment.strip(),
            endpoint_url=payload.endpoint_url.strip(),
            status=payload.status,
            latency_ms=payload.latency_ms,
            error_rate_pct=payload.error_rate_pct,
            cpu_pct=payload.cpu_pct,
            memory_pct=payload.memory_pct,
            quota_used_pct=payload.quota_used_pct,
            cert_expires_at=ensure_utc(payload.cert_expires_at),
            last_checked_at=now,
            metadata_json=payload.metadata,
        )
        db.add(svc)
    else:
        svc.environment = payload.environment.strip()
        svc.endpoint_url = payload.endpoint_url.strip()
        svc.status = payload.status
        svc.latency_ms = payload.latency_ms
        svc.error_rate_pct = payload.error_rate_pct
        svc.cpu_pct = payload.cpu_pct
        svc.memory_pct = payload.memory_pct
        svc.quota_used_pct = payload.quota_used_pct
        svc.cert_expires_at = ensure_utc(payload.cert_expires_at)
        svc.last_checked_at = now
        svc.metadata_json = payload.metadata

    await db.flush()
    enriched = enrich_service_check(svc, settings)

    triggered_alerts: list[str] = []
    if svc.status in ("degraded", "outage"):
        a, _ = await _upsert_alert_record(
            db,
            service_name=svc.service_name,
            alert_name=f"service_{svc.status}",
            source="healthcheck",
            severity="sev1" if svc.status == "outage" else "sev2",
            metric_value=svc.error_rate_pct,
            threshold_value=5.0,
            summary=(
                f"Service '{svc.service_name}' reported status='{svc.status}' "
                f"(error rate {svc.error_rate_pct:.1f}%, p99 latency {svc.latency_ms:.0f}ms)."
            ),
        )
        triggered_alerts.append(a.alert_name)

    if enriched.cert_expiring_soon and enriched.cert_days_remaining is not None:
        cert_sev = "sev1" if enriched.cert_days_remaining <= 7 else "sev2"
        a, _ = await _upsert_alert_record(
            db,
            service_name=svc.service_name,
            alert_name="tls_cert_expiring",
            source="cert_monitor",
            severity=cert_sev,
            metric_value=float(enriched.cert_days_remaining),
            threshold_value=float(settings.cert_expiry_warning_days),
            summary=(
                f"TLS certificate for '{svc.service_name}' expires in "
                f"{enriched.cert_days_remaining} day(s)."
            ),
        )
        triggered_alerts.append(a.alert_name)

    if enriched.quota_warning:
        quota_sev = "sev1" if svc.quota_used_pct >= 95.0 else "sev2"
        a, _ = await _upsert_alert_record(
            db,
            service_name=svc.service_name,
            alert_name="resource_quota_high",
            source="quota_monitor",
            severity=quota_sev,
            metric_value=svc.quota_used_pct,
            threshold_value=settings.quota_warning_pct,
            summary=(
                f"Resource quota utilization on '{svc.service_name}' reached "
                f"{svc.quota_used_pct:.1f}% (threshold {settings.quota_warning_pct:.0f}%)."
            ),
        )
        triggered_alerts.append(a.alert_name)

    if svc.error_rate_pct >= 5.0 and svc.status == "healthy":
        a, _ = await _upsert_alert_record(
            db,
            service_name=svc.service_name,
            alert_name="high_http_error_rate",
            source="healthcheck",
            severity="sev2",
            metric_value=svc.error_rate_pct,
            threshold_value=5.0,
            summary=f"HTTP error rate elevated at {svc.error_rate_pct:.1f}% on {svc.service_name}.",
        )
        triggered_alerts.append(a.alert_name)

    if svc.latency_ms >= 1500.0:
        a, _ = await _upsert_alert_record(
            db,
            service_name=svc.service_name,
            alert_name="high_latency_p99",
            source="healthcheck",
            severity="sev3",
            metric_value=svc.latency_ms,
            threshold_value=1500.0,
            summary=f"Latency degraded to {svc.latency_ms:.0f}ms on {svc.service_name}.",
        )
        triggered_alerts.append(a.alert_name)

    await record_audit_event(
        db,
        event_type="telemetry.service_ingested",
        actor=actor,
        entity_type="service_check",
        entity_id=svc.id,
        action="ingested",
        details={
            "service_name": svc.service_name,
            "status": svc.status,
            "triggered_alerts": triggered_alerts,
        },
    )
    await db.commit()
    await db.refresh(svc)
    return enrich_service_check(svc, settings)


async def _next_incident_key(db: AsyncSession) -> str:
    keys = list((await db.execute(select(Incident.incident_key))).scalars().all())
    highest = 1000
    for key in keys:
        if key.startswith("INC-") and key[4:].isdigit():
            highest = max(highest, int(key[4:]))
    return f"INC-{highest + 1}"


async def triage_incident(
    db: AsyncSession,
    *,
    llm_router: LLMRouter,
    settings: Settings,
    payload: IncidentTriageIn,
    actor: Actor,
) -> Incident:
    """Correlate firing alerts into a classified Incident with cited runbook hypotheses."""
    stmt = select(TelemetryAlert).where(TelemetryAlert.status != "resolved")
    if payload.alert_ids:
        stmt = stmt.where(TelemetryAlert.id.in_(payload.alert_ids))
    else:
        stmt = stmt.where(TelemetryAlert.incident_id.is_(None))
        if payload.service_name:
            stmt = stmt.where(TelemetryAlert.service_name == payload.service_name.strip())

    alerts = list((await db.execute(stmt)).scalars().all())
    if not alerts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No untriaged firing alerts available to triage.",
        )

    primary_service = (
        payload.service_name.strip() if payload.service_name else alerts[0].service_name
    )
    svc = (
        await db.execute(select(ServiceCheck).where(ServiceCheck.service_name == primary_service))
    ).scalar_one_or_none()

    best_rank = min(_SEVERITY_RANK.get(a.severity, 4) for a in alerts)
    total_occurrences = sum(a.occurrence_count for a in alerts)
    if (svc is not None and svc.status == "outage") or (best_rank == 2 and total_occurrences >= 10):
        best_rank = 1
    elif svc is not None and svc.status == "degraded" and best_rank > 2:
        best_rank = 2

    severity = next((k for k, v in _SEVERITY_RANK.items() if v == best_rank), "sev2")

    alert_context = " | ".join(f"{a.alert_name}: {a.summary}" for a in alerts)
    runbook_hits = await hybrid_search_runbooks(
        db,
        query=f"{primary_service} {alert_context}",
        service_name=primary_service,
        top_k=3,
        dimensions=settings.embedding_dimensions,
    )

    cited_ids = [h.runbook_id for h in runbook_hits]
    cited_titles = ", ".join(f"{h.slug} ({h.title})" for h in runbook_hits) or "none"

    recommended_steps: list[str] = []
    for hit in runbook_hits[:2]:
        for cmd in hit.safe_commands:
            recommended_steps.append(f"[{hit.slug}] {cmd.get('label')}: {cmd.get('command')}")
    if not recommended_steps:
        recommended_steps = [
            f"Inspect /api/v1/health/ready and error logs for {primary_service}",
            "Verify recent deployments, TLS certificate validity, and resource quotas",
        ]

    prompt = (
        f"Service: {primary_service}\nSeverity: {severity}\n"
        f"Alerts ({len(alerts)}, total occurrences {total_occurrences}): {alert_context}\n"
        f"Cited Runbooks: {cited_titles}"
    )
    llm_resp = await llm_router.generate(
        prompt=prompt,
        system_prompt=(
            "You are an SRE incident commander. Synthesize a concise root-cause hypothesis "
            "grounded in telemetry alerts and cited runbooks."
        ),
        task_type="incident_triage",
    )

    incident_key = await _next_incident_key(db)
    title = (
        payload.title.strip()
        if payload.title and payload.title.strip()
        else f"{primary_service}: {alerts[0].alert_name.replace('_', ' ').title()}"
    )
    fingerprints = sorted({a.fingerprint for a in alerts})
    now = utcnow()

    incident = Incident(
        incident_key=incident_key,
        title=title,
        service_name=primary_service,
        severity=severity,
        status="triaged",
        alert_count=len(alerts),
        deduplicated_fingerprints_json=fingerprints,
        root_cause_hypothesis=llm_resp.content,
        cited_runbook_ids_json=cited_ids,
        recommended_steps_json=recommended_steps,
        llm_provider=llm_resp.provider,
        pii_redacted=llm_resp.pii_redacted,
        created_by=actor.email,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    await db.flush()

    for alert in alerts:
        alert.incident_id = incident.id
        if alert.status == "firing":
            alert.status = "acknowledged"

    await record_audit_event(
        db,
        event_type="telemetry.incident_triaged",
        actor=actor,
        entity_type="incident",
        entity_id=incident.id,
        action="triaged",
        details={
            "incident_key": incident.incident_key,
            "service_name": primary_service,
            "severity": severity,
            "alert_count": len(alerts),
            "cited_runbook_count": len(cited_ids),
        },
    )
    await db.commit()
    await db.refresh(incident)
    return incident


async def update_incident_status(
    db: AsyncSession,
    *,
    incident_id: str,
    payload: IncidentStatusUpdateIn,
    actor: Actor,
) -> Incident:
    """Update incident lifecycle status and resolve linked alerts when resolved."""
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )

    incident.status = payload.status
    if payload.assigned_to is not None:
        incident.assigned_to = payload.assigned_to.strip() or None
    incident.updated_at = utcnow()

    if payload.status == "resolved":
        linked_alerts = list(
            (
                await db.execute(
                    select(TelemetryAlert).where(TelemetryAlert.incident_id == incident.id)
                )
            )
            .scalars()
            .all()
        )
        for alert in linked_alerts:
            alert.status = "resolved"

    await record_audit_event(
        db,
        event_type="telemetry.incident_updated",
        actor=actor,
        entity_type="incident",
        entity_id=incident.id,
        action=payload.status,
        details={
            "incident_key": incident.incident_key,
            "status": payload.status,
            "assigned_to": incident.assigned_to,
        },
    )
    await db.commit()
    await db.refresh(incident)
    return incident
