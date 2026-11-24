from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ServiceCheckIn(BaseModel):
    service_name: str = Field(min_length=2, max_length=128)
    environment: str = Field(default="production", max_length=64)
    endpoint_url: str = Field(min_length=4, max_length=512)
    status: Literal["healthy", "degraded", "outage"] = "healthy"
    latency_ms: float = Field(default=45.0, ge=0.0)
    error_rate_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    cpu_pct: float = Field(default=25.0, ge=0.0, le=100.0)
    memory_pct: float = Field(default=40.0, ge=0.0, le=100.0)
    quota_used_pct: float = Field(default=35.0, ge=0.0, le=100.0)
    cert_expires_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ServiceCheckOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    service_name: str
    environment: str
    endpoint_url: str
    status: str
    latency_ms: float
    error_rate_pct: float
    cpu_pct: float
    memory_pct: float
    quota_used_pct: float
    cert_expires_at: datetime | None = None
    last_checked_at: datetime
    metadata_json: dict[str, Any]
    cert_days_remaining: int | None = None
    cert_expiring_soon: bool = False
    quota_warning: bool = False
    needs_attention: bool = False


class AlertIngestIn(BaseModel):
    service_name: str = Field(min_length=2, max_length=128)
    alert_name: str = Field(min_length=2, max_length=128)
    source: Literal["prometheus", "healthcheck", "cert_monitor", "quota_monitor"] = "prometheus"
    severity: Literal["sev1", "sev2", "sev3", "sev4"] = "sev2"
    metric_value: float = 0.0
    threshold_value: float = 0.0
    summary: str = Field(min_length=3, max_length=2000)


class TelemetryAlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    fingerprint: str
    service_name: str
    alert_name: str
    source: str
    severity: str
    metric_value: float
    threshold_value: float
    summary: str
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    status: str
    incident_id: str | None = None


class AlertIngestOut(BaseModel):
    alert: TelemetryAlertOut
    deduplicated: bool


class IncidentTriageIn(BaseModel):
    service_name: str | None = None
    alert_ids: list[str] = Field(default_factory=list)
    title: str | None = None


class IncidentStatusUpdateIn(BaseModel):
    status: Literal["open", "triaged", "mitigating", "resolved"]
    assigned_to: str | None = None


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_key: str
    title: str
    service_name: str
    severity: str
    status: str
    alert_count: int
    deduplicated_fingerprints_json: list[str]
    root_cause_hypothesis: str
    cited_runbook_ids_json: list[str]
    recommended_steps_json: list[str]
    llm_provider: str
    pii_redacted: bool
    assigned_to: str | None = None
    created_by: str
    created_at: datetime
    updated_at: datetime
