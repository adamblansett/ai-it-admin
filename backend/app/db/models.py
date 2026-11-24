from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, new_uuid, utcnow


class ApprovalRequest(Base):
    """Human-in-the-loop approval record gating high-impact IT operations."""

    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    action_requested: Mapped[str] = mapped_column(String(128), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    diff_preview_json: Mapped[Any] = mapped_column(JSON, nullable=False, default=list)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    decided_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DirectoryUser(Base):
    """Corporate identity directory user record."""

    __tablename__ = "directory_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    employee_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    department: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    role_template_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    employment_status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    manager_email: Mapped[str] = mapped_column(String(255), nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_enrolled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class RoleTemplate(Base):
    """Least-privilege RBAC/SCIM role template."""

    __tablename__ = "role_templates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    code: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    department: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_groups_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_apps_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    requires_mfa: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ProvisioningPlan(Base):
    """Joiner/mover/leaver SCIM change plan awaiting or reflecting HITL approval."""

    __tablename__ = "provisioning_plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    plan_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_name: Mapped[str] = mapped_column(String(255), nullable=False)
    department: Mapped[str] = mapped_column(String(128), nullable=False)
    from_role_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    to_role_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scim_provider: Mapped[str] = mapped_column(String(64), nullable=False, default="okta")
    scim_diff_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    least_privilege_warnings_json: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False, default="low")
    llm_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    llm_provider: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="pending_approval", index=True
    )
    approval_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("approval_requests.id"), nullable=True
    )
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ServiceCheck(Base):
    """Monitored infrastructure service telemetry snapshot."""

    __tablename__ = "service_checks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    service_name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    environment: Mapped[str] = mapped_column(String(64), nullable=False, default="production")
    endpoint_url: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="healthy")
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    error_rate_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cpu_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    memory_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    quota_used_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cert_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class Incident(Base):
    """Triaged incident correlated from deduplicated alerts and runbooks."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    incident_key: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    service_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="triaged", index=True)
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    deduplicated_fingerprints_json: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )
    root_cause_hypothesis: Mapped[str] = mapped_column(Text, nullable=False)
    cited_runbook_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    recommended_steps_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    llm_provider: Mapped[str] = mapped_column(String(64), nullable=False)
    pii_redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class TelemetryAlert(Base):
    """Deduplicated infrastructure or service alert."""

    __tablename__ = "telemetry_alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    service_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    alert_name: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    metric_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    threshold_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="firing", index=True)
    incident_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("incidents.id"), nullable=True
    )


class SaaSEntitlement(Base):
    """SaaS application account and token entitlement record."""

    __tablename__ = "saas_entitlements"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    app_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    user_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    account_status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    assigned_role: Mapped[str] = mapped_column(String(64), nullable=False)
    is_privileged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    token_created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    token_last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expected_by_role: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class AccessAuditRun(Base):
    """Recorded execution summary of an entitlement & access-drift scan."""

    __tablename__ = "access_audit_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scope: Mapped[str] = mapped_column(String(128), nullable=False, default="all_saas")
    total_entitlements_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stale_tokens_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    orphaned_accounts_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    privilege_drift_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    llm_summary: Mapped[str] = mapped_column(Text, nullable=False)
    llm_provider: Mapped[str] = mapped_column(String(64), nullable=False)
    run_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class AccessFinding(Base):
    """Detected stale token, orphaned account, privilege drift, or missing MFA issue."""

    __tablename__ = "access_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    audit_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("access_audit_runs.id"), nullable=False, index=True
    )
    entitlement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("saas_entitlements.id"), nullable=False, index=True
    )
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    app_name: Mapped[str] = mapped_column(String(128), nullable=False)
    user_email: Mapped[str] = mapped_column(String(255), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)
    approval_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("approval_requests.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class Runbook(Base):
    """Operational runbook indexed with deterministic semantic embeddings."""

    __tablename__ = "runbooks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    slug: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    service_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity_scope: Mapped[str] = mapped_column(String(64), nullable=False, default="sev1,sev2")
    content_markdown: Mapped[str] = mapped_column(Text, nullable=False)
    safe_commands_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    tags_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    embedding_json: Mapped[list[float]] = mapped_column(JSON, nullable=False, default=list)
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class RemediationDraft(Base):
    """Advisory-only incident remediation plan grounded in cited runbooks."""

    __tablename__ = "remediation_drafts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    incident_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("incidents.id"), nullable=True
    )
    query_text: Mapped[str] = mapped_column(Text, nullable=False)
    diagnosis_summary: Mapped[str] = mapped_column(Text, nullable=False)
    cited_runbooks_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    proposed_steps_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    blocked_shell_patterns_json: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )
    execution_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, default="advisory_only"
    )
    llm_provider: Mapped[str] = mapped_column(String(64), nullable=False)
    pii_redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft", index=True)
    approval_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("approval_requests.id"), nullable=True
    )
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class AuditEvent(Base):
    """Tamper-evident SHA-256 hash-chained operational audit event."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    sequence_no: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_email: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
