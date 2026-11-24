"""Initial AI IT Administrator schema.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-24

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "approval_requests",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=36), nullable=False),
        sa.Column("action_requested", sa.String(length=128), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("diff_preview_json", sa.JSON(), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("decided_by", sa.String(length=255), nullable=True),
        sa.Column("decision_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_approval_requests_entity_type", "approval_requests", ["entity_type"])
    op.create_index("ix_approval_requests_entity_id", "approval_requests", ["entity_id"])
    op.create_index("ix_approval_requests_status", "approval_requests", ["status"])

    op.create_table(
        "directory_users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("employee_id", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=False),
        sa.Column("department", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=128), nullable=False),
        sa.Column("role_template_code", sa.String(length=64), nullable=True),
        sa.Column("employment_status", sa.String(length=32), nullable=False),
        sa.Column("manager_email", sa.String(length=255), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("mfa_enrolled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("employee_id"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_directory_users_email", "directory_users", ["email"])

    op.create_table(
        "role_templates",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("department", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("allowed_groups_json", sa.JSON(), nullable=False),
        sa.Column("allowed_apps_json", sa.JSON(), nullable=False),
        sa.Column("requires_mfa", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code"),
    )
    op.create_index("ix_role_templates_code", "role_templates", ["code"])

    op.create_table(
        "provisioning_plans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("plan_type", sa.String(length=32), nullable=False),
        sa.Column("target_email", sa.String(length=255), nullable=False),
        sa.Column("target_name", sa.String(length=255), nullable=False),
        sa.Column("department", sa.String(length=128), nullable=False),
        sa.Column("from_role_code", sa.String(length=64), nullable=True),
        sa.Column("to_role_code", sa.String(length=64), nullable=True),
        sa.Column("scim_provider", sa.String(length=64), nullable=False),
        sa.Column("scim_diff_json", sa.JSON(), nullable=False),
        sa.Column("least_privilege_warnings_json", sa.JSON(), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=False),
        sa.Column("llm_rationale", sa.Text(), nullable=False),
        sa.Column("llm_provider", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("approval_id", sa.String(length=36), nullable=True),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["approval_id"], ["approval_requests.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_provisioning_plans_target_email", "provisioning_plans", ["target_email"])
    op.create_index("ix_provisioning_plans_status", "provisioning_plans", ["status"])

    op.create_table(
        "service_checks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("service_name", sa.String(length=128), nullable=False),
        sa.Column("environment", sa.String(length=64), nullable=False),
        sa.Column("endpoint_url", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=False),
        sa.Column("error_rate_pct", sa.Float(), nullable=False),
        sa.Column("cpu_pct", sa.Float(), nullable=False),
        sa.Column("memory_pct", sa.Float(), nullable=False),
        sa.Column("quota_used_pct", sa.Float(), nullable=False),
        sa.Column("cert_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("service_name"),
    )
    op.create_index("ix_service_checks_service_name", "service_checks", ["service_name"])

    op.create_table(
        "incidents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("incident_key", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("service_name", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.Column("deduplicated_fingerprints_json", sa.JSON(), nullable=False),
        sa.Column("root_cause_hypothesis", sa.Text(), nullable=False),
        sa.Column("cited_runbook_ids_json", sa.JSON(), nullable=False),
        sa.Column("recommended_steps_json", sa.JSON(), nullable=False),
        sa.Column("llm_provider", sa.String(length=64), nullable=False),
        sa.Column("pii_redacted", sa.Boolean(), nullable=False),
        sa.Column("assigned_to", sa.String(length=255), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_key"),
    )
    op.create_index("ix_incidents_incident_key", "incidents", ["incident_key"])
    op.create_index("ix_incidents_service_name", "incidents", ["service_name"])
    op.create_index("ix_incidents_status", "incidents", ["status"])

    op.create_table(
        "telemetry_alerts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("service_name", sa.String(length=128), nullable=False),
        sa.Column("alert_name", sa.String(length=128), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("metric_value", sa.Float(), nullable=False),
        sa.Column("threshold_value", sa.Float(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_telemetry_alerts_fingerprint", "telemetry_alerts", ["fingerprint"])
    op.create_index("ix_telemetry_alerts_service_name", "telemetry_alerts", ["service_name"])
    op.create_index("ix_telemetry_alerts_status", "telemetry_alerts", ["status"])

    op.create_table(
        "saas_entitlements",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("app_name", sa.String(length=128), nullable=False),
        sa.Column("user_email", sa.String(length=255), nullable=False),
        sa.Column("account_status", sa.String(length=32), nullable=False),
        sa.Column("assigned_role", sa.String(length=64), nullable=False),
        sa.Column("is_privileged", sa.Boolean(), nullable=False),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False),
        sa.Column("token_created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("token_last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expected_by_role", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_saas_entitlements_app_name", "saas_entitlements", ["app_name"])
    op.create_index("ix_saas_entitlements_user_email", "saas_entitlements", ["user_email"])

    op.create_table(
        "access_audit_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scope", sa.String(length=128), nullable=False),
        sa.Column("total_entitlements_scanned", sa.Integer(), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("critical_count", sa.Integer(), nullable=False),
        sa.Column("high_count", sa.Integer(), nullable=False),
        sa.Column("medium_count", sa.Integer(), nullable=False),
        sa.Column("stale_tokens_count", sa.Integer(), nullable=False),
        sa.Column("orphaned_accounts_count", sa.Integer(), nullable=False),
        sa.Column("privilege_drift_count", sa.Integer(), nullable=False),
        sa.Column("llm_summary", sa.Text(), nullable=False),
        sa.Column("llm_provider", sa.String(length=64), nullable=False),
        sa.Column("run_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "access_findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("audit_run_id", sa.String(length=36), nullable=False),
        sa.Column("entitlement_id", sa.String(length=36), nullable=False),
        sa.Column("finding_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("app_name", sa.String(length=128), nullable=False),
        sa.Column("user_email", sa.String(length=255), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("recommended_action", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("approval_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approval_id"], ["approval_requests.id"]),
        sa.ForeignKeyConstraint(["audit_run_id"], ["access_audit_runs.id"]),
        sa.ForeignKeyConstraint(["entitlement_id"], ["saas_entitlements.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_access_findings_audit_run_id", "access_findings", ["audit_run_id"])
    op.create_index("ix_access_findings_entitlement_id", "access_findings", ["entitlement_id"])
    op.create_index("ix_access_findings_finding_type", "access_findings", ["finding_type"])
    op.create_index("ix_access_findings_status", "access_findings", ["status"])

    op.create_table(
        "runbooks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("slug", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("service_name", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("severity_scope", sa.String(length=64), nullable=False),
        sa.Column("content_markdown", sa.Text(), nullable=False),
        sa.Column("safe_commands_json", sa.JSON(), nullable=False),
        sa.Column("tags_json", sa.JSON(), nullable=False),
        sa.Column("embedding_json", sa.JSON(), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index("ix_runbooks_slug", "runbooks", ["slug"])
    op.create_index("ix_runbooks_service_name", "runbooks", ["service_name"])

    op.create_table(
        "remediation_drafts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=True),
        sa.Column("query_text", sa.Text(), nullable=False),
        sa.Column("diagnosis_summary", sa.Text(), nullable=False),
        sa.Column("cited_runbooks_json", sa.JSON(), nullable=False),
        sa.Column("proposed_steps_json", sa.JSON(), nullable=False),
        sa.Column("blocked_shell_patterns_json", sa.JSON(), nullable=False),
        sa.Column("execution_mode", sa.String(length=32), nullable=False),
        sa.Column("llm_provider", sa.String(length=64), nullable=False),
        sa.Column("pii_redacted", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("approval_id", sa.String(length=36), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approval_id"], ["approval_requests.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_remediation_drafts_status", "remediation_drafts", ["status"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("sequence_no", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("actor_email", sa.String(length=255), nullable=False),
        sa.Column("actor_role", sa.String(length=32), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=36), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("details_json", sa.JSON(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sequence_no"),
    )
    op.create_index("ix_audit_events_sequence_no", "audit_events", ["sequence_no"])
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_event_type", table_name="audit_events")
    op.drop_index("ix_audit_events_sequence_no", table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_index("ix_remediation_drafts_status", table_name="remediation_drafts")
    op.drop_table("remediation_drafts")

    op.drop_index("ix_runbooks_service_name", table_name="runbooks")
    op.drop_index("ix_runbooks_slug", table_name="runbooks")
    op.drop_table("runbooks")

    op.drop_index("ix_access_findings_status", table_name="access_findings")
    op.drop_index("ix_access_findings_finding_type", table_name="access_findings")
    op.drop_index("ix_access_findings_entitlement_id", table_name="access_findings")
    op.drop_index("ix_access_findings_audit_run_id", table_name="access_findings")
    op.drop_table("access_findings")

    op.drop_table("access_audit_runs")

    op.drop_index("ix_saas_entitlements_user_email", table_name="saas_entitlements")
    op.drop_index("ix_saas_entitlements_app_name", table_name="saas_entitlements")
    op.drop_table("saas_entitlements")

    op.drop_index("ix_telemetry_alerts_status", table_name="telemetry_alerts")
    op.drop_index("ix_telemetry_alerts_service_name", table_name="telemetry_alerts")
    op.drop_index("ix_telemetry_alerts_fingerprint", table_name="telemetry_alerts")
    op.drop_table("telemetry_alerts")

    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_index("ix_incidents_service_name", table_name="incidents")
    op.drop_index("ix_incidents_incident_key", table_name="incidents")
    op.drop_table("incidents")

    op.drop_index("ix_service_checks_service_name", table_name="service_checks")
    op.drop_table("service_checks")

    op.drop_index("ix_provisioning_plans_status", table_name="provisioning_plans")
    op.drop_index("ix_provisioning_plans_target_email", table_name="provisioning_plans")
    op.drop_table("provisioning_plans")

    op.drop_index("ix_role_templates_code", table_name="role_templates")
    op.drop_table("role_templates")

    op.drop_index("ix_directory_users_email", table_name="directory_users")
    op.drop_table("directory_users")

    op.drop_index("ix_approval_requests_status", table_name="approval_requests")
    op.drop_index("ix_approval_requests_entity_id", table_name="approval_requests")
    op.drop_index("ix_approval_requests_entity_type", table_name="approval_requests")
    op.drop_table("approval_requests")
