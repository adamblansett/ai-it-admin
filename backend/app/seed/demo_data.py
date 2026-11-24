from datetime import timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.access_audit.service import run_access_audit_scan
from app.core.auth import Actor
from app.core.config import Settings
from app.db.base import utcnow
from app.db.models import (
    AccessAuditRun,
    AccessFinding,
    ApprovalRequest,
    AuditEvent,
    DirectoryUser,
    Incident,
    ProvisioningPlan,
    RemediationDraft,
    RoleTemplate,
    Runbook,
    SaaSEntitlement,
    ServiceCheck,
    TelemetryAlert,
)
from app.identity.schemas import ProvisioningPreviewIn, RoleAppGrant
from app.identity.service import preview_provisioning_plan
from app.llm.embeddings import compute_deterministic_embedding
from app.llm.router import LLMRouter
from app.runbooks.schemas import RemediationAssistIn
from app.runbooks.service import generate_remediation_draft
from app.telemetry.schemas import AlertIngestIn, IncidentTriageIn
from app.telemetry.service import ingest_alert, triage_incident

_DELETE_ORDER = (
    AuditEvent,
    RemediationDraft,
    AccessFinding,
    AccessAuditRun,
    TelemetryAlert,
    Incident,
    ProvisioningPlan,
    ApprovalRequest,
    SaaSEntitlement,
    DirectoryUser,
    RoleTemplate,
    ServiceCheck,
    Runbook,
)


async def seed_demo_dataset(
    db: AsyncSession,
    *,
    llm_router: LLMRouter,
    settings: Settings,
    actor: Actor,
    reset: bool = False,
) -> dict[str, object]:
    """Populate realistic enterprise IT demo state idempotently (or cleanly reset)."""
    existing_templates = int(
        (await db.execute(select(func.count(RoleTemplate.id)))).scalar_one() or 0
    )
    if existing_templates > 0 and not reset:
        existing_users = int(
            (await db.execute(select(func.count(DirectoryUser.id)))).scalar_one() or 0
        )
        existing_services = int(
            (await db.execute(select(func.count(ServiceCheck.id)))).scalar_one() or 0
        )
        return {
            "seeded": False,
            "message": "Demo dataset is already initialized.",
            "role_templates": existing_templates,
            "directory_users": existing_users,
            "services": existing_services,
        }

    if reset:
        for model in _DELETE_ORDER:
            await db.execute(delete(model))
        await db.commit()

    now = utcnow()

    templates = [
        RoleTemplate(
            code="eng-backend",
            name="Backend Software Engineer",
            department="Engineering",
            description="Standard least-privilege engineering access without prod root admin.",
            allowed_groups_json=["okta-engineering", "github-devs", "vpn-eng"],
            allowed_apps_json=[
                {"app": "GitHub", "role": "maintainer", "privileged": False},
                {"app": "AWS", "role": "developer-readonly", "privileged": False},
                {"app": "Datadog", "role": "viewer", "privileged": False},
            ],
            requires_mfa=True,
        ),
        RoleTemplate(
            code="eng-sre",
            name="Site Reliability Engineer",
            department="Platform",
            description=(
                "Production incident responder with scoped elevated Kubernetes & AWS roles."
            ),
            allowed_groups_json=["okta-platform", "sre-oncall", "vpn-prod"],
            allowed_apps_json=[
                {"app": "GitHub", "role": "admin", "privileged": True},
                {"app": "AWS", "role": "prod-operator", "privileged": True},
                {"app": "Datadog", "role": "editor", "privileged": False},
            ],
            requires_mfa=True,
        ),
        RoleTemplate(
            code="finance-analyst",
            name="Finance Operations Analyst",
            department="Finance",
            description="ERP and reporting access scoped to financial dashboards.",
            allowed_groups_json=["okta-finance", "netsuite-analysts"],
            allowed_apps_json=[
                {"app": "NetSuite", "role": "analyst", "privileged": False},
                {"app": "Okta", "role": "user", "privileged": False},
            ],
            requires_mfa=True,
        ),
        RoleTemplate(
            code="sales-ae",
            name="Account Executive",
            department="Sales",
            description="CRM and customer engagement tools with strict MFA enforcement.",
            allowed_groups_json=["okta-sales", "crm-users"],
            allowed_apps_json=[
                {"app": "Salesforce", "role": "standard-user", "privileged": False},
                {"app": "Slack", "role": "member", "privileged": False},
            ],
            requires_mfa=True,
        ),
        RoleTemplate(
            code="support-tier1",
            name="Customer Support Specialist",
            department="Support",
            description="Ticketing triage and read-only status diagnostics.",
            allowed_groups_json=["okta-support", "zendesk-agents"],
            allowed_apps_json=[
                {"app": "Zendesk", "role": "agent", "privileged": False},
                {"app": "Slack", "role": "member", "privileged": False},
            ],
            requires_mfa=True,
        ),
    ]
    db.add_all(templates)

    users = [
        DirectoryUser(
            employee_id="EMP-1001",
            email="maya.patel@acme-it.local",
            full_name="Maya Patel",
            department="Platform",
            title="Staff SRE",
            role_template_code="eng-sre",
            employment_status="active",
            manager_email="vp-infra@acme-it.local",
            last_login_at=now - timedelta(hours=3),
            mfa_enrolled=True,
        ),
        DirectoryUser(
            employee_id="EMP-1002",
            email="liam.oconnor@acme-it.local",
            full_name="Liam O'Connor",
            department="Engineering",
            title="Senior Backend Engineer",
            role_template_code="eng-backend",
            employment_status="active",
            manager_email="maya.patel@acme-it.local",
            last_login_at=now - timedelta(days=1),
            mfa_enrolled=True,
        ),
        DirectoryUser(
            employee_id="EMP-1003",
            email="priya.nair@acme-it.local",
            full_name="Priya Nair",
            department="Finance",
            title="Senior Finance Analyst",
            role_template_code="finance-analyst",
            employment_status="active",
            manager_email="controller@acme-it.local",
            last_login_at=now - timedelta(days=2),
            mfa_enrolled=True,
        ),
        DirectoryUser(
            employee_id="EMP-1004",
            email="marcus.vance@acme-it.local",
            full_name="Marcus Vance",
            department="Sales",
            title="Enterprise Account Executive",
            role_template_code="sales-ae",
            employment_status="active",
            manager_email="cro@acme-it.local",
            last_login_at=now - timedelta(days=4),
            mfa_enrolled=True,
        ),
        DirectoryUser(
            employee_id="EMP-1005",
            email="elena.rostova@acme-it.local",
            full_name="Elena Rostova",
            department="Support",
            title="Support Specialist",
            role_template_code="support-tier1",
            employment_status="onboarding",
            manager_email="support-lead@acme-it.local",
            last_login_at=None,
            mfa_enrolled=True,
        ),
        DirectoryUser(
            employee_id="EMP-1006",
            email="david.kim@acme-it.local",
            full_name="David Kim",
            department="Engineering",
            title="Former Contractor",
            role_template_code="eng-backend",
            employment_status="terminated",
            manager_email="maya.patel@acme-it.local",
            last_login_at=now - timedelta(days=75),
            mfa_enrolled=False,
        ),
    ]
    db.add_all(users)

    entitlements = [
        SaaSEntitlement(
            app_name="GitHub",
            user_email="maya.patel@acme-it.local",
            account_status="active",
            assigned_role="admin",
            is_privileged=True,
            mfa_enabled=True,
            token_created_at=now - timedelta(days=30),
            token_last_used_at=now - timedelta(days=1),
            last_login_at=now - timedelta(hours=3),
            expected_by_role=True,
        ),
        SaaSEntitlement(
            app_name="AWS",
            user_email="maya.patel@acme-it.local",
            account_status="active",
            assigned_role="prod-operator",
            is_privileged=True,
            mfa_enabled=True,
            token_created_at=now - timedelta(days=20),
            token_last_used_at=now - timedelta(days=2),
            last_login_at=now - timedelta(hours=5),
            expected_by_role=True,
        ),
        SaaSEntitlement(
            app_name="GitHub",
            user_email="liam.oconnor@acme-it.local",
            account_status="active",
            assigned_role="maintainer",
            is_privileged=False,
            mfa_enabled=True,
            token_created_at=now - timedelta(days=180),
            token_last_used_at=now - timedelta(days=135),  # Stale token (>90d)
            last_login_at=now - timedelta(days=1),
            expected_by_role=True,
        ),
        SaaSEntitlement(
            app_name="Datadog",
            user_email="liam.oconnor@acme-it.local",
            account_status="active",
            assigned_role="admin",  # Privilege drift: template expects viewer
            is_privileged=True,
            mfa_enabled=True,
            token_created_at=now - timedelta(days=45),
            token_last_used_at=now - timedelta(days=5),
            last_login_at=now - timedelta(days=2),
            expected_by_role=False,
        ),
        SaaSEntitlement(
            app_name="AWS",
            user_email="liam.oconnor@acme-it.local",
            account_status="active",
            assigned_role="developer-readonly",
            is_privileged=False,
            mfa_enabled=True,
            token_created_at=now - timedelta(days=25),
            token_last_used_at=now - timedelta(days=4),
            last_login_at=now - timedelta(days=1),
            expected_by_role=True,
        ),
        SaaSEntitlement(
            app_name="NetSuite",
            user_email="priya.nair@acme-it.local",
            account_status="active",
            assigned_role="analyst",
            is_privileged=False,
            mfa_enabled=True,
            token_created_at=now - timedelta(days=14),
            token_last_used_at=now - timedelta(days=1),
            last_login_at=now - timedelta(days=2),
            expected_by_role=True,
        ),
        SaaSEntitlement(
            app_name="Salesforce",
            user_email="marcus.vance@acme-it.local",
            account_status="active",
            assigned_role="standard-user",
            is_privileged=False,
            mfa_enabled=True,
            token_created_at=now - timedelta(days=160),
            token_last_used_at=now - timedelta(days=118),  # Stale token
            last_login_at=now - timedelta(days=4),
            expected_by_role=True,
        ),
        SaaSEntitlement(
            app_name="Zendesk",
            user_email="marcus.vance@acme-it.local",
            account_status="active",
            assigned_role="agent",
            is_privileged=False,
            mfa_enabled=False,  # Missing MFA + drift
            token_created_at=now - timedelta(days=30),
            token_last_used_at=now - timedelta(days=10),
            last_login_at=now - timedelta(days=10),
            expected_by_role=False,
        ),
        SaaSEntitlement(
            app_name="GitHub",
            user_email="david.kim@acme-it.local",
            account_status="active",  # Orphaned: terminated user
            assigned_role="admin",
            is_privileged=True,
            mfa_enabled=False,
            token_created_at=now - timedelta(days=210),
            token_last_used_at=now - timedelta(days=98),
            last_login_at=now - timedelta(days=75),
            expected_by_role=False,
        ),
        SaaSEntitlement(
            app_name="AWS",
            user_email="unknown-svc-acct@external-vendor.io",
            account_status="orphaned",  # Orphaned account without directory record
            assigned_role="billing-admin",
            is_privileged=True,
            mfa_enabled=False,
            token_created_at=now - timedelta(days=240),
            token_last_used_at=now - timedelta(days=150),
            last_login_at=now - timedelta(days=150),
            expected_by_role=False,
        ),
    ]
    db.add_all(entitlements)

    services = [
        ServiceCheck(
            service_name="payments-api",
            environment="production",
            endpoint_url="https://payments.internal.acme/health",
            status="healthy",
            latency_ms=34.0,
            error_rate_pct=0.04,
            cpu_pct=31.0,
            memory_pct=48.0,
            quota_used_pct=42.0,
            cert_expires_at=now + timedelta(days=140),
            last_checked_at=now,
            metadata_json={"region": "us-east-1", "replicas": 6},
        ),
        ServiceCheck(
            service_name="auth-gateway",
            environment="production",
            endpoint_url="https://auth.internal.acme/ready",
            status="degraded",
            latency_ms=890.0,
            error_rate_pct=7.4,
            cpu_pct=78.0,
            memory_pct=82.0,
            quota_used_pct=68.0,
            cert_expires_at=now + timedelta(days=95),
            last_checked_at=now,
            metadata_json={"region": "us-east-1", "replicas": 4},
        ),
        ServiceCheck(
            service_name="postgres-primary",
            environment="production",
            endpoint_url="postgres://pg-primary.internal.acme:5432",
            status="degraded",
            latency_ms=145.0,
            error_rate_pct=0.2,
            cpu_pct=69.0,
            memory_pct=88.0,
            quota_used_pct=91.0,
            cert_expires_at=now + timedelta(days=75),
            last_checked_at=now,
            metadata_json={"storage_tb": 4.0, "connections": 410},
        ),
        ServiceCheck(
            service_name="edge-ingress",
            environment="production",
            endpoint_url="https://edge.acme-it.local/healthz",
            status="healthy",
            latency_ms=18.5,
            error_rate_pct=0.01,
            cpu_pct=24.0,
            memory_pct=36.0,
            quota_used_pct=51.0,
            cert_expires_at=now + timedelta(days=11),
            last_checked_at=now,
            metadata_json={"tls_issuer": "LetsEncrypt-R11"},
        ),
        ServiceCheck(
            service_name="okta-scim-sync",
            environment="production",
            endpoint_url="https://scim.internal.acme/v2/Users",
            status="healthy",
            latency_ms=52.0,
            error_rate_pct=0.0,
            cpu_pct=19.0,
            memory_pct=33.0,
            quota_used_pct=28.0,
            cert_expires_at=now + timedelta(days=180),
            last_checked_at=now,
            metadata_json={"sync_lag_sec": 3},
        ),
    ]
    db.add_all(services)

    raw_runbooks: list[dict[str, Any]] = [
        {
            "slug": "rb-auth-gateway-5xx-surge",
            "title": "Auth Gateway 5xx Surge & JWKS Pool Saturation",
            "service_name": "auth-gateway",
            "category": "incident",
            "severity_scope": "sev1,sev2",
            "tags": ["auth-gateway", "5xx", "jwks", "redis", "latency"],
            "content_markdown": (
                "# Auth Gateway 5xx Surge\n\n"
                "## Symptoms\n"
                "Elevated HTTP 502/503 responses and token verification latency >500ms.\n\n"
                "## Safe Triage Steps\n"
                "1. Check downstream Redis session cache hit ratio and connection pool.\n"
                "2. Inspect JWKS key cache refresh errors before restarting replicas.\n"
                "3. Scale read replicas via GitOps pull request if CPU remains >75%."
            ),
            "safe_commands": [
                {
                    "label": "Check Auth Gateway Readiness",
                    "command": "curl -fsS https://auth.internal.acme/ready",
                    "read_only": True,
                },
                {
                    "label": "Inspect Pod HPA & Replicas",
                    "command": "kubectl get hpa -n identity-prod",
                    "read_only": True,
                },
            ],
        },
        {
            "slug": "rb-tls-cert-rotation",
            "title": "Edge Ingress TLS Certificate Expiry & Renewal",
            "service_name": "edge-ingress",
            "category": "certificates",
            "severity_scope": "sev2,sev3",
            "tags": ["tls", "certificate", "expiry", "edge-ingress", "cert-manager"],
            "content_markdown": (
                "# TLS Certificate Renewal Runbook\n\n"
                "## Symptoms\n"
                "Certificate expires within 30 days on edge-ingress or ACME fails.\n\n"
                "## Safe Triage Steps\n"
                "1. Verify cert-manager CertificateRequest status and DNS-01 TXT propagation.\n"
                "2. Inspect x509 NotAfter date on the ingress secret prior to renewal."
            ),
            "safe_commands": [
                {
                    "label": "Inspect Cert-Manager Certificate Status",
                    "command": "kubectl describe certificate edge-tls -n ingress-prod",
                    "read_only": True,
                },
                {
                    "label": "Check Public TLS Expiration",
                    "command": (
                        "openssl s_client -connect edge.acme-it.local:443 "
                        "-servername edge.acme-it.local"
                    ),
                    "read_only": True,
                },
            ],
        },
        {
            "slug": "rb-postgres-quota-and-connections",
            "title": "PostgreSQL Primary Storage Quota & Connection Exhaustion",
            "service_name": "postgres-primary",
            "category": "database",
            "severity_scope": "sev1,sev2",
            "tags": ["postgres", "quota", "disk", "connections", "pgvector"],
            "content_markdown": (
                "# PostgreSQL Storage Quota & Pool Runbook\n\n"
                "## Symptoms\n"
                "Volume quota >85% or active connections nearing max_connections.\n\n"
                "## Safe Triage Steps\n"
                "1. Query pg_stat_activity for idle-in-transaction sessions first.\n"
                "2. Review WAL archive retention and dead tuple bloat across high-churn tables."
            ),
            "safe_commands": [
                {
                    "label": "Inspect Connection States",
                    "command": (
                        "psql -c \"SELECT state, count(*) FROM pg_stat_activity "
                        "GROUP BY state;\""
                    ),
                    "read_only": True,
                },
                {
                    "label": "Check PVC Disk Utilization",
                    "command": "kubectl get pvc -n data-prod",
                    "read_only": True,
                },
            ],
        },
        {
            "slug": "rb-okta-scim-sync-recovery",
            "title": "Okta SCIM Sync Lag & Rate-Limit Recovery",
            "service_name": "okta-scim-sync",
            "category": "identity",
            "severity_scope": "sev2,sev3",
            "tags": ["okta", "scim", "provisioning", "429", "identity"],
            "content_markdown": (
                "# Okta SCIM Sync Recovery\n\n"
                "## Symptoms\n"
                "Provisioning queue backlog or HTTP 429 limits from Okta SCIM.\n\n"
                "## Safe Triage Steps\n"
                "1. Inspect SCIM connector dead-letter queue without replaying leaver steps.\n"
                "2. Validate OAuth service client token expiry."
            ),
            "safe_commands": [
                {
                    "label": "Check SCIM Connector Health",
                    "command": "curl -fsS https://scim.internal.acme/healthz",
                    "read_only": True,
                },
            ],
        },
        {
            "slug": "rb-compromised-account-containment",
            "title": "Orphaned or Compromised SaaS Account Containment",
            "service_name": "okta-scim-sync",
            "category": "security",
            "severity_scope": "sev1,sev2",
            "tags": ["orphaned", "stale-token", "containment", "mfa", "iam"],
            "content_markdown": (
                "# Compromised or Orphaned Account Containment\n\n"
                "## Symptoms\n"
                "Active SaaS tokens for terminated staff or anomalous privilege drift.\n\n"
                "## Safe Triage Steps\n"
                "1. Submit HITL approval request to suspend account and revoke tokens.\n"
                "2. Preserve immutable audit trail before rotating shared service credentials."
            ),
            "safe_commands": [
                {
                    "label": "Verify Audit Chain Integrity",
                    "command": (
                        "curl -fsS http://127.0.0.1:8000/api/v1/governance/audit/events/verify"
                    ),
                    "read_only": True,
                },
            ],
        },
    ]

    for rb_cfg in raw_runbooks:
        index_text = (
            f"{rb_cfg['title']}\n{rb_cfg['service_name']}\n{rb_cfg['category']}\n"
            f"{' '.join(rb_cfg['tags'])}\n{rb_cfg['content_markdown']}"
        )
        db.add(
            Runbook(
                slug=str(rb_cfg["slug"]),
                title=str(rb_cfg["title"]),
                service_name=str(rb_cfg["service_name"]),
                category=str(rb_cfg["category"]),
                severity_scope=str(rb_cfg["severity_scope"]),
                content_markdown=str(rb_cfg["content_markdown"]),
                safe_commands_json=list(rb_cfg["safe_commands"]),
                tags_json=list(rb_cfg["tags"]),
                embedding_json=compute_deterministic_embedding(
                    index_text, dimensions=settings.embedding_dimensions
                ),
                updated_by=actor.email,
            )
        )

    await db.commit()

    # Ingest deduplicated alerts and triage 2 incidents
    auth_alert_in = AlertIngestIn(
        service_name="auth-gateway",
        alert_name="http_5xx_rate_high",
        source="prometheus",
        severity="sev2",
        metric_value=7.4,
        threshold_value=5.0,
        summary="Auth Gateway HTTP 502/503 error rate surged to 7.4% with elevated JWKS latency.",
    )
    auth_alert, _ = await ingest_alert(db, payload=auth_alert_in, actor=actor)
    await ingest_alert(db, payload=auth_alert_in, actor=actor)
    await ingest_alert(db, payload=auth_alert_in, actor=actor)

    pg_alert_in = AlertIngestIn(
        service_name="postgres-primary",
        alert_name="storage_quota_critical",
        source="quota_monitor",
        severity="sev2",
        metric_value=91.0,
        threshold_value=85.0,
        summary="PostgreSQL primary volume utilization reached 91.0% on pg-primary.",
    )
    pg_alert, _ = await ingest_alert(db, payload=pg_alert_in, actor=actor)
    await ingest_alert(db, payload=pg_alert_in, actor=actor)

    # Triage both into realistic open/triaged incidents citing runbooks
    auth_inc = await triage_incident(
        db,
        llm_router=llm_router,
        settings=settings,
        payload=IncidentTriageIn(
            service_name="auth-gateway",
            alert_ids=[auth_alert.id],
            title="Auth Gateway 5xx Surge (JWKS Cache Saturation)",
        ),
        actor=actor,
    )
    await triage_incident(
        db,
        llm_router=llm_router,
        settings=settings,
        payload=IncidentTriageIn(
            service_name="postgres-primary",
            alert_ids=[pg_alert.id],
            title="PostgreSQL Primary Storage Quota >90%",
        ),
        actor=actor,
    )

    # Leave 2 active firing alerts with dedup counts > 1 ready for operator triage
    cert_alert_in = AlertIngestIn(
        service_name="edge-ingress",
        alert_name="tls_cert_expiring",
        source="cert_monitor",
        severity="sev2",
        metric_value=11.0,
        threshold_value=30.0,
        summary="TLS certificate for edge-ingress expires in 11 days.",
    )
    for _ in range(3):
        await ingest_alert(db, payload=cert_alert_in, actor=actor)

    latency_alert_in = AlertIngestIn(
        service_name="auth-gateway",
        alert_name="jwks_p99_latency_spike",
        source="healthcheck",
        severity="sev3",
        metric_value=890.0,
        threshold_value=500.0,
        summary="Auth Gateway p99 token verification latency climbed to 890ms.",
    )
    for _ in range(2):
        await ingest_alert(db, payload=latency_alert_in, actor=actor)

    # Create 2 pending SCIM provisioning plans (Joiner w/ extra app warning + Leaver)
    await preview_provisioning_plan(
        db,
        llm_router=llm_router,
        payload=ProvisioningPreviewIn(
            plan_type="joiner",
            target_email="jordan.rivera@acme-it.local",
            target_name="Jordan Rivera",
            department="Engineering",
            to_role_code="eng-backend",
            scim_provider="okta",
            requested_extra_apps=[
                RoleAppGrant(app="Datadog", role="admin", privileged=True),
            ],
        ),
        actor=actor,
    )
    await preview_provisioning_plan(
        db,
        llm_router=llm_router,
        payload=ProvisioningPreviewIn(
            plan_type="leaver",
            target_email="david.kim@acme-it.local",
            target_name="David Kim",
            scim_provider="okta",
        ),
        actor=actor,
    )

    # Run initial access audit scan
    await run_access_audit_scan(
        db,
        llm_router=llm_router,
        settings=settings,
        scope="all_saas",
        actor=actor,
    )

    # Generate 1 advisory-only remediation draft linked to auth-gateway incident
    await generate_remediation_draft(
        db,
        llm_router=llm_router,
        settings=settings,
        payload=RemediationAssistIn(
            query_text="Investigate auth-gateway 5xx surge and JWKS cache latency",
            incident_id=auth_inc.id,
            service_name="auth-gateway",
            request_approval=True,
        ),
        actor=actor,
    )

    return {
        "seeded": True,
        "message": "Enterprise AI IT Administrator demo dataset initialized.",
        "role_templates": len(templates),
        "directory_users": len(users),
        "services": len(services),
        "runbooks": len(raw_runbooks),
    }
