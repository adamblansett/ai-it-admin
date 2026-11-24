# AI IT Administrator — Architecture Blueprint

## Overview

Open-source, self-hosted AI IT administration platform for user provisioning, infrastructure health monitoring, access control audits, and incident triage ticketing.

## Implemented Domain Modules (`backend/app/`)

- `identity/` — Least-privilege RBAC role templates and Joiner/Mover/Leaver SCIM dry-run planner (`GET /templates`, `POST /templates`, `GET /users`, `GET /plans`, `POST /plans/preview`). Directory records and SaaS entitlements remain untouched until an `it_approver` or `admin` approves the pending change.
- `telemetry/` — Service health, TLS certificate expiry, and storage/quota monitoring (`GET /services`, `POST /services/ingest`), fingerprint-based alert deduplication (`GET /alerts`, `POST /alerts/ingest`), and severity-classified incident triage citing operational runbooks (`GET /incidents`, `POST /incidents/triage`, `PATCH /incidents/{id}/status`).
- `access_audit/` — Periodic SaaS entitlement auditing across `saas_entitlements` and `directory_users` (`GET /entitlements`, `POST /entitlements`, `POST /scans`, `GET /scans`, `GET /findings`, `POST /findings/{id}/request-remediation`) detecting orphaned accounts, stale tokens, privilege drift, and missing MFA.
- `runbooks/` — Deterministic hybrid vector + keyword RAG retrieval (`GET /`, `POST /`, `POST /search`) and citation-grounded incident remediation drafting (`POST /assist`, `GET /drafts`) locked permanently to `execution_mode="advisory_only"` with zero blind shell execution (`guardrails.py`).
- `governance/` — Unified human-in-the-loop approval queue (`GET /approvals`, `POST /approvals/{id}/decide`), SHA-256 hash-chained operational audit log (`GET /audit/events`, `GET /audit/events/verify`), and outbound cloud secret/PII redaction preview (`POST /pii/redact`).
- `api/v1/` & `seed/` — Versioned health probes (`/health`, `/health/live`, `/health/ready` with DB readiness), RBAC auth (`/auth/me`, `/auth/token`), cross-module KPI aggregation (`/overview`), and idempotent enterprise demo seeder (`/seed/demo`).

## Persistence & Migrations

- **Async SQLAlchemy 2.0 ORM (`backend/app/db/models.py`):** 13 portable tables (`approval_requests`, `directory_users`, `role_templates`, `provisioning_plans`, `service_checks`, `incidents`, `telemetry_alerts`, `saas_entitlements`, `access_audit_runs`, `access_findings`, `runbooks`, `remediation_drafts`, `audit_events`) supporting SQLite (`aiosqlite`) locally and PostgreSQL (`pgvector`, `asyncpg`) in Compose/production.
- **Alembic (`backend/alembic/`):** Async migration setup with initial schema revision `0001_initial_schema`.

## Security & Operational Invariants

1. **Fail-Fast Production Validation:** `validate_production_security()` refuses startup in `APP_ENV=production` if default dev secrets (`AUTH_SECRET_KEY`) or wildcard `*` CORS origins remain active.
2. **RBAC & Strict Token Auth:** Role boundaries (`viewer`, `operator`, `it_approver`, `admin`) enforced via `require_roles()`; HMAC-SHA256 Bearer tokens mandatory when `APP_ENV=production` or `AUTH_REQUIRE_TOKEN=true`.
3. **Cloud PII & Secret Redaction:** Outbound cloud LLM requests (`GeminiLLMAdapter`) scrub PEM private keys, AWS keys, JWT/Bearer/SaaS tokens, API secrets, SSNs, emails, phones, and IPv4 addresses via `app/llm/pii.py` when `LLM_REDACT_PII_FOR_CLOUD=true`.
4. **Human-in-the-Loop Approvals & Hash-Chained Audit Log:** SCIM directory/entitlement mutations and SaaS access remediations execute atomically only upon `it_approver`/`admin` approval and append SHA-256 hash-chained `AuditEvent` records verifiable via `/api/v1/governance/audit/events/verify`.
5. **Zero Blind Shell Execution:** No `subprocess` or shell-execution modules exist in `backend/app/`; dangerous shell patterns (`rm -rf`, `curl ... | bash`, `DROP DATABASE`, `kubectl delete namespace`, command substitutions) are detected and neutralized in `app/runbooks/guardrails.py`.
6. **Non-Root Containers:** Both the FastAPI API image and Nginx frontend image run as non-root users with `/api/v1/health/live` and `/api/v1/health/ready` probes.
