# AI IT Administrator

> Open-source, self-hosted AI IT administration platform for user provisioning, infrastructure health monitoring, access control audits, and incident triage ticketing.

**Roadmap Stage:** Phase 1 — Core Professional & Enterprise Operations · **Status:** Implemented MVP

## Core Capabilities

- **Identity & SCIM Provisioning (`/api/v1/identity`):** Joiner/mover/leaver least-privilege role templates, SCIM 2.0 dry-run diff previews, RFC 7644 `BulkRequest` JSON payload export, extra-app privilege deviation warnings, and HITL-gated atomic directory/entitlement updates.
- **Health Monitoring & Incident Triage (`/api/v1/telemetry`):** Service telemetry ingestion, TLS certificate expiry and quota alerts, HMAC-SHA256 Alertmanager webhooks, fingerprint-based alert deduplication, severity classification, and cited runbook triage.
- **Access Control Audits (`/api/v1/access-audit`):** Automated SaaS entitlement scans detecting orphaned accounts, stale API tokens, privilege drift, and missing MFA with approval-gated remediation.
- **Runbooks RAG & Advisory Remediation (`/api/v1/runbooks`):** Deterministic hybrid vector + keyword retrieval and citation-grounded incident remediation drafts permanently locked to `advisory_only` with zero blind shell execution.
- **Governance, Integrations & Observability (`/api/v1/governance`, `/api/v1/integrations`, `/api/v1/metrics`):** Unified HITL approval queue (`viewer`, `operator`, `it_approver`, `admin` RBAC), SSRF-guarded Slack/PagerDuty notification connectors, sliding-window rate limiting, Prometheus metrics, tamper-evident SHA-256 audit chain verification, and outbound cloud secret/PII scrubbing (`LLM_REDACT_PII_FOR_CLOUD=true`).

## Architecture & Engineering Standards

- **Backend (`backend/`):** Python 3.12+, FastAPI, Pydantic v2, async SQLAlchemy 2.0 + Alembic migrations, typed settings with production fail-fast validation, sliding-window `RateLimitMiddleware`, pure ASGI security-header middleware, structured `structlog` JSON logging, Prometheus `/api/v1/metrics`, and `/api/v1/health` (`/live`, `/ready`) probes.
- **Frontend (`frontend/`):** React 18, TypeScript, Vite, Tailwind CSS control plane across 6 modules (`Overview`, `Identity & SCIM`, `Health & Triage`, `Access Audits`, `Runbooks RAG`, `Approvals & Audit`) with Vitest + Testing Library unit tests served behind unprivileged Nginx in production.
- **Privacy & AI Routing (`backend/app/llm/`):** Offline deterministic `mock` mode for CI/dev, local-first open-weights Ollama adapter, and PII/secret-redacted cloud Gemini fallback.
- **Containers & CI (`.github/workflows/ci.yml`):** Multi-stage Dockerfiles, PostgreSQL (`pgvector`) + Redis Compose topology, Ruff + Mypy + Pytest checks, TypeScript + Vitest + Vite build, `npm audit`, and Trivy filesystem scanning.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full module and security architecture and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for production deployment, Cloud Run, Prometheus, and Alertmanager configuration.

## Quickstart

### Backend (Local Dev & Tests)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

Verify lint, types, and tests:

```bash
ruff check app tests alembic
mypy app
pytest -v
```

### Frontend (Local Dev & Tests)

```bash
cd frontend
npm ci
npm run dev
```

Verify typecheck, unit tests, and production bundle:

```bash
npx tsc --noEmit
npm run test
npm run build
```

### Docker Compose

```bash
docker compose up --build
```

- Frontend UI: `http://localhost:3000`
- Backend API & OpenAPI Docs: `http://localhost:8000/docs`

---

## License

Licensed under the [MIT License](LICENSE).
