# Deployment & Production Hardening Guide

## 1. Mandatory Production Environment Checklist

Set these variables before starting with `APP_ENV=production`:

- `APP_ENV=production`
- `AUTH_SECRET_KEY` — unique >=32-byte random secret (`validate_production_security()` refuses startup otherwise)
- `AUTH_REQUIRE_TOKEN=true` — disables development `X-Actor-*` header auth and enforces HMAC-SHA256 Bearer tokens
- `CORS_ORIGINS` — explicit comma-separated frontend origins (wildcards `*` are rejected at startup)
- `WEBHOOK_SECRET` — HMAC-SHA256 signing secret for `/api/v1/telemetry/webhooks/alertmanager` (empty secret returns `503` in production)
- `LLM_REDACT_PII_FOR_CLOUD=true` — scrubs credentials and PII prior to any cloud LLM request
- `RATE_LIMIT_ENABLED=true` & `RATE_LIMIT_REQUESTS_PER_MINUTE=120`

## 2. Docker Compose (PostgreSQL + pgvector + Redis)

```bash
cp .env.example .env
# Edit .env with production secrets and DATABASE_URL
docker compose up -d postgres redis
docker compose exec api alembic upgrade head
docker compose up -d --build
```

- Frontend UI: `http://localhost:3000`
- Backend API & OpenAPI Docs: `http://localhost:8000/docs`
- Health probes: `/api/v1/health/live` and `/api/v1/health/ready`

## 3. Google Cloud Run Deployment

Both `backend/Dockerfile` (`${PORT:-8000}`) and `frontend/Dockerfile` (`8080`) run as non-root containers.

```bash
gcloud run deploy ai-it-admin-api \
  --source ./backend \
  --region us-central1 \
  --no-allow-unauthenticated \
  --set-env-vars "APP_ENV=production,AUTH_REQUIRE_TOKEN=true,LLM_REDACT_PII_FOR_CLOUD=true" \
  --set-secrets "AUTH_SECRET_KEY=ai-it-admin-auth-secret:latest,WEBHOOK_SECRET=ai-it-admin-webhook-secret:latest,DATABASE_URL=ai-it-admin-db-url:latest"
```

## 4. Prometheus & Alertmanager Integration

### Prometheus Scrape Target

Point Prometheus at `/api/v1/metrics` (`text/plain; version=0.0.4`):

```yaml
scrape_configs:
  - job_name: "ai-it-admin"
    metrics_path: /api/v1/metrics
    static_configs:
      - targets: ["api:8000"]
```

Exposed gauges include `ai_it_admin_pending_approvals`, `ai_it_admin_firing_alerts`, `ai_it_admin_open_incidents`, `ai_it_admin_open_access_findings`, and `ai_it_admin_audit_chain_valid`.

### Alertmanager Webhook HMAC Signing

`POST /api/v1/telemetry/webhooks/alertmanager` verifies `X-Webhook-Signature: sha256=<hex>` using `HMAC-SHA256(WEBHOOK_SECRET, raw_body)`:

```bash
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" -hex | awk '{print $2}')
curl -X POST http://127.0.0.1:8000/api/v1/telemetry/webhooks/alertmanager \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: sha256=$SIG" \
  -d "$BODY"
```

## 5. Live PostgreSQL + Redis Integration Tests

To run `@pytest.mark.integration` tests against live Compose Postgres & Redis:

```bash
cd backend
RUN_LIVE_INTEGRATION_TESTS=1 \
  TEST_POSTGRES_URL="postgresql+asyncpg://app:app@127.0.0.1:5432/ai_it_admin" \
  TEST_REDIS_URL="redis://127.0.0.1:6379/0" \
  pytest -m integration -v
```
