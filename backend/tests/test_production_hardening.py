import asyncio
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.auth import Actor
from app.governance.service import record_audit_event, verify_audit_chain
from tests.conftest import APPROVER_HEADERS, OPERATOR_HEADERS, make_test_app


@pytest.mark.asyncio
async def test_rate_limiting_and_exempt_health_probes(tmp_path: Path) -> None:
    app = make_test_app(tmp_path, rate_limit_requests_per_minute=3)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for _ in range(3):
            res = await client.get("/api/v1/auth/me", headers=OPERATOR_HEADERS)
            assert res.status_code == 200
            assert res.headers["x-ratelimit-limit"] == "3"

        blocked = await client.get("/api/v1/auth/me", headers=OPERATOR_HEADERS)
        assert blocked.status_code == 429
        assert int(blocked.headers["retry-after"]) >= 1
        assert blocked.headers["x-content-type-options"] == "nosniff"
        assert "x-request-id" in blocked.headers

        # Health & metrics probes remain exempt
        health = await client.get("/api/v1/health/live")
        assert health.status_code == 200


@pytest.mark.asyncio
async def test_prometheus_metrics_and_process_time_header(tmp_path: Path) -> None:
    app = make_test_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/api/v1/seed/demo", headers=APPROVER_HEADERS)
        me_res = await client.get("/api/v1/auth/me", headers=OPERATOR_HEADERS)
        assert "x-process-time-ms" in me_res.headers

        metrics_res = await client.get("/api/v1/metrics")
        assert metrics_res.status_code == 200
        body = metrics_res.text
        assert "ai_it_admin_http_requests_total" in body
        assert "ai_it_admin_pending_approvals" in body
        assert "ai_it_admin_audit_chain_valid 1" in body


@pytest.mark.asyncio
async def test_alertmanager_hmac_webhook_ingest_dedup_and_resolve(tmp_path: Path) -> None:
    secret = "test-alertmanager-hmac-secret-32chars"
    app = make_test_app(tmp_path, webhook_secret=secret)

    firing_payload = {
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "HighErrorRate",
                    "service": "billing-api",
                    "severity": "critical",
                },
                "annotations": {"summary": "Billing API 5xx exceeded 5%"},
            }
        ],
    }
    raw_firing = json.dumps(firing_payload).encode("utf-8")
    valid_sig = hmac.new(secret.encode("utf-8"), raw_firing, hashlib.sha256).hexdigest()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Missing/invalid signature rejected with 401
        bad_res = await client.post(
            "/api/v1/telemetry/webhooks/alertmanager",
            content=raw_firing,
            headers={"Content-Type": "application/json", "X-Webhook-Signature": "sha256=bad"},
        )
        assert bad_res.status_code == 401

        # First valid delivery creates firing alert
        first = await client.post(
            "/api/v1/telemetry/webhooks/alertmanager",
            content=raw_firing,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": f"sha256={valid_sig}",
            },
        )
        assert first.status_code == 200
        assert first.json()["firing_ingested"] == 1
        assert first.json()["deduplicated"] == 0

        # Second valid delivery deduplicates
        second = await client.post(
            "/api/v1/telemetry/webhooks/alertmanager",
            content=raw_firing,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": f"sha256={valid_sig}",
            },
        )
        assert second.status_code == 200
        assert second.json()["deduplicated"] == 1

        # Resolved notification clears active alert
        resolved_payload = {
            "status": "resolved",
            "alerts": [
                {
                    "status": "resolved",
                    "labels": {
                        "alertname": "HighErrorRate",
                        "service": "billing-api",
                    },
                }
            ],
        }
        raw_res = json.dumps(resolved_payload).encode("utf-8")
        res_sig = hmac.new(secret.encode("utf-8"), raw_res, hashlib.sha256).hexdigest()
        res_resp = await client.post(
            "/api/v1/telemetry/webhooks/alertmanager",
            content=raw_res,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": f"sha256={res_sig}",
            },
        )
        assert res_resp.status_code == 200
        assert res_resp.json()["resolved"] == 1


@pytest.mark.asyncio
async def test_scim_bulk_payload_export_and_ssrf_webhooks(tmp_path: Path) -> None:
    app = make_test_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/api/v1/seed/demo", headers=APPROVER_HEADERS)

        plans = (await client.get("/api/v1/identity/plans", headers=OPERATOR_HEADERS)).json()
        assert len(plans) >= 1
        scim_res = await client.get(
            f"/api/v1/identity/plans/{plans[0]['id']}/scim-payload",
            headers=OPERATOR_HEADERS,
        )
        assert scim_res.status_code == 200
        scim_data = scim_res.json()
        assert scim_data["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"]
        assert len(scim_data["Operations"]) >= 1

        # SSRF blocks internal/metadata/loopback URLs
        for blocked_url in (
            "http://127.0.0.1:8000/hook",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/hook",
            "http://localhost/hook",
        ):
            bad_wh = await client.post(
                "/api/v1/integrations/webhooks",
                json={"name": "Bad Hook", "channel_type": "generic", "target_url": blocked_url},
                headers=APPROVER_HEADERS,
            )
            assert bad_wh.status_code == 400

        # Valid external HTTPS webhook succeeds and dry-run scrubs PII
        ok_wh = await client.post(
            "/api/v1/integrations/webhooks",
            json={
                "name": "Ops PagerDuty",
                "channel_type": "pagerduty",
                "target_url": "https://events.pagerduty.com/v2/enqueue",
            },
            headers=APPROVER_HEADERS,
        )
        assert ok_wh.status_code == 200
        wh_id = ok_wh.json()["id"]

        test_res = await client.post(
            f"/api/v1/integrations/webhooks/{wh_id}/test",
            json={
                "event_type": "incident.triaged",
                "message": "User alice@acme.local leaked AKIA1234567890ABCDEF from 192.168.1.5",
                "dry_run": True,
            },
            headers=OPERATOR_HEADERS,
        )
        assert test_res.status_code == 200
        test_data = test_res.json()
        assert test_data["delivery_status"] == "dry_run_ok"
        assert test_data["pii_redacted_count"] >= 3
        summary_text = test_data["payload_preview"]["payload"]["summary"]
        assert "alice@acme.local" not in summary_text
        assert "AKIA1234567890ABCDEF" not in summary_text


@pytest.mark.asyncio
async def test_concurrent_audit_events_preserve_hash_chain(tmp_path: Path) -> None:
    app = make_test_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Trigger lazy DB initialization
        await client.get("/api/v1/health/ready")

    actor = Actor(email="conc@test.local", role="operator", auth_method="test")

    async def _write_one(idx: int) -> None:
        async with app.state.session_factory() as session:
            await record_audit_event(
                session,
                event_type="test.concurrent",
                actor=actor,
                entity_type="test_entity",
                entity_id=f"ent-{idx}",
                action="ping",
                details={"idx": idx},
            )
            await session.commit()

    await asyncio.gather(*[_write_one(i) for i in range(6)])

    async with app.state.session_factory() as session:
        chain = await verify_audit_chain(session)
        assert chain.valid is True
        assert chain.total_events == 6
