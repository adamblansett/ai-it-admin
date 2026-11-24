from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import OPERATOR_HEADERS, make_test_app


@pytest.mark.asyncio
async def test_service_ingestion_alert_dedup_and_incident_triage(tmp_path: Path) -> None:
    app = make_test_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Index a runbook so triage cites it
        rb_res = await client.post(
            "/api/v1/runbooks",
            json={
                "slug": "rb-checkout-outage",
                "title": "Checkout API Outage & TLS Renewal",
                "service_name": "checkout-api",
                "category": "incident",
                "content_markdown": (
                    "# Checkout API Outage\n"
                    "Check TLS cert expiry and HTTP 5xx error spikes on checkout-api."
                ),
                "safe_commands": [
                    {
                        "label": "Check Ready",
                        "command": "curl -fsS https://checkout.internal/ready",
                        "read_only": True,
                    }
                ],
                "tags": ["checkout-api", "tls", "outage"],
            },
            headers=OPERATOR_HEADERS,
        )
        assert rb_res.status_code == 200

        # Ingest service with expiring cert (10 days) and high quota (92%)
        soon_expiry = (datetime.now(UTC) + timedelta(days=10)).isoformat()
        svc_res = await client.post(
            "/api/v1/telemetry/services/ingest",
            json={
                "service_name": "checkout-api",
                "environment": "production",
                "endpoint_url": "https://checkout.internal/ready",
                "status": "outage",
                "latency_ms": 1800.0,
                "error_rate_pct": 14.5,
                "quota_used_pct": 92.0,
                "cert_expires_at": soon_expiry,
            },
            headers=OPERATOR_HEADERS,
        )
        assert svc_res.status_code == 200
        svc_data = svc_res.json()
        assert svc_data["cert_expiring_soon"] is True
        assert svc_data["quota_warning"] is True
        assert svc_data["needs_attention"] is True

        # Send duplicate alerts -> same fingerprint increments occurrence_count
        alert_payload = {
            "service_name": "checkout-api",
            "alert_name": "http_5xx_spike",
            "source": "prometheus",
            "severity": "sev2",
            "metric_value": 14.5,
            "threshold_value": 5.0,
            "summary": "Checkout API 5xx surge detected",
        }
        first_alert = await client.post(
            "/api/v1/telemetry/alerts/ingest", json=alert_payload, headers=OPERATOR_HEADERS
        )
        assert first_alert.status_code == 200
        assert first_alert.json()["deduplicated"] is False
        assert first_alert.json()["alert"]["occurrence_count"] == 1

        second_alert = await client.post(
            "/api/v1/telemetry/alerts/ingest", json=alert_payload, headers=OPERATOR_HEADERS
        )
        assert second_alert.status_code == 200
        assert second_alert.json()["deduplicated"] is True
        assert second_alert.json()["alert"]["occurrence_count"] == 2
        assert (
            second_alert.json()["alert"]["fingerprint"]
            == first_alert.json()["alert"]["fingerprint"]
        )

        # Triage firing alerts into an Incident -> sev1 due to outage + cites runbook
        triage_res = await client.post(
            "/api/v1/telemetry/incidents/triage",
            json={"service_name": "checkout-api"},
            headers=OPERATOR_HEADERS,
        )
        assert triage_res.status_code == 200
        inc = triage_res.json()
        assert inc["incident_key"] == "INC-1001"
        assert inc["severity"] == "sev1"
        assert len(inc["cited_runbook_ids_json"]) >= 1
        assert inc["alert_count"] >= 2

        # Resolve incident -> linked alerts transition to resolved
        resolve_res = await client.patch(
            f"/api/v1/telemetry/incidents/{inc['id']}/status",
            json={"status": "resolved", "assigned_to": "oncall@test.local"},
            headers=OPERATOR_HEADERS,
        )
        assert resolve_res.status_code == 200
        assert resolve_res.json()["status"] == "resolved"

        alerts_after = (
            await client.get(
                "/api/v1/telemetry/alerts?service_name=checkout-api", headers=OPERATOR_HEADERS
            )
        ).json()
        assert all(a["status"] == "resolved" for a in alerts_after)
