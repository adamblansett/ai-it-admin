from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.config import Settings
from app.db.models import AuditEvent
from app.llm.pii import redact_pii
from app.llm.router import LLMRouter
from tests.conftest import APPROVER_HEADERS, OPERATOR_HEADERS, make_test_app


def test_it_pii_and_secret_redaction() -> None:
    sample = (
        "Alert from 10.24.8.15 reported by ops.lead@acme-it.local (555-234-5678). "
        "SSN 123-45-6789. "
        "AWS key AKIA1234567890ABCDEF leaked with Authorization: Bearer "
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.signature123456 "
        "and api_key=ghp_supersecret1234567890abcd.\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtest\n-----END RSA PRIVATE KEY-----"
    )
    res = redact_pii(sample)
    assert "10.24.8.15" not in res.redacted_text
    assert "ops.lead@acme-it.local" not in res.redacted_text
    assert "555-234-5678" not in res.redacted_text
    assert "123-45-6789" not in res.redacted_text
    assert "AKIA1234567890ABCDEF" not in res.redacted_text
    assert "eyJhbGciOiJIUzI1NiIs" not in res.redacted_text
    assert "ghp_supersecret" not in res.redacted_text
    assert "MIIEowIBAAKCAQEAtest" not in res.redacted_text
    assert "[REDACTED_PRIVATE_KEY]" in res.redacted_text
    assert "[REDACTED_AWS_KEY]" in res.redacted_text
    assert "[REDACTED_TOKEN]" in res.redacted_text
    assert "[REDACTED_IP]" in res.redacted_text
    assert res.total_redactions >= 7


@pytest.mark.asyncio
async def test_llm_router_cloud_redaction_and_fallback() -> None:
    # 1. Successful Gemini adapter receives scrubbed prompt when redaction is enabled
    cfg = Settings(
        llm_default_provider="gemini",
        llm_fallback_providers="mock",
        gemini_api_key="test-key",
        llm_redact_pii_for_cloud=True,
    )
    router = LLMRouter(cfg)
    captured_prompts: list[str] = []

    class _FakeGemini:
        provider_name = "gemini"
        model_name = "gemini-2.5-flash"

        async def generate(self, prompt: str, system_prompt: str, task_type: str) -> str:
            _ = (system_prompt, task_type)
            captured_prompts.append(prompt)
            return "Cloud redacted diagnosis"

    router.adapters["gemini"] = _FakeGemini()
    resp = await router.generate(
        prompt="User alice@acme.local key AKIA1234567890ABCDEF host 192.168.10.4",
        task_type="incident_triage",
    )
    assert resp.provider == "gemini"
    assert resp.pii_redacted is True
    assert resp.redaction_count >= 3
    assert "alice@acme.local" not in captured_prompts[0]
    assert "AKIA1234567890ABCDEF" not in captured_prompts[0]
    assert "192.168.10.4" not in captured_prompts[0]

    # 2. Missing Gemini key falls back cleanly to deterministic mock provider
    fallback_cfg = Settings(
        llm_default_provider="gemini",
        llm_fallback_providers="mock",
        gemini_api_key="",
    )
    fallback_router = LLMRouter(fallback_cfg)
    fb_resp = await fallback_router.generate(prompt="Test fallback", task_type="incident_triage")
    assert fb_resp.provider == "mock"


@pytest.mark.asyncio
async def test_audit_hash_chain_verification_and_tamper_detection(tmp_path: Path) -> None:
    app = make_test_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/api/v1/seed/demo", headers=APPROVER_HEADERS)

        verify_ok = await client.get(
            "/api/v1/governance/audit/events/verify", headers=OPERATOR_HEADERS
        )
        assert verify_ok.status_code == 200
        v_data = verify_ok.json()
        assert v_data["valid"] is True
        assert v_data["total_events"] >= 5

        # Tamper directly with sequence #2 in SQLite and verify detection
        async with app.state.session_factory() as session:
            ev2 = (
                await session.execute(select(AuditEvent).where(AuditEvent.sequence_no == 2))
            ).scalar_one()
            ev2.action = "tampered_action"
            await session.commit()

        verify_tampered = await client.get(
            "/api/v1/governance/audit/events/verify", headers=OPERATOR_HEADERS
        )
        assert verify_tampered.status_code == 200
        t_data = verify_tampered.json()
        assert t_data["valid"] is False
        assert t_data["broken_sequence_no"] == 2
