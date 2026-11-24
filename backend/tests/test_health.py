from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.auth import create_access_token
from app.core.config import Settings
from app.main import app, create_app
from tests.conftest import (
    APPROVER_HEADERS,
    OPERATOR_HEADERS,
    VIEWER_HEADERS,
    make_test_app,
)


@pytest.mark.asyncio
async def test_health_and_readiness_endpoints(tmp_path: Path) -> None:
    for path in ("/api/v1/health", "/api/v1/health/live"):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get(path)
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ok"
            assert data["service"] == "ai-it-admin"
            assert data["app_name"] == "AI IT Administrator"
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["x-frame-options"] == "DENY"

    isolated = make_test_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=isolated), base_url="http://test") as client:
        ready = await client.get("/api/v1/health/ready")
        assert ready.status_code == 200
        assert ready.json()["db_ready"] is True
        assert ready.json()["status"] == "ok"


def test_production_security_validation_rejects_default_secret() -> None:
    insecure = Settings(app_env="production")
    with pytest.raises(RuntimeError, match="AUTH_SECRET_KEY"):
        create_app(insecure)


@pytest.mark.asyncio
async def test_rbac_enforcement_and_bearer_auth(tmp_path: Path) -> None:
    isolated = make_test_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=isolated), base_url="http://test") as client:
        # Viewer cannot trigger mutations
        denied_scan = await client.post(
            "/api/v1/access-audit/scans",
            json={"scope": "all_saas"},
            headers=VIEWER_HEADERS,
        )
        assert denied_scan.status_code == 403

        # Seed demo to get a pending approval
        seed_res = await client.post("/api/v1/seed/demo", headers=APPROVER_HEADERS)
        assert seed_res.status_code == 200

        approvals = (
            await client.get("/api/v1/governance/approvals?status=pending", headers=VIEWER_HEADERS)
        ).json()
        assert len(approvals) >= 1

        # Operator cannot decide HITL approvals
        op_decide = await client.post(
            f"/api/v1/governance/approvals/{approvals[0]['id']}/decide",
            json={"decision": "approved", "notes": "operator attempt"},
            headers=OPERATOR_HEADERS,
        )
        assert op_decide.status_code == 403

        # Issue dev token and authenticate via Bearer scheme
        tok_res = await client.post(
            "/api/v1/auth/token",
            json={"email": "sre-bot@test.local", "role": "operator"},
        )
        assert tok_res.status_code == 200
        token = tok_res.json()["access_token"]

        me_res = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me_res.status_code == 200
        assert me_res.json()["email"] == "sre-bot@test.local"
        assert me_res.json()["auth_method"] == "bearer_token"

        bad_res = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid.jwt.sig"},
        )
        assert bad_res.status_code == 401


@pytest.mark.asyncio
async def test_strict_token_mode_blocks_dev_headers_and_expired_tokens(tmp_path: Path) -> None:
    secret = "strict-test-secret-key-at-least-32-bytes"
    strict_app = make_test_app(
        tmp_path,
        auth_require_token=True,
        auth_secret_key=secret,
    )
    async with AsyncClient(
        transport=ASGITransport(app=strict_app), base_url="http://test"
    ) as client:
        # Dev headers must be rejected when auth_require_token=True
        no_bearer = await client.get("/api/v1/auth/me", headers=APPROVER_HEADERS)
        assert no_bearer.status_code == 401

        expired = create_access_token("admin@test.local", "admin", secret, ttl_seconds=-10)
        exp_res = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {expired}"},
        )
        assert exp_res.status_code == 401

        # Non-admin bearer cannot mint tokens in strict mode
        op_token = create_access_token("op@test.local", "operator", secret)
        forbidden_mint = await client.post(
            "/api/v1/auth/token",
            json={"email": "new@test.local", "role": "viewer"},
            headers={"Authorization": f"Bearer {op_token}"},
        )
        assert forbidden_mint.status_code == 403

        # Admin bearer can mint tokens in strict mode
        admin_token = create_access_token("admin@test.local", "admin", secret)
        ok_mint = await client.post(
            "/api/v1/auth/token",
            json={"email": "new@test.local", "role": "viewer"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert ok_mint.status_code == 200
