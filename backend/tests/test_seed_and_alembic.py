import asyncio
from pathlib import Path

import pytest
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import inspect

from alembic import command
from app.db.session import build_engine
from tests.conftest import APPROVER_HEADERS, make_test_app


@pytest.mark.asyncio
async def test_seed_idempotency_reset_and_overview_kpis(tmp_path: Path) -> None:
    app = make_test_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/api/v1/seed/demo", headers=APPROVER_HEADERS)
        assert first.status_code == 200
        assert first.json()["seeded"] is True
        assert first.json()["role_templates"] == 5
        assert first.json()["services"] == 5

        second = await client.post("/api/v1/seed/demo", headers=APPROVER_HEADERS)
        assert second.status_code == 200
        assert second.json()["seeded"] is False

        overview = await client.get("/api/v1/overview", headers=APPROVER_HEADERS)
        assert overview.status_code == 200
        ov = overview.json()
        assert ov["active_users"] >= 4
        assert ov["services_total"] == 5
        assert ov["expiring_certs_count"] >= 1
        assert ov["quota_warnings_count"] >= 1
        assert ov["pending_approvals_count"] >= 3
        assert ov["open_access_findings"] >= 4
        assert ov["runbooks_count"] == 5
        assert ov["audit_chain_valid"] is True

        # Clean reset re-establishes GENESIS-linked audit chain from sequence_no=1
        reset_res = await client.post("/api/v1/seed/demo?reset=true", headers=APPROVER_HEADERS)
        assert reset_res.status_code == 200
        assert reset_res.json()["seeded"] is True

        verify = await client.get(
            "/api/v1/governance/audit/events/verify", headers=APPROVER_HEADERS
        )
        assert verify.status_code == 200
        assert verify.json()["valid"] is True


def test_alembic_initial_migration_creates_all_tables(tmp_path: Path) -> None:
    backend_dir = Path(__file__).resolve().parents[1]
    db_path = tmp_path / "alembic_test.db"
    db_url = f"sqlite+aiosqlite:///{db_path.as_posix()}"

    alembic_cfg = Config(str(backend_dir / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(alembic_cfg, "head")

    async def _list_tables() -> set[str]:
        engine = build_engine(db_url)
        try:
            async with engine.connect() as conn:
                return await conn.run_sync(
                    lambda sync_conn: set(inspect(sync_conn).get_table_names())
                )
        finally:
            await engine.dispose()

    tables = asyncio.run(_list_tables())
    expected = {
        "approval_requests",
        "directory_users",
        "role_templates",
        "provisioning_plans",
        "service_checks",
        "incidents",
        "telemetry_alerts",
        "saas_entitlements",
        "access_audit_runs",
        "access_findings",
        "runbooks",
        "remediation_drafts",
        "audit_events",
        "alembic_version",
    }
    assert expected <= tables
