from pathlib import Path
from typing import Any

from fastapi import FastAPI

from app.core.config import Settings
from app.main import create_app

APPROVER_HEADERS = {
    "X-Actor-Email": "approver@test.local",
    "X-Actor-Role": "it_approver",
}
OPERATOR_HEADERS = {
    "X-Actor-Email": "operator@test.local",
    "X-Actor-Role": "operator",
}
VIEWER_HEADERS = {
    "X-Actor-Email": "viewer@test.local",
    "X-Actor-Role": "viewer",
}
ADMIN_HEADERS = {
    "X-Actor-Email": "admin@test.local",
    "X-Actor-Role": "admin",
}


def make_test_app(tmp_path: Path, **overrides: Any) -> FastAPI:
    """Create an isolated FastAPI app backed by a per-test SQLite database."""
    db_file = tmp_path / "test_it_admin.db"
    cfg = Settings(
        database_url=f"sqlite+aiosqlite:///{db_file.as_posix()}",
        llm_default_provider="mock",
        auto_create_tables=True,
        seed_demo_data=False,
        **overrides,
    )
    return create_app(cfg)
