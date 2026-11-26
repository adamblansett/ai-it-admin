import os

import pytest
from sqlalchemy import text

from app.db.session import build_engine

_RUN_LIVE = os.getenv("RUN_LIVE_INTEGRATION_TESTS") == "1"


@pytest.mark.integration
@pytest.mark.skipif(not _RUN_LIVE, reason="Set RUN_LIVE_INTEGRATION_TESTS=1 to run.")
@pytest.mark.asyncio
async def test_live_postgres_and_redis_connectivity() -> None:
    pg_url = os.getenv(
        "TEST_POSTGRES_URL",
        "postgresql+asyncpg://app:app@127.0.0.1:5432/ai_it_admin",
    )
    redis_url = os.getenv("TEST_REDIS_URL", "redis://127.0.0.1:6379/0")

    engine = build_engine(pg_url)
    try:
        async with engine.connect() as conn:
            res = await conn.execute(text("SELECT 1"))
            assert res.scalar_one() == 1
    finally:
        await engine.dispose()

    redis_async = pytest.importorskip("redis.asyncio")
    client = redis_async.from_url(redis_url)
    try:
        pong = await client.ping()
        assert pong is True
    finally:
        await client.aclose()
