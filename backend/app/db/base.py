from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def ensure_utc(dt: datetime | None) -> datetime | None:
    """Normalize naive datetimes (e.g., returned by SQLite) to UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def new_uuid() -> str:
    """Return a new string UUID."""
    return str(uuid4())
