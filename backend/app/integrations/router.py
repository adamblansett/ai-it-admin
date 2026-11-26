from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor, get_current_actor, require_roles
from app.core.config import Settings, get_settings
from app.db.models import NotificationWebhook
from app.db.session import get_db
from app.integrations.schemas import (
    NotificationWebhookCreateIn,
    NotificationWebhookOut,
    WebhookTestIn,
    WebhookTestOut,
)
from app.integrations.service import create_notification_webhook, test_notification_webhook

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/webhooks", response_model=list[NotificationWebhookOut])
async def list_notification_webhooks(
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> list[NotificationWebhookOut]:
    """List configured outbound notification connectors."""
    rows = list(
        (
            await db.execute(
                select(NotificationWebhook).order_by(NotificationWebhook.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [NotificationWebhookOut.model_validate(row) for row in rows]


@router.post("/webhooks", response_model=NotificationWebhookOut)
async def post_create_notification_webhook(
    payload: NotificationWebhookCreateIn,
    actor: Actor = Depends(require_roles("it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> NotificationWebhookOut:
    """Register an SSRF-validated outbound Slack/PagerDuty/generic webhook."""
    webhook = await create_notification_webhook(
        db, payload=payload, settings=settings, actor=actor
    )
    return NotificationWebhookOut.model_validate(webhook)


@router.post("/webhooks/{webhook_id}/test", response_model=WebhookTestOut)
async def post_test_notification_webhook(
    webhook_id: str,
    payload: WebhookTestIn | None = None,
    actor: Actor = Depends(require_roles("operator", "it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> WebhookTestOut:
    """Test a notification webhook (defaults to PII-scrubbed dry-run preview)."""
    effective = payload or WebhookTestIn()
    return await test_notification_webhook(
        db,
        webhook_id=webhook_id,
        payload=effective,
        settings=settings,
        actor=actor,
    )
