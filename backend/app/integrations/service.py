import hashlib
import hmac
import json
from typing import Any

import httpx
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor
from app.core.config import Settings
from app.db.base import utcnow
from app.db.models import NotificationWebhook
from app.governance.service import record_audit_event
from app.integrations.schemas import NotificationWebhookCreateIn, WebhookTestIn, WebhookTestOut
from app.integrations.ssrf import validate_webhook_url
from app.llm.pii import redact_pii


async def create_notification_webhook(
    db: AsyncSession,
    *,
    payload: NotificationWebhookCreateIn,
    settings: Settings,
    actor: Actor,
) -> NotificationWebhook:
    """Validate URL against SSRF rules and persist a NotificationWebhook."""
    clean_url = validate_webhook_url(payload.target_url, app_env=settings.app_env)
    webhook = NotificationWebhook(
        name=payload.name.strip(),
        channel_type=payload.channel_type,
        target_url=clean_url,
        subscribed_events_json=[e.strip() for e in payload.subscribed_events if e.strip()],
        enabled=payload.enabled,
        signing_secret_configured=payload.signing_secret_configured
        or bool(settings.webhook_secret.strip()),
        created_by=actor.email,
    )
    db.add(webhook)
    await db.flush()

    await record_audit_event(
        db,
        event_type="integrations.webhook_created",
        actor=actor,
        entity_type="notification_webhook",
        entity_id=webhook.id,
        action="created",
        details={
            "name": webhook.name,
            "channel_type": webhook.channel_type,
            "target_url": webhook.target_url,
        },
    )
    await db.commit()
    await db.refresh(webhook)
    return webhook


def _build_channel_payload(
    *,
    channel_type: str,
    webhook_name: str,
    event_type: str,
    safe_message: str,
) -> dict[str, Any]:
    if channel_type == "slack":
        return {
            "text": f"[AI IT Admin · {event_type}] {safe_message}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{webhook_name}* (`{event_type}`)\n{safe_message}",
                    },
                }
            ],
        }
    if channel_type == "pagerduty":
        return {
            "event_action": "trigger",
            "payload": {
                "summary": f"[{event_type}] {safe_message}",
                "source": "ai-it-admin",
                "severity": "warning",
                "custom_details": {"connector": webhook_name},
            },
        }
    return {
        "source": "ai-it-admin",
        "connector": webhook_name,
        "event_type": event_type,
        "message": safe_message,
    }


async def test_notification_webhook(
    db: AsyncSession,
    *,
    webhook_id: str,
    payload: WebhookTestIn,
    settings: Settings,
    actor: Actor,
) -> WebhookTestOut:
    """Render a PII-scrubbed signed webhook test payload (dry-run or live delivery)."""
    webhook = await db.get(NotificationWebhook, webhook_id)
    if webhook is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Notification webhook '{webhook_id}' not found.",
        )

    clean_url = validate_webhook_url(webhook.target_url, app_env=settings.app_env)
    redaction = redact_pii(payload.message)
    body_dict = _build_channel_payload(
        channel_type=webhook.channel_type,
        webhook_name=webhook.name,
        event_type=payload.event_type,
        safe_message=redaction.redacted_text,
    )
    raw_bytes = json.dumps(body_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

    headers = {"Content-Type": "application/json", "X-AI-IT-Admin-Event": payload.event_type}
    if settings.webhook_secret.strip():
        sig = hmac.new(
            settings.webhook_secret.strip().encode("utf-8"), raw_bytes, hashlib.sha256
        ).hexdigest()
        headers["X-Webhook-Signature"] = f"sha256={sig}"

    if payload.dry_run:
        delivery_status = "dry_run_ok"
    else:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(clean_url, content=raw_bytes, headers=headers)
            resp.raise_for_status()
            delivery_status = f"delivered_http_{resp.status_code}"

    webhook.last_delivery_status = delivery_status
    webhook.last_delivered_at = utcnow()

    await record_audit_event(
        db,
        event_type="integrations.webhook_tested",
        actor=actor,
        entity_type="notification_webhook",
        entity_id=webhook.id,
        action="dry_run" if payload.dry_run else "delivered",
        details={
            "delivery_status": delivery_status,
            "pii_redacted_count": redaction.total_redactions,
        },
    )
    await db.commit()

    return WebhookTestOut(
        webhook_id=webhook.id,
        channel_type=webhook.channel_type,
        target_url=clean_url,
        dry_run=payload.dry_run,
        delivery_status=delivery_status,
        pii_redacted_count=redaction.total_redactions,
        headers_preview=headers,
        payload_preview=body_dict,
    )
