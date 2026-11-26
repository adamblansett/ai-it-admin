from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class NotificationWebhookCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    channel_type: Literal["slack", "pagerduty", "generic"] = "slack"
    target_url: str = Field(min_length=8, max_length=1024)
    subscribed_events: list[str] = Field(
        default_factory=lambda: ["incident.triaged", "approval.pending"]
    )
    enabled: bool = True
    signing_secret_configured: bool = False


class NotificationWebhookOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    channel_type: str
    target_url: str
    subscribed_events_json: list[str]
    enabled: bool
    signing_secret_configured: bool
    last_delivery_status: str | None = None
    last_delivered_at: datetime | None = None
    created_by: str
    created_at: datetime


class WebhookTestIn(BaseModel):
    event_type: str = Field(default="incident.triaged", max_length=64)
    message: str = Field(
        default="Test notification from AI IT Administrator control plane.",
        max_length=2000,
    )
    dry_run: bool = True


class WebhookTestOut(BaseModel):
    webhook_id: str
    channel_type: str
    target_url: str
    dry_run: bool
    delivery_status: str
    pii_redacted_count: int
    headers_preview: dict[str, str]
    payload_preview: dict[str, Any]
