from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SafeCommandItem(BaseModel):
    label: str = Field(min_length=2, max_length=128)
    command: str = Field(min_length=2, max_length=500)
    read_only: bool = True


class RunbookCreateIn(BaseModel):
    slug: str = Field(min_length=2, max_length=128)
    title: str = Field(min_length=3, max_length=255)
    service_name: str = Field(min_length=2, max_length=128)
    category: str = Field(min_length=2, max_length=64)
    severity_scope: str = Field(default="sev1,sev2", max_length=64)
    content_markdown: str = Field(min_length=10, max_length=50000)
    safe_commands: list[SafeCommandItem] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class RunbookOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    slug: str
    title: str
    service_name: str
    category: str
    severity_scope: str
    content_markdown: str
    safe_commands_json: list[dict[str, Any]]
    tags_json: list[str]
    updated_by: str
    created_at: datetime
    updated_at: datetime


class RunbookSearchIn(BaseModel):
    query: str = Field(min_length=2, max_length=2000)
    service_name: str | None = None
    top_k: int = Field(default=3, ge=1, le=10)


class RunbookSearchHit(BaseModel):
    runbook_id: str
    slug: str
    title: str
    service_name: str
    category: str
    score: float
    excerpt: str
    safe_commands: list[dict[str, Any]]


class RemediationAssistIn(BaseModel):
    query_text: str = Field(min_length=2, max_length=4000)
    incident_id: str | None = None
    service_name: str | None = None
    request_approval: bool = False


class RemediationDraftOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str | None = None
    query_text: str
    diagnosis_summary: str
    cited_runbooks_json: list[dict[str, Any]]
    proposed_steps_json: list[dict[str, Any]]
    blocked_shell_patterns_json: list[str]
    execution_mode: str
    llm_provider: str
    pii_redacted: bool
    status: str
    approval_id: str | None = None
    created_by: str
    created_at: datetime
