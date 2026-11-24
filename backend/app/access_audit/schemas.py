from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class EntitlementCreateIn(BaseModel):
    app_name: str = Field(min_length=2, max_length=128)
    user_email: str = Field(min_length=3, max_length=255)
    account_status: Literal["active", "suspended", "orphaned"] = "active"
    assigned_role: str = Field(min_length=2, max_length=64)
    is_privileged: bool = False
    mfa_enabled: bool = True
    token_created_at: datetime | None = None
    token_last_used_at: datetime | None = None
    last_login_at: datetime | None = None
    expected_by_role: bool = True


class SaaSEntitlementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    app_name: str
    user_email: str
    account_status: str
    assigned_role: str
    is_privileged: bool
    mfa_enabled: bool
    token_created_at: datetime | None = None
    token_last_used_at: datetime | None = None
    last_login_at: datetime | None = None
    expected_by_role: bool
    created_at: datetime


class AccessScanIn(BaseModel):
    scope: str = Field(default="all_saas", max_length=128)


class AccessAuditRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scope: str
    total_entitlements_scanned: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    stale_tokens_count: int
    orphaned_accounts_count: int
    privilege_drift_count: int
    llm_summary: str
    llm_provider: str
    run_by: str
    created_at: datetime


class AccessFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    audit_run_id: str
    entitlement_id: str
    finding_type: str
    severity: str
    app_name: str
    user_email: str
    detail: str
    recommended_action: str
    status: str
    approval_id: str | None = None
    created_at: datetime
