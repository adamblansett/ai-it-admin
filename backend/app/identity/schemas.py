from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class RoleAppGrant(BaseModel):
    app: str = Field(min_length=2, max_length=128)
    role: str = Field(min_length=2, max_length=64)
    privileged: bool = False


class RoleTemplateCreateIn(BaseModel):
    code: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=2, max_length=128)
    department: str = Field(min_length=2, max_length=128)
    description: str = Field(min_length=5, max_length=1000)
    allowed_groups: list[str] = Field(default_factory=list)
    allowed_apps: list[RoleAppGrant] = Field(default_factory=list)
    requires_mfa: bool = True


class RoleTemplateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    code: str
    name: str
    department: str
    description: str
    allowed_groups_json: list[str]
    allowed_apps_json: list[dict[str, Any]]
    requires_mfa: bool
    created_at: datetime


class DirectoryUserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    employee_id: str
    email: str
    full_name: str
    department: str
    title: str
    role_template_code: str | None = None
    employment_status: str
    manager_email: str
    last_login_at: datetime | None = None
    mfa_enrolled: bool
    created_at: datetime
    updated_at: datetime
    active_entitlements_count: int = 0


class ProvisioningPreviewIn(BaseModel):
    plan_type: Literal["joiner", "mover", "leaver"]
    target_email: str = Field(min_length=3, max_length=255)
    target_name: str = Field(default="", max_length=255)
    department: str = Field(default="", max_length=128)
    from_role_code: str | None = None
    to_role_code: str | None = None
    scim_provider: Literal["okta", "entra_id", "google_workspace"] = "okta"
    requested_extra_apps: list[RoleAppGrant] = Field(default_factory=list)


class ProvisioningPlanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    plan_type: str
    target_email: str
    target_name: str
    department: str
    from_role_code: str | None = None
    to_role_code: str | None = None
    scim_provider: str
    scim_diff_json: list[dict[str, Any]]
    least_privilege_warnings_json: list[str]
    risk_level: str
    llm_rationale: str
    llm_provider: str
    status: str
    approval_id: str | None = None
    requested_by: str
    created_at: datetime
    applied_at: datetime | None = None
