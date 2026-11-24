from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import APPROVER_HEADERS, OPERATOR_HEADERS, make_test_app


@pytest.mark.asyncio
async def test_joiner_mover_leaver_scim_hitl_lifecycle(tmp_path: Path) -> None:
    app = make_test_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create two role templates
        t_eng = await client.post(
            "/api/v1/identity/templates",
            json={
                "code": "eng-backend",
                "name": "Backend Engineer",
                "department": "Engineering",
                "description": "Least-privilege backend access",
                "allowed_groups": ["okta-eng", "github-devs"],
                "allowed_apps": [
                    {"app": "GitHub", "role": "maintainer", "privileged": False},
                    {"app": "Datadog", "role": "viewer", "privileged": False},
                ],
                "requires_mfa": True,
            },
            headers=APPROVER_HEADERS,
        )
        assert t_eng.status_code == 200

        t_sre = await client.post(
            "/api/v1/identity/templates",
            json={
                "code": "eng-sre",
                "name": "Site Reliability Engineer",
                "department": "Platform",
                "description": "Production SRE access",
                "allowed_groups": ["okta-platform", "sre-oncall"],
                "allowed_apps": [
                    {"app": "GitHub", "role": "admin", "privileged": True},
                    {"app": "AWS", "role": "prod-operator", "privileged": True},
                ],
                "requires_mfa": True,
            },
            headers=APPROVER_HEADERS,
        )
        assert t_sre.status_code == 200

        # 1. Joiner preview with extra privileged app triggers least-privilege warning
        joiner_res = await client.post(
            "/api/v1/identity/plans/preview",
            json={
                "plan_type": "joiner",
                "target_email": "alex.chen@test.local",
                "target_name": "Alex Chen",
                "to_role_code": "eng-backend",
                "scim_provider": "okta",
                "requested_extra_apps": [
                    {"app": "AWS", "role": "AdministratorAccess", "privileged": True}
                ],
            },
            headers=OPERATOR_HEADERS,
        )
        assert joiner_res.status_code == 200
        joiner_plan = joiner_res.json()
        assert joiner_plan["status"] == "pending_approval"
        assert joiner_plan["risk_level"] == "critical"
        assert any(
            "outside role template" in w for w in joiner_plan["least_privilege_warnings_json"]
        )

        # Directory must NOT be mutated before HITL approval
        users_before = (await client.get("/api/v1/identity/users", headers=OPERATOR_HEADERS)).json()
        assert not any(u["email"] == "alex.chen@test.local" for u in users_before)

        # Approve joiner plan -> creates user & grants entitlements atomically
        approve_joiner = await client.post(
            f"/api/v1/governance/approvals/{joiner_plan['approval_id']}/decide",
            json={"decision": "approved", "notes": "Approved for onboarding"},
            headers=APPROVER_HEADERS,
        )
        assert approve_joiner.status_code == 200
        assert approve_joiner.json()["status"] == "approved"

        users_after = (await client.get("/api/v1/identity/users", headers=OPERATOR_HEADERS)).json()
        alex = next(u for u in users_after if u["email"] == "alex.chen@test.local")
        assert alex["employment_status"] == "active"
        assert alex["role_template_code"] == "eng-backend"
        assert alex["active_entitlements_count"] == 3  # GitHub, Datadog, AWS

        # 2. Mover preview: eng-backend -> eng-sre revokes Datadog and upgrades GitHub/AWS
        mover_res = await client.post(
            "/api/v1/identity/plans/preview",
            json={
                "plan_type": "mover",
                "target_email": "alex.chen@test.local",
                "to_role_code": "eng-sre",
                "scim_provider": "okta",
            },
            headers=OPERATOR_HEADERS,
        )
        assert mover_res.status_code == 200
        mover_plan = mover_res.json()
        diff_actions = {(op["action"], op["target"]) for op in mover_plan["scim_diff_json"]}
        assert ("revoke_app", "Datadog") in diff_actions
        assert ("grant_app", "GitHub") in diff_actions

        approve_mover = await client.post(
            f"/api/v1/governance/approvals/{mover_plan['approval_id']}/decide",
            json={"decision": "approved", "notes": "Role transfer confirmed"},
            headers=APPROVER_HEADERS,
        )
        assert approve_mover.status_code == 200

        users_moved = (await client.get("/api/v1/identity/users", headers=OPERATOR_HEADERS)).json()
        alex_moved = next(u for u in users_moved if u["email"] == "alex.chen@test.local")
        assert alex_moved["role_template_code"] == "eng-sre"
        assert alex_moved["active_entitlements_count"] == 2  # GitHub, AWS (Datadog suspended)

        # 3. Leaver preview -> reject leaves user active, approve terminates & suspends
        leaver_rej_plan = (
            await client.post(
                "/api/v1/identity/plans/preview",
                json={"plan_type": "leaver", "target_email": "alex.chen@test.local"},
                headers=OPERATOR_HEADERS,
            )
        ).json()
        assert leaver_rej_plan["risk_level"] == "critical"

        await client.post(
            f"/api/v1/governance/approvals/{leaver_rej_plan['approval_id']}/decide",
            json={"decision": "rejected", "notes": "Offboarding postponed"},
            headers=APPROVER_HEADERS,
        )
        users_still_active = (
            await client.get("/api/v1/identity/users", headers=OPERATOR_HEADERS)
        ).json()
        assert (
            next(u for u in users_still_active if u["email"] == "alex.chen@test.local")[
                "employment_status"
            ]
            == "active"
        )

        leaver_ok_plan = (
            await client.post(
                "/api/v1/identity/plans/preview",
                json={"plan_type": "leaver", "target_email": "alex.chen@test.local"},
                headers=OPERATOR_HEADERS,
            )
        ).json()
        await client.post(
            f"/api/v1/governance/approvals/{leaver_ok_plan['approval_id']}/decide",
            json={"decision": "approved", "notes": "Final day completed"},
            headers=APPROVER_HEADERS,
        )
        users_termed = (await client.get("/api/v1/identity/users", headers=OPERATOR_HEADERS)).json()
        alex_termed = next(u for u in users_termed if u["email"] == "alex.chen@test.local")
        assert alex_termed["employment_status"] == "terminated"
        assert alex_termed["active_entitlements_count"] == 0
