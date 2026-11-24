from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import APPROVER_HEADERS, OPERATOR_HEADERS, make_test_app


@pytest.mark.asyncio
async def test_access_audit_scan_dedup_and_hitl_remediation(tmp_path: Path) -> None:
    app = make_test_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Seed base directory users & templates
        await client.post(
            "/api/v1/identity/templates",
            json={
                "code": "eng-backend",
                "name": "Backend Engineer",
                "department": "Engineering",
                "description": "Standard dev scope",
                "allowed_groups": ["eng"],
                "allowed_apps": [{"app": "GitHub", "role": "maintainer", "privileged": False}],
                "requires_mfa": True,
            },
            headers=APPROVER_HEADERS,
        )
        joiner = (
            await client.post(
                "/api/v1/identity/plans/preview",
                json={
                    "plan_type": "joiner",
                    "target_email": "dev.user@test.local",
                    "target_name": "Dev User",
                    "to_role_code": "eng-backend",
                },
                headers=OPERATOR_HEADERS,
            )
        ).json()
        await client.post(
            f"/api/v1/governance/approvals/{joiner['approval_id']}/decide",
            json={"decision": "approved", "notes": "ok"},
            headers=APPROVER_HEADERS,
        )

        old_ts = (datetime.now(UTC) - timedelta(days=125)).isoformat()
        recent_ts = (datetime.now(UTC) - timedelta(days=2)).isoformat()

        # Import stale token + privilege drift + missing MFA + orphaned account
        await client.post(
            "/api/v1/access-audit/entitlements",
            json={
                "app_name": "Datadog",
                "user_email": "dev.user@test.local",
                "account_status": "active",
                "assigned_role": "admin",
                "is_privileged": True,
                "mfa_enabled": False,
                "token_created_at": old_ts,
                "token_last_used_at": old_ts,
                "last_login_at": recent_ts,
                "expected_by_role": False,
            },
            headers=OPERATOR_HEADERS,
        )
        await client.post(
            "/api/v1/access-audit/entitlements",
            json={
                "app_name": "AWS",
                "user_email": "ghost.contractor@test.local",
                "account_status": "active",
                "assigned_role": "admin",
                "is_privileged": True,
                "mfa_enabled": True,
                "token_created_at": recent_ts,
                "token_last_used_at": recent_ts,
                "last_login_at": recent_ts,
                "expected_by_role": False,
            },
            headers=OPERATOR_HEADERS,
        )

        scan1 = await client.post(
            "/api/v1/access-audit/scans", json={"scope": "all_saas"}, headers=OPERATOR_HEADERS
        )
        assert scan1.status_code == 200
        run_data = scan1.json()
        assert run_data["orphaned_accounts_count"] >= 1
        assert run_data["stale_tokens_count"] >= 1
        assert run_data["privilege_drift_count"] >= 1

        findings = (
            await client.get("/api/v1/access-audit/findings", headers=OPERATOR_HEADERS)
        ).json()
        types_found = {f["finding_type"] for f in findings}
        assert {"orphaned_account", "stale_token", "privilege_drift", "missing_mfa"} <= types_found

        # Repeat scan must NOT duplicate open findings
        scan2 = await client.post(
            "/api/v1/access-audit/scans", json={"scope": "all_saas"}, headers=OPERATOR_HEADERS
        )
        assert scan2.status_code == 200
        findings_after_rescan = (
            await client.get("/api/v1/access-audit/findings", headers=OPERATOR_HEADERS)
        ).json()
        assert len(findings_after_rescan) == len(findings)

        # Request HITL remediation for orphaned account and approve -> entitlement suspended
        orphan = next(f for f in findings if f["finding_type"] == "orphaned_account")
        req_rem = await client.post(
            f"/api/v1/access-audit/findings/{orphan['id']}/request-remediation",
            headers=OPERATOR_HEADERS,
        )
        assert req_rem.status_code == 200
        assert req_rem.json()["status"] == "pending_approval"
        approval_id = req_rem.json()["approval_id"]

        decide = await client.post(
            f"/api/v1/governance/approvals/{approval_id}/decide",
            json={"decision": "approved", "notes": "Suspend orphaned AWS account"},
            headers=APPROVER_HEADERS,
        )
        assert decide.status_code == 200

        aws_ents = (
            await client.get(
                "/api/v1/access-audit/entitlements?app_name=AWS", headers=OPERATOR_HEADERS
            )
        ).json()
        ghost_ent = next(e for e in aws_ents if e["user_email"] == "ghost.contractor@test.local")
        assert ghost_ent["account_status"] == "suspended"

        # Approve privilege_drift remediation -> downgrades role to viewer & is_privileged=False
        drift = next(f for f in findings if f["finding_type"] == "privilege_drift")
        req_drift = await client.post(
            f"/api/v1/access-audit/findings/{drift['id']}/request-remediation",
            headers=OPERATOR_HEADERS,
        )
        await client.post(
            f"/api/v1/governance/approvals/{req_drift.json()['approval_id']}/decide",
            json={"decision": "approved", "notes": "Downgrade to viewer"},
            headers=APPROVER_HEADERS,
        )
        dd_ents = (
            await client.get(
                "/api/v1/access-audit/entitlements?app_name=Datadog", headers=OPERATOR_HEADERS
            )
        ).json()
        dd_ent = next(e for e in dd_ents if e["user_email"] == "dev.user@test.local")
        assert dd_ent["assigned_role"] == "viewer"
        assert dd_ent["is_privileged"] is False
