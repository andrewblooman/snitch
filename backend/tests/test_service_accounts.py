"""
Tests for service accounts: create, list, revoke, rotate, auth verify, push auth.
"""
import uuid as uuid_mod

import pytest
from httpx import AsyncClient

from app.core.auth import hash_token


@pytest.fixture
def sa_payload():
    # Use a unique name per test run to avoid DB conflicts (session-scoped engine)
    unique = uuid_mod.uuid4().hex[:8]
    return {"name": f"ci-sa-{unique}", "description": "Test SA", "team_name": "platform"}


async def create_sa(client: AsyncClient, payload: dict) -> dict:
    resp = await client.post("/api/v1/service-accounts", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestServiceAccountCRUD:
    async def test_create_returns_token(self, client: AsyncClient, sa_payload):
        data = await create_sa(client, sa_payload)
        assert data["token"].startswith("snitch_")
        assert data["token_prefix"] == data["token"][:12]
        assert data["is_active"] is True
        assert "token_hash" not in data

    async def test_create_duplicate_name_returns_409(self, client: AsyncClient, sa_payload):
        await create_sa(client, sa_payload)
        resp = await client.post("/api/v1/service-accounts", json=sa_payload)
        assert resp.status_code == 409

    async def test_list_service_accounts(self, client: AsyncClient, sa_payload):
        await create_sa(client, sa_payload)
        resp = await client.get("/api/v1/service-accounts")
        assert resp.status_code == 200
        accounts = resp.json()
        assert isinstance(accounts, list)
        assert any(a["name"] == sa_payload["name"] for a in accounts)

    async def test_revoke_sets_inactive(self, client: AsyncClient, sa_payload):
        data = await create_sa(client, sa_payload)
        sa_id = data["id"]
        resp = await client.delete(f"/api/v1/service-accounts/{sa_id}")
        assert resp.status_code == 204

        # Confirm revoked token is rejected at /auth/verify
        token = data["token"]
        resp = await client.get(
            "/api/v1/auth/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    async def test_revoke_nonexistent_returns_404(self, client: AsyncClient):
        resp = await client.delete(f"/api/v1/service-accounts/{uuid_mod.uuid4()}")
        assert resp.status_code == 404

    async def test_rotate_invalidates_old_token(self, client: AsyncClient, sa_payload):
        data = await create_sa(client, sa_payload)
        sa_id = data["id"]
        old_token = data["token"]

        rotate_resp = await client.post(f"/api/v1/service-accounts/{sa_id}/rotate")
        assert rotate_resp.status_code == 200
        new_data = rotate_resp.json()
        new_token = new_data["token"]

        assert new_token != old_token
        assert new_token.startswith("snitch_")

        # Old token should now be rejected
        resp = await client.get(
            "/api/v1/auth/verify",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        assert resp.status_code == 401

        # New token should work
        resp = await client.get(
            "/api/v1/auth/verify",
            headers={"Authorization": f"Bearer {new_token}"},
        )
        assert resp.status_code == 200


class TestAuthVerify:
    async def test_verify_valid_token(self, client: AsyncClient, sa_payload):
        data = await create_sa(client, sa_payload)
        token = data["token"]
        resp = await client.get(
            "/api/v1/auth/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["authenticated"] is True
        assert body["service_account"]["name"] == sa_payload["name"]
        assert body["service_account"]["team_name"] == sa_payload["team_name"]

    async def test_verify_missing_token_returns_401(self, client: AsyncClient):
        resp = await client.get("/api/v1/auth/verify")
        assert resp.status_code == 401

    async def test_verify_invalid_token_returns_401(self, client: AsyncClient):
        resp = await client.get(
            "/api/v1/auth/verify",
            headers={"Authorization": "Bearer snitch_thisisnotavalidtoken"},
        )
        assert resp.status_code == 401


class TestCiCdPushAuth:
    async def test_push_without_token_returns_401(self, client: AsyncClient):
        resp = await client.post(
            f"/api/v1/cicd-scans/push?application_id={uuid_mod.uuid4()}",
            json={"results": []},
        )
        assert resp.status_code == 401

    async def test_push_with_valid_token_but_missing_app_returns_404(
        self, client: AsyncClient, sa_payload
    ):
        data = await create_sa(client, sa_payload)
        token = data["token"]
        resp = await client.post(
            f"/api/v1/cicd-scans/push?application_id={uuid_mod.uuid4()}",
            json={"results": []},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404

    async def test_push_semgrep_results_creates_scan(self, client: AsyncClient, sa_payload):
        # Create an application first (with required fields)
        unique = uuid_mod.uuid4().hex[:8]
        app_resp = await client.post(
            "/api/v1/applications",
            json={
                "name": f"push-test-app-{unique}",
                "language": "python",
                "github_org": "test-org",
                "github_repo": "test-repo",
                "repo_url": "https://github.com/test-org/test-repo",
                "team_name": "platform",
            },
        )
        assert app_resp.status_code == 201, app_resp.text
        app_id = app_resp.json()["id"]

        data = await create_sa(client, sa_payload)
        token = data["token"]

        semgrep_payload = {
            "version": "1.0.0",
            "results": [
                {
                    "check_id": "python.security.injection",
                    "path": "app/views.py",
                    "start": {"line": 10, "col": 1},
                    "extra": {
                        "message": "SQL injection vulnerability",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-89"]},
                    },
                }
            ],
            "errors": [],
        }

        resp = await client.post(
            f"/api/v1/cicd-scans/push?application_id={app_id}&branch=main&commit_sha=abc123",
            json=semgrep_payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["scan_type"] == "semgrep"
        assert body["status"] == "completed"
        assert body["findings_count"] >= 1
