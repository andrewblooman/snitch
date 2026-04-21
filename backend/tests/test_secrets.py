"""Tests for the Secrets findings and custom pattern API."""
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

BASE = "/api/v1/secrets"
FINDINGS_BASE = f"{BASE}/findings"
PATTERNS_BASE = f"{BASE}/patterns"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_application(client: AsyncClient) -> dict:
    name = f"TestApp-{uuid.uuid4().hex[:6]}"
    resp = await client.post(
        "/api/v1/applications",
        json={
            "name": name,
            "github_org": "test-org",
            "github_repo": name.lower(),
            "repo_url": "https://github.com/test-org/repo",
            "team_name": "security",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _insert_finding(db: AsyncSession, application_id, **overrides):
    from app.models.finding import Finding

    finding = Finding(
        application_id=application_id,
        title=overrides.get("title", f"Secret {uuid.uuid4().hex[:6]}"),
        description=overrides.get("description", "AWS key ****1234"),
        severity=overrides.get("severity", "high"),
        status=overrides.get("status", "open"),
        finding_type=overrides.get("finding_type", "secrets"),
        scanner=overrides.get("scanner", "gitleaks"),
        rule_id=overrides.get("rule_id", f"aws-key-{uuid.uuid4().hex[:4]}"),
        file_path=overrides.get("file_path", "src/config.py"),
    )
    db.add(finding)
    await db.flush()
    await db.refresh(finding)
    return finding


async def _create_pattern(client: AsyncClient, **overrides) -> dict:
    payload = {
        "name": f"Pattern-{uuid.uuid4().hex[:6]}",
        "pattern": r"MYKEY-[A-Z0-9]{32}",
        "severity": "high",
        **overrides,
    }
    resp = await client.post(PATTERNS_BASE, json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Findings — list
# ---------------------------------------------------------------------------


async def test_list_findings_empty(client: AsyncClient):
    resp = await client.get(FINDINGS_BASE)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data


async def test_list_findings_returns_only_secrets_type(client: AsyncClient, db_session: AsyncSession):
    app = await _create_application(client)
    app_id = uuid.UUID(app["id"])
    await _insert_finding(db_session, app_id, finding_type="secrets")
    await _insert_finding(db_session, app_id, finding_type="SAST")

    resp = await client.get(FINDINGS_BASE)
    assert resp.status_code == 200
    assert all(f["finding_type"] == "secrets" for f in resp.json()["items"])


async def test_list_findings_filter_by_application(client: AsyncClient, db_session: AsyncSession):
    app1 = await _create_application(client)
    app2 = await _create_application(client)
    await _insert_finding(db_session, uuid.UUID(app1["id"]))
    await _insert_finding(db_session, uuid.UUID(app2["id"]))

    resp = await client.get(FINDINGS_BASE, params={"application_id": app1["id"]})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert all(f["application_id"] == app1["id"] for f in data["items"])


async def test_list_findings_filter_by_severity(client: AsyncClient, db_session: AsyncSession):
    app = await _create_application(client)
    app_id = uuid.UUID(app["id"])
    await _insert_finding(db_session, app_id, severity="critical")
    await _insert_finding(db_session, app_id, severity="low")

    resp = await client.get(FINDINGS_BASE, params={"application_id": app["id"], "severity": "critical"})
    assert resp.status_code == 200
    assert all(f["severity"] == "critical" for f in resp.json()["items"])


async def test_list_findings_filter_by_status(client: AsyncClient, db_session: AsyncSession):
    app = await _create_application(client)
    app_id = uuid.UUID(app["id"])
    await _insert_finding(db_session, app_id, status="open")
    await _insert_finding(db_session, app_id, status="accepted")

    resp = await client.get(FINDINGS_BASE, params={"application_id": app["id"], "status": "accepted"})
    assert resp.status_code == 200
    assert all(f["status"] == "accepted" for f in resp.json()["items"])


# ---------------------------------------------------------------------------
# Findings — get
# ---------------------------------------------------------------------------


async def test_get_finding(client: AsyncClient, db_session: AsyncSession):
    app = await _create_application(client)
    finding = await _insert_finding(db_session, uuid.UUID(app["id"]))
    resp = await client.get(f"{FINDINGS_BASE}/{finding.id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == str(finding.id)


async def test_get_finding_not_found(client: AsyncClient):
    resp = await client.get(f"{FINDINGS_BASE}/{uuid.uuid4()}")
    assert resp.status_code == 404


async def test_get_finding_wrong_type_returns_404(client: AsyncClient, db_session: AsyncSession):
    app = await _create_application(client)
    finding = await _insert_finding(db_session, uuid.UUID(app["id"]), finding_type="SAST")
    resp = await client.get(f"{FINDINGS_BASE}/{finding.id}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Findings — patch
# ---------------------------------------------------------------------------


async def test_patch_finding_status(client: AsyncClient, db_session: AsyncSession):
    app = await _create_application(client)
    finding = await _insert_finding(db_session, uuid.UUID(app["id"]), status="open")
    resp = await client.patch(f"{FINDINGS_BASE}/{finding.id}", json={"status": "accepted"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "accepted"


async def test_patch_finding_not_found(client: AsyncClient):
    resp = await client.patch(f"{FINDINGS_BASE}/{uuid.uuid4()}", json={"status": "accepted"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Findings — stats
# ---------------------------------------------------------------------------


async def test_stats_returns_expected_fields(client: AsyncClient):
    resp = await client.get(f"{FINDINGS_BASE}/stats")
    assert resp.status_code == 200
    data = resp.json()
    for key in ("total", "critical", "high", "medium", "low", "open", "accepted", "false_positive", "by_rule"):
        assert key in data, f"missing key: {key}"


async def test_stats_counts_by_severity(client: AsyncClient, db_session: AsyncSession):
    app = await _create_application(client)
    app_id = uuid.UUID(app["id"])
    await _insert_finding(db_session, app_id, severity="critical")
    await _insert_finding(db_session, app_id, severity="critical")
    await _insert_finding(db_session, app_id, severity="medium")

    resp = await client.get(f"{FINDINGS_BASE}/stats", params={"application_id": app["id"]})
    assert resp.status_code == 200
    data = resp.json()
    assert data["critical"] == 2
    assert data["medium"] == 1
    assert data["total"] == 3


async def test_stats_filter_by_application(client: AsyncClient, db_session: AsyncSession):
    app1 = await _create_application(client)
    app2 = await _create_application(client)
    await _insert_finding(db_session, uuid.UUID(app1["id"]), severity="high")
    await _insert_finding(db_session, uuid.UUID(app2["id"]), severity="critical")

    resp = await client.get(f"{FINDINGS_BASE}/stats", params={"application_id": app1["id"]})
    data = resp.json()
    assert data["total"] == 1
    assert data["high"] == 1
    assert data["critical"] == 0


# ---------------------------------------------------------------------------
# Patterns — list
# ---------------------------------------------------------------------------


async def test_list_patterns_empty(client: AsyncClient):
    resp = await client.get(PATTERNS_BASE)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data


async def test_list_patterns_with_data(client: AsyncClient):
    await _create_pattern(client)
    resp = await client.get(PATTERNS_BASE)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1


# ---------------------------------------------------------------------------
# Patterns — create
# ---------------------------------------------------------------------------


async def test_create_pattern(client: AsyncClient):
    data = await _create_pattern(client, name=f"MyPattern-{uuid.uuid4().hex[:6]}", severity="critical")
    assert data["severity"] == "critical"
    assert data["is_active"] is True
    assert "id" in data


async def test_create_pattern_invalid_regex(client: AsyncClient):
    resp = await client.post(PATTERNS_BASE, json={"name": "Bad", "pattern": "[invalid(", "severity": "high"})
    assert resp.status_code == 422


async def test_create_pattern_invalid_severity(client: AsyncClient):
    resp = await client.post(PATTERNS_BASE, json={"name": "Bad2", "pattern": r"\d+", "severity": "extreme"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Patterns — get
# ---------------------------------------------------------------------------


async def test_get_pattern(client: AsyncClient):
    pattern = await _create_pattern(client)
    resp = await client.get(f"{PATTERNS_BASE}/{pattern['id']}")
    assert resp.status_code == 200
    assert resp.json()["id"] == pattern["id"]


async def test_get_pattern_not_found(client: AsyncClient):
    resp = await client.get(f"{PATTERNS_BASE}/{uuid.uuid4()}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Patterns — update
# ---------------------------------------------------------------------------


async def test_update_pattern(client: AsyncClient):
    pattern = await _create_pattern(client)
    resp = await client.put(
        f"{PATTERNS_BASE}/{pattern['id']}",
        json={"name": pattern["name"], "pattern": r"\d{16}", "severity": "critical", "is_active": False},
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["severity"] == "critical"
    assert updated["is_active"] is False


async def test_update_pattern_invalid_regex(client: AsyncClient):
    pattern = await _create_pattern(client)
    resp = await client.put(
        f"{PATTERNS_BASE}/{pattern['id']}",
        json={"name": pattern["name"], "pattern": "[broken(", "severity": "high"},
    )
    assert resp.status_code == 422


async def test_update_pattern_not_found(client: AsyncClient):
    resp = await client.put(
        f"{PATTERNS_BASE}/{uuid.uuid4()}",
        json={"name": "x", "pattern": r"\d+", "severity": "low"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Patterns — delete
# ---------------------------------------------------------------------------


async def test_delete_pattern(client: AsyncClient):
    pattern = await _create_pattern(client)
    resp = await client.delete(f"{PATTERNS_BASE}/{pattern['id']}")
    assert resp.status_code == 204
    resp2 = await client.get(f"{PATTERNS_BASE}/{pattern['id']}")
    assert resp2.status_code == 404


async def test_delete_pattern_not_found(client: AsyncClient):
    resp = await client.delete(f"{PATTERNS_BASE}/{uuid.uuid4()}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Patterns — test regex
# ---------------------------------------------------------------------------


async def test_pattern_test_valid_with_matches(client: AsyncClient):
    resp = await client.post(
        f"{PATTERNS_BASE}/test",
        json={"pattern": r"MYKEY-[A-Z0-9]{32}", "sample_text": "found MYKEY-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 here"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["match_count"] == 1
    assert len(data["matches"]) == 1


async def test_pattern_test_valid_no_matches(client: AsyncClient):
    resp = await client.post(
        f"{PATTERNS_BASE}/test",
        json={"pattern": r"SECRET-\d{10}", "sample_text": "nothing to see here"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["match_count"] == 0


async def test_pattern_test_invalid_regex(client: AsyncClient):
    resp = await client.post(
        f"{PATTERNS_BASE}/test",
        json={"pattern": "[invalid(", "sample_text": "any text"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["match_count"] == 0
    assert data["error"] is not None
