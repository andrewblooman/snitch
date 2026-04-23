"""Tests for the Rules library API and policy rule membership endpoints."""

import uuid

import pytest
from httpx import AsyncClient

BASE = "/api/v1/rules"
POLICIES_BASE = "/api/v1/policies"


async def _create_policy(client: AsyncClient, **overrides) -> dict:
    payload = {
        "name": f"Test Policy {uuid.uuid4().hex[:6]}",
        "action": "inform",
        "min_severity": "medium",
        "enabled_scan_types": [],
        "rule_blocklist": [],
        "rule_allowlist": [],
        **overrides,
    }
    resp = await client.post(POLICIES_BASE, json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# GET /api/v1/rules — catalog listing
# ---------------------------------------------------------------------------


async def test_rules_list_returns_catalog(client: AsyncClient):
    resp = await client.get(BASE)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] > 0
    assert data["catalog_count"] >= 30  # static catalog has ~37 rules
    assert "items" in data


async def test_rules_list_has_expected_fields(client: AsyncClient):
    resp = await client.get(BASE)
    assert resp.status_code == 200
    item = resp.json()["items"][0]
    for field in ("id", "name", "description", "severity", "scanner", "scan_type",
                  "category", "remediation", "source", "policy_memberships"):
        assert field in item, f"Missing field: {field}"


async def test_rules_filter_by_scan_type_iac(client: AsyncClient):
    resp = await client.get(BASE, params={"scan_type": "iac"})
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) > 0
    assert all(r["scan_type"] == "iac" for r in items)


async def test_rules_filter_by_scanner_semgrep(client: AsyncClient):
    resp = await client.get(BASE, params={"scanner": "semgrep"})
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) > 0
    assert all(r["scanner"] == "semgrep" for r in items)


async def test_rules_filter_by_severity_critical(client: AsyncClient):
    resp = await client.get(BASE, params={"severity": "critical"})
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) > 0
    assert all(r["severity"] == "critical" for r in items)


async def test_rules_search_by_rule_id(client: AsyncClient):
    resp = await client.get(BASE, params={"search": "CKV_AWS_1"})
    assert resp.status_code == 200
    items = resp.json()["items"]
    ids = [r["id"] for r in items]
    assert "CKV_AWS_1" in ids


async def test_rules_search_by_keyword(client: AsyncClient):
    resp = await client.get(BASE, params={"search": "SQL injection"})
    assert resp.status_code == 200
    assert resp.json()["total"] > 0


async def test_rules_filter_by_source_catalog(client: AsyncClient):
    resp = await client.get(BASE, params={"source": "catalog"})
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert all(r["source"] == "catalog" for r in items)


async def test_rules_pagination(client: AsyncClient):
    resp = await client.get(BASE, params={"page": 1, "page_size": 5})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) <= 5
    assert data["pages"] >= 1


# ---------------------------------------------------------------------------
# Policy rule membership — POST /{policy_id}/rules
# ---------------------------------------------------------------------------


async def test_add_rule_to_blocklist(client: AsyncClient):
    policy = await _create_policy(client)
    pid = policy["id"]

    resp = await client.post(
        f"{POLICIES_BASE}/{pid}/rules",
        json={"rule_id": "CKV_AWS_1", "list_type": "blocklist"},
    )
    assert resp.status_code == 200
    assert "CKV_AWS_1" in resp.json()["rule_blocklist"]


async def test_add_rule_to_allowlist(client: AsyncClient):
    policy = await _create_policy(client)
    pid = policy["id"]

    resp = await client.post(
        f"{POLICIES_BASE}/{pid}/rules",
        json={"rule_id": "CKV_AWS_7", "list_type": "allowlist"},
    )
    assert resp.status_code == 200
    assert "CKV_AWS_7" in resp.json()["rule_allowlist"]


async def test_add_rule_idempotent(client: AsyncClient):
    policy = await _create_policy(client)
    pid = policy["id"]

    await client.post(f"{POLICIES_BASE}/{pid}/rules", json={"rule_id": "CKV_AWS_24", "list_type": "blocklist"})
    resp = await client.post(f"{POLICIES_BASE}/{pid}/rules", json={"rule_id": "CKV_AWS_24", "list_type": "blocklist"})
    assert resp.status_code == 200
    assert resp.json()["rule_blocklist"].count("CKV_AWS_24") == 1


async def test_add_rule_moves_between_lists(client: AsyncClient):
    """Adding a rule to blocklist should remove it from allowlist and vice-versa."""
    policy = await _create_policy(client, rule_allowlist=["CKV_AWS_20"])
    pid = policy["id"]

    resp = await client.post(
        f"{POLICIES_BASE}/{pid}/rules",
        json={"rule_id": "CKV_AWS_20", "list_type": "blocklist"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "CKV_AWS_20" in data["rule_blocklist"]
    assert "CKV_AWS_20" not in data["rule_allowlist"]


async def test_add_rule_missing_rule_id(client: AsyncClient):
    policy = await _create_policy(client)
    resp = await client.post(
        f"{POLICIES_BASE}/{policy['id']}/rules",
        json={"list_type": "blocklist"},
    )
    assert resp.status_code == 422


async def test_add_rule_invalid_list_type(client: AsyncClient):
    policy = await _create_policy(client)
    resp = await client.post(
        f"{POLICIES_BASE}/{policy['id']}/rules",
        json={"rule_id": "CKV_AWS_1", "list_type": "invalid"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Policy rule membership — DELETE /{policy_id}/rules/{rule_id}
# ---------------------------------------------------------------------------


async def test_remove_rule_from_blocklist(client: AsyncClient):
    policy = await _create_policy(client, rule_blocklist=["CKV_AWS_1", "CKV_AWS_7"])
    pid = policy["id"]

    resp = await client.delete(f"{POLICIES_BASE}/{pid}/rules/CKV_AWS_1", params={"list_type": "blocklist"})
    assert resp.status_code == 204

    updated = await client.get(f"{POLICIES_BASE}/{pid}")
    assert "CKV_AWS_1" not in updated.json()["rule_blocklist"]
    assert "CKV_AWS_7" in updated.json()["rule_blocklist"]


async def test_remove_rule_from_both_lists(client: AsyncClient):
    """Omitting list_type removes from both lists."""
    policy = await _create_policy(client, rule_blocklist=["CKV_AWS_36"])
    pid = policy["id"]

    resp = await client.delete(f"{POLICIES_BASE}/{pid}/rules/CKV_AWS_36")
    assert resp.status_code == 204

    updated = await client.get(f"{POLICIES_BASE}/{pid}")
    assert "CKV_AWS_36" not in updated.json()["rule_blocklist"]


# ---------------------------------------------------------------------------
# Policy memberships in rules list
# ---------------------------------------------------------------------------


async def test_rules_list_shows_policy_memberships(client: AsyncClient):
    policy = await _create_policy(client, rule_blocklist=["CKV_AWS_1"])
    pid = policy["id"]

    resp = await client.get(BASE, params={"search": "CKV_AWS_1"})
    assert resp.status_code == 200
    items = resp.json()["items"]
    ckv1 = next((r for r in items if r["id"] == "CKV_AWS_1"), None)
    assert ckv1 is not None
    memberships = ckv1["policy_memberships"]
    assert any(m["policy_id"] == pid and m["list_type"] == "blocklist" for m in memberships)
