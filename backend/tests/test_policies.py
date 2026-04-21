"""Tests for the Policy CRUD API and policy evaluation logic."""
import uuid

import pytest
from httpx import AsyncClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE = "/api/v1/policies"


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
    resp = await client.post(BASE, json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


async def test_create_policy(client: AsyncClient):
    data = await _create_policy(
        client,
        name="SAST Policy",
        action="block",
        min_severity="high",
        enabled_scan_types=["sast"],
    )
    assert data["name"] == "SAST Policy"
    assert data["action"] == "block"
    assert data["min_severity"] == "high"
    assert data["enabled_scan_types"] == ["sast"]
    assert data["is_active"] is False
    assert "id" in data


async def test_create_policy_duplicate_name(client: AsyncClient):
    name = f"Unique-{uuid.uuid4().hex[:6]}"
    await _create_policy(client, name=name)
    resp = await client.post(BASE, json={"name": name, "action": "inform", "min_severity": "low"})
    assert resp.status_code == 409


async def test_create_policy_invalid_action(client: AsyncClient):
    resp = await client.post(BASE, json={"name": "Bad", "action": "explode", "min_severity": "low"})
    assert resp.status_code == 422


async def test_create_policy_invalid_severity(client: AsyncClient):
    resp = await client.post(BASE, json={"name": "Bad2", "action": "inform", "min_severity": "extreme"})
    assert resp.status_code == 422


async def test_create_policy_invalid_scan_type(client: AsyncClient):
    resp = await client.post(
        BASE,
        json={"name": "Bad3", "action": "inform", "min_severity": "low", "enabled_scan_types": ["unknown_type"]},
    )
    assert resp.status_code == 422


async def test_get_policy(client: AsyncClient):
    policy = await _create_policy(client, name=f"GetMe-{uuid.uuid4().hex[:6]}")
    resp = await client.get(f"{BASE}/{policy['id']}")
    assert resp.status_code == 200
    assert resp.json()["id"] == policy["id"]


async def test_get_policy_not_found(client: AsyncClient):
    resp = await client.get(f"{BASE}/{uuid.uuid4()}")
    assert resp.status_code == 404


async def test_list_policies(client: AsyncClient):
    await _create_policy(client)
    resp = await client.get(BASE)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert data["total"] >= 1


async def test_list_policies_filter_active(client: AsyncClient):
    await _create_policy(client, is_active=True, name=f"ActivePolicy-{uuid.uuid4().hex[:6]}")
    resp = await client.get(f"{BASE}?is_active=true")
    assert resp.status_code == 200
    data = resp.json()
    assert all(p["is_active"] for p in data["items"])


async def test_update_policy(client: AsyncClient):
    policy = await _create_policy(client)
    resp = await client.patch(f"{BASE}/{policy['id']}", json={"is_active": True, "min_severity": "critical"})
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["is_active"] is True
    assert updated["min_severity"] == "critical"


async def test_update_policy_name_conflict(client: AsyncClient):
    p1 = await _create_policy(client, name=f"P1-{uuid.uuid4().hex[:6]}")
    p2 = await _create_policy(client, name=f"P2-{uuid.uuid4().hex[:6]}")
    resp = await client.patch(f"{BASE}/{p2['id']}", json={"name": p1["name"]})
    assert resp.status_code == 409


async def test_delete_policy(client: AsyncClient):
    policy = await _create_policy(client)
    resp = await client.delete(f"{BASE}/{policy['id']}")
    assert resp.status_code == 204
    resp2 = await client.get(f"{BASE}/{policy['id']}")
    assert resp2.status_code == 404


async def test_delete_policy_not_found(client: AsyncClient):
    resp = await client.delete(f"{BASE}/{uuid.uuid4()}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Policy evaluation logic
# ---------------------------------------------------------------------------


def _make_finding(**kwargs):
    """Build a minimal mock Finding object for unit tests."""
    from unittest.mock import MagicMock
    f = MagicMock()
    f.id = uuid.uuid4()
    f.title = kwargs.get("title", "Test finding")
    f.severity = kwargs.get("severity", "medium")
    f.status = kwargs.get("status", "open")
    f.scanner = kwargs.get("scanner", "semgrep")
    f.finding_type = kwargs.get("finding_type", "SAST")
    f.rule_id = kwargs.get("rule_id", None)
    f.cve_id = kwargs.get("cve_id", None)
    f.package_name = kwargs.get("package_name", None)
    return f


def _make_policy(**kwargs):
    from unittest.mock import MagicMock
    p = MagicMock()
    p.id = uuid.uuid4()
    p.name = kwargs.get("name", "Test Policy")
    p.is_active = kwargs.get("is_active", True)
    p.action = kwargs.get("action", "inform")
    p.min_severity = kwargs.get("min_severity", "medium")
    p.enabled_scan_types = kwargs.get("enabled_scan_types", [])
    p.rule_blocklist = kwargs.get("rule_blocklist", [])
    p.rule_allowlist = kwargs.get("rule_allowlist", [])
    return p


def test_evaluate_severity_threshold_flags_above():
    from app.services.policy_evaluator import evaluate_policy
    policy = _make_policy(min_severity="medium")
    findings = [
        _make_finding(severity="low"),      # below threshold — not flagged
        _make_finding(severity="medium"),   # at threshold — flagged
        _make_finding(severity="high"),     # above — flagged
        _make_finding(severity="critical"), # above — flagged
    ]
    result = evaluate_policy(policy, findings)
    assert result["total_violations"] == 3


def test_evaluate_severity_threshold_info_catches_all():
    from app.services.policy_evaluator import evaluate_policy
    policy = _make_policy(min_severity="info")
    findings = [_make_finding(severity=s) for s in ["info", "low", "medium", "high", "critical"]]
    result = evaluate_policy(policy, findings)
    assert result["total_violations"] == 5


def test_evaluate_ignores_non_open_findings():
    from app.services.policy_evaluator import evaluate_policy
    policy = _make_policy(min_severity="low")
    findings = [
        _make_finding(severity="critical", status="fixed"),
        _make_finding(severity="critical", status="accepted"),
        _make_finding(severity="critical", status="open"),
    ]
    result = evaluate_policy(policy, findings)
    assert result["total_violations"] == 1


def test_evaluate_blocklist_overrides_severity():
    from app.services.policy_evaluator import evaluate_policy
    policy = _make_policy(min_severity="critical", rule_blocklist=["CVE-2024-1234"])
    findings = [
        _make_finding(severity="low", cve_id="CVE-2024-1234"),  # below threshold but blocklisted
    ]
    result = evaluate_policy(policy, findings)
    assert result["total_violations"] == 1
    assert result["violations"][0]["reason"] == "blocklisted_rule"


def test_evaluate_allowlist_skips_finding():
    from app.services.policy_evaluator import evaluate_policy
    policy = _make_policy(min_severity="low", rule_allowlist=["python.lang.security.audit.dangerous-system-call"])
    findings = [
        _make_finding(severity="critical", rule_id="python.lang.security.audit.dangerous-system-call"),
    ]
    result = evaluate_policy(policy, findings)
    assert result["total_violations"] == 0


def test_evaluate_allowlist_beats_blocklist():
    from app.services.policy_evaluator import evaluate_policy
    policy = _make_policy(
        min_severity="critical",
        rule_blocklist=["CVE-2024-9999"],
        rule_allowlist=["CVE-2024-9999"],
    )
    findings = [_make_finding(severity="low", cve_id="CVE-2024-9999")]
    result = evaluate_policy(policy, findings)
    assert result["total_violations"] == 0


def test_evaluate_scan_type_filter():
    from app.services.policy_evaluator import evaluate_policy
    policy = _make_policy(min_severity="low", enabled_scan_types=["sast"])
    findings = [
        _make_finding(severity="critical", finding_type="SAST", scanner="semgrep"),   # included
        _make_finding(severity="critical", finding_type="container", scanner="grype"), # excluded
        _make_finding(severity="critical", finding_type="SCA", scanner="trivy"),       # excluded
    ]
    result = evaluate_policy(policy, findings)
    assert result["total_violations"] == 1


def test_evaluate_empty_scan_types_applies_to_all():
    from app.services.policy_evaluator import evaluate_policy
    policy = _make_policy(min_severity="low", enabled_scan_types=[])
    findings = [
        _make_finding(severity="high", finding_type="SAST", scanner="semgrep"),
        _make_finding(severity="high", finding_type="container", scanner="grype"),
        _make_finding(severity="high", finding_type="SCA", scanner="trivy"),
    ]
    result = evaluate_policy(policy, findings)
    assert result["total_violations"] == 3


def test_evaluate_action_block_sets_blocked():
    from app.services.policy_evaluator import evaluate_policy
    policy = _make_policy(min_severity="low", action="block")
    findings = [_make_finding(severity="high")]
    result = evaluate_policy(policy, findings)
    assert result["blocked"] is True


def test_evaluate_action_inform_does_not_block():
    from app.services.policy_evaluator import evaluate_policy
    policy = _make_policy(min_severity="low", action="inform")
    findings = [_make_finding(severity="high")]
    result = evaluate_policy(policy, findings)
    assert result["blocked"] is False


def test_evaluate_action_both_blocks():
    from app.services.policy_evaluator import evaluate_policy
    policy = _make_policy(min_severity="low", action="both")
    findings = [_make_finding(severity="high")]
    result = evaluate_policy(policy, findings)
    assert result["blocked"] is True


def test_evaluate_no_violations_never_blocks():
    from app.services.policy_evaluator import evaluate_policy
    policy = _make_policy(min_severity="critical", action="block")
    findings = [_make_finding(severity="low")]
    result = evaluate_policy(policy, findings)
    assert result["blocked"] is False
    assert result["total_violations"] == 0


# ---------------------------------------------------------------------------
# Evaluate API endpoints
# ---------------------------------------------------------------------------


async def test_evaluate_policy_endpoint(client: AsyncClient):
    policy = await _create_policy(client, is_active=True, min_severity="low")
    resp = await client.post(f"{BASE}/{policy['id']}/evaluate")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_violations" in data
    assert "violations" in data
    assert data["policy_id"] == policy["id"]


async def test_evaluate_all_active_endpoint(client: AsyncClient):
    await _create_policy(client, is_active=True, name=f"ActiveEval-{uuid.uuid4().hex[:6]}")
    resp = await client.get(f"{BASE}/evaluate/all")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# Seed endpoint
# ---------------------------------------------------------------------------


async def test_seed_creates_default_policies(client: AsyncClient):
    resp = await client.post(f"{BASE}/seed")
    assert resp.status_code == 201
    data = resp.json()
    assert data["policies_created"] == 5


async def test_seed_idempotent(client: AsyncClient):
    resp1 = await client.post(f"{BASE}/seed")
    assert resp1.status_code == 201
    assert resp1.json()["policies_created"] == 5

    resp2 = await client.post(f"{BASE}/seed")
    assert resp2.status_code == 201
    assert resp2.json()["policies_created"] == 0


async def test_seed_policy_names(client: AsyncClient):
    await client.post(f"{BASE}/seed")
    resp = await client.get(BASE, params={"page_size": 20})
    assert resp.status_code == 200
    names = {p["name"] for p in resp.json()["items"]}
    assert "Baseline SAST Policy" in names
    assert "Critical Vulnerability Block" in names
    assert "Secrets Detection" in names
    assert "IaC Security (CIS Level 1)" in names


async def test_seed_iac_policy_has_cis_rules(client: AsyncClient):
    await client.post(f"{BASE}/seed")
    resp = await client.get(BASE, params={"page_size": 20})
    policies = resp.json()["items"]
    iac_policy = next(p for p in policies if p["name"] == "IaC Security (CIS Level 1)")
    blocklist = iac_policy["rule_blocklist"]
    assert "CKV_AWS_1" in blocklist
    assert "CKV_AWS_24" in blocklist
    assert "CKV_AWS_20" in blocklist
    assert len(blocklist) >= 10


async def test_seed_all_policies_active(client: AsyncClient):
    await client.post(f"{BASE}/seed")
    resp = await client.get(BASE, params={"is_active": "true", "page_size": 20})
    assert resp.json()["total"] == 5
