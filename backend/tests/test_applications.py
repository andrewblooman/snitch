import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_create_application(client: AsyncClient):
    payload = {
        "name": "test-api",
        "github_org": "test-org",
        "github_repo": "test-api",
        "repo_url": "https://github.com/test-org/test-api",
        "team_name": "Test Team",
        "language": "Python",
    }
    resp = await client.post("/api/v1/applications", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "test-api"
    assert data["risk_score"] == 0.0
    assert data["risk_level"] == "info"
    return data["id"]


@pytest.mark.asyncio
async def test_list_applications(client: AsyncClient):
    resp = await client.get("/api/v1/applications")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "pages" in data


@pytest.mark.asyncio
async def test_get_application_not_found(client: AsyncClient):
    import uuid
    resp = await client.get(f"/api/v1/applications/{uuid.uuid4()}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_and_get_application(client: AsyncClient):
    payload = {
        "name": "another-api",
        "github_org": "my-org",
        "github_repo": "another-api",
        "repo_url": "https://github.com/my-org/another-api",
        "team_name": "Security",
        "language": "Go",
    }
    create_resp = await client.post("/api/v1/applications", json=payload)
    assert create_resp.status_code == 201
    app_id = create_resp.json()["id"]

    get_resp = await client.get(f"/api/v1/applications/{app_id}")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["name"] == "another-api"
    assert data["team_name"] == "Security"


@pytest.mark.asyncio
async def test_update_application(client: AsyncClient):
    payload = {
        "name": "update-test-api",
        "github_org": "org",
        "github_repo": "repo",
        "repo_url": "https://github.com/org/repo",
        "team_name": "OldTeam",
    }
    create_resp = await client.post("/api/v1/applications", json=payload)
    assert create_resp.status_code == 201
    app_id = create_resp.json()["id"]

    update_resp = await client.put(f"/api/v1/applications/{app_id}", json={"team_name": "NewTeam"})
    assert update_resp.status_code == 200
    assert update_resp.json()["team_name"] == "NewTeam"


@pytest.mark.asyncio
async def test_delete_application(client: AsyncClient):
    payload = {
        "name": "delete-me",
        "github_org": "org",
        "github_repo": "delete-me",
        "repo_url": "https://github.com/org/delete-me",
        "team_name": "Team",
    }
    create_resp = await client.post("/api/v1/applications", json=payload)
    app_id = create_resp.json()["id"]

    del_resp = await client.delete(f"/api/v1/applications/{app_id}")
    assert del_resp.status_code == 204

    get_resp = await client.get(f"/api/v1/applications/{app_id}")
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_trigger_scan(client: AsyncClient):
    payload = {
        "name": "scan-test-api",
        "github_org": "org",
        "github_repo": "scan-test",
        "repo_url": "https://github.com/org/scan-test",
        "team_name": "Platform",
    }
    create_resp = await client.post("/api/v1/applications", json=payload)
    app_id = create_resp.json()["id"]

    scan_resp = await client.post(f"/api/v1/applications/{app_id}/scan?scan_type=semgrep")
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["status"] == "completed"
    assert scan_data["findings_count"] >= 0


@pytest.mark.asyncio
async def test_get_application_findings(client: AsyncClient):
    payload = {
        "name": "findings-test-api",
        "github_org": "org",
        "github_repo": "findings-test",
        "repo_url": "https://github.com/org/findings-test",
        "team_name": "Product",
    }
    create_resp = await client.post("/api/v1/applications", json=payload)
    app_id = create_resp.json()["id"]

    await client.post(f"/api/v1/applications/{app_id}/scan?scan_type=all")

    resp = await client.get(f"/api/v1/applications/{app_id}/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert data["total"] >= 0


@pytest.mark.asyncio
async def test_filter_applications_by_team(client: AsyncClient):
    for i in range(3):
        await client.post("/api/v1/applications", json={
            "name": f"team-filter-app-{i}",
            "github_org": "org",
            "github_repo": f"repo-{i}",
            "repo_url": f"https://github.com/org/repo-{i}",
            "team_name": "FilterTeam",
        })

    resp = await client.get("/api/v1/applications?team=FilterTeam")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 3
    for item in data["items"]:
        assert item["team_name"] == "FilterTeam"
