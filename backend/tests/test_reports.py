import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_overview_empty(client: AsyncClient):
    resp = await client.get("/api/v1/reports/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_apps" in data
    assert "total_findings" in data
    assert "avg_risk_score" in data
    assert "apps_by_risk_level" in data


@pytest.mark.asyncio
async def test_leaderboard_empty(client: AsyncClient):
    resp = await client.get("/api/v1/reports/leaderboard")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_trend_empty(client: AsyncClient):
    resp = await client.get("/api/v1/reports/trend")
    assert resp.status_code == 200
    data = resp.json()
    assert "data_points" in data
    assert "period_days" in data
    assert data["period_days"] == 90


@pytest.mark.asyncio
async def test_pull_requests_empty(client: AsyncClient):
    resp = await client.get("/api/v1/reports/pull-requests")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_top_vulnerabilities_empty(client: AsyncClient):
    resp = await client.get("/api/v1/reports/top-vulnerabilities")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_overview_with_data(client: AsyncClient):
    from unittest.mock import MagicMock, patch

    create_resp = await client.post("/api/v1/applications", json={
        "name": "report-test-app",
        "github_org": "org",
        "github_repo": "report-test",
        "repo_url": "https://github.com/org/report-test",
        "team_name": "ReportTeam",
    })
    app_id = create_resp.json()["id"]

    mock_task = MagicMock()
    mock_task.delay = MagicMock(return_value=MagicMock(id="mock-task-id"))
    with patch("app.worker.tasks.scan_application_task", mock_task):
        await client.post(f"/api/v1/applications/{app_id}/scan?scan_type=all")

    resp = await client.get("/api/v1/reports/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_apps"] >= 1
    assert data["total_findings"] >= 0


@pytest.mark.asyncio
async def test_leaderboard_with_data(client: AsyncClient):
    await client.post("/api/v1/applications", json={
        "name": "leaderboard-app",
        "github_org": "org",
        "github_repo": "leaderboard",
        "repo_url": "https://github.com/org/leaderboard",
        "team_name": "LeaderTeam",
    })

    resp = await client.get("/api/v1/reports/leaderboard")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    if data:
        first = data[0]
        assert "rank" in first
        assert "team_name" in first
        assert "avg_risk_score" in first
        # Verify sorted ascending by risk score (lower = better, rank 1)
        for i in range(len(data) - 1):
            assert data[i]["avg_risk_score"] <= data[i + 1]["avg_risk_score"]


@pytest.mark.asyncio
async def test_trend_with_days_param(client: AsyncClient):
    resp = await client.get("/api/v1/reports/trend?days=30")
    assert resp.status_code == 200
    data = resp.json()
    assert data["period_days"] == 30
    assert len(data["data_points"]) == 30


@pytest.mark.asyncio
async def test_top_vulnerabilities_with_data(client: AsyncClient):
    from unittest.mock import MagicMock, patch

    create_resp = await client.post("/api/v1/applications", json={
        "name": "vuln-test-app",
        "github_org": "org",
        "github_repo": "vuln-test",
        "repo_url": "https://github.com/org/vuln-test",
        "team_name": "VulnTeam",
    })
    app_id = create_resp.json()["id"]

    mock_task = MagicMock()
    mock_task.delay = MagicMock(return_value=MagicMock(id="mock-task-id"))
    with patch("app.worker.tasks.scan_application_task", mock_task):
        await client.post(f"/api/v1/applications/{app_id}/scan?scan_type=trivy")

    resp = await client.get("/api/v1/reports/top-vulnerabilities")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_finding_stats(client: AsyncClient):
    resp = await client.get("/api/v1/findings/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "critical" in data
    assert "by_scanner" in data
    assert "by_type" in data
