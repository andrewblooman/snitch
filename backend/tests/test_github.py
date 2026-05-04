"""
Tests for the GitHub service and the /api/v1/github/repos endpoint.
"""
from unittest.mock import MagicMock, patch, AsyncMock

import pytest
from httpx import AsyncClient

from app.services.github_service import list_accessible_repos


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_repo(full_name: str, private: bool = False, archived: bool = False, language: str = "Python"):
    owner_login, repo_name = full_name.split("/", 1)
    repo = MagicMock()
    repo.full_name = full_name
    repo.name = repo_name
    repo.owner.login = owner_login
    repo.description = f"Description for {repo_name}"
    repo.language = language
    repo.html_url = f"https://github.com/{full_name}"
    repo.private = private
    repo.archived = archived
    repo.default_branch = "main"
    from datetime import datetime, timezone
    repo.updated_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    return repo


_MOCK_PR_LIST = [
    {
        "pr_number": 42,
        "title": "Add authentication middleware",
        "state": "open",
        "author": "alice",
        "author_url": "https://github.com/alice",
        "pr_url": "https://github.com/acme/api/pull/42",
        "base_branch": "main",
        "head_branch": "feat/auth",
        "created_at": "2024-03-01T10:00:00Z",
        "updated_at": "2024-03-02T10:00:00Z",
        "merged_at": None,
        "closed_at": None,
        "draft": False,
        "merged": False,
    },
    {
        "pr_number": 41,
        "title": "Fix XSS vulnerability",
        "state": "closed",
        "author": "bob",
        "author_url": "https://github.com/bob",
        "pr_url": "https://github.com/acme/api/pull/41",
        "base_branch": "main",
        "head_branch": "fix/xss",
        "created_at": "2024-02-28T08:00:00Z",
        "updated_at": "2024-03-01T08:00:00Z",
        "merged_at": "2024-03-01T08:00:00Z",
        "closed_at": "2024-03-01T08:00:00Z",
        "draft": False,
        "merged": True,
    },
]


# ---------------------------------------------------------------------------
# list_accessible_repos unit tests
# ---------------------------------------------------------------------------

def test_list_accessible_repos_returns_formatted_dicts():
    mock_g = MagicMock()
    mock_g.get_user.return_value.get_repos.return_value = [
        _mock_repo("acme/api-service"),
        _mock_repo("acme/frontend", private=True),
    ]

    with patch("github.Github", return_value=mock_g):
        repos = list_accessible_repos("fake-token")

    assert len(repos) == 2

    first = repos[0]
    assert first["github_org"] == "acme"
    assert first["github_repo"] == "api-service"
    assert first["full_name"] == "acme/api-service"
    assert first["repo_url"] == "https://github.com/acme/api-service"
    assert first["private"] is False
    assert first["archived"] is False
    assert first["language"] == "Python"
    assert first["updated_at"] == "2024-01-01T00:00:00+00:00"

    second = repos[1]
    assert second["private"] is True


def test_list_accessible_repos_returns_empty_on_exception():
    with patch("github.Github", side_effect=Exception("network error")):
        repos = list_accessible_repos("bad-token")

    assert repos == []


def test_list_accessible_repos_includes_archived():
    mock_g = MagicMock()
    mock_g.get_user.return_value.get_repos.return_value = [
        _mock_repo("acme/old-service", archived=True),
    ]

    with patch("github.Github", return_value=mock_g):
        repos = list_accessible_repos("fake-token")

    assert len(repos) == 1
    assert repos[0]["archived"] is True


# ---------------------------------------------------------------------------
# GET /api/v1/github/repos endpoint tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_github_repos_no_token(client: AsyncClient):
    from app.core.config import settings as real_settings
    original = real_settings.GITHUB_TOKEN
    try:
        real_settings.GITHUB_TOKEN = ""
        resp = await client.get("/api/v1/github/repos")
        assert resp.status_code == 400
        assert "GITHUB_TOKEN" in resp.json()["detail"]
    finally:
        real_settings.GITHUB_TOKEN = original


@pytest.mark.asyncio
async def test_github_repos_returns_list(client: AsyncClient):
    from app.core.config import settings as real_settings
    mock_repos = [
        {
            "github_org": "acme",
            "github_repo": "api",
            "full_name": "acme/api",
            "description": "API service",
            "language": "Go",
            "repo_url": "https://github.com/acme/api",
            "private": False,
            "archived": False,
            "default_branch": "main",
            "updated_at": "2024-01-01T00:00:00+00:00",
        }
    ]

    original = real_settings.GITHUB_TOKEN
    try:
        real_settings.GITHUB_TOKEN = "fake-token"
        with patch("app.api.v1.github.list_accessible_repos", return_value=mock_repos):
            resp = await client.get("/api/v1/github/repos")
    finally:
        real_settings.GITHUB_TOKEN = original

    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    for item in data:
        assert "tracked" in item
        assert "application_id" in item


@pytest.mark.asyncio
async def test_github_repos_exclude_archived_by_default(client: AsyncClient):
    from app.core.config import settings as real_settings
    mock_repos = [
        {
            "github_org": "acme", "github_repo": "active",
            "full_name": "acme/active", "description": None,
            "language": "Python", "repo_url": "https://github.com/acme/active",
            "private": False, "archived": False,
            "default_branch": "main", "updated_at": None,
        },
        {
            "github_org": "acme", "github_repo": "old",
            "full_name": "acme/old", "description": None,
            "language": "Python", "repo_url": "https://github.com/acme/old",
            "private": False, "archived": True,
            "default_branch": "main", "updated_at": None,
        },
    ]

    original = real_settings.GITHUB_TOKEN
    try:
        real_settings.GITHUB_TOKEN = "fake-token"
        with patch("app.api.v1.github.list_accessible_repos", return_value=mock_repos):
            resp = await client.get("/api/v1/github/repos")
    finally:
        real_settings.GITHUB_TOKEN = original

    assert resp.status_code == 200
    data = resp.json()
    repos_returned = [r["github_repo"] for r in data]
    assert "active" in repos_returned
    assert "old" not in repos_returned


@pytest.mark.asyncio
async def test_github_repos_include_archived_when_requested(client: AsyncClient):
    from app.core.config import settings as real_settings
    mock_repos = [
        {
            "github_org": "acme", "github_repo": "old",
            "full_name": "acme/old", "description": None,
            "language": "Python", "repo_url": "https://github.com/acme/old",
            "private": False, "archived": True,
            "default_branch": "main", "updated_at": None,
        },
    ]

    original = real_settings.GITHUB_TOKEN
    try:
        real_settings.GITHUB_TOKEN = "fake-token"
        with patch("app.api.v1.github.list_accessible_repos", return_value=mock_repos):
            resp = await client.get("/api/v1/github/repos?include_archived=true")
    finally:
        real_settings.GITHUB_TOKEN = original

    assert resp.status_code == 200
    data = resp.json()
    assert any(r["github_repo"] == "old" for r in data)


@pytest.mark.asyncio
async def test_github_repos_marks_tracked_app(client: AsyncClient):
    """A repo already added as an Application should have tracked=True and an application_id."""
    from app.core.config import settings as real_settings

    create_resp = await client.post("/api/v1/applications", json={
        "name": "my-service",
        "github_org": "acme",
        "github_repo": "my-service",
        "repo_url": "https://github.com/acme/my-service",
        "team_name": "Platform",
    })
    assert create_resp.status_code == 201
    app_id = create_resp.json()["id"]

    mock_repos = [
        {
            "github_org": "acme", "github_repo": "my-service",
            "full_name": "acme/my-service", "description": None,
            "language": "Python", "repo_url": "https://github.com/acme/my-service",
            "private": False, "archived": False,
            "default_branch": "main", "updated_at": None,
        },
    ]

    original = real_settings.GITHUB_TOKEN
    try:
        real_settings.GITHUB_TOKEN = "fake-token"
        with patch("app.api.v1.github.list_accessible_repos", return_value=mock_repos):
            resp = await client.get("/api/v1/github/repos")
    finally:
        real_settings.GITHUB_TOKEN = original

    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["tracked"] is True
    assert data[0]["application_id"] == app_id


# ---------------------------------------------------------------------------
# GET /api/v1/github/apps/{app_id}/pr-reviews endpoint tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pr_reviews_app_not_found(client: AsyncClient):
    import uuid
    fake_id = str(uuid.uuid4())
    resp = await client.get(f"/api/v1/github/apps/{fake_id}/pr-reviews")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_pr_reviews_no_github_repo(client: AsyncClient):
    """An application with no GitHub repo configured should return 400."""
    create_resp = await client.post("/api/v1/applications", json={
        "name": "no-repo-app",
        "github_org": "",
        "github_repo": "",
        "repo_url": "https://example.com",
        "team_name": "Backend",
    })
    assert create_resp.status_code == 201
    app_id = create_resp.json()["id"]

    resp = await client.get(f"/api/v1/github/apps/{app_id}/pr-reviews")
    assert resp.status_code == 400
    assert "GitHub repository" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_pr_reviews_returns_prs_with_findings(client: AsyncClient):
    """PRs with linked findings should be included in findings_introduced."""
    create_resp = await client.post("/api/v1/applications", json={
        "name": "pr-test-app",
        "github_org": "acme",
        "github_repo": "api",
        "repo_url": "https://github.com/acme/api",
        "team_name": "Security",
    })
    assert create_resp.status_code == 201
    app_id = create_resp.json()["id"]

    with patch(
        "app.api.v1.github.fetch_pull_requests",
        new_callable=AsyncMock,
        return_value=_MOCK_PR_LIST,
    ):
        resp = await client.get(f"/api/v1/github/apps/{app_id}/pr-reviews")

    assert resp.status_code == 200
    data = resp.json()
    assert data["application_id"] == app_id
    assert data["github_org"] == "acme"
    assert data["github_repo"] == "api"
    assert data["total_prs"] == 2

    pr_numbers = [pr["pr_number"] for pr in data["prs"]]
    assert 42 in pr_numbers
    assert 41 in pr_numbers

    # No findings in DB for these PRs so both lists should be empty
    pr42 = next(pr for pr in data["prs"] if pr["pr_number"] == 42)
    assert pr42["findings_introduced"] == []
    assert pr42["findings_addressed"] == []
    assert pr42["state"] == "open"
    assert pr42["merged"] is False


@pytest.mark.asyncio
async def test_pr_reviews_introduced_finding_appears(client: AsyncClient, db_session):
    """An open finding linked to a PR should appear in findings_introduced."""
    import uuid

    create_resp = await client.post("/api/v1/applications", json={
        "name": "pr-finding-app",
        "github_org": "acme",
        "github_repo": "api2",
        "repo_url": "https://github.com/acme/api2",
        "team_name": "Security",
    })
    assert create_resp.status_code == 201
    app_id = create_resp.json()["id"]

    # Seed a finding linked to PR #42 directly via the shared db_session
    from app.models.finding import Finding
    app_uuid = uuid.UUID(app_id)
    finding = Finding(
        id=uuid.uuid4(),
        application_id=app_uuid,
        title="SQL Injection in user endpoint",
        severity="critical",
        finding_type="sast",
        scanner="semgrep",
        status="open",
        pr_number=42,
        pr_url="https://github.com/acme/api2/pull/42",
    )
    db_session.add(finding)
    await db_session.flush()

    with patch(
        "app.api.v1.github.fetch_pull_requests",
        new_callable=AsyncMock,
        return_value=_MOCK_PR_LIST,
    ):
        resp = await client.get(f"/api/v1/github/apps/{app_id}/pr-reviews")

    assert resp.status_code == 200
    data = resp.json()
    pr42 = next(pr for pr in data["prs"] if pr["pr_number"] == 42)
    assert len(pr42["findings_introduced"]) == 1
    assert pr42["findings_introduced"][0]["title"] == "SQL Injection in user endpoint"
    assert pr42["findings_introduced"][0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_pr_reviews_empty_when_no_prs(client: AsyncClient):
    """When GitHub returns no PRs the response should have total_prs=0."""
    create_resp = await client.post("/api/v1/applications", json={
        "name": "empty-pr-app",
        "github_org": "acme",
        "github_repo": "quiet-repo",
        "repo_url": "https://github.com/acme/quiet-repo",
        "team_name": "Infra",
    })
    assert create_resp.status_code == 201
    app_id = create_resp.json()["id"]

    with patch(
        "app.api.v1.github.fetch_pull_requests",
        new_callable=AsyncMock,
        return_value=[],
    ):
        resp = await client.get(f"/api/v1/github/apps/{app_id}/pr-reviews")

    assert resp.status_code == 200
    data = resp.json()
    assert data["total_prs"] == 0
    assert data["prs"] == []



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_repo(full_name: str, private: bool = False, archived: bool = False, language: str = "Python"):
    owner_login, repo_name = full_name.split("/", 1)
    repo = MagicMock()
    repo.full_name = full_name
    repo.name = repo_name
    repo.owner.login = owner_login
    repo.description = f"Description for {repo_name}"
    repo.language = language
    repo.html_url = f"https://github.com/{full_name}"
    repo.private = private
    repo.archived = archived
    repo.default_branch = "main"
    from datetime import datetime, timezone
    repo.updated_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    return repo


# ---------------------------------------------------------------------------
# list_accessible_repos unit tests
# ---------------------------------------------------------------------------

def test_list_accessible_repos_returns_formatted_dicts():
    mock_g = MagicMock()
    mock_g.get_user.return_value.get_repos.return_value = [
        _mock_repo("acme/api-service"),
        _mock_repo("acme/frontend", private=True),
    ]

    with patch("github.Github", return_value=mock_g):
        repos = list_accessible_repos("fake-token")

    assert len(repos) == 2

    first = repos[0]
    assert first["github_org"] == "acme"
    assert first["github_repo"] == "api-service"
    assert first["full_name"] == "acme/api-service"
    assert first["repo_url"] == "https://github.com/acme/api-service"
    assert first["private"] is False
    assert first["archived"] is False
    assert first["language"] == "Python"
    assert first["updated_at"] == "2024-01-01T00:00:00+00:00"

    second = repos[1]
    assert second["private"] is True


def test_list_accessible_repos_returns_empty_on_exception():
    with patch("github.Github", side_effect=Exception("network error")):
        repos = list_accessible_repos("bad-token")

    assert repos == []


def test_list_accessible_repos_includes_archived():
    mock_g = MagicMock()
    mock_g.get_user.return_value.get_repos.return_value = [
        _mock_repo("acme/old-service", archived=True),
    ]

    with patch("github.Github", return_value=mock_g):
        repos = list_accessible_repos("fake-token")

    assert len(repos) == 1
    assert repos[0]["archived"] is True


# ---------------------------------------------------------------------------
# GET /api/v1/github/repos endpoint tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_github_repos_no_token(client: AsyncClient):
    from app.core.config import settings as real_settings
    original = real_settings.GITHUB_TOKEN
    try:
        real_settings.GITHUB_TOKEN = ""
        resp = await client.get("/api/v1/github/repos")
        assert resp.status_code == 400
        assert "GITHUB_TOKEN" in resp.json()["detail"]
    finally:
        real_settings.GITHUB_TOKEN = original


@pytest.mark.asyncio
async def test_github_repos_returns_list(client: AsyncClient):
    from app.core.config import settings as real_settings
    mock_repos = [
        {
            "github_org": "acme",
            "github_repo": "api",
            "full_name": "acme/api",
            "description": "API service",
            "language": "Go",
            "repo_url": "https://github.com/acme/api",
            "private": False,
            "archived": False,
            "default_branch": "main",
            "updated_at": "2024-01-01T00:00:00+00:00",
        }
    ]

    original = real_settings.GITHUB_TOKEN
    try:
        real_settings.GITHUB_TOKEN = "fake-token"
        with patch("app.api.v1.github.list_accessible_repos", return_value=mock_repos):
            resp = await client.get("/api/v1/github/repos")
    finally:
        real_settings.GITHUB_TOKEN = original

    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    for item in data:
        assert "tracked" in item
        assert "application_id" in item


@pytest.mark.asyncio
async def test_github_repos_exclude_archived_by_default(client: AsyncClient):
    from app.core.config import settings as real_settings
    mock_repos = [
        {
            "github_org": "acme", "github_repo": "active",
            "full_name": "acme/active", "description": None,
            "language": "Python", "repo_url": "https://github.com/acme/active",
            "private": False, "archived": False,
            "default_branch": "main", "updated_at": None,
        },
        {
            "github_org": "acme", "github_repo": "old",
            "full_name": "acme/old", "description": None,
            "language": "Python", "repo_url": "https://github.com/acme/old",
            "private": False, "archived": True,
            "default_branch": "main", "updated_at": None,
        },
    ]

    original = real_settings.GITHUB_TOKEN
    try:
        real_settings.GITHUB_TOKEN = "fake-token"
        with patch("app.api.v1.github.list_accessible_repos", return_value=mock_repos):
            resp = await client.get("/api/v1/github/repos")
    finally:
        real_settings.GITHUB_TOKEN = original

    assert resp.status_code == 200
    data = resp.json()
    repos_returned = [r["github_repo"] for r in data]
    assert "active" in repos_returned
    assert "old" not in repos_returned


@pytest.mark.asyncio
async def test_github_repos_include_archived_when_requested(client: AsyncClient):
    from app.core.config import settings as real_settings
    mock_repos = [
        {
            "github_org": "acme", "github_repo": "old",
            "full_name": "acme/old", "description": None,
            "language": "Python", "repo_url": "https://github.com/acme/old",
            "private": False, "archived": True,
            "default_branch": "main", "updated_at": None,
        },
    ]

    original = real_settings.GITHUB_TOKEN
    try:
        real_settings.GITHUB_TOKEN = "fake-token"
        with patch("app.api.v1.github.list_accessible_repos", return_value=mock_repos):
            resp = await client.get("/api/v1/github/repos?include_archived=true")
    finally:
        real_settings.GITHUB_TOKEN = original

    assert resp.status_code == 200
    data = resp.json()
    assert any(r["github_repo"] == "old" for r in data)


@pytest.mark.asyncio
async def test_github_repos_marks_tracked_app(client: AsyncClient):
    """A repo already added as an Application should have tracked=True and an application_id."""
    from app.core.config import settings as real_settings

    create_resp = await client.post("/api/v1/applications", json={
        "name": "my-service",
        "github_org": "acme",
        "github_repo": "my-service",
        "repo_url": "https://github.com/acme/my-service",
        "team_name": "Platform",
    })
    assert create_resp.status_code == 201
    app_id = create_resp.json()["id"]

    mock_repos = [
        {
            "github_org": "acme", "github_repo": "my-service",
            "full_name": "acme/my-service", "description": None,
            "language": "Python", "repo_url": "https://github.com/acme/my-service",
            "private": False, "archived": False,
            "default_branch": "main", "updated_at": None,
        },
    ]

    original = real_settings.GITHUB_TOKEN
    try:
        real_settings.GITHUB_TOKEN = "fake-token"
        with patch("app.api.v1.github.list_accessible_repos", return_value=mock_repos):
            resp = await client.get("/api/v1/github/repos")
    finally:
        real_settings.GITHUB_TOKEN = original

    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["tracked"] is True
    assert data[0]["application_id"] == app_id
