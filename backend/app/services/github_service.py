import logging
from typing import Optional

from app.core.config import settings
from app.models.application import Application

logger = logging.getLogger(__name__)


def list_accessible_repos(token: str) -> list[dict]:
    """Return all repos accessible to the given GitHub token."""
    try:
        from github import Github

        g = Github(token)
        repos = []
        for repo in g.get_user().get_repos(sort="updated"):
            repos.append({
                "github_org": repo.owner.login,
                "github_repo": repo.name,
                "full_name": repo.full_name,
                "description": repo.description,
                "language": repo.language,
                "repo_url": repo.html_url,
                "private": repo.private,
                "archived": repo.archived,
                "default_branch": repo.default_branch,
                "updated_at": repo.updated_at.isoformat() if repo.updated_at else None,
            })
        return repos
    except Exception as e:
        logger.error("Failed to list accessible repos: %s", e)
        return []


def sync_github_security_alerts(app: Application, token: str) -> list[dict]:
    """Fetch code scanning alerts from GitHub and convert to internal finding format."""
    try:
        from github import Github, GithubException

        g = Github(token)
        repo = g.get_repo(f"{app.github_org}/{app.github_repo}")

        findings = []
        try:
            alerts = repo.get_codescan_alerts()
            for alert in alerts:
                severity_map = {
                    "critical": "critical",
                    "high": "high",
                    "medium": "medium",
                    "warning": "medium",
                    "low": "low",
                    "note": "info",
                    "error": "high",
                }
                severity = severity_map.get(
                    getattr(alert.rule, "severity", "medium"), "medium"
                )
                findings.append({
                    "title": alert.rule.description or alert.rule.id,
                    "description": getattr(alert.rule, "full_description", None),
                    "severity": severity,
                    "finding_type": "SAST",
                    "scanner": "semgrep",
                    "file_path": alert.most_recent_instance.location.path
                    if alert.most_recent_instance
                    else None,
                    "line_number": alert.most_recent_instance.location.start_line
                    if alert.most_recent_instance
                    else None,
                    "rule_id": alert.rule.id,
                    "status": "open" if alert.state == "open" else "fixed",
                })
        except GithubException as e:
            logger.warning("Failed to fetch code scanning alerts: %s", e)

        return findings
    except Exception as e:
        logger.error("GitHub sync failed: %s", e)
        return []


def create_branch(repo_full_name: str, branch_name: str, token: str) -> bool:
    """Create a new branch in a GitHub repository."""
    try:
        from github import Github

        g = Github(token)
        repo = g.get_repo(repo_full_name)
        default_branch = repo.default_branch
        source = repo.get_branch(default_branch)
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=source.commit.sha)
        return True
    except Exception as e:
        logger.error("Failed to create branch %s: %s", branch_name, e)
        return False


def create_pull_request(
    repo_full_name: str,
    branch: str,
    title: str,
    body: str,
    token: str,
) -> Optional[dict]:
    """Create a pull request on GitHub."""
    try:
        from github import Github

        g = Github(token)
        repo = g.get_repo(repo_full_name)
        pr = repo.create_pull(
            title=title,
            body=body,
            head=branch,
            base=repo.default_branch,
        )
        return {
            "pr_number": pr.number,
            "pr_url": pr.html_url,
            "pr_status": "open",
        }
    except Exception as e:
        logger.error("Failed to create pull request: %s", e)
        return None
