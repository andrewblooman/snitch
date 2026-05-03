import logging
import re
from typing import Optional

import httpx

from app.core.config import settings
from app.models.application import Application

logger = logging.getLogger(__name__)

_GH_API = "https://api.github.com"
_REPO_LIST_LIMIT = 200

# Severity mapping for code scanning rule severity
_CODE_SCAN_SEVERITY = {
    "critical": "critical",
    "error": "high",
    "high": "high",
    "warning": "medium",
    "medium": "medium",
    "note": "low",
    "low": "low",
    "none": "info",
    "info": "info",
}

def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _extract_pr_number(ref: str | None) -> int | None:
    """Extract PR number from a git ref like refs/pull/123/head."""
    if ref and (m := re.match(r"refs/pull/(\d+)/", ref)):
        return int(m.group(1))
    return None


def list_accessible_repos(token: str) -> list[dict]:
    """Return up to the most-recently-updated 200 repos accessible to the given GitHub token."""
    try:
        from github import Github

        g = Github(token, per_page=100)
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
            if len(repos) >= _REPO_LIST_LIMIT:
                break
        return repos
    except Exception as e:
        logger.error("Failed to list accessible repos: %s", e)
        return []


def lookup_public_repo(owner: str, repo_name: str, token: str | None = None) -> dict | None:
    """Fetch metadata for any public GitHub repository. Works without a token for public repos."""
    try:
        from github import Github, GithubException, UnknownObjectException

        g = Github(token) if token else Github()
        try:
            repo = g.get_repo(f"{owner}/{repo_name}")
        except UnknownObjectException:
            return None
        return {
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
        }
    except Exception as e:
        logger.error("Failed to look up repo %s/%s: %s", owner, repo_name, e)
        return None


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


# ── GitHub Advanced Security alert helpers ────────────────────────────────────

def _gh_headers(token: str | None) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _get_commit_author(client: httpx.AsyncClient, owner: str, repo: str, sha: str) -> str | None:
    """Return the GitHub login of the commit author, or None on error."""
    try:
        r = await client.get(f"{_GH_API}/repos/{owner}/{repo}/commits/{sha}")
        if r.status_code == 200:
            data = r.json()
            return (data.get("author") or {}).get("login") or data.get("commit", {}).get("author", {}).get("name")
    except Exception:
        pass
    return None


async def fetch_github_security_alerts(owner: str, repo: str, token: str | None) -> list[dict]:
    """
    Fetch code-scanning, dependabot, and secret-scanning alerts for a repo.
    Returns a list of normalised finding dicts ready to be upserted.
    """
    findings: list[dict] = []
    headers = _gh_headers(token)

    async with httpx.AsyncClient(headers=headers, timeout=30) as client:
        # ── Code Scanning ──────────────────────────────────────────────────
        try:
            page = 1
            while True:
                r = await client.get(
                    f"{_GH_API}/repos/{owner}/{repo}/code-scanning/alerts",
                    params={"state": "open", "per_page": 100, "page": page},
                )
                if r.status_code in (403, 404, 422):
                    logger.debug("Code scanning not available for %s/%s: %s", owner, repo, r.status_code)
                    break
                r.raise_for_status()
                alerts = r.json()
                if not alerts:
                    break
                for a in alerts:
                    instance = a.get("most_recent_instance") or {}
                    loc = instance.get("location") or {}
                    ref = instance.get("ref")
                    sha = instance.get("commit_sha")
                    pr_num = _extract_pr_number(ref)
                    rule = a.get("rule") or {}
                    tool_name = (a.get("tool") or {}).get("name", "codeql").lower().replace(" ", "_")
                    # Normalize Semgrep OSS → semgrep so historical and current alerts share the same scanner label
                    if tool_name == "semgrep_oss":
                        tool_name = "semgrep"
                    # Determine severity
                    sec_sev = rule.get("security_severity_level") or rule.get("severity") or "warning"
                    severity = _CODE_SCAN_SEVERITY.get(sec_sev.lower(), "medium")
                    # Get commit author if we have a SHA
                    author: str | None = None
                    if sha:
                        author = await _get_commit_author(client, owner, repo, sha)
                    findings.append({
                        "title": rule.get("name") or rule.get("id") or "Code scanning finding",
                        "description": rule.get("full_description") or rule.get("description") or "",
                        "severity": severity,
                        "finding_type": "sast",
                        "scanner": tool_name,
                        "rule_id": rule.get("id"),
                        "file_path": loc.get("path"),
                        "line_number": loc.get("start_line"),
                        "commit_sha": sha,
                        "introduced_by": author,
                        "pr_number": pr_num,
                        "pr_url": f"https://github.com/{owner}/{repo}/pull/{pr_num}" if pr_num else None,
                        "github_alert_url": a.get("html_url"),
                        "github_alert_number": a.get("number"),
                        "status": "open",
                    })
                if len(alerts) < 100:
                    break
                page += 1
        except httpx.HTTPStatusError as e:
            logger.warning("Code scanning alerts error for %s/%s: %s", owner, repo, e)
        except Exception as e:
            logger.warning("Unexpected error fetching code scanning for %s/%s: %s", owner, repo, e)

        # ── Dependabot ─────────────────────────────────────────────────────
        try:
            page = 1
            while True:
                r = await client.get(
                    f"{_GH_API}/repos/{owner}/{repo}/dependabot/alerts",
                    params={"state": "open", "per_page": 100, "page": page},
                )
                if r.status_code in (403, 404):
                    logger.debug("Dependabot not available for %s/%s: %s", owner, repo, r.status_code)
                    break
                r.raise_for_status()
                alerts = r.json()
                if not alerts:
                    break
                for a in alerts:
                    advisory = a.get("security_advisory") or {}
                    vuln = a.get("security_vulnerability") or {}
                    pkg = vuln.get("package") or {}
                    cvss_score = (advisory.get("cvss") or {}).get("score")
                    severity = advisory.get("severity") or _cvss_to_severity(cvss_score)
                    if isinstance(severity, str):
                        severity = _CODE_SCAN_SEVERITY.get(severity.lower(), "medium")
                    findings.append({
                        "title": advisory.get("summary") or f"Dependabot: {pkg.get('name', 'unknown')}",
                        "description": advisory.get("description") or "",
                        "severity": severity,
                        "finding_type": "sca",
                        "scanner": "dependabot",
                        "cve_id": advisory.get("cve_id"),
                        "package_name": pkg.get("name"),
                        "package_version": vuln.get("vulnerable_version_range"),
                        "fixed_version": (vuln.get("first_patched_version") or {}).get("identifier"),
                        "cvss_score": cvss_score,
                        "rule_id": advisory.get("ghsa_id"),
                        "github_alert_url": a.get("html_url"),
                        "github_alert_number": a.get("number"),
                        "status": "open",
                        # No commit SHA available for Dependabot alerts
                        "commit_sha": None,
                        "introduced_by": None,
                        "pr_number": None,
                        "pr_url": None,
                    })
                if len(alerts) < 100:
                    break
                page += 1
        except httpx.HTTPStatusError as e:
            logger.warning("Dependabot alerts error for %s/%s: %s", owner, repo, e)
        except Exception as e:
            logger.warning("Unexpected error fetching dependabot for %s/%s: %s", owner, repo, e)

        # ── Secret Scanning ────────────────────────────────────────────────
        try:
            page = 1
            while True:
                r = await client.get(
                    f"{_GH_API}/repos/{owner}/{repo}/secret-scanning/alerts",
                    params={"state": "open", "per_page": 100, "page": page},
                )
                if r.status_code in (403, 404):
                    logger.debug("Secret scanning not available for %s/%s: %s", owner, repo, r.status_code)  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
                    break
                r.raise_for_status()
                alerts = r.json()
                if not alerts:
                    break
                for a in alerts:
                    findings.append({
                        "title": a.get("secret_type_display_name") or a.get("secret_type") or "Secret detected",
                        "description": f"Secret type: {a.get('secret_type', 'unknown')}",
                        "severity": "high",
                        "finding_type": "secrets",
                        "scanner": "github_secret_scanning",
                        "rule_id": a.get("secret_type"),
                        "github_alert_url": a.get("html_url"),
                        "github_alert_number": a.get("number"),
                        "status": "open",
                        "commit_sha": None,
                        "introduced_by": None,
                        "pr_number": None,
                        "pr_url": None,
                    })
                if len(alerts) < 100:
                    break
                page += 1
        except httpx.HTTPStatusError as e:
            logger.warning("Secret scanning alerts error for %s/%s: %s", owner, repo, e)  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
        except Exception as e:
            logger.warning("Unexpected error fetching secret scanning for %s/%s: %s", owner, repo, e)  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure

    return findings

