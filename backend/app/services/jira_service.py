"""Jira REST API v3 client — no SDK, uses httpx + Basic Auth."""
import base64
import logging
import re
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from app.models.application import Application
    from app.models.finding import Finding

logger = logging.getLogger(__name__)


def _auth_header(email: str, api_token: str) -> str:
    credentials = base64.b64encode(f"{email}:{api_token}".encode()).decode()
    return f"Basic {credentials}"


def _headers(config: dict) -> dict:
    return {
        "Authorization": _auth_header(config["email"], config["api_token"]),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _base(config: dict) -> str:
    return config["jira_url"].rstrip("/")


def test_connection(config: dict) -> tuple[bool, str]:
    try:
        resp = httpx.get(
            f"{_base(config)}/rest/api/3/myself",
            headers=_headers(config),
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            return True, f"Connected as {data.get('displayName', data.get('emailAddress', 'unknown'))}"
        return False, f"Auth failed: HTTP {resp.status_code}"
    except Exception as exc:
        return False, str(exc)


def _finding_description_adf(finding: "Finding") -> dict:
    """Build an Atlassian Document Format body for the Jira issue description."""
    lines = []

    def paragraph(text: str) -> dict:
        return {"type": "paragraph", "content": [{"type": "text", "text": text}]}

    def bold_paragraph(label: str, value: str) -> dict:
        return {
            "type": "paragraph",
            "content": [
                {"type": "text", "text": f"{label}: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": value},
            ],
        }

    lines.append(paragraph(f"Detected by Snitch AppSec Platform via {finding.scanner}."))
    if finding.description:
        lines.append(paragraph(finding.description[:2000]))

    if finding.cve_id:
        lines.append(bold_paragraph("CVE", finding.cve_id))
    if finding.rule_id:
        lines.append(bold_paragraph("Rule ID", finding.rule_id))
    if finding.cvss_score is not None:
        lines.append(bold_paragraph("CVSS Score", str(finding.cvss_score)))
    if finding.epss_percentile is not None:
        pct = round(finding.epss_percentile * 100, 1)
        lines.append(bold_paragraph("EPSS Percentile", f"{pct}%"))
    if finding.package_name:
        pkg = f"{finding.package_name} {finding.package_version or ''}".strip()
        lines.append(bold_paragraph("Affected Package", pkg))
    if finding.fixed_version:
        lines.append(bold_paragraph("Fixed In Version", finding.fixed_version))
    if finding.file_path:
        loc = finding.file_path
        if finding.line_number:
            loc += f":{finding.line_number}"
        lines.append(bold_paragraph("Location", loc))
    if finding.compliance_tags:
        lines.append(bold_paragraph("Compliance Tags", ", ".join(finding.compliance_tags)))

    lines.append(bold_paragraph("Snitch Finding ID", str(finding.id)))

    return {"type": "doc", "version": 1, "content": lines}


def create_issue(
    config: dict,
    finding: "Finding",
    application: "Application",
) -> dict:
    """Create a Jira issue for a finding. Returns {issue_key, issue_url}."""
    severity = (finding.severity or "info").upper()
    summary = f"[{severity}] {finding.title}"[:255]

    labels = [
        "snitch",
        f"snitch-finding-{finding.id}",
        finding.severity or "info",
        finding.finding_type or "unknown",
    ]
    if finding.cve_id:
        labels.append(finding.cve_id.replace(" ", "-"))

    payload: dict[str, Any] = {
        "fields": {
            "project": {"key": config["project_key"]},
            "summary": summary,
            "description": _finding_description_adf(finding),
            "issuetype": {"name": config.get("issue_type", "Bug")},
            "labels": labels,
        }
    }

    resp = httpx.post(
        f"{_base(config)}/rest/api/3/issue",
        headers=_headers(config),
        json=payload,
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    issue_key = data["key"]
    issue_url = f"{_base(config)}/browse/{issue_key}"
    return {"issue_key": issue_key, "issue_url": issue_url}


def add_comment(config: dict, issue_key: str, body_text: str) -> bool:
    payload = {
        "body": {
            "type": "doc",
            "version": 1,
            "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": body_text}]}
            ],
        }
    }
    try:
        resp = httpx.post(
            f"{_base(config)}/rest/api/3/issue/{issue_key}/comment",
            headers=_headers(config),
            json=payload,
            timeout=15,
        )
        return resp.status_code in (200, 201)
    except Exception as exc:
        logger.error("Failed to add Jira comment to %s: %s", issue_key, exc)
        return False


def get_issue(config: dict, issue_key: str) -> dict:
    resp = httpx.get(
        f"{_base(config)}/rest/api/3/issue/{issue_key}",
        headers=_headers(config),
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def crawl_epic(config: dict, epic_keys: list[str]) -> list[dict]:
    """
    Fetch all child issues for the given epic keys.
    Returns a list of {epic_key, issues: [{key, summary, status, labels, description_text}]}.
    """
    results = []
    for epic_key in epic_keys:
        jql = f'parent = "{epic_key}" ORDER BY created DESC'
        issues = _search_jql(config, jql)
        results.append({"epic_key": epic_key, "issues": issues})
    return results


def _search_jql(config: dict, jql: str, max_results: int = 100) -> list[dict]:
    payload = {"jql": jql, "maxResults": max_results, "fields": ["summary", "status", "labels", "description", "assignee"]}
    try:
        resp = httpx.post(
            f"{_base(config)}/rest/api/3/search/jql",
            headers=_headers(config),
            json=payload,
            timeout=15,
        )
        if resp.status_code == 404:
            # Fallback to legacy search endpoint
            resp = httpx.get(
                f"{_base(config)}/rest/api/3/search",
                headers=_headers(config),
                params={"jql": jql, "maxResults": max_results, "fields": "summary,status,labels,description,assignee"},
                timeout=15,
            )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.error("Jira JQL search failed: %s", exc)
        return []

    issues = []
    for item in data.get("issues", []):
        fields = item.get("fields", {})
        status_obj = fields.get("status") or {}
        description_text = _extract_adf_text(fields.get("description"))
        issues.append({
            "key": item["key"],
            "summary": fields.get("summary", ""),
            "status": status_obj.get("name", "Unknown"),
            "labels": fields.get("labels", []),
            "description_text": description_text,
            "url": f"{_base(config)}/browse/{item['key']}",
        })
    return issues


def _extract_adf_text(adf: Any) -> str:
    """Recursively extract plain text from an Atlassian Document Format node."""
    if not adf:
        return ""
    if isinstance(adf, str):
        return adf
    if isinstance(adf, dict):
        if adf.get("type") == "text":
            return adf.get("text", "")
        return " ".join(_extract_adf_text(c) for c in adf.get("content", []))
    if isinstance(adf, list):
        return " ".join(_extract_adf_text(item) for item in adf)
    return ""


def match_findings_to_issues(
    epic_results: list[dict],
    findings: list["Finding"],
) -> dict:
    """
    Match Snitch findings against Jira epic child issues.
    Returns {covered, uncovered, external} finding/issue groupings.
    """
    all_issues = []
    for result in epic_results:
        all_issues.extend(result["issues"])

    # Index issues by: labels containing snitch-finding-{id}, CVE IDs, package names
    snitch_finding_re = re.compile(r"snitch-finding-([a-f0-9\-]+)")
    cve_re = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

    issue_finding_ids: set[str] = set()
    issue_cves: set[str] = set()
    issue_packages: set[str] = set()

    for issue in all_issues:
        for label in issue.get("labels", []):
            m = snitch_finding_re.match(label)
            if m:
                issue_finding_ids.add(m.group(1))
        text = f"{issue['summary']} {issue['description_text']}"
        for cve in cve_re.findall(text):
            issue_cves.add(cve.upper())

    covered = []
    uncovered = []

    for finding in findings:
        fid = str(finding.id)
        matched = False
        if fid in issue_finding_ids:
            matched = True
        elif finding.cve_id and finding.cve_id.upper() in issue_cves:
            matched = True
        elif finding.package_name:
            pkg_lower = finding.package_name.lower()
            for issue in all_issues:
                if pkg_lower in f"{issue['summary']} {issue['description_text']}".lower():
                    matched = True
                    break
        if matched:
            covered.append(fid)
        else:
            uncovered.append(fid)

    # External: Jira issues that don't correspond to any Snitch finding
    covered_finding_ids = set(covered)
    external = []
    for issue in all_issues:
        linked_finding_ids = set()
        for label in issue.get("labels", []):
            m = snitch_finding_re.match(label)
            if m:
                linked_finding_ids.add(m.group(1))
        if not linked_finding_ids.intersection(covered_finding_ids):
            # Check CVE match too
            text = f"{issue['summary']} {issue['description_text']}"
            issue_cve_matches = {c.upper() for c in cve_re.findall(text)}
            finding_cves = {f.cve_id.upper() for f in findings if f.cve_id}
            if not issue_cve_matches.intersection(finding_cves):
                external.append({"key": issue["key"], "summary": issue["summary"], "status": issue["status"], "url": issue["url"]})

    return {"covered": covered, "uncovered": uncovered, "external": external}
