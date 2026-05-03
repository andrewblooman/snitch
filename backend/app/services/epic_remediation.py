"""Generate an AI remediation plan from Jira epic context + uncovered Snitch findings."""
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.finding import Finding

logger = logging.getLogger(__name__)


def generate_epic_remediation_plan(
    uncovered_findings: list["Finding"],
    epic_results: list[dict],
    app_name: str,
) -> str:
    try:
        from anthropic import Anthropic
        from app.core.config import settings
        if not settings.ANTHROPIC_API_KEY:
            raise ValueError("No API key")
        client = Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        return _ai_plan(client, uncovered_findings, epic_results, app_name)
    except Exception as exc:
        logger.warning("AI remediation plan unavailable (%s), using template", exc)
        return _template_plan(uncovered_findings, epic_results, app_name)


def _ai_plan(client: "Anthropic", uncovered_findings: list["Finding"], epic_results: list[dict], app_name: str) -> str:  # noqa: F821
    findings_text = _format_findings(uncovered_findings)
    epic_text = _format_epic_issues(epic_results)

    prompt = f"""You are a senior application security engineer. Your task is to produce a prioritised remediation plan.

APPLICATION: {app_name}

EXISTING JIRA ISSUES IN EPIC (already planned or in-progress work):
{epic_text}

UNCOVERED FINDINGS (Snitch findings with no corresponding Jira issue yet):
{findings_text}

Produce a remediation plan that:
1. Groups the uncovered findings by theme (e.g., "Upgrade X to fix N CVEs", "Fix SQL injection in Y module")
2. For each group, suggests a Jira issue title and description (ready to paste)
3. Notes any existing Jira issues that partially address a gap
4. Orders by risk priority (critical/high EPSS first)
5. Estimates rough effort (S/M/L) per group
6. Keeps the plan concise and actionable — this goes straight to a dev team

Format as markdown."""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def _template_plan(uncovered_findings: list["Finding"], epic_results: list[dict], app_name: str) -> str:
    if not uncovered_findings:
        return f"No uncovered findings for {app_name}. All scanned findings have corresponding Jira issues."

    lines = [
        f"# Remediation Plan — {app_name}",
        "",
        f"**{len(uncovered_findings)} finding(s) have no corresponding Jira issue.**",
        "",
        "## Findings Requiring Jira Issues",
        "",
    ]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        uncovered_findings,
        key=lambda f: severity_order.get(f.severity or "info", 4),
    )

    for i, finding in enumerate(sorted_findings, 1):
        identifier = finding.cve_id or finding.rule_id or "—"
        pkg = f" ({finding.package_name} {finding.package_version or ''})" if finding.package_name else ""
        lines.append(f"### {i}. [{finding.severity.upper()}] {finding.title}")
        lines.append(f"- **Identifier:** {identifier}{pkg}")
        lines.append(f"- **Scanner:** {finding.scanner}")
        if finding.fixed_version:
            lines.append(f"- **Suggested Fix:** Upgrade to {finding.fixed_version}")
        if finding.epss_percentile is not None:
            pct = round(finding.epss_percentile * 100, 1)
            lines.append(f"- **EPSS:** {pct}th percentile")
        lines.append(f"- **Suggested Jira Title:** `[{finding.severity.upper()}] {finding.title[:80]}`")
        lines.append("")

    existing_count = sum(len(r["issues"]) for r in epic_results)
    if existing_count:
        lines += [
            "## Existing Epic Coverage",
            "",
            f"{existing_count} issue(s) already exist in the linked epic(s). Review for partial overlap.",
        ]

    return "\n".join(lines)


def _format_findings(findings: list["Finding"]) -> str:
    if not findings:
        return "(none)"
    lines = []
    for f in findings[:50]:
        identifier = f.cve_id or f.rule_id or "—"
        pkg = f", package={f.package_name} {f.package_version or ''}" if f.package_name else ""
        epss = f", EPSS={round(f.epss_percentile*100,1)}%" if f.epss_percentile else ""
        lines.append(f"- [{f.severity.upper()}] {f.title} (id={f.id}, {identifier}{pkg}{epss})")
    if len(findings) > 50:
        lines.append(f"... and {len(findings) - 50} more")
    return "\n".join(lines)


def _format_epic_issues(epic_results: list[dict]) -> str:
    lines = []
    for result in epic_results:
        lines.append(f"Epic {result['epic_key']}:")
        for issue in result["issues"][:20]:
            lines.append(f"  - {issue['key']} [{issue['status']}]: {issue['summary']}")
    return "\n".join(lines) if lines else "(none)"
