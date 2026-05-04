import logging
from typing import List, Optional

from app.models.application import Application
from app.models.finding import Finding

logger = logging.getLogger(__name__)


def _build_prompt(app: Application, findings: List[Finding]) -> str:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))

    lines = [
        f"# Security Remediation Plan for {app.name}",
        f"Repository: {app.repo_url}",
        f"Team: {app.team_name}",
        f"Language: {app.language or 'unknown'}",
        "",
        f"## Findings Summary ({len(findings)} total)",
    ]

    for f in sorted_findings:
        lines.append(
            f"\n### [{f.severity.upper()}] {f.title}"
        )
        if f.cve_id:
            lines.append(f"- CVE: {f.cve_id}")
        if f.rule_id:
            lines.append(f"- Rule: {f.rule_id}")
        if f.file_path:
            lines.append(f"- File: {f.file_path}" + (f" (line {f.line_number})" if f.line_number else ""))
        if f.package_name:
            lines.append(f"- Package: {f.package_name} {f.package_version or ''}")
            if f.fixed_version:
                lines.append(f"- Fixed in: {f.fixed_version}")
        if f.cvss_score:
            lines.append(f"- CVSS Score: {f.cvss_score}")
        if f.description:
            lines.append(f"- Description: {f.description}")

    lines += [
        "",
        "## Instructions",
        "Generate a detailed, actionable remediation plan in Markdown. For each finding:",
        "1. Explain the risk and impact",
        "2. Provide specific code changes or upgrade commands",
        "3. Include priority ordering (fix criticals first)",
        "4. Suggest a test plan to verify the fix",
        "5. Note any breaking changes",
        "",
        "Group related findings together where possible. Be practical and developer-friendly.",
    ]

    return "\n".join(lines)


def _upgrade_command(language: str | None, package: str, version: str) -> str:
    lang = (language or "").lower()
    if lang in ("javascript", "typescript", "js", "ts"):
        return f"npm install {package}@{version}"
    if lang == "go":
        return f"go get {package}@v{version}"
    if lang == "java":
        return f"# Update pom.xml or build.gradle: {package} to {version}"
    if lang == "ruby":
        return f"bundle update {package}"
    if lang == "rust":
        return f"cargo update {package}"
    # Default: Python / unknown
    return f"pip install '{package}>={version}'"


def _mock_plan(app: Application, findings: List[Finding]) -> str:
    severity_counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1

    lines = [
        f"# Security Remediation Plan for {app.name}",
        f"> **Note:** This is a template plan — no AI provider available. Set `ANTHROPIC_API_KEY` or `OLLAMA_URL` to enable AI-powered remediation.",
        "",
        f"## Summary",
        f"- **Critical:** {severity_counts['critical']} findings",
        f"- **High:** {severity_counts['high']} findings",
        f"- **Medium:** {severity_counts['medium']} findings",
        f"- **Low:** {severity_counts['low']} findings",
        "",
        "## Prioritized Remediation Steps",
        "",
    ]

    priority = 1
    for sev in ["critical", "high", "medium", "low"]:
        sev_findings = [f for f in findings if f.severity == sev]
        if not sev_findings:
            continue
        lines.append(f"### Priority {priority}: {sev.capitalize()} Severity")
        for f in sev_findings:
            lines.append(f"\n#### {f.title}")
            if f.package_name and f.fixed_version:
                cmd = _upgrade_command(app.language, f.package_name, f.fixed_version)
                lines.append(f"```bash\n# Upgrade {f.package_name} to {f.fixed_version}\n{cmd}\n```")
            elif f.file_path:
                lines.append(f"- Review `{f.file_path}`" + (f" at line {f.line_number}" if f.line_number else ""))
                lines.append("- Apply the recommended code fix for this rule")
            if f.cve_id:
                lines.append(f"- Reference: https://nvd.nist.gov/vuln/detail/{f.cve_id}")
        priority += 1

    lines += [
        "",
        "## Testing",
        "1. Run the full test suite after applying fixes",
        "2. Re-run security scans to confirm findings are resolved",
        "3. Perform a code review before merging",
    ]

    return "\n".join(lines)


async def generate_remediation_plan(
    app: Application,
    findings: List[Finding],
) -> tuple[str, Optional[str]]:
    from app.services.llm_provider import MockProvider, get_llm_provider

    provider = get_llm_provider()
    if isinstance(provider, MockProvider):
        return _mock_plan(app, findings), None

    try:
        prompt = _build_prompt(app, findings)
        result = await provider.complete(prompt, max_tokens=16000, use_thinking=True)
        return result.text, result.model or None
    except Exception as e:
        logger.error("AI remediation failed: %s", e)
        return _mock_plan(app, findings), None
