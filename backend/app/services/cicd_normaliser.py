"""
Normalise raw Semgrep and Grype JSON output into Snitch's internal finding dict format.

Expected output dict shape (matches Finding model fields):
  title, description, severity, finding_type, scanner,
  file_path, line_number, rule_id,           # SAST
  cve_id, package_name, package_version,      # SCA/container
  fixed_version, cvss_score,
  status (always "open")
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_SEMGREP_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

_GRYPE_SEVERITY_MAP = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Negligible": "low",
    "Unknown": "info",
}


def detect_format(data: dict) -> str:
    """Return 'semgrep', 'grype', or 'checkov' based on JSON structure, or 'unknown'."""
    if "results" in data and "version" in data:
        return "semgrep"
    if "matches" in data and "source" in data:
        return "grype"
    # Checkov: {"results": {"passed_checks": [...], "failed_checks": [...]}}
    # or a list of per-framework dicts with the same structure
    if _is_checkov(data):
        return "checkov"
    return "unknown"


def _is_checkov(data: dict | list) -> bool:
    """Return True if the data looks like checkov --output json output."""
    if isinstance(data, list):
        return len(data) > 0 and all(isinstance(s, dict) and _is_checkov_section(s) for s in data)
    return _is_checkov_section(data)


def _is_checkov_section(section: dict) -> bool:
    results = section.get("results")
    if isinstance(results, dict):
        return "failed_checks" in results or "passed_checks" in results
    return False


def normalise_semgrep(data: dict) -> list[dict]:
    """Convert Semgrep JSON output (--json) to Snitch finding dicts."""
    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        raw_severity = extra.get("severity", "INFO").upper()
        severity = _SEMGREP_SEVERITY_MAP.get(raw_severity, "info")

        findings.append({
            "title": extra.get("message", result.get("check_id", "Unknown"))[:512],
            "description": extra.get("message"),
            "severity": severity,
            "finding_type": "SAST",
            "scanner": "semgrep",
            "file_path": result.get("path"),
            "line_number": result.get("start", {}).get("line"),
            "rule_id": result.get("check_id"),
            "cve_id": None,
            "package_name": None,
            "package_version": None,
            "fixed_version": None,
            "cvss_score": None,
            "status": "open",
        })
    return findings


def normalise_grype(data: dict) -> list[dict]:
    """Convert Grype JSON output (-o json) to Snitch finding dicts."""
    findings = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        raw_severity = vuln.get("severity", "Unknown")
        severity = _GRYPE_SEVERITY_MAP.get(raw_severity, "info")

        cve_id = vuln.get("id")  # e.g. "CVE-2021-44228"
        package_name = artifact.get("name")
        package_version = artifact.get("version")

        # Best fixed version from the first fix entry
        fix_versions = vuln.get("fix", {}).get("versions", [])
        fixed_version = fix_versions[0] if fix_versions else None

        # CVSS score — prefer v3, fall back to v2
        cvss_score = None
        for cvss in vuln.get("cvss", []):
            if cvss.get("version", "").startswith("3"):
                cvss_score = cvss.get("metrics", {}).get("baseScore")
                break
        if cvss_score is None:
            for cvss in vuln.get("cvss", []):
                cvss_score = cvss.get("metrics", {}).get("baseScore")
                break

        title = f"{cve_id}: {package_name}" if cve_id and package_name else (cve_id or package_name or "Unknown")

        findings.append({
            "title": title[:512],
            "description": vuln.get("description"),
            "severity": severity,
            "finding_type": "container",
            "scanner": "grype",
            "file_path": None,
            "line_number": None,
            "rule_id": None,
            "cve_id": cve_id,
            "package_name": package_name,
            "package_version": package_version,
            "fixed_version": fixed_version,
            "cvss_score": cvss_score,
            "status": "open",
        })
    return findings


def normalise_checkov(data: dict | list) -> list[dict]:
    """Convert Checkov JSON output (--output json) to Snitch finding dicts.

    Checkov can return a single dict or a list of dicts (one per framework).
    Only failed_checks are ingested; passed_checks are discarded.
    """
    _CHECKOV_SEVERITY: dict[str, str] = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
    }

    sections: list[dict] = data if isinstance(data, list) else [data]
    findings = []

    for section in sections:
        check_type = section.get("check_type", "")
        for check in section.get("results", {}).get("failed_checks", []):
            check_id = check.get("check_id", "")
            check_name = check.get("check", {})
            if isinstance(check_name, dict):
                check_name = check_name.get("name", check_id)
            elif not isinstance(check_name, str):
                check_name = check_id

            resource = check.get("resource", "")
            raw_severity = (check.get("severity") or "").upper()
            severity = _CHECKOV_SEVERITY.get(raw_severity, "medium")

            file_path = check.get("repo_file_path") or check.get("file_path") or None
            line_range = check.get("file_line_range")
            line_number = line_range[0] if isinstance(line_range, list) and line_range else None

            findings.append({
                "title": f"{check_id}: {check_name}"[:512],
                "description": f"Resource: {resource}. Framework: {check_type}.",
                "severity": severity,
                "finding_type": "IaC",
                "scanner": "checkov",
                "file_path": file_path,
                "line_number": line_number,
                "rule_id": check_id or None,
                "cve_id": None,
                "package_name": None,
                "package_version": None,
                "fixed_version": None,
                "cvss_score": None,
                "status": "open",
            })

    return findings


def normalise(data: dict | list) -> tuple[list[dict], str]:
    """
    Auto-detect format and normalise to Snitch finding dicts.

    Returns (findings, detected_scan_type) where scan_type is one of:
    'semgrep', 'grype', or 'checkov'.
    Raises ValueError for unrecognised formats.
    """
    fmt = detect_format(data)
    if fmt == "semgrep":
        return normalise_semgrep(data), "semgrep"
    if fmt == "grype":
        return normalise_grype(data), "grype"
    if fmt == "checkov":
        return normalise_checkov(data), "checkov"
    raise ValueError("Unrecognised scan result format — could not detect semgrep, grype, or checkov structure")
