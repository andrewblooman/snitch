import json
import logging
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.models.application import Application

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Semgrep severity mapping
# ---------------------------------------------------------------------------
def _mask_secret(secret: str) -> str:
    if not secret or len(secret) < 4:
        return "****"
    return f"****{secret[-4:]}"


_SEMGREP_SEVERITY: dict[str, str] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}
_SEMGREP_IMPACT: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

# Trivy severity is already lowercase-compatible
_TRIVY_SEVERITY: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


class RealScannerService:
    """Clones a GitHub repo and runs real Semgrep + Trivy scans."""

    def _clone_repo(self, app: Application, dest: Path) -> bool:
        from app.core.config import settings

        token = settings.GITHUB_TOKEN
        repo_url = app.repo_url
        if token:
            # Inject token into HTTPS URL for auth
            repo_url = repo_url.replace("https://", f"https://{token}@")

        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(dest)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            logger.error("git clone failed for %s: %s", app.repo_url, result.stderr)
            return False
        return True

    def run_semgrep_scan(self, app: Application, repo_path: Path) -> list[dict[str, Any]]:
        try:
            result = subprocess.run(
                ["semgrep", "--config", "auto", "--json", "--quiet", str(repo_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("semgrep failed for %s: %s", app.name, e)
            return []

        if result.returncode not in (0, 1):
            # semgrep exits 0 for no findings, 1 for findings; 2+ means error
            logger.error(
                "semgrep error (exit %d) for %s:\nstderr: %s\nstdout: %s",
                result.returncode, app.name,
                result.stderr[:2000] if result.stderr else "",
                result.stdout[:500] if result.stdout else "",
            )
            return []

        try:
            output = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as e:
            logger.error("semgrep JSON parse error for %s: %s\nstdout: %s", app.name, e, result.stdout[:500])
            return []

        findings = []
        for item in output.get("results", []):
            extra = item.get("extra", {})
            meta = extra.get("metadata", {})

            raw_severity = extra.get("severity", "INFO")
            impact = str(meta.get("impact", meta.get("confidence", ""))).upper()
            severity = _SEMGREP_IMPACT.get(impact) or _SEMGREP_SEVERITY.get(raw_severity, "medium")

            file_path = item.get("path", "")
            # Make path relative to the repo root
            try:
                file_path = str(Path(file_path).relative_to(repo_path))
            except ValueError:
                pass

            findings.append({
                "title": extra.get("message", item.get("check_id", "Unknown finding"))[:512],
                "description": extra.get("message"),
                "severity": severity,
                "finding_type": "SAST",
                "scanner": "semgrep",
                "file_path": file_path or None,
                "line_number": item.get("start", {}).get("line"),
                "rule_id": item.get("check_id"),
                "status": "open",
            })

        logger.info("semgrep found %d findings in %s", len(findings), app.name)
        return findings

    def run_trivy_scan(self, app: Application, repo_path: Path) -> list[dict[str, Any]]:
        try:
            result = subprocess.run(
                [
                    "trivy", "fs",
                    "--format", "json",
                    "--quiet",
                    "--no-progress",
                    str(repo_path),
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("trivy failed for %s: %s", app.name, e)
            return []

        if result.returncode != 0:
            logger.error(
                "trivy error (exit %d) for %s:\nstderr: %s\nstdout: %s",
                result.returncode, app.name,
                result.stderr[:2000] if result.stderr else "",
                result.stdout[:500] if result.stdout else "",
            )
            return []

        try:
            output = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as e:
            logger.error("trivy JSON parse error for %s: %s\nstdout: %s", app.name, e, result.stdout[:500])
            return []

        findings = []
        for target_result in output.get("Results", []):
            for vuln in target_result.get("Vulnerabilities") or []:
                severity = _TRIVY_SEVERITY.get(vuln.get("Severity", "UNKNOWN"), "info")
                cvss_score = None
                cvss_data = vuln.get("CVSS", {})
                for source in ("nvd", "redhat"):
                    v3 = cvss_data.get(source, {}).get("V3Score")
                    if v3 is not None:
                        cvss_score = float(v3)
                        break

                cve_id = vuln.get("VulnerabilityID")
                pkg = vuln.get("PkgName", "")
                findings.append({
                    "title": f"{cve_id}: {vuln.get('Title', pkg)}"[:512],
                    "description": vuln.get("Description"),
                    "severity": severity,
                    "finding_type": "SCA",
                    "scanner": "trivy",
                    "cve_id": cve_id,
                    "package_name": pkg or None,
                    "package_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "cvss_score": cvss_score,
                    "status": "open",
                })

        logger.info("trivy found %d findings in %s", len(findings), app.name)
        return findings

    def run_govulncheck_scan(self, app: Application, repo_path: Path) -> list[dict[str, Any]]:
        """Run govulncheck for Go stdlib + module vulnerability coverage."""
        if not (repo_path / "go.mod").exists():
            return []

        try:
            result = subprocess.run(
                ["govulncheck", "-json", "-mode=module", "./..."],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(repo_path),
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("govulncheck failed for %s: %s", app.name, e)
            return []

        if result.returncode not in (0, 3):
            # 0 = no vulns, 3 = vulns found; any other code is an error
            logger.error(
                "govulncheck error (exit %d) for %s:\nstderr: %s",
                result.returncode, app.name,
                result.stderr[:2000] if result.stderr else "",
            )
            return []

        findings = []
        seen_osv: set[str] = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            # govulncheck -json emits a stream: {"osv": {...}}, {"finding": {...}}, etc.
            osv = msg.get("osv")
            if not osv:
                continue
            osv_id = osv.get("id", "")
            if osv_id in seen_osv:
                continue
            seen_osv.add(osv_id)

            # Map CVSS score from database_specific if available
            cvss_score = None
            db_specific = osv.get("database_specific", {})
            cvss_v3 = db_specific.get("cvss_v3", {})
            if isinstance(cvss_v3, dict):
                cvss_score = cvss_v3.get("baseScore")

            severity_str = (db_specific.get("severity") or "").upper()
            severity = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(severity_str, "medium")

            aliases = osv.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), None) or osv_id

            # Pick the most informative summary
            summary = osv.get("summary") or osv.get("details") or osv_id
            description = osv.get("details") or osv.get("summary")

            affected = osv.get("affected", [])
            package_name = affected[0].get("package", {}).get("name") if affected else None
            fixed_version = None
            if affected:
                ranges = affected[0].get("ranges", [])
                for r in ranges:
                    for ev in r.get("events", []):
                        if "fixed" in ev:
                            fixed_version = ev["fixed"]
                            break

            findings.append({
                "title": f"{cve_id}: {summary}"[:512],
                "description": description,
                "severity": severity,
                "finding_type": "SCA",
                "scanner": "govulncheck",
                "cve_id": cve_id,
                "package_name": package_name,
                "fixed_version": fixed_version,
                "cvss_score": float(cvss_score) if cvss_score else None,
                "status": "open",
            })

        logger.info("govulncheck found %d findings in %s", len(findings), app.name)
        return findings

    def run_gitleaks_scan(
        self,
        app: Application,
        repo_path: Path,
        custom_patterns: list[dict] | None = None,
    ) -> list[dict[str, Any]]:
        config_path: Path | None = None
        try:
            if custom_patterns:
                toml_lines = ['title = "snitch"\n', "\n", "[extend]\n", "useDefault = true\n"]
                for p in custom_patterns:
                    toml_lines += [
                        "\n[[rules]]\n",
                        f'id = "custom-{p["id"]}"\n',
                        f'description = "{p["name"]}"\n',
                        f"regex = '''{p['pattern']}'''\n",
                        f'severity = "{p["severity"].upper()}"\n',
                    ]
                tmp_cfg = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".toml", delete=False, prefix="snitch-gitleaks-"
                )
                tmp_cfg.writelines(toml_lines)
                tmp_cfg.flush()
                config_path = Path(tmp_cfg.name)

            cmd = [
                "gitleaks", "detect",
                "--source", str(repo_path),
                "--no-git",
                "--report-format", "json",
                "--report-path", "/dev/stdout",
                "--exit-code", "0",
            ]
            if config_path:
                cmd += ["--config", str(config_path)]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.error("gitleaks failed for %s: %s", app.name, e)
                return []

            if result.returncode != 0:
                logger.error(
                    "gitleaks error (exit %d) for %s:\nstderr: %s",
                    result.returncode, app.name,
                    result.stderr[:2000] if result.stderr else "",
                )
                return []

            stdout = (result.stdout or "").strip()
            if not stdout:
                return []

            try:
                raw_output = json.loads(stdout)
            except json.JSONDecodeError as e:
                logger.error("gitleaks JSON parse error for %s: %s\nstdout: %s", app.name, e, stdout[:500])
                return []

            if not isinstance(raw_output, list):
                return []

            findings = []
            for item in raw_output:
                rule_id = item.get("RuleID", "")
                file_path = item.get("File", "") or None
                line_number = item.get("StartLine")
                secret = item.get("Secret", "") or ""
                match_text = item.get("Match", "") or ""
                description = item.get("Description", rule_id)

                try:
                    if file_path:
                        file_path = str(Path(file_path).relative_to(repo_path))
                except ValueError:
                    pass

                findings.append({
                    "title": f"Secret detected: {description}"[:512],
                    "description": f"Rule: {rule_id}. Match context: {_mask_secret(secret or match_text)}",
                    "severity": "high",
                    "finding_type": "secrets",
                    "scanner": "gitleaks",
                    "file_path": file_path,
                    "line_number": line_number,
                    "rule_id": rule_id or None,
                    "status": "open",
                })

            logger.info("gitleaks found %d findings in %s", len(findings), app.name)
            return findings
        finally:
            if config_path and config_path.exists():
                config_path.unlink(missing_ok=True)

    def run_scan(
        self,
        app: Application,
        scan_type: str = "all",
        custom_secret_patterns: list[dict] | None = None,
    ) -> list[dict[str, Any]]:
        """Clone the repo once and run only the scanner(s) requested by *scan_type*.

        Supported values: ``"all"``, ``"semgrep"``, ``"trivy"``, ``"govulncheck"``, ``"gitleaks"``.
        Unknown values fall back to ``"all"`` so callers are never silently broken.
        """
        _KNOWN_TYPES = {"all", "semgrep", "trivy", "govulncheck", "gitleaks"}
        if scan_type not in _KNOWN_TYPES:
            logger.warning("Unknown scan_type %r — running all scanners", scan_type)
            scan_type = "all"

        with tempfile.TemporaryDirectory(prefix="snitch-scan-") as tmp:
            repo_path = Path(tmp) / "repo"
            if not self._clone_repo(app, repo_path):
                raise RuntimeError(f"Failed to clone repository: {app.repo_url}")

            findings: list[dict[str, Any]] = []
            if scan_type in ("all", "semgrep"):
                findings += self.run_semgrep_scan(app, repo_path)
            if scan_type in ("all", "trivy"):
                findings += self.run_trivy_scan(app, repo_path)
            if scan_type in ("all", "govulncheck"):
                findings += self.run_govulncheck_scan(app, repo_path)
            if scan_type in ("all", "gitleaks"):
                findings += self.run_gitleaks_scan(app, repo_path, custom_secret_patterns)

        return findings

    def run_all_scans(self, app: Application) -> list[dict[str, Any]]:
        return self.run_scan(app, scan_type="all")


# ---------------------------------------------------------------------------
# Mock scanner (kept for testing / when tools are unavailable)
# ---------------------------------------------------------------------------
import random

GITLEAKS_RULES = [
    ("aws-access-token", "AWS Access Key", "AKIA1234567890ABCDEF", "config/aws.py"),
    ("github-pat", "GitHub Personal Access Token", "ghp_1234567890abcdef", ".env"),
    ("generic-api-key", "Generic API Key", "api_key_xYzAbC123456", "src/config.py"),
    ("stripe-access-token", "Stripe API Key", "sk_live_123456789abc", "payments/client.py"),
    ("slack-webhook", "Slack Webhook URL", "https://hooks.slack.com/services/T00/B00/xxx", "notify.py"),
    ("private-key", "Private Key", "-----BEGIN RSA PRIVATE KEY-----", "certs/server.key"),
]

SEMGREP_RULES = [
    ("python.django.security.injection.sql.sql-injection-using-db-cursor-fetchone", "SQL Injection via cursor", "critical"),
    ("python.flask.security.xss.reflected-xss", "Reflected XSS in Flask route", "high"),
    ("python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5", "Use of MD5 hash algorithm", "medium"),
    ("python.requests.security.no-auth-over-http", "Credentials sent over HTTP", "high"),
    ("javascript.express.security.audit.xss.mustache-unescaped-variable", "Unescaped Mustache variable", "medium"),
    ("javascript.lang.security.audit.prototype-pollution", "Prototype pollution vulnerability", "high"),
    ("javascript.node.security.audit.path-traversal", "Path traversal vulnerability", "critical"),
    ("go.lang.security.audit.dangerous-exec-command", "Dangerous exec.Command usage", "high"),
    ("java.lang.security.audit.xss.no-direct-response-writer", "XSS via response writer", "medium"),
    ("python.lang.security.audit.insecure-transport.requests.request-with-http", "Insecure HTTP transport", "low"),
    ("python.django.security.audit.csrf-exempt", "CSRF protection disabled", "medium"),
    ("ruby.rails.security.brakeman.check-render-inline", "Inline render XSS risk", "medium"),
]

TRIVY_CVES = [
    ("CVE-2024-3094", "XZ Utils backdoor", "critical", "xz-utils", "5.6.0", "5.6.1", 10.0),
    ("CVE-2023-4911", "Looney Tunables - glibc buffer overflow", "critical", "glibc", "2.37", "2.38-4", 7.8),
    ("CVE-2024-1086", "Linux kernel nf_tables use-after-free", "high", "linux-libc-dev", "6.1.76", "6.1.82", 7.8),
    ("CVE-2023-52425", "libexpat DoS via crafted XML", "high", "libexpat1", "2.5.0", "2.6.0", 7.5),
    ("CVE-2024-0727", "OpenSSL denial of service", "medium", "openssl", "3.0.12", "3.0.13", 5.5),
    ("CVE-2024-2961", "glibc iconv buffer overflow", "high", "libc6", "2.37-15", "2.38", 8.8),
    ("CVE-2023-6246", "glibc syslog heap buffer overflow", "high", "libc-bin", "2.36-9+deb12u3", "2.37", 8.4),
]

FILE_PATHS = [
    "src/api/handlers/auth.py",
    "src/api/handlers/users.py",
    "src/models/database.py",
    "src/utils/crypto.py",
    "app/routes/products.js",
    "app/middleware/auth.js",
    "internal/server/http.go",
    "cmd/main.go",
    "lib/database.rb",
    "app/controllers/sessions_controller.rb",
]


class MockScannerService:
    def run_semgrep_scan(self, app: Application) -> list[dict[str, Any]]:
        findings = []
        for _ in range(random.randint(3, 8)):
            rule_id, title, severity = random.choice(SEMGREP_RULES)
            findings.append({
                "title": title,
                "description": f"Static analysis finding: {title}. Review the code and apply appropriate fix.",
                "severity": severity,
                "finding_type": "SAST",
                "scanner": "semgrep",
                "file_path": random.choice(FILE_PATHS),
                "line_number": random.randint(1, 500),
                "rule_id": rule_id,
                "status": "open",
            })
        return findings

    def run_trivy_scan(self, app: Application) -> list[dict[str, Any]]:
        findings = []
        for _ in range(random.randint(2, 6)):
            cve_id, title, severity, pkg, ver, fixed, cvss = random.choice(TRIVY_CVES)
            findings.append({
                "title": f"{cve_id}: {title}",
                "description": f"SCA vulnerability: {title}. Package {pkg} version {ver} is vulnerable. Upgrade to {fixed}.",
                "severity": severity,
                "finding_type": "SCA",
                "scanner": "trivy",
                "cve_id": cve_id,
                "package_name": pkg,
                "package_version": ver,
                "fixed_version": fixed,
                "cvss_score": cvss,
                "status": "open",
            })
        return findings

    def run_gitleaks_scan(self, app: Application) -> list[dict[str, Any]]:
        findings = []
        for _ in range(random.randint(1, 4)):
            rule_id, title, secret, file_path = random.choice(GITLEAKS_RULES)
            findings.append({
                "title": f"Secret detected: {title}"[:512],
                "description": f"Rule: {rule_id}. Match context: {_mask_secret(secret)}",
                "severity": "high",
                "finding_type": "secrets",
                "scanner": "gitleaks",
                "file_path": file_path,
                "line_number": random.randint(1, 100),
                "rule_id": rule_id,
                "status": "open",
            })
        return findings

    def run_all_scans(self, app: Application) -> list[dict[str, Any]]:
        return self.run_semgrep_scan(app) + self.run_trivy_scan(app) + self.run_gitleaks_scan(app)


scanner_service = MockScannerService()
real_scanner_service = RealScannerService()

