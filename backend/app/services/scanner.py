import random
import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.application import Application


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

GRYPE_CVES = [
    ("CVE-2023-44487", "HTTP/2 Rapid Reset Attack", "critical", "golang.org/x/net", "0.14.0", "0.17.0", 7.5),
    ("CVE-2023-39325", "HTTP/2 rapid reset can cause excessive work", "high", "golang.org/x/net", "0.13.0", "0.17.0", 7.5),
    ("CVE-2024-21626", "Leaky vessels - container escape", "critical", "runc", "1.1.9", "1.1.12", 8.6),
    ("CVE-2023-47108", "OpenTelemetry gRPC DoS", "high", "go.opentelemetry.io/otel", "1.19.0", "1.20.0", 7.5),
    ("CVE-2023-29406", "HTTP/1 client insufficient validation of Host header", "medium", "stdlib", "1.20.5", "1.21.0", 6.5),
    ("CVE-2024-24786", "Infinite loop in protojson.Unmarshal", "medium", "google.golang.org/protobuf", "1.32.0", "1.33.0", 5.9),
    ("CVE-2023-48795", "Terrapin attack - SSH protocol downgrade", "medium", "golang.org/x/crypto", "0.14.0", "0.17.0", 5.9),
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
        count = random.randint(3, 8)
        for _ in range(count):
            rule_id, title, severity = random.choice(SEMGREP_RULES)
            findings.append({
                "id": str(uuid.uuid4()),
                "title": title,
                "description": f"Static analysis finding: {title}. Review the code and apply appropriate fix.",
                "severity": severity,
                "finding_type": "SAST",
                "scanner": "semgrep",
                "file_path": random.choice(FILE_PATHS),
                "line_number": random.randint(1, 500),
                "rule_id": rule_id,
                "status": "open",
                "first_seen_at": datetime.now(timezone.utc).isoformat(),
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            })
        return findings

    def run_grype_scan(self, app: Application) -> list[dict[str, Any]]:
        findings = []
        count = random.randint(2, 6)
        for _ in range(count):
            cve_id, title, severity, pkg, ver, fixed, cvss = random.choice(GRYPE_CVES)
            findings.append({
                "id": str(uuid.uuid4()),
                "title": f"{cve_id}: {title}",
                "description": f"Container image vulnerability: {title}. Upgrade {pkg} to {fixed} or later.",
                "severity": severity,
                "finding_type": "container",
                "scanner": "grype",
                "cve_id": cve_id,
                "package_name": pkg,
                "package_version": ver,
                "fixed_version": fixed,
                "cvss_score": cvss,
                "status": "open",
                "first_seen_at": datetime.now(timezone.utc).isoformat(),
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            })
        return findings

    def run_trivy_scan(self, app: Application) -> list[dict[str, Any]]:
        findings = []
        count = random.randint(2, 6)
        for _ in range(count):
            cve_id, title, severity, pkg, ver, fixed, cvss = random.choice(TRIVY_CVES)
            findings.append({
                "id": str(uuid.uuid4()),
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
                "first_seen_at": datetime.now(timezone.utc).isoformat(),
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            })
        return findings

    def run_all_scans(self, app: Application) -> list[dict[str, Any]]:
        return (
            self.run_semgrep_scan(app)
            + self.run_grype_scan(app)
            + self.run_trivy_scan(app)
        )


scanner_service = MockScannerService()
