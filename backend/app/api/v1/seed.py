import random
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.application import Application
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.scoring import calculate_risk_score

router = APIRouter(prefix="/seed", tags=["seed"])

DEMO_APPS = [
    {"name": "payments-api", "github_org": "acme-corp", "github_repo": "payments-api", "team_name": "Platform", "language": "Python", "repo_url": "https://github.com/acme-corp/payments-api", "description": "Core payment processing API"},
    {"name": "auth-service", "github_org": "acme-corp", "github_repo": "auth-service", "team_name": "Platform", "language": "Go", "repo_url": "https://github.com/acme-corp/auth-service", "description": "Authentication and authorization service"},
    {"name": "frontend-app", "github_org": "acme-corp", "github_repo": "frontend-app", "team_name": "Product", "language": "JavaScript", "repo_url": "https://github.com/acme-corp/frontend-app", "description": "Main customer-facing web application"},
    {"name": "data-pipeline", "github_org": "acme-corp", "github_repo": "data-pipeline", "team_name": "Data", "language": "Python", "repo_url": "https://github.com/acme-corp/data-pipeline", "description": "ETL data processing pipeline"},
    {"name": "inventory-service", "github_org": "acme-corp", "github_repo": "inventory-service", "team_name": "Commerce", "language": "Java", "repo_url": "https://github.com/acme-corp/inventory-service", "description": "Product inventory management service"},
    {"name": "notification-worker", "github_org": "acme-corp", "github_repo": "notification-worker", "team_name": "Product", "language": "Python", "repo_url": "https://github.com/acme-corp/notification-worker", "description": "Async notification worker"},
    {"name": "admin-dashboard", "github_org": "acme-corp", "github_repo": "admin-dashboard", "team_name": "Commerce", "language": "TypeScript", "repo_url": "https://github.com/acme-corp/admin-dashboard", "description": "Internal admin dashboard"},
    {"name": "ml-inference-api", "github_org": "acme-corp", "github_repo": "ml-inference-api", "team_name": "Data", "language": "Python", "repo_url": "https://github.com/acme-corp/ml-inference-api", "description": "Machine learning model inference API"},
]

SEED_FINDINGS = [
    ("CVE-2024-3094: XZ Utils backdoor", "SCA vulnerability in XZ Utils 5.6.0", "critical", "SCA", "trivy", None, None, None, "CVE-2024-3094", "xz-utils", "5.6.0", "5.6.1", 10.0),
    ("CVE-2023-44487: HTTP/2 Rapid Reset Attack", "HTTP/2 rapid reset attack vulnerability", "critical", "container", "grype", None, None, None, "CVE-2023-44487", "golang.org/x/net", "0.14.0", "0.17.0", 7.5),
    ("SQL Injection via cursor", "Unsanitized input in database query", "critical", "SAST", "semgrep", "src/api/handlers/auth.py", 42, "python.django.security.injection.sql.sql-injection-using-db-cursor-fetchone", None, None, None, None, None),
    ("CVE-2024-21626: Container escape", "Leaky vessels - runc container escape vulnerability", "critical", "container", "grype", None, None, None, "CVE-2024-21626", "runc", "1.1.9", "1.1.12", 8.6),
    ("Reflected XSS in Flask route", "User-controlled data rendered without sanitization", "high", "SAST", "semgrep", "src/api/handlers/users.py", 87, "python.flask.security.xss.reflected-xss", None, None, None, None, None),
    ("CVE-2023-4911: Looney Tunables glibc overflow", "glibc buffer overflow vulnerability", "high", "SCA", "trivy", None, None, None, "CVE-2023-4911", "glibc", "2.37", "2.38-4", 7.8),
    ("Path traversal vulnerability", "Unsanitized file path in user input", "high", "SAST", "semgrep", "internal/server/http.go", 156, "javascript.node.security.audit.path-traversal", None, None, None, None, None),
    ("CVE-2024-1086: Linux kernel use-after-free", "nf_tables use-after-free vulnerability", "high", "SCA", "trivy", None, None, None, "CVE-2024-1086", "linux-libc-dev", "6.1.76", "6.1.82", 7.8),
    ("Use of MD5 hash algorithm", "Weak cryptographic hash function in use", "medium", "SAST", "semgrep", "src/utils/crypto.py", 23, "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5", None, None, None, None, None),
    ("CVE-2024-0727: OpenSSL denial of service", "OpenSSL DoS vulnerability", "medium", "SCA", "trivy", None, None, None, "CVE-2024-0727", "openssl", "3.0.12", "3.0.13", 5.5),
    ("Prototype pollution vulnerability", "Prototype pollution in object merge function", "high", "SAST", "semgrep", "app/routes/products.js", 201, "javascript.lang.security.audit.prototype-pollution", None, None, None, None, None),
    ("CVE-2023-48795: Terrapin SSH attack", "SSH protocol downgrade attack", "medium", "container", "grype", None, None, None, "CVE-2023-48795", "golang.org/x/crypto", "0.14.0", "0.17.0", 5.9),
    ("CSRF protection disabled", "CSRF exempt decorator found", "medium", "SAST", "semgrep", "src/api/handlers/auth.py", 15, "python.django.security.audit.csrf-exempt", None, None, None, None, None),
    ("Insecure HTTP transport", "Credentials sent over unencrypted HTTP", "low", "SAST", "semgrep", "src/api/handlers/users.py", 312, "python.lang.security.audit.insecure-transport.requests.request-with-http", None, None, None, None, None),
    ("CVE-2024-2961: glibc iconv overflow", "glibc iconv buffer overflow", "high", "SCA", "trivy", None, None, None, "CVE-2024-2961", "libc6", "2.37-15", "2.38", 8.8),
]


@router.post("")
async def seed_data(db: AsyncSession = Depends(get_db)):
    """Create demo applications and findings for testing."""
    created_apps = []

    for app_data in DEMO_APPS:
        app = Application(**app_data)
        db.add(app)
        await db.flush()
        created_apps.append(app)

    # Create scans and assign findings
    for app in created_apps:
        scan = Scan(
            application_id=app.id,
            scan_type="all",
            status="completed",
            trigger="scheduled",
            started_at=datetime.now(timezone.utc) - timedelta(hours=2),
            completed_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        db.add(scan)
        await db.flush()

        # Randomly pick 4-10 findings per app
        num_findings = random.randint(4, 10)
        selected = random.sample(SEED_FINDINGS, min(num_findings, len(SEED_FINDINGS)))
        app_findings = []

        for f_data in selected:
            (title, desc, severity, ftype, scanner, fpath, line, rule_id,
             cve_id, pkg, ver, fixed_ver, cvss) = f_data

            # Backdate first_seen_at up to 90 days ago
            days_ago = random.randint(1, 90)
            first_seen = datetime.now(timezone.utc) - timedelta(days=days_ago)

            status_choice = random.choices(
                ["open", "open", "open", "fixed", "accepted"],
                weights=[60, 10, 10, 15, 5]
            )[0]
            fixed_at = datetime.now(timezone.utc) - timedelta(days=random.randint(0, days_ago)) if status_choice == "fixed" else None

            finding = Finding(
                application_id=app.id,
                scan_id=scan.id,
                title=title,
                description=desc,
                severity=severity,
                finding_type=ftype,
                scanner=scanner,
                file_path=fpath,
                line_number=line,
                rule_id=rule_id,
                cve_id=cve_id,
                package_name=pkg,
                package_version=ver,
                fixed_version=fixed_ver,
                cvss_score=cvss,
                status=status_choice,
                first_seen_at=first_seen,
                last_seen_at=datetime.now(timezone.utc),
                fixed_at=fixed_at,
            )
            db.add(finding)
            app_findings.append(finding)

        await db.flush()

        scan.findings_count = len(app_findings)
        scan.critical_count = sum(1 for f in app_findings if f.severity == "critical")
        scan.high_count = sum(1 for f in app_findings if f.severity == "high")
        scan.medium_count = sum(1 for f in app_findings if f.severity == "medium")
        scan.low_count = sum(1 for f in app_findings if f.severity == "low")

        risk_score, risk_level = calculate_risk_score(app_findings)
        app.risk_score = risk_score
        app.risk_level = risk_level
        app.last_scan_at = datetime.now(timezone.utc)

    await db.flush()

    return {
        "message": "Seed data created successfully",
        "apps_created": len(created_apps),
    }
