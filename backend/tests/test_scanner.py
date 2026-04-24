"""
Unit tests for scanner parsing logic and deduplication service.
"""
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.base import Base
from app.services.deduplication import _match_key, upsert_findings
from app.services.scanner import RealScannerService, _SEMGREP_SEVERITY, _TRIVY_SEVERITY

# ---------------------------------------------------------------------------
# _match_key
# ---------------------------------------------------------------------------

def test_match_key_sast():
    raw = {"rule_id": "python.flask.xss", "file_path": "app/views.py", "scanner": "semgrep", "title": "XSS"}
    assert _match_key(raw) == ("sast", "python.flask.xss", "app/views.py")


def test_match_key_sca():
    raw = {"cve_id": "CVE-2023-1234", "package_name": "requests", "scanner": "trivy", "title": "vuln"}
    assert _match_key(raw) == ("sca", "CVE-2023-1234", "requests")


def test_match_key_generic_fallback():
    raw = {"scanner": "semgrep", "title": "Some Finding"}
    assert _match_key(raw) == ("generic", "semgrep", "Some Finding")


def test_match_key_prefers_sast_over_sca():
    # Has both rule_id/file_path AND cve_id/package_name — SAST wins
    raw = {
        "rule_id": "my.rule", "file_path": "foo.py",
        "cve_id": "CVE-0000", "package_name": "pkg",
    }
    assert _match_key(raw)[0] == "sast"


def test_match_key_title_truncated_to_255():
    raw = {"scanner": "x", "title": "A" * 300}
    _, _, title_part = _match_key(raw)
    assert len(title_part) == 255


# ---------------------------------------------------------------------------
# Semgrep severity mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("ERROR", "high"),
    ("WARNING", "medium"),
    ("INFO", "low"),
])
def test_semgrep_severity_map(raw, expected):
    assert _SEMGREP_SEVERITY[raw] == expected


# ---------------------------------------------------------------------------
# Trivy severity mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("CRITICAL", "critical"),
    ("HIGH", "high"),
    ("MEDIUM", "medium"),
    ("LOW", "low"),
    ("UNKNOWN", "info"),
])
def test_trivy_severity_map(raw, expected):
    assert _TRIVY_SEVERITY[raw] == expected


# ---------------------------------------------------------------------------
# RealScannerService — semgrep output parsing
# ---------------------------------------------------------------------------

SEMGREP_OUTPUT = {
    "results": [
        {
            "check_id": "python.flask.xss",
            "path": "/tmp/repo/app/views.py",
            "start": {"line": 42},
            "extra": {
                "message": "Potential XSS vulnerability",
                "severity": "ERROR",
                "metadata": {"impact": "HIGH"},
            },
        },
        {
            "check_id": "python.md5.weak-hash",
            "path": "/tmp/repo/utils/crypto.py",
            "start": {"line": 7},
            "extra": {
                "message": "Use of MD5",
                "severity": "WARNING",
                "metadata": {},
            },
        },
    ]
}


def _make_app(name="test-app", repo_url="https://github.com/org/repo"):
    app = MagicMock()
    app.name = name
    app.repo_url = repo_url
    return app


def test_run_semgrep_scan_parses_findings():
    from pathlib import Path
    svc = RealScannerService()
    app = _make_app()
    repo_path = Path("/tmp/repo")

    import json
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(SEMGREP_OUTPUT),
            stderr="",
        )
        findings = svc.run_semgrep_scan(app, repo_path)

    assert len(findings) == 2

    xss = findings[0]
    assert xss["rule_id"] == "python.flask.xss"
    assert xss["severity"] == "high"          # impact=HIGH takes precedence
    assert xss["finding_type"] == "SAST"
    assert xss["scanner"] == "semgrep"
    assert xss["line_number"] == 42
    assert xss["file_path"] == "app/views.py"  # relative to repo_path

    md5 = findings[1]
    assert md5["severity"] == "medium"         # WARNING → medium


def test_run_semgrep_scan_empty_on_bad_json():
    from pathlib import Path
    svc = RealScannerService()
    app = _make_app()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="not-json", stderr="")
        findings = svc.run_semgrep_scan(app, Path("/tmp/repo"))

    assert findings == []


def test_run_semgrep_scan_empty_on_timeout():
    import subprocess
    from pathlib import Path
    svc = RealScannerService()
    app = _make_app()

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("semgrep", 300)):
        findings = svc.run_semgrep_scan(app, Path("/tmp/repo"))

    assert findings == []


# ---------------------------------------------------------------------------
# RealScannerService — trivy output parsing
# ---------------------------------------------------------------------------

TRIVY_OUTPUT = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-99999",
                    "PkgName": "requests",
                    "InstalledVersion": "2.27.0",
                    "FixedVersion": "2.31.0",
                    "Severity": "HIGH",
                    "Title": "SSRF in requests",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                }
            ],
        },
        {
            "Target": "go.sum",
            "Vulnerabilities": None,  # Trivy may return null for no vulns
        },
    ]
}


def test_run_trivy_scan_parses_findings():
    from pathlib import Path
    import json
    svc = RealScannerService()
    app = _make_app()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(TRIVY_OUTPUT),
            stderr="",
        )
        findings = svc.run_trivy_scan(app, Path("/tmp/repo"))

    assert len(findings) == 1
    f = findings[0]
    assert f["cve_id"] == "CVE-2023-99999"
    assert f["package_name"] == "requests"
    assert f["package_version"] == "2.27.0"
    assert f["fixed_version"] == "2.31.0"
    assert f["severity"] == "high"
    assert f["cvss_score"] == 7.5
    assert f["finding_type"] == "SCA"
    assert f["scanner"] == "trivy"


def test_run_trivy_scan_handles_null_vulnerabilities():
    from pathlib import Path
    import json
    svc = RealScannerService()
    app = _make_app()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"Results": [{"Target": "go.sum", "Vulnerabilities": None}]}),
            stderr="",
        )
        findings = svc.run_trivy_scan(app, Path("/tmp/repo"))

    assert findings == []


# ---------------------------------------------------------------------------
# Deduplication — upsert_findings
# ---------------------------------------------------------------------------

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def dedup_db():
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
        await session.rollback()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.mark.asyncio
async def test_upsert_creates_new_findings(dedup_db):
    app_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    raw = [
        {"title": "XSS", "severity": "high", "finding_type": "SAST", "scanner": "semgrep",
         "rule_id": "xss.rule", "file_path": "views.py", "status": "open"},
    ]
    findings, created, updated = await upsert_findings(dedup_db, app_id, scan_id, raw)
    assert created == 1
    assert updated == 0
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_upsert_updates_existing_finding(dedup_db):
    app_id = uuid.uuid4()
    scan_id_1 = uuid.uuid4()
    scan_id_2 = uuid.uuid4()
    raw = [{"title": "XSS", "severity": "high", "finding_type": "SAST", "scanner": "semgrep",
            "rule_id": "xss.rule", "file_path": "views.py", "status": "open"}]

    await upsert_findings(dedup_db, app_id, scan_id_1, raw)
    findings, created, updated = await upsert_findings(dedup_db, app_id, scan_id_2, raw)

    assert created == 0
    assert updated == 1
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_upsert_marks_missing_findings_fixed(dedup_db):
    app_id = uuid.uuid4()
    scan_id_1 = uuid.uuid4()
    scan_id_2 = uuid.uuid4()

    raw_first = [
        {"title": "XSS", "severity": "high", "finding_type": "SAST", "scanner": "semgrep",
         "rule_id": "xss.rule", "file_path": "views.py", "status": "open"},
        {"title": "SQLi", "severity": "critical", "finding_type": "SAST", "scanner": "semgrep",
         "rule_id": "sql.rule", "file_path": "db.py", "status": "open"},
    ]
    await upsert_findings(dedup_db, app_id, scan_id_1, raw_first)

    # Second scan only returns XSS; SQLi should be marked fixed
    raw_second = [raw_first[0]]
    findings, created, updated = await upsert_findings(dedup_db, app_id, scan_id_2, raw_second)

    fixed = [f for f in findings if f.status == "fixed"]
    open_ = [f for f in findings if f.status == "open"]
    assert len(fixed) == 1
    assert fixed[0].rule_id == "sql.rule"
    assert len(open_) == 1


@pytest.mark.asyncio
async def test_upsert_reopens_previously_fixed_finding(dedup_db):
    app_id = uuid.uuid4()
    raw = [{"title": "XSS", "severity": "high", "finding_type": "SAST", "scanner": "semgrep",
            "rule_id": "xss.rule", "file_path": "views.py", "status": "open"}]

    # Scan 1: create finding
    await upsert_findings(dedup_db, app_id, uuid.uuid4(), raw)
    # Scan 2: empty — finding becomes fixed
    findings, _, _ = await upsert_findings(dedup_db, app_id, uuid.uuid4(), [])
    assert findings[0].status == "fixed"

    # Scan 3: finding reappears — should reopen
    findings, _, updated = await upsert_findings(dedup_db, app_id, uuid.uuid4(), raw)
    assert findings[0].status == "open"
    assert findings[0].fixed_at is None
    assert updated == 1


# ---------------------------------------------------------------------------
# govulncheck output parsing
# ---------------------------------------------------------------------------

def _make_app(name="test-go-app"):
    app = MagicMock()
    app.name = name
    app.repo_url = "https://github.com/example/test-go-app"
    return app


def _govulncheck_ndjson(*osv_records: dict) -> str:
    """Build a govulncheck -json stdout from a list of osv dicts."""
    import json as _json
    lines = [_json.dumps({"osv": r}) for r in osv_records]
    return "\n".join(lines)


def test_govulncheck_skipped_if_no_go_mod(tmp_path):
    svc = RealScannerService()
    app = _make_app()
    # no go.mod in tmp_path
    result = svc.run_govulncheck_scan(app, tmp_path)
    assert result == []


def test_govulncheck_returns_empty_on_error(tmp_path):
    (tmp_path / "go.mod").write_text("module x\ngo 1.21\n")
    svc = RealScannerService()
    app = _make_app()

    mock_result = MagicMock()
    mock_result.returncode = 1   # not 0 or 3 — treated as error
    mock_result.stderr = "some internal error"
    mock_result.stdout = ""

    with patch("subprocess.run", return_value=mock_result):
        result = svc.run_govulncheck_scan(app, tmp_path)
    assert result == []


def test_govulncheck_parses_single_osv(tmp_path):
    (tmp_path / "go.mod").write_text("module x\ngo 1.21\n")
    svc = RealScannerService()
    app = _make_app()

    osv = {
        "id": "GO-2023-1234",
        "aliases": ["CVE-2023-1234"],
        "summary": "Memory corruption in net/http",
        "details": "An attacker can cause memory corruption via crafted request.",
        "database_specific": {"severity": "HIGH", "cvss_v3": {"baseScore": 7.5}},
        "affected": [
            {"package": {"name": "stdlib"},
             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.21.6"}]}]}
        ],
    }
    stdout = _govulncheck_ndjson(osv)
    mock_result = MagicMock()
    mock_result.returncode = 3  # vulns found
    mock_result.stdout = stdout
    mock_result.stderr = ""

    with patch("subprocess.run", return_value=mock_result):
        findings = svc.run_govulncheck_scan(app, tmp_path)

    assert len(findings) == 1
    f = findings[0]
    assert f["cve_id"] == "CVE-2023-1234"
    assert f["severity"] == "high"
    assert f["scanner"] == "govulncheck"
    assert f["finding_type"] == "SCA"
    assert f["cvss_score"] == 7.5
    assert f["fixed_version"] == "1.21.6"
    assert f["package_name"] == "stdlib"


def test_govulncheck_deduplicates_by_osv_id(tmp_path):
    (tmp_path / "go.mod").write_text("module x\ngo 1.21\n")
    svc = RealScannerService()
    app = _make_app()

    osv = {
        "id": "GO-2023-9999",
        "aliases": ["CVE-2023-9999"],
        "summary": "Duplicate vuln",
        "database_specific": {"severity": "MEDIUM"},
    }
    # Emit same OSV twice — should only produce one finding
    stdout = _govulncheck_ndjson(osv, osv)
    mock_result = MagicMock()
    mock_result.returncode = 3
    mock_result.stdout = stdout
    mock_result.stderr = ""

    with patch("subprocess.run", return_value=mock_result):
        findings = svc.run_govulncheck_scan(app, tmp_path)

    assert len(findings) == 1


def test_govulncheck_falls_back_to_osv_id_when_no_cve_alias(tmp_path):
    (tmp_path / "go.mod").write_text("module x\ngo 1.21\n")
    svc = RealScannerService()
    app = _make_app()

    osv = {
        "id": "GO-2023-7777",
        "aliases": ["GHSA-xxxx-yyyy-zzzz"],   # no CVE alias
        "summary": "Non-CVE finding",
        "database_specific": {"severity": "LOW"},
    }
    stdout = _govulncheck_ndjson(osv)
    mock_result = MagicMock()
    mock_result.returncode = 3
    mock_result.stdout = stdout
    mock_result.stderr = ""

    with patch("subprocess.run", return_value=mock_result):
        findings = svc.run_govulncheck_scan(app, tmp_path)

    assert len(findings) == 1
    assert findings[0]["cve_id"] == "GO-2023-7777"


# ---------------------------------------------------------------------------
# RealScannerService — checkov output parsing
# ---------------------------------------------------------------------------

CHECKOV_OUTPUT_SINGLE = {
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_18",
                "check": "Ensure the S3 bucket has access logging enabled",
                "check_type": "terraform",
                "resource": "aws_s3_bucket.my_bucket",
                "file_path": "/tmp/repo/main.tf",
                "repo_file_path": "/tmp/repo/main.tf",
                "file_line_range": [10, 25],
                "severity": "MEDIUM",
            }
        ],
        "passed_checks": [],
    }
}

CHECKOV_OUTPUT_LIST = [
    {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_18",
                    "check": "Ensure the S3 bucket has access logging enabled",
                    "check_type": "terraform",
                    "resource": "aws_s3_bucket.my_bucket",
                    "file_path": "/tmp/repo/main.tf",
                    "repo_file_path": "/tmp/repo/main.tf",
                    "file_line_range": [10, 25],
                    "severity": "HIGH",
                }
            ],
            "passed_checks": [],
        }
    },
    {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_2",
                    "check": "ALB HTTPS check",
                    "check_type": "cloudformation",
                    "resource": "AWS::ElasticLoadBalancingV2::Listener",
                    "file_path": "/tmp/repo/template.yaml",
                    "repo_file_path": "/tmp/repo/template.yaml",
                    "file_line_range": [5, 10],
                    "severity": "CRITICAL",
                }
            ],
            "passed_checks": [],
        }
    },
]


def test_run_checkov_scan_single_dict():
    """Checkov returns a single dict — check field mapping."""
    import json
    from pathlib import Path

    svc = RealScannerService()
    app = _make_app("terraform-app")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=1,  # checkov exits 1 when findings found
            stdout=json.dumps(CHECKOV_OUTPUT_SINGLE),
            stderr="",
        )
        findings = svc.run_checkov_scan(app, Path("/tmp/repo"))

    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "CKV_AWS_18"
    assert f["finding_type"] == "IaC"
    assert f["scanner"] == "checkov"
    assert f["severity"] == "medium"
    assert f["line_number"] == 10
    assert f["status"] == "open"
    assert "CKV_AWS_18" in f["title"]


def test_run_checkov_scan_list_format():
    """Checkov returns a list (one section per framework) — both sections parsed."""
    import json
    from pathlib import Path

    svc = RealScannerService()
    app = _make_app("tf-app")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps(CHECKOV_OUTPUT_LIST),
            stderr="",
        )
        findings = svc.run_checkov_scan(app, Path("/tmp/repo"))

    assert len(findings) == 2
    check_ids = {f["rule_id"] for f in findings}
    assert check_ids == {"CKV_AWS_18", "CKV_AWS_2"}
    # Severities mapped correctly
    severities = {f["rule_id"]: f["severity"] for f in findings}
    assert severities["CKV_AWS_18"] == "high"
    assert severities["CKV_AWS_2"] == "critical"


def test_run_checkov_scan_exit_zero_no_findings():
    """Checkov exits 0 when all checks pass — should return empty list, not error."""
    import json
    from pathlib import Path

    svc = RealScannerService()
    app = _make_app()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"results": {"failed_checks": [], "passed_checks": []}}),
            stderr="",
        )
        findings = svc.run_checkov_scan(app, Path("/tmp/repo"))

    assert findings == []


def test_run_checkov_scan_returns_empty_on_not_found():
    """If checkov binary is missing, return empty list."""
    import subprocess
    from pathlib import Path

    svc = RealScannerService()
    app = _make_app()

    with patch("subprocess.run", side_effect=FileNotFoundError("checkov not found")):
        findings = svc.run_checkov_scan(app, Path("/tmp/repo"))

    assert findings == []


# ---------------------------------------------------------------------------
# RealScannerService — grype output parsing
# ---------------------------------------------------------------------------

GRYPE_OUTPUT = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2021-44228",
                "description": "Log4Shell remote code execution",
                "severity": "Critical",
                "fix": {"versions": ["2.15.0"]},
                "cvss": [
                    {"version": "3.1", "metrics": {"baseScore": 10.0}}
                ],
            },
            "artifact": {
                "name": "log4j-core",
                "version": "2.14.1",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2022-22965",
                "description": "Spring4Shell",
                "severity": "High",
                "fix": {"versions": []},
                "cvss": [],
            },
            "artifact": {
                "name": "spring-webmvc",
                "version": "5.3.17",
            },
        },
    ]
}


def test_run_grype_scan_parses_findings():
    """Grype output should map to container findings."""
    import json
    from pathlib import Path

    svc = RealScannerService()
    app = _make_app("nginx-app")
    app.container_image = "nginx:1.24"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(GRYPE_OUTPUT),
            stderr="",
        )
        findings = svc.run_grype_scan(app, "nginx:1.24")

    assert len(findings) == 2

    log4shell = findings[0]
    assert log4shell["cve_id"] == "CVE-2021-44228"
    assert log4shell["package_name"] == "log4j-core"
    assert log4shell["package_version"] == "2.14.1"
    assert log4shell["fixed_version"] == "2.15.0"
    assert log4shell["severity"] == "critical"
    assert log4shell["cvss_score"] == 10.0
    assert log4shell["finding_type"] == "container"
    assert log4shell["scanner"] == "grype"

    spring = findings[1]
    assert spring["severity"] == "high"
    assert spring["fixed_version"] is None
    assert spring["cvss_score"] is None


def test_run_grype_scan_returns_empty_for_no_image():
    """If container_image is empty/None, grype is skipped."""
    from pathlib import Path

    svc = RealScannerService()
    app = _make_app()

    findings = svc.run_grype_scan(app, "")
    assert findings == []

    findings = svc.run_grype_scan(app, None)
    assert findings == []


def test_run_grype_scan_returns_empty_on_nonzero_exit():
    """Non-zero grype exit (e.g. image not found) returns empty list."""
    import json
    from pathlib import Path

    svc = RealScannerService()
    app = _make_app()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="image not found")
        findings = svc.run_grype_scan(app, "does-not-exist:latest")

    assert findings == []


def test_govulncheck_no_findings_on_returncode_zero(tmp_path):
    (tmp_path / "go.mod").write_text("module x\ngo 1.21\n")
    svc = RealScannerService()
    app = _make_app()

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = ""
    mock_result.stderr = ""

    with patch("subprocess.run", return_value=mock_result):
        findings = svc.run_govulncheck_scan(app, tmp_path)
    assert findings == []

