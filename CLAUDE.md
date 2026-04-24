# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules
ALWAYS create a new branch before writing new code when in plan mode.
ALWAYS update CLAUDE.md before pushing any code to GitHub
ALWAYS update README.md before pushing any code to GitHub
ALWAYS update API Docs / swagger before pushing any code to GitHub
ALWAYS push the branch to GitHub and open a PR

## What This Is

Snitch is an AppSec platform that aggregates security findings from Semgrep (SAST), Grype (container CVEs), Trivy (SCA), Checkov (IaC/Terraform), and Gitleaks (secrets), calculates per-app risk scores, and provides AI-powered remediation via Anthropic Claude. Includes a User Profile page with light/dark mode toggle (stored in localStorage). UI uses a vibrant dark theme with CSS design tokens in `frontend/static/css/theme.css` (severity palette, gradient, glow variables).

The sidebar is a shared JS component defined in `frontend/static/js/sidebar.js`. Each HTML page uses `<div id="sidebar-mount"></div>` followed by `<script src="/static/js/sidebar.js"></script>` — the script renders the full sidebar, auto-detects the active nav link, and defines `window.applyTheme()`. Do not duplicate sidebar HTML across pages; edit `sidebar.js` for any sidebar changes.

The header user widget is a shared JS component defined in `frontend/static/js/header.js`. Each HTML page includes `<script src="/static/js/header.js"></script>` after the sidebar script and adds `id="header-user-slot"` to the right-side container inside `<header>`. The script injects a circular user avatar button with a dropdown (Profile link + disabled Logout placeholder) into that slot. Do not duplicate the widget HTML across pages; edit `header.js` for any user-menu changes.

The sidebar nav is structured into four sections: **Overview** (Dashboard, Applications, Reports, Secrets), **Config** (Policies, Rules), **Admin** (Settings, Repositories, Service Accounts), **Help** (Documentation `/help.html`, About `/about.html`, API Docs `/docs`). The Profile link has been removed from the sidebar — it is only accessible via the header user widget dropdown. Nav items that open external links set `external: true` in NAV_SECTIONS and are rendered with a target="_blank" and an external-link icon.

The `/settings.html` page is the admin configuration page for platform integrations (GitHub token, Anthropic API key), scan defaults, and read-only system info. It stores token presence flags in `localStorage` only — raw secrets are never persisted client-side.

The `/service-accounts.html` page is the admin management page for service accounts — machine identities used by CI/CD pipelines. It lists accounts (name, team, token prefix, status, last used), supports creating new accounts (token shown once in a modal with copy button), rotating tokens (old token immediately revoked), and revoking accounts. Token format is `snitch_<32chars>` (SHA-256 hash stored, plaintext never persisted).

The applications page (`/applications.html`) uses a sortable list/table view instead of a card grid. Default sort is risk score descending. Clicking any column header toggles ascending/descending sort.

The `/help.html` page is a single-page developer documentation hub with four tabs: Quick Start, GitHub Actions CI/CD integration guide (includes 3-secret setup: SNITCH_URL, SNITCH_APPLICATION_ID, SNITCH_TOKEN; Stage 1 auth verify step; Stage 2 push step for Semgrep, Trivy, Checkov, Gitleaks, Grype), General Usage walkthrough, and API Reference with curl examples.

The `/about.html` page contains the platform overview, technology stack cards, license info, and a timeline-style release notes changelog (v0.8 → v1.5).

## Commands

```bash
# Start the full stack
docker compose up --build

# Run all backend tests
cd backend && python -m pytest tests/ -v

# Run a single test file
cd backend && python -m pytest tests/test_applications.py -v

# Run a single test by name
cd backend && python -m pytest tests/ -v -k "test_create_application"

# Run locally (requires PostgreSQL on localhost:5432)
cd backend && DATABASE_URL=postgresql+asyncpg://snitch:snitch@localhost:5432/snitch uvicorn app.main:app --reload

# Apply database migrations
cd backend && alembic upgrade head

# Create a new migration
cd backend && alembic revision --autogenerate -m "description"
```

## Architecture

**Backend:** FastAPI + async SQLAlchemy (PostgreSQL). Celery workers handle async scan tasks; Celery Beat runs periodic jobs. Redis is the broker.

**Frontend:** Plain HTML/CSS/JS (`frontend/`) served as static files mounted at `/` by FastAPI. No build step required.

```
backend/app/
├── main.py          # FastAPI app, CORS, static mount, lifespan (creates tables on startup)
├── core/config.py   # pydantic-settings: DATABASE_URL, GITHUB_TOKEN, ANTHROPIC_API_KEY, REDIS_URL
├── db/session.py    # async SQLAlchemy engine + get_db() dependency
├── models/          # SQLAlchemy ORM: Application, Scan, Finding, Remediation, CiCdScan, Policy, SecretPattern
├── schemas/         # Pydantic request/response schemas (mirrors models/)
├── api/v1/          # Route handlers; all mounted under /api/v1/ via router.py
│   │                # includes: applications, findings, scans, remediation, reports,
│   │                #           cicd_scans, policies, secrets, github, seed, rules
├── worker/          # Celery task definitions (scans, periodic scheduled jobs)
└── services/
    ├── scanner.py         # Semgrep/Trivy/Govulncheck/Gitleaks/Checkov/Grype + MockScannerService
    ├── scoring.py         # Risk score calculator
    ├── deduplication.py   # Finding deduplication logic (SAST/SCA/secrets/generic keys)
    ├── cicd_normaliser.py # Normalise Semgrep/Grype/Checkov CI/CD JSON output
    ├── policy_evaluator.py # Evaluate policy rules against findings
    ├── rule_catalog.py    # Static catalog of ~37 rules (Checkov/IaC, Semgrep/SAST, Gitleaks/secrets)
    ├── ai_remediation.py  # Claude integration; falls back to mock plan if no API key
    └── github_service.py  # GitHub code scanning sync + branch/PR creation via PyGitHub
```

## Key Conventions

### Models & Schemas
- All PKs are `uuid.UUID` using `UUID(as_uuid=True)` (PostgreSQL). Tests use SQLite in-memory, which handles UUIDs as strings.
- Relationships use `cascade="all, delete-orphan"` on the owning side.
- Every model has `created_at` / `updated_at` with `server_default=func.now()`.
- Schemas in `app/schemas/` mirror model names (e.g., `ApplicationCreate`, `ApplicationResponse`, `PaginatedApplications`).

### API Routes
- All routes are prefixed `/api/v1/` via `app/api/v1/router.py`.
- Each router file sets its own `prefix` and `tags`.
- DB session injected via `Depends(get_db)`.

### Risk Scoring
`score = (critical × 25) + (high × 10) + (medium × 3) + (low × 1)`, capped at 100. Only `status == "open"` findings count. Risk levels: 0 = info, 1–24 = low, 25–49 = medium, 50–74 = high, 75–100 = critical.

### Finding Fields
- `severity`: `critical` / `high` / `medium` / `low` / `info`
- `status`: `open` / `fixed` / `accepted` / `false_positive`
- `finding_type`: `SAST` / `SCA` / `container` / `secrets`
- `scanner`: `semgrep` / `grype` / `trivy` / `govulncheck` / `gitleaks`

### Secrets Scanning
Gitleaks runs alongside Semgrep/Trivy in `scan_application_task`. Active `SecretPattern` rows are loaded from the DB at scan time and written to a temp TOML config passed to gitleaks via `--config`. Raw secret values are never stored — masked to `****{last4}` in the `description` field. Dedup key: `("secrets", rule_id, file_path)`.

### IaC Scanning (Checkov)
Checkov runs on the cloned repo path using `--framework terraform,cloudformation,arm,bicep --output json`. Failed checks are mapped to `finding_type="IaC"`, `scanner="checkov"`. Checkov exits 0 (all pass) or 1 (findings found) — both are valid. The policy engine maps `iac` scan type to checkov findings. Checkov JSON is also supported in the CI/CD push path via `cicd_normaliser.normalise_checkov()`.

### Container Scanning (Grype)
Grype scans a container image by name (e.g. `nginx:latest`, `ghcr.io/org/app:sha`). The `Application` model has a nullable `container_image` field — if empty, the grype step is silently skipped. Grype JSON output is parsed via `cicd_normaliser.normalise_grype()`. Results are stored as `finding_type="container"`, `scanner="grype"`. The policy engine maps `container` scan type to grype findings.

### Scan Types
`RealScannerService.run_scan(scan_type)` accepts: `"all"`, `"semgrep"`, `"trivy"`, `"govulncheck"`, `"gitleaks"`, `"checkov"`, `"grype"`. Policy evaluation runs for `"all"` and targeted complete scans (`"checkov"`, `"grype"`); it is skipped for partial single-scanner runs that would leave incomplete finding sets.

### Policy Engine
`Policy` model stores rules (min_severity, enabled_scan_types, rule_blocklist, rule_allowlist, action). `policy_evaluator.evaluate_policy()` is called after every scan in `scan_application_task`. Actions: `inform` (log only) or `block` (sets blocked=True in task result). Scan type labels: `sast`, `sca`, `container`, `secrets`, `iac`.

### AI Remediation
Uses `claude-3-5-sonnet-20241022` with extended thinking (`budget_tokens=10000`). When `ANTHROPIC_API_KEY` is not set, `_mock_plan()` is returned — no error is raised. The Anthropic client is imported lazily inside the function.

### Testing
- `pytest-asyncio` with `asyncio_mode = auto` (set in `pytest.ini`).
- Test DB is SQLite in-memory (`sqlite+aiosqlite:///:memory:`). Engine is session-scoped; `db_session` fixture rolls back after each test.
- DB dependency overridden via `app.dependency_overrides[get_db] = override_get_db`.
- HTTP client uses `httpx.AsyncClient` with `ASGITransport`.

### Settings
Loaded from `.env` via `pydantic-settings`. See `.env.example`. Optional: `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`. `DATABASE_URL` defaults to the Docker Compose PostgreSQL instance.
