# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules
ALWAYS create a new branch before writing new code when in plan mode.
ALWAYS update CLAUDE.md before pushing any code to GitHub
ALWAYS update README.md before pushing any code to GitHub
ALWAYS update API Docs / swagger before pushing any code to GitHub
ALWAYS push the branch to GitHub and open a PR

## Claude Code Skills

This project uses the **ui-ux-pro-max** Claude Code skill for UI/UX design work. The skill provides a searchable database of 67 styles, 96 colour palettes, 57 font pairings, and 25 chart types with opinionated recommendations for product type, stack, and accessibility.

- **Skill source:** https://github.com/nextlevelbuilder/ui-ux-pro-max-skill
- **Installed at:** `.claude/skills/ui-ux-pro-max/`
- **Invoke via:** `/ui-ux-pro-max <your design request>` inside Claude Code

When making frontend changes, run the design-system generator first:
```bash
python3.14 .claude/skills/ui-ux-pro-max/scripts/search.py "<query>" --design-system -p "Snitch AppSec Platform"
```

## What This Is

Snitch is an AppSec platform that aggregates security findings from Semgrep (SAST), Grype (container CVEs), Trivy (SCA), Checkov (IaC/Terraform), and Gitleaks (secrets), calculates per-app risk scores, and provides AI-powered remediation via Anthropic Claude. Includes a User Profile page with light/dark mode toggle (stored in localStorage). UI uses a cybersecurity dark theme with CSS design tokens in `frontend/static/css/theme.css` (severity palette, gradient, glow variables).

**New features (v1.6+):**
- **Global Findings Hub** (`/findings.html`) — paginated view of all findings across all apps; filters for Severity, Type, Scanner, Status; default sort by severity; sortable by Severity or Date Discovered; slide-in detail panel with live status editing; deep-linked from dashboard severity cards.
- **Compliance Posture** (`/compliance.html`) — maps findings to 5 frameworks: OWASP Top 10 2021, PCI-DSS v4.0, CIS Benchmarks, DORA, SOC 2 Type II. Shows per-framework compliance score (% controls with zero violations) as an SVG ring, control drill-down links to filtered findings, and a "Reapply Tags" button.
- **Threat Intelligence** (`/threat-intel.html`) — aggregates live RSS feeds from 7 threat intel sources (The Hacker News, Bleeping Computer, CISA, Wiz, Krebs, Shadowserver, Dark Reading) with a 3D globe visualisation of active threat locations (powered by globe.gl + Claude AI if API key is set).
- **EPSS Integration** — after each scan, CVE-bearing findings have their Exploit Prediction Scoring System (EPSS) score and percentile fetched from first.org and stored on the finding. The risk score calculator applies a boost (+15 or +5 pts) for findings with high EPSS percentiles.
- **SBOM Generation** — `GET /api/v1/applications/{id}/sbom` returns a CycloneDX v1.4 JSON SBOM of all SCA/container findings for an application.

**New features (v1.7+):**
- **Integrations** (`/integrations.html`) — configure Slack (incoming webhook) and Jira (REST API v3) integrations. Notifications fire automatically after every scan via Celery. Per-integration **Notification Rules** filter by event type (new finding, scan complete, risk spike, policy violation), minimum severity, finding type, and app scope. Jira integration includes deduplication (no duplicate tickets per finding) — if a finding already has a Jira issue, a comment is added instead.
- **Jira Epic Crawler** — input one or more Jira epic keys; Snitch crawls child issues, matches against open Snitch findings (by CVE ID, `snitch-finding-{id}` label, and package name), and classifies findings as: **Covered** (have a Jira issue), **Uncovered** (need a Jira issue), or **External** (Jira issues with no matching Snitch finding). Generates an AI remediation plan (Claude) for uncovered findings with suggested Jira issue titles, effort estimates, and thematic groupings. Bulk "Create Jira Issues for Uncovered" button available from the crawler UI.
- **Security fixes** — `defusedxml` replaces `xml.etree.ElementTree` for RSS feed parsing (XXE prevention); ReDoS-safe regex validation in secrets patterns endpoint using `ThreadPoolExecutor` with 2-second timeout.

**Design System:** The UI follows a cybersecurity HUD aesthetic — near-black page background (`#03040c`), cards with `linear-gradient(145deg, #0f1b34, #080f1d)` and a `rgba(0,229,255,0.14)` cyan border, electric cyan accent `#00e5ff`, and **Fira Code** monospace font for all metric numbers, labels, and headings. These are injected globally via `sidebar.js`. The dashboard and app-detail pages use a "Threat Intelligence Strip" (horizontal panel) instead of four stat tiles — severity counts in 52px Fira Code with a dynamic threat-level indicator and SVG arc gauge. Do not revert to generic SaaS tile layouts. Design tokens live in `frontend/static/css/theme.css`; new cybersecurity utility classes (`.mono-id`, `.terminal-label`, `.card-threat-c/h/m/l`, `.threat-pulse`, `.scan-line`, `.glitch-hover`) are defined there too.

The sidebar is a shared JS component defined in `frontend/static/js/sidebar.js`. Each HTML page uses `<div id="sidebar-mount"></div>` followed by `<script src="/static/js/sidebar.js"></script>` — the script renders the full sidebar, auto-detects the active nav link, injects Google Fonts (Fira Code + Fira Sans), and defines `window.applyTheme()`. Do not duplicate sidebar HTML across pages; edit `sidebar.js` for any sidebar changes.

The header user widget is a shared JS component defined in `frontend/static/js/header.js`. Each HTML page includes `<script src="/static/js/header.js"></script>` after the sidebar script and adds `id="header-user-slot"` to the right-side container inside `<header>`. The script injects a circular user avatar button with a dropdown (Profile link + disabled Logout placeholder) into that slot. Do not duplicate the widget HTML across pages; edit `header.js` for any user-menu changes.

The sidebar nav is structured into four sections: **Overview** (Dashboard, Applications, Findings, Reports, Secrets, Threat Intel, Compliance), **Config** (Policies, Rules), **Admin** (Settings, Integrations, Repositories, Service Accounts), **Help** (Documentation `/help.html`, About `/about.html`, API Docs `/docs`). The Profile link has been removed from the sidebar — it is only accessible via the header user widget dropdown. Nav items that open external links set `external: true` in NAV_SECTIONS and are rendered with a target="_blank" and an external-link icon. The sidebar `<aside>` uses `height:100vh;overflow:hidden` so the `<nav>` (which has `overflow-y:auto`) scrolls within the fixed viewport height.

The application detail page (`/app-detail.html`) has four main tabs: **Findings**, **Scan History**, **Remediations**, and **GitHub**. The GitHub tab has three sub-tabs rendered by `switchSubTab()`: **Commits** (calls `GET /api/v1/github/apps/{id}/commits`, renders commit history with avatar/sha/message), **Pull Requests** (calls `GET /api/v1/github/apps/{id}/pr-reviews`, shows PR cards with collapsible security findings), and **Security** (GHAS alerts via "Sync GitHub Alerts" button). The GitHub repo link appears as a small SVG icon button (34×34px, absolute-positioned top-right of the app info card) — no text, hover shows org/repo tooltip.

The `/settings.html` page is the admin configuration page for platform integrations (GitHub token, Anthropic API key), scan defaults, and read-only system info. It stores token presence flags in `localStorage` only — raw secrets are never persisted client-side.

The `/service-accounts.html` page is the admin management page for service accounts — machine identities used by CI/CD pipelines. It lists accounts (name, team, token prefix, status, last used), supports creating new accounts (token shown once in a modal with copy button), rotating tokens (old token immediately revoked), and revoking accounts. Token format is `snitch_<32chars>` (SHA-256 hash stored, plaintext never persisted).

The applications page (`/applications.html`) uses a sortable list/table view instead of a card grid. Default sort is risk score descending. Clicking any column header toggles ascending/descending sort.

The `/help.html` page is a single-page developer documentation hub with four tabs: Quick Start, GitHub Actions CI/CD integration guide (includes 3-secret setup: SNITCH_URL, SNITCH_APPLICATION_ID, SNITCH_TOKEN; Stage 1 auth verify step; Stage 2 push step for Semgrep, Trivy, Checkov, Gitleaks, Grype), General Usage walkthrough, and API Reference with curl examples.

The `/about.html` page contains the platform overview, technology stack cards, license info, and a timeline-style release notes changelog (v0.8 → v1.5).

The `/findings.html` page is the Global Findings Hub — lists all findings platform-wide with filters (Severity, Type, Scanner, Status), default severity sort (critical first), sortable Severity/Discovered columns, and a slide-in detail panel. Clicking a severity card on the dashboard deep-links here with `?severity=X&status=open`. The Top Vulnerabilities table on the reports page deep-links here with `?identifier=<cve/rule>&severity=X&finding_type=Y`. The compliance page deep-links here with `?compliance_tag=<framework|control>`. A dismissible header chip shows the active filter.

The `/compliance.html` page shows compliance posture across 5 frameworks. Each framework card has an SVG score ring (% controls passing), a control breakdown table, and "View findings →" links that navigate to the filtered findings page. The "Reapply Tags" button calls `POST /api/v1/reports/compliance/retag` to re-apply the current rule set to all findings. Tags are stored as JSON arrays on each `Finding` row (e.g. `["OWASP Top 10 2021|A03 — Injection"]`) and applied at scan time by `apply_compliance_tags()` in `services/compliance.py`.

The `/threat-intel.html` page aggregates live RSS from 7 cybersecurity news sources and renders them as cards alongside a 3D globe (globe.gl) showing threat locations. Locations are extracted by Claude AI (`/api/v1/threat-intel/locations`) if `ANTHROPIC_API_KEY` is set, otherwise a keyword-based fallback is used.

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

**GitHub Code Scanning:** `.github/workflows/semgrep.yml` uses `semgrep/semgrep-action@v1` (current org, not the old `returntocorp` org) + `github/codeql-action/upload-sarif@v4`. Job sets `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true` to opt-in to Node.js 24 ahead of GitHub's forced migration (June 2026). `publishDeployment` is not a valid input and must not be added.

**Frontend:** Plain HTML/CSS/JS (`frontend/`) served as static files mounted at `/` by FastAPI. No build step required.

```
backend/app/
├── main.py          # FastAPI app, CORS, static mount, lifespan (creates tables on startup)
├── core/config.py   # pydantic-settings: DATABASE_URL, GITHUB_TOKEN, ANTHROPIC_API_KEY, REDIS_URL
├── db/session.py    # async SQLAlchemy engine + get_db() dependency
├── models/          # SQLAlchemy ORM: Application, Scan, Finding, Remediation, CiCdScan, Policy, SecretPattern,
│                    #                 Integration, NotificationRule, JiraIssueLink
├── schemas/         # Pydantic request/response schemas (mirrors models/)
├── api/v1/          # Route handlers; all mounted under /api/v1/ via router.py
│   │                # includes: applications, findings, scans, remediation, reports,
│   │                #           cicd_scans, policies, secrets, github, seed, rules,
│   │                #           service_accounts, auth, threat_intel, integrations
├── worker/          # Celery task definitions (scans, EPSS fetch, notification dispatch)
└── services/
    ├── scanner.py         # Semgrep/Trivy/Govulncheck/Gitleaks/Checkov/Grype + MockScannerService
    ├── scoring.py         # Risk score calculator (includes EPSS boost)
    ├── deduplication.py   # Finding deduplication logic (SAST/SCA/secrets/generic keys)
    ├── cicd_normaliser.py # Normalise Semgrep/Grype/Checkov CI/CD JSON output
    ├── policy_evaluator.py # Evaluate policy rules against findings
    ├── rule_catalog.py    # Static catalog of ~37 rules (Checkov/IaC, Semgrep/SAST, Gitleaks/secrets)
    ├── ai_remediation.py  # Claude integration; falls back to mock plan if no API key
    ├── github_service.py  # GitHub code scanning sync + branch/PR creation via PyGitHub; lookup_public_repo() fetches any public repo (no token required); fetch_github_security_alerts() polls GHAS APIs (code scanning, Dependabot, secret scanning) via httpx
    ├── compliance.py      # 30 compliance mapping rules across OWASP/PCI-DSS/CIS/DORA/SOC2
    ├── slack_service.py   # Slack Block Kit notifications via incoming webhook (httpx)
    ├── jira_service.py    # Jira REST API v3 client — create issues, crawl epics, dedup via JiraIssueLink
    └── epic_remediation.py # AI remediation plan generator for uncovered findings from Jira epic crawl
    └── epss.py            # Async EPSS score fetcher from api.first.org
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
Base: `score = (critical × 25) + (high × 10) + (medium × 3) + (low × 1)`, capped at 100. Only `status == "open"` findings count. EPSS boost applied after base score: +15 pts per finding with `epss_percentile > 0.85`, +5 pts per finding with `epss_percentile > 0.50`. Risk levels: 0 = info, 1–24 = low, 25–49 = medium, 50–74 = high, 75–100 = critical.

### Finding Fields
- `severity`: `critical` / `high` / `medium` / `low` / `info`
- `status`: `open` / `fixed` / `accepted` / `false_positive`
- `finding_type`: `sast` / `sca` / `container` / `secrets` / `iac`
- `scanner`: `semgrep` / `grype` / `trivy` / `govulncheck` / `gitleaks` / `checkov`
- `epss_score`: float (0–1) probability of exploitation in the next 30 days; null if no CVE or EPSS lookup not yet run
- `epss_percentile`: float (0–1) relative to all scored CVEs; null if no CVE
- `compliance_tags`: JSON array of `"Framework|Control"` strings (e.g. `["OWASP Top 10 2021|A03 — Injection"]`); populated at scan time and on retag

### EPSS Scoring
After each scan, CVE IDs from new findings are queued to `fetch_epss_scores_task` (Celery). The task calls `https://api.first.org/data/v1/epss` and writes `epss_score` + `epss_percentile` back to matching findings, then recalculates the app's risk score. EPSS data is informational only — it does not change `severity`. If the EPSS API is unreachable the task retries up to 3 times and fails silently.

### Compliance Mapping
`services/compliance.py` holds 30 rules across 5 frameworks. Each rule is a dict with `framework`, `control`, and a `match` lambda that receives a `Finding` ORM object. Tags are applied synchronously during `_upsert_findings_sync` (scan tasks) via `apply_compliance_tags()`, which calls `flush()` — the surrounding task is responsible for `commit()`. To re-apply tags to all existing findings call `POST /api/v1/reports/compliance/retag`. When adding new mapping rules, run the retag endpoint to back-fill existing findings.

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

### Database Migrations
The migration `c2b28485c8a7_add_epss_and_compliance` adds `epss_score` (Float), `epss_percentile` (Float), and `compliance_tags` (JSON) to the `findings` table. The migration `009_add_integrations` creates the `integrations`, `notification_rules`, and `jira_issue_links` tables. Always run `alembic upgrade head` inside the backend container after pulling changes that include new migrations. **After applying a migration that adds columns to a model already in use, restart the Celery worker container** (`docker restart snitch-worker-1`) — the worker forks processes at startup and will have a stale SQLAlchemy mapper that doesn't know about the new columns, causing `AttributeError` on access.

### Global Findings API
`GET /api/v1/findings` is the platform-wide findings list endpoint. Supported query params: `application_id`, `severity`, `finding_type`, `scanner`, `status`, `identifier` (matches `cve_id OR rule_id`), `compliance_tag` (text search within the JSON array), `sort_by` (`severity` | `created_at`, default `severity`), `sort_dir` (`asc` | `desc`), `page`, `page_size`. Severity sort uses a SQL `CASE` expression (critical=0 → info=4). The endpoint eagerly loads the `application` relationship via `selectinload` so `application_name` is populated in the response.

### GitHub Repos API
`GET /api/v1/github/repos` lists all repos accessible to `GITHUB_TOKEN` with tracking status. The underlying PyGitHub call is run via `asyncio.to_thread()` to avoid blocking the async event loop. Capped at 200 repos (`per_page=100`).
`GET /api/v1/github/repos/lookup?owner=ORG&repo=REPO` fetches metadata for any public (or private, if the token has access) GitHub repository. Works without a `GITHUB_TOKEN` for public repos (unauthenticated GitHub API, 60 req/hr per IP). Used by the "Track Public Repo" modal on `repositories.html`.

### GitHub Advanced Security (GHAS) Polling
`GITHUB_TOKEN` requires `security_events` + `vulnerability_alerts` scopes for full access. Three alert types are polled every 5 minutes via Celery Beat:
- **Code Scanning** (`scanner=codeql` or tool name, `finding_type=sast`) — CodeQL, Semgrep, etc.
- **Dependabot** (`scanner=dependabot`, `finding_type=sca`) — CVE/SCA alerts
- **Secret Scanning** (`scanner=github_secret_scanning`, `finding_type=secrets`)

Each finding includes: `commit_sha` (SHA that introduced it), `introduced_by` (GitHub username), `pr_number` + `pr_url` (if finding was in a PR ref), `github_alert_url` (direct link), `github_alert_number` (dedup key).

Dedup key: `(application_id, scanner, github_alert_number)`. If a token lacks scope for an alert type, that type is silently skipped. Commit author is fetched via `GET /repos/{owner}/{repo}/commits/{sha}` — not fetched for Dependabot (no commit SHA available).

**Cross-scanner deduplication:** When a new GHAS finding is about to be inserted, `_has_native_duplicate()` in `github_tasks.py` checks whether a native scanner (semgrep, grype, trivy, etc.) already tracks the same vulnerability. For Dependabot: matches on `cve_id` + `package_name`; for code-scanning SAST: matches on `rule_id` + `file_path`. Secret-scanning alerts are never deduplicated. If a null field prevents matching, the GHAS finding is allowed through (conservative). `_GHAS_SCANNERS = frozenset({"codeql", "github_secret_scanning", "dependabot"})` is the exclusion set for native-scanner queries.

`POST /api/v1/github/apps/{app_id}/sync-alerts` triggers an immediate sync for one app (returns task ID). The beat schedule fires every 5 minutes for all tracked apps. Last sync time stored in `Application.last_github_sync_at`.

`GET /api/v1/github/apps/{app_id}/commits?limit=20` returns recent commit history from `GET /repos/{owner}/{repo}/commits`. Response: `CommitsResponse` with `total_commits`, `commits[]` (sha, short_sha, message, author_name, author_login, author_avatar, date, commit_url). Implemented in `fetch_recent_commits()` in `github_service.py`.

New Finding fields (migration 010): `commit_sha`, `introduced_by`, `pr_number`, `pr_url`, `github_alert_url`, `github_alert_number`. New Application field: `last_github_sync_at`.

### Integrations API
`/api/v1/integrations` manages Slack and Jira integration configurations. Config JSON is stored as `Text` in the DB (never returned in API responses — GET responses return `config_summary` with sensitive keys masked as `***`). The full config is returned **only once** on `POST /integrations` (similar to service account token reveal). Notification rules (`/integrations/{id}/rules`) define what triggers notifications: `event_type`, `min_severity`, `finding_types` (empty = all), `application_ids` (empty = all apps). After every scan, `dispatch_finding_notifications` Celery task evaluates all active rules and dispatches to matching integrations. Jira deduplication uses the `jira_issue_links` table — if a finding already has a link for that integration, a comment is added instead of creating a duplicate ticket. The epic crawler (`POST /integrations/jira/{id}/crawl-epic`) uses JQL `parent = "{epic_key}"` to fetch child issues and matches against open findings by CVE ID, `snitch-finding-{id}` label, and package name.
