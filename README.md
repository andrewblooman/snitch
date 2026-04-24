# 🕵️ Snitch — Application Security Platform

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.13-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.6-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED.svg?logo=docker&logoColor=white)](docker-compose.yml)
[![Powered by Claude](https://img.shields.io/badge/AI-Claude%203.5%20Sonnet-orange.svg?logo=anthropic)](https://www.anthropic.com/)
[![GitHub Issues](https://img.shields.io/github/issues/andrewblooman/snitch)](https://github.com/andrewblooman/snitch/issues)

> **Snitch** is a developer-focused AppSec platform that collects security findings from Semgrep (SAST), Grype (container scanning), Trivy (SCA), Checkov (IaC/Terraform), and Gitleaks (secrets), calculates per-application risk scores, and provides AI-powered remediation via Anthropic Claude.

![Dashboard](docs/images/image.png)

---

## Features

| Feature | Description |
|---|---|
| 📊 **Risk Scoring** | Automatic risk score (0–100) per app derived from open findings by severity |
| 🔍 **Multi-Scanner** | Semgrep (SAST), Grype (container CVEs), Trivy (SCA/OS vulnerabilities), Checkov (IaC/Terraform), Gitleaks (secrets) |
| 🔑 **Secrets Detection** | Gitleaks integration with configurable custom regex patterns per organisation |
| 🤖 **AI Remediation** | Claude-powered "Plan Remediation" generates fix instructions, then creates a GitHub PR |
| 📈 **90-Day Trends** | Management reporting with vulnerability trends, team leaderboard, and MTTR |
| 🔗 **GitHub Integration** | Sync code-scanning alerts from GitHub Security; auto-create branches & PRs |
| 🚦 **Policy Engine** | Define pass/fail gates by severity, scan type, and rule — evaluated on every scan |
| 🌐 **REST API** | Full OpenAPI/Swagger docs at `/docs` |
| 🎨 **Consistent UI** | Shared sidebar (`sidebar.js`) and header (`header.js`) components with design tokens in `theme.css` — single source of truth for navigation and styles |
| ⚙️ **Settings Page** | Admin configuration page for platform integrations (GitHub, Anthropic), scan defaults, and system status |
| 📋 **Applications List View** | Sortable table view for the applications portfolio — click any column header to re-sort |

---

## Quick Start (Docker)

### Prerequisites
- Docker Desktop or Docker Engine + Compose v2
- (Optional) Anthropic API key for AI remediation
- (Optional) GitHub personal access token for GitHub Security sync

### 1. Clone and configure

```bash
git clone https://github.com/andrewblooman/snitch.git
cd snitch
cp .env.example .env
# Edit .env with your API keys (optional)
```

### 2. Run

```bash
docker compose up --build
```

The platform will be available at **http://localhost:8000**

- 🏠 Dashboard: http://localhost:8000/
- 📱 Applications: http://localhost:8000/applications.html
- 📊 Reports: http://localhost:8000/reports.html
- 🔑 Secrets: http://localhost:8000/secrets.html
- 📖 API Docs: http://localhost:8000/docs

### 3. Seed demo data (optional)

```bash
curl -X POST http://localhost:8000/api/v1/seed
```

Creates 8 realistic demo applications with findings from Semgrep, Grype, and Trivy across 4 teams.

---

## Architecture

```
snitch/
├── backend/                    # FastAPI + SQLAlchemy application
│   ├── app/
│   │   ├── main.py             # FastAPI app, middleware, static mount
│   │   ├── core/config.py      # Settings (pydantic-settings)
│   │   ├── db/                 # SQLAlchemy async engine + session
│   │   ├── models/             # ORM models
│   │   │   ├── application.py, scan.py, finding.py, remediation.py
│   │   │   ├── cicd_scan.py    # CI/CD scan ingestion records
│   │   │   ├── policy.py       # Policy engine rules
│   │   │   └── secret_pattern.py  # Custom Gitleaks regex patterns
│   │   ├── schemas/            # Pydantic request/response schemas
│   │   ├── api/v1/             # API route handlers
│   │   │   ├── applications.py # CRUD + scan trigger + GitHub sync
│   │   │   ├── findings.py     # Finding management
│   │   │   ├── scans.py        # Scan history
│   │   │   ├── remediation.py  # AI plan + PR execution
│   │   │   ├── reports.py      # Overview, leaderboard, trend, top CVEs
│   │   │   ├── cicd_scans.py   # CI/CD scan results (S3/SQS ingestion)
│   │   │   ├── policies.py     # Policy CRUD + evaluation
│   │   │   ├── secrets.py      # Secrets findings + custom pattern CRUD
│   │   │   └── seed.py         # Demo data seeder
│   │   ├── services/
│   │   │   ├── scanner.py      # Semgrep/Trivy/Govulncheck/Gitleaks scanners
│   │   │   ├── scoring.py      # Risk score calculator
│   │   │   ├── deduplication.py   # Finding upsert + dedup logic
│   │   │   ├── cicd_normaliser.py # Normalise Semgrep/Grype CI output
│   │   │   ├── policy_evaluator.py
│   │   │   ├── ai_remediation.py  # Anthropic Claude integration
│   │   │   └── github_service.py  # GitHub Security sync + PR creation
│   │   └── worker/             # Celery async tasks
│   │       ├── tasks.py        # scan_application_task, poll_sqs_task, weekly_scan_all
│   │       └── celery_app.py
│   ├── alembic/                # Database migrations (005 revisions)
│   ├── tests/                  # pytest test suite
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/                   # Static HTML/CSS/JS (no build step)
│   ├── index.html              # Dashboard
│   ├── applications.html       # Application portfolio
│   ├── app-detail.html         # Per-app findings + remediation
│   ├── reports.html            # Management reporting
│   ├── repositories.html       # GitHub repo browser
│   ├── policies.html           # Policy engine UI
│   ├── secrets.html            # Secrets findings + custom pattern manager
│   └── static/js/              # Bundled Chart.js + Lucide icons
├── docker-compose.yml
└── .env.example
```

---

## API Reference

All endpoints are documented via Swagger UI at `/docs` and ReDoc at `/redoc`.

### Core Endpoints

Full interactive docs at `/docs` (Swagger UI) and `/redoc`.

**Applications & Findings**

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/applications` | List apps with risk scores (filterable by team, risk level) |
| `POST` | `/api/v1/applications` | Register a new application |
| `GET` | `/api/v1/applications/{id}` | Get app detail with finding summary |
| `POST` | `/api/v1/applications/{id}/scan` | Trigger Semgrep/Trivy/Gitleaks scan |
| `GET` | `/api/v1/applications/{id}/findings` | Get findings (filterable by severity, type, status) |
| `POST` | `/api/v1/applications/{id}/sync-github` | Sync from GitHub Security alerts |
| `GET` | `/api/v1/findings` | List all findings across apps |
| `PATCH` | `/api/v1/findings/{id}` | Update finding status (open/fixed/accepted/false_positive) |

**Secrets**

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/secrets/findings` | List secrets findings (filterable by app, severity, status) |
| `GET` | `/api/v1/secrets/findings/stats` | Secrets counts by severity and rule |
| `PATCH` | `/api/v1/secrets/findings/{id}` | Update secret finding status |
| `GET` | `/api/v1/secrets/patterns` | List custom Gitleaks regex patterns |
| `POST` | `/api/v1/secrets/patterns` | Create custom pattern |
| `PUT` | `/api/v1/secrets/patterns/{id}` | Update pattern |
| `DELETE` | `/api/v1/secrets/patterns/{id}` | Delete pattern |
| `POST` | `/api/v1/secrets/patterns/test` | Test a regex against sample text |

**Policies**

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/policies` | List policies |
| `POST` | `/api/v1/policies` | Create policy |
| `PATCH` | `/api/v1/policies/{id}` | Update policy |
| `DELETE` | `/api/v1/policies/{id}` | Delete policy |
| `POST` | `/api/v1/policies/{id}/evaluate` | Evaluate policy against current findings |
| `GET` | `/api/v1/policies/evaluate/all` | Evaluate all active policies |

**Reports & CI/CD**

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/remediation/plan` | Generate AI remediation plan for selected findings |
| `POST` | `/api/v1/remediation/{id}/execute` | Execute plan: create branch + GitHub PR |
| `GET` | `/api/v1/reports/overview` | Platform-wide stats |
| `GET` | `/api/v1/reports/leaderboard` | Team security leaderboard |
| `GET` | `/api/v1/reports/trend?days=90` | 90-day vulnerability trend |
| `GET` | `/api/v1/reports/top-vulnerabilities` | Most common CVEs/rules |
| `GET` | `/api/v1/cicd-scans` | List CI/CD scan results ingested via S3/SQS |
| `POST` | `/api/v1/seed` | Seed demo data |

---

## Risk Scoring

Risk scores are calculated from open findings:

| Severity | Points |
|---|---|
| Critical | 25 pts each |
| High | 10 pts each |
| Medium | 3 pts each |
| Low | 1 pt each |

**Score is capped at 100.** Risk levels: `0` = Info, `1–24` = Low, `25–49` = Medium, `50–74` = High, `75–100` = Critical.

---

## AI Remediation Flow

1. Developer clicks **"Plan Remediation"** on the Application detail page
2. Selected findings are sent to `POST /api/v1/remediation/plan`
3. The AI service builds a structured prompt and calls `claude-3-5-sonnet-20241022`
4. The AI plan (Markdown) is displayed in a modal
5. Developer clicks **"Execute Remediation"**
6. Snitch calls the GitHub API to create a branch and open a Pull Request
7. PR is tracked in the Reports → Pull Requests view

> If `ANTHROPIC_API_KEY` is not set, a realistic mock plan is returned for demo purposes.

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://snitch:snitch@db:5432/snitch` | PostgreSQL connection |
| `SECRET_KEY` | `change-me-in-production` | App secret |
| `GITHUB_TOKEN` | *(optional)* | GitHub PAT for Security sync and PR creation |
| `ANTHROPIC_API_KEY` | *(optional)* | Claude API key for AI remediation |
| `FRONTEND_DIR` | auto-detected | Override frontend static files path |

---

## Development

### Run locally (without Docker)

```bash
# Start PostgreSQL
docker run -e POSTGRES_USER=snitch -e POSTGRES_PASSWORD=snitch -e POSTGRES_DB=snitch -p 5432:5432 postgres:15-alpine

# Install backend
cd backend
pip install -r requirements.txt
alembic upgrade head

# Run
DATABASE_URL=postgresql+asyncpg://snitch:snitch@localhost:5432/snitch uvicorn app.main:app --reload
```

### Run tests

```bash
cd backend
pytest tests/ -v
```

---

## CI/CD Pipeline Integration

Snitch supports two scanning modes that can be used independently or together.

### Mode 1 — Pull model (Snitch scans your repo)

Snitch clones your repository and runs all scanners itself. No pipeline changes required.

```bash
# Trigger a full scan via the API
curl -X POST "http://localhost:8000/api/v1/applications/{app_id}/scan?scan_type=all"

# Or trigger a specific scanner only
curl -X POST "http://localhost:8000/api/v1/applications/{app_id}/scan?scan_type=checkov"
curl -X POST "http://localhost:8000/api/v1/applications/{app_id}/scan?scan_type=grype"
```

| `scan_type` | Scanner | What it scans |
|---|---|---|
| `semgrep` | Semgrep | SAST — first-party code |
| `trivy` | Trivy | SCA — third-party dependencies |
| `govulncheck` | Govulncheck | SCA — Go modules |
| `gitleaks` | Gitleaks | Secrets in code |
| `checkov` | Checkov | IaC — Terraform, CloudFormation, ARM, Bicep |
| `grype` | Grype | Container image CVEs (requires `container_image` set on the app) |
| `all` | All of the above | Full scan |

For Grype to run, set a `container_image` when registering the application:

```bash
curl -X POST http://localhost:8000/api/v1/applications \
  -H "Content-Type: application/json" \
  -d '{"name": "my-api", "github_org": "myorg", "github_repo": "my-api",
       "repo_url": "https://github.com/myorg/my-api",
       "team_name": "platform", "container_image": "ghcr.io/myorg/my-api:latest"}'
```

---

### Mode 2 — Push model (your pipeline uploads scan results)

Your CI/CD pipeline runs the scanner and uploads the JSON output to S3. Snitch polls an SQS queue, downloads the results, normalises them, and stores the findings — including CI context (commit SHA, branch, workflow run ID).

**Supported push formats:** Semgrep JSON, Grype JSON, Checkov JSON

#### Infrastructure setup

You need:
- An **S3 bucket** with event notifications → **SQS queue**
- Snitch configured with AWS credentials

```bash
# .env additions
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
S3_CICD_BUCKET=my-snitch-scans
SQS_CICD_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789/snitch-cicd
```

#### S3 key format

Results must be uploaded to a key matching:

```
{github_org}/{github_repo}/{scan_type}/{YYYYMMDD}-{run_id}.json
```

Example: `myorg/my-api/semgrep/20260424-12345.json`

Snitch uses the org/repo path to look up the registered application. The `scan_type` segment is informational — Snitch auto-detects the format from JSON content.

#### S3 object metadata (optional but recommended)

| Metadata key | Description |
|---|---|
| `commit-sha` | The commit SHA that was scanned |
| `branch` | Branch name (e.g. `main`, `feature/xyz`) |
| `workflow-run-id` | CI run ID for traceability |
| `ci-provider` | e.g. `github-actions`, `gitlab-ci` (defaults to `github-actions`) |

---

### GitHub Actions — Semgrep SAST

```yaml
name: Snitch — SAST scan
on: [push, pull_request]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Semgrep
        run: |
          pip install semgrep
          semgrep --config auto --json --quiet > semgrep-results.json || true

      - name: Upload results to Snitch (S3)
        if: always()
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_REGION: us-east-1
          S3_BUCKET: my-snitch-scans
        run: |
          DATE=$(date +%Y%m%d)
          KEY="${{ github.repository_owner }}/${{ github.event.repository.name }}/semgrep/${DATE}-${{ github.run_id }}.json"
          aws s3 cp semgrep-results.json "s3://${S3_BUCKET}/${KEY}" \
            --metadata "commit-sha=${{ github.sha }},branch=${{ github.ref_name }},workflow-run-id=${{ github.run_id }},ci-provider=github-actions"
```

---

### GitHub Actions — Grype container scan

```yaml
name: Snitch — Container scan
on:
  push:
    branches: [main]

jobs:
  grype:
    runs-on: ubuntu-latest
    steps:
      - name: Run Grype
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
          grype ghcr.io/${{ github.repository }}:latest -o json > grype-results.json || true

      - name: Upload results to Snitch (S3)
        if: always()
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_REGION: us-east-1
          S3_BUCKET: my-snitch-scans
        run: |
          DATE=$(date +%Y%m%d)
          KEY="${{ github.repository_owner }}/${{ github.event.repository.name }}/grype/${DATE}-${{ github.run_id }}.json"
          aws s3 cp grype-results.json "s3://${S3_BUCKET}/${KEY}" \
            --metadata "commit-sha=${{ github.sha }},branch=${{ github.ref_name }},workflow-run-id=${{ github.run_id }},ci-provider=github-actions"
```

---

### GitHub Actions — Checkov IaC scan

```yaml
name: Snitch — IaC scan
on: [push, pull_request]

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Checkov
        run: |
          pip install checkov
          checkov --directory . --framework terraform,cloudformation,arm,bicep --output json --compact --quiet > checkov-results.json || true

      - name: Upload results to Snitch (S3)
        if: always()
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_REGION: us-east-1
          S3_BUCKET: my-snitch-scans
        run: |
          DATE=$(date +%Y%m%d)
          KEY="${{ github.repository_owner }}/${{ github.event.repository.name }}/checkov/${DATE}-${{ github.run_id }}.json"
          aws s3 cp checkov-results.json "s3://${S3_BUCKET}/${KEY}" \
            --metadata "commit-sha=${{ github.sha }},branch=${{ github.ref_name }},workflow-run-id=${{ github.run_id }},ci-provider=github-actions"
```

---

### Policy gate — fail the pipeline on violations

Use the Snitch API to evaluate active policies after uploading results. This lets Snitch act as a quality gate in your pipeline.

```yaml
      - name: Check Snitch policy gate
        run: |
          RESULT=$(curl -sf "$SNITCH_URL/api/v1/policies/evaluate/all" \
            -H "Content-Type: application/json" \
            -d "{\"application_id\": \"$APP_ID\"}")
          BLOCKED=$(echo "$RESULT" | jq '.blocked')
          if [ "$BLOCKED" = "true" ]; then
            echo "❌ Snitch policy gate FAILED — pipeline blocked"
            echo "$RESULT" | jq '.policies[] | select(.blocked) | {name, violations}'
            exit 1
          fi
          echo "✅ Snitch policy gate passed"
        env:
          SNITCH_URL: https://snitch.internal
          APP_ID: ${{ vars.SNITCH_APP_ID }}
```

> Set `SNITCH_APP_ID` as a GitHub Actions variable per repository. Create policies in the Snitch UI under **Config → Policies**.

---

## Screenshots

| Dashboard | Applications |
|---|---|
| ![Dashboard](https://github.com/user-attachments/assets/36512a1b-3b76-41cc-af98-0ad688ce1784) | ![Applications](https://github.com/user-attachments/assets/040b732a-3908-455d-a7b4-063ab398e23a) |

| Reports | Security Reports |
|---|---|
| ![Reports](https://github.com/user-attachments/assets/e134de5a-1efb-4d1c-be5e-6bfb98fca6e5) | ![Overview](https://github.com/user-attachments/assets/31654329-37c4-4f35-a1e7-dbea190d7f35) |

---

## License

Apache 2.0 — see [LICENSE](LICENSE)
