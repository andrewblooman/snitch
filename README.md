# 🕵️ Snitch — Application Security Platform

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.13-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.6-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED.svg?logo=docker&logoColor=white)](docker-compose.yml)
[![Powered by Claude](https://img.shields.io/badge/AI-Claude%203.5%20Sonnet-orange.svg?logo=anthropic)](https://www.anthropic.com/)
[![GitHub Issues](https://img.shields.io/github/issues/andrewblooman/snitch)](https://github.com/andrewblooman/snitch/issues)

> **Snitch** is a developer-focused AppSec platform that collects security findings from Semgrep (SAST), Grype (container scanning), and Trivy (SCA), calculates per-application risk scores, and provides AI-powered remediation via Anthropic Claude.

![Dashboard](https://github.com/user-attachments/assets/36512a1b-3b76-41cc-af98-0ad688ce1784)

---

## Features

| Feature | Description |
|---|---|
| 📊 **Risk Scoring** | Automatic risk score (0–100) per app derived from open findings by severity |
| 🔍 **Multi-Scanner** | Semgrep (SAST), Grype (container CVEs), Trivy (SCA/OS vulnerabilities) |
| 🤖 **AI Remediation** | Claude-powered "Plan Remediation" generates fix instructions, then creates a GitHub PR |
| 📈 **90-Day Trends** | Management reporting with vulnerability trends, team leaderboard, and MTTR |
| 🔗 **GitHub Integration** | Sync code-scanning alerts from GitHub Security; auto-create branches & PRs |
| 🌐 **REST API** | Full OpenAPI/Swagger docs at `/docs` |

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
- 📖 API Docs: http://localhost:8000/docs

### 3. Seed demo data

Click the **"Seed Demo Data"** button on the dashboard, or call the API directly:

```bash
curl -X POST http://localhost:8000/api/v1/seed
```

This creates 8 realistic demo applications with findings from Semgrep, Grype, and Trivy across 4 teams.

---

## Architecture

```
snitch/
├── backend/                    # FastAPI + SQLAlchemy application
│   ├── app/
│   │   ├── main.py             # FastAPI app, middleware, static mount
│   │   ├── core/config.py      # Settings (pydantic-settings)
│   │   ├── db/                 # SQLAlchemy async engine + session
│   │   ├── models/             # ORM models (Application, Scan, Finding, Remediation)
│   │   ├── schemas/            # Pydantic request/response schemas
│   │   ├── api/v1/             # API route handlers
│   │   │   ├── applications.py # CRUD + scan trigger + GitHub sync
│   │   │   ├── findings.py     # Finding management
│   │   │   ├── scans.py        # Scan history
│   │   │   ├── remediation.py  # AI plan + PR execution
│   │   │   ├── reports.py      # Overview, leaderboard, trend, top CVEs
│   │   │   └── seed.py         # Demo data seeder
│   │   └── services/
│   │       ├── scanner.py      # Mock Semgrep/Grype/Trivy scanner
│   │       ├── scoring.py      # Risk score calculator
│   │       ├── ai_remediation.py  # Anthropic Claude integration
│   │       └── github_service.py  # GitHub Security sync + PR creation
│   ├── alembic/                # Database migrations
│   ├── tests/                  # pytest test suite (20 tests)
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/                   # Static HTML/CSS/JS dashboard
│   ├── index.html              # Main dashboard
│   ├── applications.html       # Application portfolio view
│   ├── app-detail.html         # Per-app findings + remediation
│   ├── reports.html            # Management reporting
│   └── static/
│       └── js/                 # Bundled Chart.js + Lucide icons
├── docker-compose.yml
└── .env.example
```

---

## API Reference

All endpoints are documented via Swagger UI at `/docs` and ReDoc at `/redoc`.

### Core Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/applications` | List apps with risk scores (filterable by team, risk level) |
| `POST` | `/api/v1/applications` | Register a new application |
| `GET` | `/api/v1/applications/{id}` | Get app detail with finding summary |
| `POST` | `/api/v1/applications/{id}/scan` | Trigger Semgrep/Grype/Trivy scan |
| `GET` | `/api/v1/applications/{id}/findings` | Get findings (filterable by severity, type, status) |
| `POST` | `/api/v1/applications/{id}/sync-github` | Sync from GitHub Security alerts |
| `GET` | `/api/v1/findings` | List all findings across apps |
| `PATCH` | `/api/v1/findings/{id}` | Update finding status (open/fixed/accepted/false_positive) |
| `POST` | `/api/v1/remediation/plan` | Generate AI remediation plan for selected findings |
| `POST` | `/api/v1/remediation/{id}/execute` | Execute plan: create branch + GitHub PR |
| `GET` | `/api/v1/reports/overview` | Platform-wide stats |
| `GET` | `/api/v1/reports/leaderboard` | Team security leaderboard |
| `GET` | `/api/v1/reports/trend?days=90` | 90-day vulnerability trend |
| `GET` | `/api/v1/reports/pull-requests` | All Snitch-created PRs |
| `GET` | `/api/v1/reports/top-vulnerabilities` | Most common CVEs/rules |
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

### GitHub Actions integration

To send CI scan results to Snitch, add a step to your workflow:

```yaml
- name: Upload findings to Snitch
  if: always()
  run: |
    curl -X POST "$SNITCH_URL/api/v1/applications/$APP_ID/scan?scan_type=all" \
      -H "Content-Type: application/json"
```

Or enable **GitHub Security** (code scanning + Dependabot) and use the **"Sync from GitHub"** button in the application detail page.

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

MIT — see [LICENSE](LICENSE)
