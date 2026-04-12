# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Snitch is an AppSec platform that aggregates security findings from Semgrep (SAST), Grype (container CVEs), and Trivy (SCA), calculates per-app risk scores, and provides AI-powered remediation via Anthropic Claude.

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
├── models/          # SQLAlchemy ORM: Application, Scan, Finding, Remediation
├── schemas/         # Pydantic request/response schemas (mirrors models/)
├── api/v1/          # Route handlers; all mounted under /api/v1/ via router.py
├── worker/          # Celery task definitions (scans, periodic jobs)
└── services/
    ├── scanner.py         # Mock Semgrep/Grype/Trivy scanner (returns fake findings)
    ├── scoring.py         # Risk score calculator
    ├── deduplication.py   # Finding deduplication logic
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
- `finding_type`: `SAST` / `SCA` / `container`
- `scanner`: `semgrep` / `grype` / `trivy`

### AI Remediation
Uses `claude-3-5-sonnet-20241022` with extended thinking (`budget_tokens=10000`). When `ANTHROPIC_API_KEY` is not set, `_mock_plan()` is returned — no error is raised. The Anthropic client is imported lazily inside the function.

### Testing
- `pytest-asyncio` with `asyncio_mode = auto` (set in `pytest.ini`).
- Test DB is SQLite in-memory (`sqlite+aiosqlite:///:memory:`). Engine is session-scoped; `db_session` fixture rolls back after each test.
- DB dependency overridden via `app.dependency_overrides[get_db] = override_get_db`.
- HTTP client uses `httpx.AsyncClient` with `ASGITransport`.

### Settings
Loaded from `.env` via `pydantic-settings`. See `.env.example`. Optional: `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`. `DATABASE_URL` defaults to the Docker Compose PostgreSQL instance.
