# Snitch — Copilot Instructions

## Project Overview

Snitch is an AppSec platform that aggregates security findings from Semgrep (SAST), Grype (container CVEs), and Trivy (SCA), calculates per-app risk scores, and provides AI-powered remediation via Anthropic Claude. The backend is FastAPI + SQLAlchemy async; the frontend is plain HTML/CSS/JS served as static files.

## Commands

```bash
# Run all backend tests
cd backend && python -m pytest tests/ -v

# Run a single test file
cd backend && python -m pytest tests/test_applications.py -v

# Run a single test by name
cd backend && python -m pytest tests/ -v -k "test_create_application"

# Start the full stack
docker compose up --build

# Run locally (requires PostgreSQL on localhost:5432)
cd backend && DATABASE_URL=postgresql+asyncpg://snitch:snitch@localhost:5432/snitch uvicorn app.main:app --reload

# Run database migrations
cd backend && alembic upgrade head

# Create a new migration
cd backend && alembic revision --autogenerate -m "description"
```

## Architecture

```
backend/app/
├── main.py          # FastAPI app, CORS, static mount, lifespan (creates tables on startup)
├── core/config.py   # pydantic-settings: DATABASE_URL, GITHUB_TOKEN, ANTHROPIC_API_KEY
├── db/session.py    # async SQLAlchemy engine + get_db() dependency
├── models/          # SQLAlchemy ORM: Application, Scan, Finding, Remediation
├── schemas/         # Pydantic request/response schemas (mirrors models/)
├── api/v1/          # Route handlers; all mounted under /api/v1/ via router.py
└── services/
    ├── scanner.py         # Mock Semgrep/Grype/Trivy scanner (returns fake findings)
    ├── scoring.py         # Risk score calculator
    ├── ai_remediation.py  # Claude integration; falls back to mock plan if no API key
    └── github_service.py  # GitHub code scanning sync + branch/PR creation via PyGitHub
```

The frontend (`frontend/`) is served as static files mounted at `/` by FastAPI. The root `/` redirects to `/index.html`.

## Key Conventions

### Models & Schemas
- All primary keys are `uuid.UUID` using `UUID(as_uuid=True)` (PostgreSQL dialect). Tests run on SQLite in-memory, which handles UUIDs as strings.
- Relationships use `cascade="all, delete-orphan"` on the owning side.
- Every model has `created_at` / `updated_at` using `server_default=func.now()`.
- Schemas live in `app/schemas/` and mirror model names (e.g., `ApplicationCreate`, `ApplicationResponse`, `PaginatedApplications`).

### API Routes
- All routes are prefixed `/api/v1/` via `app/api/v1/router.py`.
- Each router file defines its own `prefix` and `tags` (e.g., `router = APIRouter(prefix="/applications", tags=["applications"])`).
- DB session is injected via `Depends(get_db)`.

### Risk Scoring
Score = `(critical × 25) + (high × 10) + (medium × 3) + (low × 1)`, capped at 100. Only `status == "open"` findings count. Risk levels: 0 = info, 1–24 = low, 25–49 = medium, 50–74 = high, 75–100 = critical.

### Finding Fields
- `severity`: `critical` / `high` / `medium` / `low` / `info`
- `status`: `open` / `fixed` / `accepted` / `false_positive`
- `finding_type`: `SAST` / `SCA` / `container`
- `scanner`: `semgrep` / `grype` / `trivy`

### AI Remediation
Uses `claude-3-5-sonnet-20241022` with extended thinking (`budget_tokens=10000`). When `ANTHROPIC_API_KEY` is not set, `_mock_plan()` is returned instead — no error is raised. The Anthropic client is imported lazily inside the function to avoid hard dependency.

### Testing
- Tests use `pytest-asyncio` with `asyncio_mode = auto` (set in `pytest.ini`).
- The test DB is SQLite in-memory (`sqlite+aiosqlite:///:memory:`). The engine is session-scoped; `db_session` fixture rolls back after each test.
- DB dependency is overridden via `app.dependency_overrides[get_db] = override_get_db`.
- Test client uses `httpx.AsyncClient` with `ASGITransport`.

### Settings
Loaded from `.env` via `pydantic-settings`. See `.env.example`. Optional keys: `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`. The `DATABASE_URL` defaults to the Docker Compose PostgreSQL instance.
