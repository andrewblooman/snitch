import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api.v1.router import api_router
from app.core.config import settings
from app.db.base import Base
from app.db.session import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables on startup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Application Security Platform — collect, triage, and remediate security findings",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

cors_origins = list(settings.CORS_ORIGINS)
explicit_cors_origins = [origin for origin in cors_origins if origin != "*"]
allow_credentials = len(explicit_cors_origins) > 0 and len(explicit_cors_origins) == len(cors_origins)

app.add_middleware(
    CORSMiddleware,
    allow_origins=explicit_cors_origins if allow_credentials else ["*"],  # nosemgrep: python.fastapi.security.wildcard-cors.wildcard-cors
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/health", tags=["health"])
async def health_check():
    return {"status": "ok", "version": settings.VERSION}


@app.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse(url="/index.html")


def _find_frontend_dir() -> str | None:
    """Resolve frontend directory: env var, Docker path, or relative to repo root."""
    candidates = [
        os.environ.get("FRONTEND_DIR"),
        "/app/frontend",
        str(Path(__file__).resolve().parents[2] / "frontend"),
    ]
    for path in candidates:
        if path and Path(path).is_dir():
            return path
    return None


# Mount frontend static files
_frontend = _find_frontend_dir()
if _frontend:
    app.mount("/", StaticFiles(directory=_frontend, html=True), name="frontend")
