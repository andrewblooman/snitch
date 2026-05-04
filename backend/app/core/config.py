from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "Snitch"
    VERSION: str = "1.0.0"

    DATABASE_URL: str = "postgresql+asyncpg://snitch:snitch@db:5432/snitch"
    SECRET_KEY: str = "change-me-in-production"

    GITHUB_TOKEN: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    OLLAMA_URL: Optional[str] = None
    OLLAMA_MODEL: str = "llama3.1"
    REDIS_URL: str = "redis://redis:6379/0"

    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000", "*"]

    # AWS — not used; retained for backwards compatibility if env vars are set
    AWS_REGION: str = "us-east-1"
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None


settings = Settings()
