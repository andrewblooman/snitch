import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Integration(Base):
    __tablename__ = "integrations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # "slack" | "jira"
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Stores webhook_url/api_token/etc — never returned in API responses (masked)
    config: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_status: Mapped[str | None] = mapped_column(String(20), nullable=True)  # "ok" | "error"
    last_test_message: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    rules: Mapped[list["NotificationRule"]] = relationship(  # noqa: F821
        "NotificationRule", back_populates="integration", cascade="all, delete-orphan"
    )
    jira_links: Mapped[list["JiraIssueLink"]] = relationship(  # noqa: F821
        "JiraIssueLink", back_populates="integration", cascade="all, delete-orphan"
    )
