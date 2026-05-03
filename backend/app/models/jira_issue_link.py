import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class JiraIssueLink(Base):
    __tablename__ = "jira_issue_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    integration_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("integrations.id", ondelete="CASCADE"), nullable=False
    )
    jira_issue_key: Mapped[str] = mapped_column(String(100), nullable=False)
    jira_issue_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    jira_status: Mapped[str] = mapped_column(String(100), default="To Do", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    integration: Mapped["Integration"] = relationship(  # noqa: F821
        "Integration", back_populates="jira_links"
    )
