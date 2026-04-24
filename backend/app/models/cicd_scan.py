import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from sqlalchemy import ForeignKey


class CiCdScan(Base):
    __tablename__ = "cicd_scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )

    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)  # semgrep / grype
    status: Mapped[str] = mapped_column(String(50), default="processing", nullable=False)
    # processing / completed / failed

    # CI/CD context
    commit_sha: Mapped[str | None] = mapped_column(String(255), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    workflow_run_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ci_provider: Mapped[str | None] = mapped_column(String(100), nullable=True)  # github-actions / gitlab-ci / etc.

    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    application: Mapped["Application"] = relationship(  # noqa: F821
        "Application", back_populates="cicd_scans"
    )
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        "Finding", back_populates="cicd_scan"
    )
