import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Application(Base):
    __tablename__ = "applications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    github_org: Mapped[str] = mapped_column(String(255), nullable=False)
    github_repo: Mapped[str] = mapped_column(String(255), nullable=False)
    repo_url: Mapped[str] = mapped_column(String(512), nullable=False)
    team_name: Mapped[str] = mapped_column(String(255), nullable=False)
    language: Mapped[str | None] = mapped_column(String(100), nullable=True)
    scan_schedule: Mapped[str] = mapped_column(String(50), default="none", nullable=False, server_default="none")
    container_image: Mapped[str | None] = mapped_column(String(512), nullable=True)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(50), default="info", nullable=False)

    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    scans: Mapped[list["Scan"]] = relationship(  # noqa: F821
        "Scan", back_populates="application", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        "Finding", back_populates="application", cascade="all, delete-orphan"
    )
    remediations: Mapped[list["Remediation"]] = relationship(  # noqa: F821
        "Remediation", back_populates="application", cascade="all, delete-orphan"
    )
    cicd_scans: Mapped[list["CiCdScan"]] = relationship(  # noqa: F821
        "CiCdScan", back_populates="application", cascade="all, delete-orphan"
    )
