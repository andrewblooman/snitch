import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    cicd_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cicd_scans.id", ondelete="SET NULL"), nullable=True
    )

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)  # critical/high/medium/low/info
    finding_type: Mapped[str] = mapped_column(String(50), nullable=False)  # SAST/SCA/container
    scanner: Mapped[str] = mapped_column(String(50), nullable=False)  # semgrep/grype/trivy

    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    cve_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    package_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    compliance_tags: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    status: Mapped[str] = mapped_column(String(50), default="open", nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    @property
    def source(self) -> str:
        return "cicd" if self.cicd_scan_id is not None else "repository"

    @property
    def application_name(self) -> str | None:
        # Only access if already eagerly loaded — avoid triggering lazy load in async context
        app = self.__dict__.get('application')
        return app.name if app else None

    application: Mapped["Application"] = relationship(  # noqa: F821
        "Application", back_populates="findings"
    )
    scan: Mapped["Scan | None"] = relationship(  # noqa: F821
        "Scan", back_populates="findings"
    )
    cicd_scan: Mapped["CiCdScan | None"] = relationship(  # noqa: F821
        "CiCdScan", back_populates="findings"
    )
