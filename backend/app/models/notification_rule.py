import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import JSON

from app.db.base import Base


class NotificationRule(Base):
    __tablename__ = "notification_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    integration_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("integrations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # "new_finding" | "scan_complete" | "risk_spike" | "policy_violation"
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # "critical" | "high" | "medium" | "low"
    min_severity: Mapped[str] = mapped_column(String(50), default="high", nullable=False)
    # JSON list of finding_type strings; empty list = all types
    finding_types: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    # JSON list of application UUID strings; empty list = all apps
    application_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    integration: Mapped["Integration"] = relationship(  # noqa: F821
        "Integration", back_populates="rules"
    )
