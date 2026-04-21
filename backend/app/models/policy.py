import uuid
from datetime import datetime

from sqlalchemy import JSON as SA_JSON
from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # action taken when a finding violates this policy
    # block | inform | both
    action: Mapped[str] = mapped_column(String(50), default="inform", nullable=False)

    # minimum severity to flag (critical > high > medium > low > info)
    min_severity: Mapped[str] = mapped_column(String(50), default="medium", nullable=False)

    # list of scan type labels to include: sast, sca, container, secrets, iac
    # empty list means "all scan types"
    enabled_scan_types: Mapped[list] = mapped_column(SA_JSON, default=list, nullable=False)

    # rule IDs / CVE IDs to always flag regardless of severity
    rule_blocklist: Mapped[list] = mapped_column(SA_JSON, default=list, nullable=False)

    # rule IDs / CVE IDs to always ignore (overrides everything)
    rule_allowlist: Mapped[list] = mapped_column(SA_JSON, default=list, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
