"""add policies table

Revision ID: 004
Revises: 003
Create Date: 2026-04-21 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("action", sa.String(50), nullable=False, server_default="inform"),
        sa.Column("min_severity", sa.String(50), nullable=False, server_default="medium"),
        sa.Column("enabled_scan_types", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("rule_blocklist", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("rule_allowlist", sa.JSON, nullable=False, server_default="[]"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_policies_name", "policies", ["name"], unique=True)
    op.create_index("ix_policies_is_active", "policies", ["is_active"])


def downgrade() -> None:
    op.drop_index("ix_policies_is_active", table_name="policies")
    op.drop_index("ix_policies_name", table_name="policies")
    op.drop_table("policies")
