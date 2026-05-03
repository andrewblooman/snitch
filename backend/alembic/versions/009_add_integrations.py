"""Add integrations, notification_rules, and jira_issue_links tables

Revision ID: 009
Revises: c2b28485c8a7
Create Date: 2026-05-03 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "009"
down_revision: Union[str, None] = "c2b28485c8a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if not inspector.has_table("integrations"):
        op.create_table(
            "integrations",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("type", sa.String(50), nullable=False),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("config", sa.Text, nullable=False, server_default="{}"),
            sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
            sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_test_status", sa.String(20), nullable=True),
            sa.Column("last_test_message", sa.String(1024), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )

    if not inspector.has_table("notification_rules"):
        op.create_table(
            "notification_rules",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "integration_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("integrations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("event_type", sa.String(50), nullable=False),
            sa.Column("min_severity", sa.String(50), nullable=False, server_default="high"),
            sa.Column("finding_types", sa.JSON, nullable=False, server_default="[]"),
            sa.Column("application_ids", sa.JSON, nullable=False, server_default="[]"),
            sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_notification_rules_integration_id", "notification_rules", ["integration_id"])

    if not inspector.has_table("jira_issue_links"):
        op.create_table(
            "jira_issue_links",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "finding_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("findings.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "integration_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("integrations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("jira_issue_key", sa.String(100), nullable=False),
            sa.Column("jira_issue_url", sa.String(2048), nullable=False),
            sa.Column("jira_status", sa.String(100), nullable=False, server_default="To Do"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_jira_issue_links_finding_id", "jira_issue_links", ["finding_id"])
        op.create_index("ix_jira_issue_links_integration_id", "jira_issue_links", ["integration_id"])


def downgrade() -> None:
    op.drop_table("jira_issue_links")
    op.drop_table("notification_rules")
    op.drop_table("integrations")
