"""initial schema

Revision ID: 001
Revises:
Create Date: 2025-01-01 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "applications",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("github_org", sa.String(255), nullable=False),
        sa.Column("github_repo", sa.String(255), nullable=False),
        sa.Column("repo_url", sa.String(512), nullable=False),
        sa.Column("team_name", sa.String(255), nullable=False),
        sa.Column("language", sa.String(100), nullable=True),
        sa.Column("risk_score", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("risk_level", sa.String(50), nullable=False, server_default="info"),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("application_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("trigger", sa.String(50), nullable=False, server_default="manual"),
        sa.Column("findings_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("critical_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("high_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("medium_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("low_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_application_id", "scans", ["application_id"])

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("application_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", sa.String(50), nullable=False),
        sa.Column("finding_type", sa.String(50), nullable=False),
        sa.Column("scanner", sa.String(50), nullable=False),
        sa.Column("file_path", sa.String(1024), nullable=True),
        sa.Column("line_number", sa.Integer, nullable=True),
        sa.Column("rule_id", sa.String(255), nullable=True),
        sa.Column("cve_id", sa.String(100), nullable=True),
        sa.Column("package_name", sa.String(255), nullable=True),
        sa.Column("package_version", sa.String(100), nullable=True),
        sa.Column("fixed_version", sa.String(100), nullable=True),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="open"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("fixed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_application_id", "findings", ["application_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_cve_id", "findings", ["cve_id"])

    op.create_table(
        "remediations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("application_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default="planned"),
        sa.Column("finding_ids", postgresql.JSON, nullable=False, server_default="[]"),
        sa.Column("ai_plan", sa.Text, nullable=True),
        sa.Column("ai_model", sa.String(100), nullable=True),
        sa.Column("branch_name", sa.String(255), nullable=True),
        sa.Column("pr_url", sa.String(512), nullable=True),
        sa.Column("pr_number", sa.Integer, nullable=True),
        sa.Column("pr_status", sa.String(50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_remediations_application_id", "remediations", ["application_id"])


def downgrade() -> None:
    op.drop_table("remediations")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("applications")
