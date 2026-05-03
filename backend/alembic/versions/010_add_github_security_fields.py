"""Add GitHub Advanced Security fields to findings table

Revision ID: 010
Revises: 009
Create Date: 2026-05-03 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "010"
down_revision: Union[str, None] = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("commit_sha", sa.String(length=40), nullable=True))
    op.add_column("findings", sa.Column("introduced_by", sa.String(length=255), nullable=True))
    op.add_column("findings", sa.Column("pr_number", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("pr_url", sa.String(length=512), nullable=True))
    op.add_column("findings", sa.Column("github_alert_url", sa.String(length=512), nullable=True))
    op.add_column("findings", sa.Column("github_alert_number", sa.Integer(), nullable=True))
    op.add_column("applications", sa.Column("last_github_sync_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("applications", "last_github_sync_at")
    op.drop_column("findings", "github_alert_number")
    op.drop_column("findings", "github_alert_url")
    op.drop_column("findings", "pr_url")
    op.drop_column("findings", "pr_number")
    op.drop_column("findings", "introduced_by")
    op.drop_column("findings", "commit_sha")
