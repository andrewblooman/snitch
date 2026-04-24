"""Remove s3_bucket and s3_key from cicd_scans (S3/SQS ingestion path removed)

Revision ID: 008
Revises: 007
Create Date: 2026-04-24
"""
from alembic import op
import sqlalchemy as sa

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("cicd_scans") as batch_op:
        batch_op.drop_column("s3_bucket")
        batch_op.drop_column("s3_key")


def downgrade() -> None:
    with op.batch_alter_table("cicd_scans") as batch_op:
        batch_op.add_column(sa.Column("s3_key", sa.String(1024), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("s3_bucket", sa.String(255), nullable=False, server_default=""))
