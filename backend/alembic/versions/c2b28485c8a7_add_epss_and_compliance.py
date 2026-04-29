"""Add EPSS and compliance

Revision ID: c2b28485c8a7
Revises: 008
Create Date: 2026-04-29 22:26:17.818859

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c2b28485c8a7'
down_revision: Union[str, None] = '008'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('findings', sa.Column('epss_score', sa.Float(), nullable=True))
    op.add_column('findings', sa.Column('epss_percentile', sa.Float(), nullable=True))
    op.add_column('findings', sa.Column('compliance_tags', sa.JSON(), nullable=True))

def downgrade() -> None:
    op.drop_column('findings', 'compliance_tags')
    op.drop_column('findings', 'epss_percentile')
    op.drop_column('findings', 'epss_score')
