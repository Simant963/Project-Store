"""add security question recovery

Revision ID: c5a1d88f2e60
Revises: b7e3f92a40d1
Create Date: 2026-09-23
"""

import sqlalchemy as sa
from alembic import op


revision = "c5a1d88f2e60"
down_revision = "b7e3f92a40d1"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("user") as batch_op:
        batch_op.add_column(sa.Column("security_question", sa.String(30), nullable=True))
        batch_op.add_column(
            sa.Column("security_answer_hash", sa.String(255), nullable=True)
        )


def downgrade():
    with op.batch_alter_table("user") as batch_op:
        batch_op.drop_column("security_answer_hash")
        batch_op.drop_column("security_question")
