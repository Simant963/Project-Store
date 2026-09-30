"""revoke sessions after password change

Revision ID: b7e3f92a40d1
Revises: a61d93b807c4
Create Date: 2026-09-23
"""

import sqlalchemy as sa
from alembic import op


revision = "b7e3f92a40d1"
down_revision = "a61d93b807c4"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("user") as batch_op:
        batch_op.add_column(
            sa.Column("session_version", sa.Integer(), server_default="0", nullable=False)
        )


def downgrade():
    with op.batch_alter_table("user") as batch_op:
        batch_op.drop_column("session_version")
