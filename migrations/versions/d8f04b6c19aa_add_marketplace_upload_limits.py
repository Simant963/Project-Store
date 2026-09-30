"""add marketplace upload limits

Revision ID: d8f04b6c19aa
Revises: c5a1d88f2e60
Create Date: 2026-09-23
"""

import sqlalchemy as sa
from alembic import op
from datetime import datetime, timezone


revision = "d8f04b6c19aa"
down_revision = "c5a1d88f2e60"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("user") as batch_op:
        batch_op.add_column(sa.Column("app_upload_limit", sa.Integer(), nullable=True))
    settings = op.create_table(
        "marketplace_settings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("default_app_limit", sa.Integer(), nullable=False),
        sa.Column("max_apk_size_mb", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.bulk_insert(
        settings,
        [{
            "id": 1,
            "default_app_limit": 2,
            "max_apk_size_mb": 200,
            "updated_at": datetime.now(timezone.utc),
        }],
    )


def downgrade():
    op.drop_table("marketplace_settings")
    with op.batch_alter_table("user") as batch_op:
        batch_op.drop_column("app_upload_limit")
