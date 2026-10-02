"""add manual administrator-approved password resets

Revision ID: e4a19c7d2b31
Revises: d8f04b6c19aa
"""

from alembic import op
import sqlalchemy as sa


revision = "e4a19c7d2b31"
down_revision = "d8f04b6c19aa"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "manual_password_reset",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("reference", sa.String(length=24), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "approved",
                "rejected",
                "used",
                name="manualresetstatus",
                native_enum=False,
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("code_hash", sa.String(length=64), nullable=True),
        sa.Column("code_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("reviewed_by_id", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["reviewed_by_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("reference"),
    )
    op.create_index(
        "ix_manual_password_reset_reference",
        "manual_password_reset",
        ["reference"],
        unique=True,
    )
    op.create_index(
        "ix_manual_password_reset_user_id",
        "manual_password_reset",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_manual_password_reset_status",
        "manual_password_reset",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_manual_password_reset_code_expires_at",
        "manual_password_reset",
        ["code_expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_manual_reset_status_created",
        "manual_password_reset",
        ["status", "created_at"],
        unique=False,
    )


def downgrade():
    op.drop_index("ix_manual_reset_status_created", table_name="manual_password_reset")
    op.drop_index(
        "ix_manual_password_reset_code_expires_at",
        table_name="manual_password_reset",
    )
    op.drop_index("ix_manual_password_reset_status", table_name="manual_password_reset")
    op.drop_index("ix_manual_password_reset_user_id", table_name="manual_password_reset")
    op.drop_index("ix_manual_password_reset_reference", table_name="manual_password_reset")
    op.drop_table("manual_password_reset")
