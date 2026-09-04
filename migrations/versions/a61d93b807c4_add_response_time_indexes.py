"""add response time indexes

Revision ID: a61d93b807c4
Revises: df2feea83d09
Create Date: 2026-09-03
"""

from alembic import op


revision = "a61d93b807c4"
down_revision = "df2feea83d09"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("user") as batch_op:
        batch_op.create_index(
            "ix_user_role_status_created", ["role", "status", "created_at"]
        )
    with op.batch_alter_table("store_app") as batch_op:
        batch_op.create_index(
            "ix_store_app_status_approved", ["status", "approved_at", "id"]
        )
        batch_op.create_index(
            "ix_store_app_developer_submitted",
            ["developer_id", "submitted_at", "id"],
        )
    with op.batch_alter_table("download_record") as batch_op:
        batch_op.create_index("ix_download_user_time", ["user_id", "downloaded_at"])
        batch_op.create_index("ix_download_app_time", ["app_id", "downloaded_at"])
    with op.batch_alter_table("app_review") as batch_op:
        batch_op.create_index("ix_app_review_app_status", ["app_id", "status"])
    with op.batch_alter_table("notification") as batch_op:
        batch_op.create_index(
            "ix_notification_recipient_created", ["recipient_id", "created_at"]
        )


def downgrade():
    with op.batch_alter_table("notification") as batch_op:
        batch_op.drop_index("ix_notification_recipient_created")
    with op.batch_alter_table("app_review") as batch_op:
        batch_op.drop_index("ix_app_review_app_status")
    with op.batch_alter_table("download_record") as batch_op:
        batch_op.drop_index("ix_download_app_time")
        batch_op.drop_index("ix_download_user_time")
    with op.batch_alter_table("store_app") as batch_op:
        batch_op.drop_index("ix_store_app_developer_submitted")
        batch_op.drop_index("ix_store_app_status_approved")
    with op.batch_alter_table("user") as batch_op:
        batch_op.drop_index("ix_user_role_status_created")
