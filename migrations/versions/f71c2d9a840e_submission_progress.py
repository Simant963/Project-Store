"""Track latest submission workflow and immutable transition history."""
from alembic import op
import sqlalchemy as sa

revision = "f71c2d9a840e"
down_revision = "e4a19c7d2b31"
branch_labels = depends_on = None


def upgrade():
    with op.batch_alter_table("store_app") as batch:
        batch.add_column(sa.Column("submission_status", sa.String(30), nullable=False, server_default="SECURITY_CHECK_PENDING"))
        batch.add_column(sa.Column("submission_revision", sa.Integer(), nullable=False, server_default="1"))
        batch.add_column(sa.Column("verified_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("verified_by_id", sa.Integer()))
        batch.add_column(sa.Column("published_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("submission_feedback", sa.Text()))
        batch.add_column(sa.Column("changes_requested", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("scan_started_at", sa.DateTime(timezone=True)))
        batch.create_foreign_key("fk_store_app_verified_by", "user", ["verified_by_id"], ["id"])
        batch.create_index("ix_store_app_submission_status", ["submission_status"])
    op.execute("""UPDATE store_app SET submission_status = CASE
        WHEN pending_release_status = 'rejected' THEN 'ADMIN_REJECTED'
        WHEN pending_release_status = 'pending' THEN 'SECURITY_CHECK_PENDING'
        WHEN status IN ('approved', 'blocked') OR (status = 'deleted' AND approved_at IS NOT NULL) THEN 'PUBLISHED'
        WHEN status = 'rejected' THEN 'ADMIN_REJECTED'
        WHEN security_scan_status = 'failed' OR malware_scan_status = 'failed' THEN 'SECURITY_CHECK_FAILED'
        ELSE 'SECURITY_CHECK_PENDING' END,
        published_at = approved_at, verified_at = approved_at,
        submission_feedback = COALESCE(pending_release_note, review_note)""")
    op.create_table("application_status_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("application_id", sa.Integer(), sa.ForeignKey("store_app.id"), nullable=False),
        sa.Column("version", sa.String(40), nullable=False),
        sa.Column("previous_status", sa.String(30)), sa.Column("new_status", sa.String(30), nullable=False),
        sa.Column("changed_by_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("changed_by_role", sa.String(20), nullable=False), sa.Column("reason", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_application_status_history_application_id", "application_status_history", ["application_id"])
    op.execute("""INSERT INTO application_status_history
        (application_id, version, new_status, changed_by_role, reason, created_at)
        SELECT id, COALESCE(pending_version, version), submission_status, 'system',
        'Existing submission imported; historical reviewer identity is unavailable', updated_at FROM store_app""")


def downgrade():
    op.drop_table("application_status_history")
    with op.batch_alter_table("store_app") as batch:
        batch.drop_index("ix_store_app_submission_status")
        batch.drop_constraint("fk_store_app_verified_by", type_="foreignkey")
        for column in ["scan_started_at", "changes_requested", "submission_feedback", "published_at",
                       "verified_by_id", "verified_at", "submission_revision", "submission_status"]:
            batch.drop_column(column)
