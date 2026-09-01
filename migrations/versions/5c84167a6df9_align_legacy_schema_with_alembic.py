"""align legacy schema with alembic

Revision ID: 5c84167a6df9
Revises: 8e82246948e7
Create Date: 2026-09-01 10:45:43.022167

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5c84167a6df9'
down_revision = '8e82246948e7'
branch_labels = None
depends_on = None


def upgrade():
    """Align databases created by the retired startup schema updater.

    Every operation is conditional so a new database created by the initial
    Alembic revision can safely run this migration as a no-op.
    """
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    tables = set(inspector.get_table_names())

    if 'schema_version' in tables:
        op.drop_table('schema_version')

    if 'store_app' in tables:
        app_indexes = {index['name'] for index in inspector.get_indexes('store_app')}
        with op.batch_alter_table('store_app', schema=None) as batch_op:
            if 'idx_store_app_pending_release' in app_indexes:
                batch_op.drop_index('idx_store_app_pending_release')
            if 'ix_store_app_pending_release_status' not in app_indexes:
                batch_op.create_index(
                    'ix_store_app_pending_release_status',
                    ['pending_release_status'],
                    unique=False,
                )

    if 'user' in tables:
        connection.execute(sa.text(
            "UPDATE user SET email = 'legacy-user-' || id || '@invalid.local' "
            "WHERE email IS NULL OR TRIM(email) = ''"
        ))
        connection.execute(sa.text(
            "UPDATE user SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"
        ))
        user_columns = {column['name']: column for column in inspector.get_columns('user')}
        user_indexes = {index['name'] for index in inspector.get_indexes('user')}
        with op.batch_alter_table('user', schema=None) as batch_op:
            if user_columns['email']['nullable']:
                batch_op.alter_column(
                    'email', existing_type=sa.String(length=120), nullable=False
                )
            if user_columns['created_at']['nullable']:
                batch_op.alter_column(
                    'created_at', existing_type=sa.DateTime(), nullable=False
                )
            if 'idx_user_role_status' in user_indexes:
                batch_op.drop_index('idx_user_role_status')
            if 'ix_user_email' not in user_indexes:
                batch_op.create_index('ix_user_email', ['email'], unique=True)
            if 'ix_user_status' not in user_indexes:
                batch_op.create_index('ix_user_status', ['status'], unique=False)


def downgrade():
    # This compatibility cleanup does not change the application data model.
    # Reintroducing obsolete bookkeeping tables or nullable identity fields
    # would make the database less safe, so downgrade is intentionally a no-op.
    pass
