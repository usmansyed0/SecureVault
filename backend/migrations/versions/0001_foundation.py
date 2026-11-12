"""secure foundation tables

Revision ID: 0001_foundation
"""
from alembic import op
import sqlalchemy as sa
revision = "0001_foundation"; down_revision = None; branch_labels = None; depends_on = None
def upgrade():
    op.create_table("users", sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("login_normalized", sa.String(320), nullable=False), sa.Column("password_verifier", sa.String(512), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False)); op.create_index("ix_users_login_normalized", "users", ["login_normalized"], unique=True)
    op.create_table("devices", sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False), sa.Column("name", sa.String(128), nullable=False), sa.Column("platform", sa.String(32), nullable=False), sa.Column("status", sa.String(16), nullable=False), sa.Column("public_key", sa.LargeBinary(), nullable=False))
    op.create_table("sessions", sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False), sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id"), nullable=False), sa.Column("refresh_hash", sa.String(512), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
def downgrade(): op.drop_table("sessions"); op.drop_table("devices"); op.drop_index("ix_users_login_normalized", table_name="users"); op.drop_table("users")
