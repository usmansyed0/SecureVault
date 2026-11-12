"""phase 3b cryptographic step-up records

Revision ID: 0003_step_up_and_device_controls
Revises: 0002_auth_sessions_devices
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_step_up_and_device_controls"
down_revision = "0002_auth_sessions_devices"
branch_labels = None
depends_on = None


def _step_up_table(name: str, secret_column: str):
    op.create_table(
        name,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("session_id", sa.Uuid(), sa.ForeignKey("sessions.id"), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column(secret_column, sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    )
    for column in ("user_id", "device_id", "session_id", "expires_at"):
        op.create_index(f"ix_{name}_{column}", name, [column])


def upgrade():
    _step_up_table("step_up_challenges", "challenge_hash")
    _step_up_table("step_up_grants", "grant_hash")


def downgrade():
    op.drop_table("step_up_grants")
    op.drop_table("step_up_challenges")
