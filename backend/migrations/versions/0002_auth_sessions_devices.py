"""phase 3a auth sessions and device authorization

Revision ID: 0002_auth_sessions_devices
Revises: 0001_foundation
"""
from alembic import op
import sqlalchemy as sa
import hashlib

revision = "0002_auth_sessions_devices"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("status", sa.String(16), nullable=False, server_default="active"))
    op.add_column("users", sa.Column("bootstrap_available", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("users", sa.Column("vault_binding_exists", sa.Boolean(), nullable=False, server_default=sa.false()))

    op.add_column("devices", sa.Column("key_fingerprint", sa.String(64), nullable=True))
    op.add_column("devices", sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")))
    op.add_column("devices", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("devices", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
    # Existing foundation deployments did not have trusted device semantics.
    op.execute("UPDATE devices SET status = 'pending' WHERE status = 'active'")
    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, public_key FROM devices"))
    for row in rows:
        bind.execute(
            sa.text("UPDATE devices SET key_fingerprint = :fingerprint WHERE id = :id"),
            {"id": row.id, "fingerprint": hashlib.sha256(bytes(row.public_key)).hexdigest()},
        )
    op.alter_column("devices", "key_fingerprint", nullable=False)
    op.create_index("ix_devices_key_fingerprint", "devices", ["key_fingerprint"])
    op.create_unique_constraint("uq_devices_user_key_fingerprint", "devices", ["user_id", "key_fingerprint"])

    op.drop_column("sessions", "refresh_hash")
    op.drop_column("sessions", "expires_at")
    op.add_column("sessions", sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")))
    op.add_column("sessions", sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")))
    op.add_column("sessions", sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")))
    op.add_column("sessions", sa.Column("revoked_reason", sa.String(32), nullable=True))
    # Existing non-rotating foundation sessions cannot be safely upgraded in place.
    op.execute("UPDATE sessions SET revoked_at = now(), revoked_reason = 'migration'")
    op.create_index("ix_sessions_idle_expires_at", "sessions", ["idle_expires_at"])
    op.create_index("ix_sessions_absolute_expires_at", "sessions", ["absolute_expires_at"])

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("session_id", sa.Uuid(), sa.ForeignKey("sessions.id"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_id", sa.Uuid(), sa.ForeignKey("refresh_tokens.id"), nullable=True),
    )
    op.create_index("ix_refresh_tokens_session_id", "refresh_tokens", ["session_id"])
    op.create_index("ix_refresh_tokens_expires_at", "refresh_tokens", ["expires_at"])

    op.create_table(
        "security_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id"), nullable=True),
        sa.Column("session_id", sa.Uuid(), sa.ForeignKey("sessions.id"), nullable=True),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_security_events_user_id", "security_events", ["user_id"])
    op.create_index("ix_security_events_device_id", "security_events", ["device_id"])
    op.create_index("ix_security_events_session_id", "security_events", ["session_id"])


def downgrade():
    op.drop_table("security_events")
    op.drop_table("refresh_tokens")
    op.drop_index("ix_sessions_absolute_expires_at", table_name="sessions")
    op.drop_index("ix_sessions_idle_expires_at", table_name="sessions")
    op.drop_column("sessions", "revoked_reason")
    op.drop_column("sessions", "absolute_expires_at")
    op.drop_column("sessions", "idle_expires_at")
    op.drop_column("sessions", "issued_at")
    op.add_column("sessions", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False))
    op.add_column("sessions", sa.Column("refresh_hash", sa.String(512), nullable=False))
    op.drop_constraint("uq_devices_user_key_fingerprint", "devices", type_="unique")
    op.drop_index("ix_devices_key_fingerprint", table_name="devices")
    op.drop_column("devices", "revoked_at")
    op.drop_column("devices", "last_seen_at")
    op.drop_column("devices", "registered_at")
    op.drop_column("devices", "key_fingerprint")
    op.drop_column("users", "vault_binding_exists")
    op.drop_column("users", "bootstrap_available")
    op.drop_column("users", "status")
