"""vault sync, object blobs, shares, backups, and user credentials

Revision ID: 0004_vault_sync_objects_shares_backups
Revises: 0003_step_up_and_device_controls
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_vault_sync_objects_shares_backups"
down_revision = "0003_step_up_and_device_controls"
branch_labels = None
depends_on = None


def upgrade():
    # User additions
    op.add_column("users", sa.Column("master_salt", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("auth_public_key", sa.LargeBinary(), nullable=True))
    op.add_column("users", sa.Column("google_sub", sa.String(128), nullable=True))
    op.create_index("ix_users_google_sub", "users", ["google_sub"])

    # Vault bindings
    op.create_table(
        "vault_bindings",
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), primary_key=True),
        sa.Column("vault_id", sa.Uuid(), nullable=False),
        sa.Column("wrapped_vrk_mek", sa.LargeBinary(), nullable=False),
        sa.Column("wrapped_vrk_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("kdf_params", sa.String(512), nullable=False, server_default="{}"),
        sa.Column("version", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # Remote vault records
    op.create_table(
        "remote_vault_records",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("vault_id", sa.Uuid(), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary(), nullable=False),
        sa.Column("wrapped_dek_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("client_revision", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_remote_vault_records_user_id", "remote_vault_records", ["user_id"])
    op.create_index("ix_remote_vault_records_vault_id", "remote_vault_records", ["vault_id"])

    # Sync changelog
    op.create_table(
        "sync_changelog",
        sa.Column("server_seq", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_sync_changelog_user_id", "sync_changelog", ["user_id"])
    op.create_index("ix_sync_changelog_record_id", "sync_changelog", ["record_id"])

    # Object blobs
    op.create_table(
        "object_blobs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("page_id", sa.Uuid(), nullable=False),
        sa.Column("page_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_object_blobs_user_id", "object_blobs", ["user_id"])
    op.create_index("ix_object_blobs_record_id", "object_blobs", ["record_id"])
    op.create_index("ix_object_blobs_page_id", "object_blobs", ["page_id"])

    # Item shares
    op.create_table(
        "item_shares",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("item_id", sa.Uuid(), nullable=False),
        sa.Column("item_type", sa.String(32), nullable=False),
        sa.Column("share_token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("encrypted_payload", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("passcode_hash", sa.String(128), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_views", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("view_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_item_shares_user_id", "item_shares", ["user_id"])
    op.create_index("ix_item_shares_item_id", "item_shares", ["item_id"])
    op.create_index("ix_item_shares_expires_at", "item_shares", ["expires_at"])

    # Backups
    op.create_table(
        "backups",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("object_id", sa.Uuid(), nullable=False),
        sa.Column("encrypted_manifest", sa.LargeBinary(), nullable=False),
        sa.Column("manifest_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_backups_user_id", "backups", ["user_id"])


def downgrade():
    op.drop_table("backups")
    op.drop_table("item_shares")
    op.drop_table("object_blobs")
    op.drop_table("sync_changelog")
    op.drop_table("remote_vault_records")
    op.drop_table("vault_bindings")
    op.drop_index("ix_users_google_sub", table_name="users")
    op.drop_column("users", "google_sub")
    op.drop_column("users", "auth_public_key")
    op.drop_column("users", "master_salt")
