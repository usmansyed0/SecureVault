"""Remove wrapped_vrk_mek and wrapped_vrk_nonce from vault_bindings

These columns stored a self-wrapped copy of the VRK (encrypted with itself)
that was never read back or used for decryption anywhere in the codebase.
VRK is re-derived on every device from Argon2id(master_password, salt).
The columns add server-side attack surface and mislead security reviewers
into thinking a password-derived MEK exists when it does not.

Revision ID: 0005_remove_wrapped_vrk_from_bindings
Revises: 0004_vault_sync_objects_shares_backups
"""
from alembic import op

revision = "0005_remove_wrapped_vrk_from_bindings"
down_revision = "0004_vault_sync_objects_shares_backups"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_column("vault_bindings", "wrapped_vrk_mek")
    op.drop_column("vault_bindings", "wrapped_vrk_nonce")


def downgrade():
    # Columns are intentionally dropped and cannot be meaningfully restored.
    # Re-adding them empty would break the non-nullable constraint, so the
    # downgrade is a no-op. Roll forward instead.
    pass
