"""add failed_passcode_count to item_shares

Revision ID: 0006_add_failed_passcode_count_to_item_shares
Revises: 0005_remove_wrapped_vrk_from_bindings
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_add_failed_passcode_count_to_item_shares"
down_revision = "0005_remove_wrapped_vrk_from_bindings"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("item_shares", sa.Column("failed_passcode_count", sa.Integer(), nullable=False, server_default="0"))


def downgrade():
    op.drop_column("item_shares", "failed_passcode_count")
