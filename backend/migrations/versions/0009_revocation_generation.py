"""Add revocation_generation to users

Revision ID: 0009_revocation_generation
Revises: 0008_phase1_google_only_auth

Safe to run on existing databases:
  - revocation_generation is added to users with default=0.
"""
from alembic import op
import sqlalchemy as sa

revision = "0009_revocation_generation"
down_revision = "0008_phase1_google_only_auth"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("revocation_generation", sa.BigInteger(), nullable=False, server_default="0"))


def downgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("revocation_generation")
