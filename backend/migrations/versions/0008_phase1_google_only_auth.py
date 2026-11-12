"""Phase 1: Make password_verifier nullable for Google-only auth and add email display metadata

Revision ID: 0008_phase1_google_only_auth
Revises: 0007_google_nonce_and_sub_unique

Safe to run on existing databases:
  - password_verifier is relaxed from NOT NULL to NULLABLE (no data dropped).
  - email is added as a NULLABLE column (display metadata only).
  - Existing accounts remain intact without destructive changes.
"""
from alembic import op
import sqlalchemy as sa

revision = "0008_phase1_google_only_auth"
down_revision = "0007_google_nonce_and_sub_unique"
branch_labels = None
depends_on = None


def upgrade():
    # 1. Allow password_verifier to be NULL for Google-only authentication
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column("password_verifier", existing_type=sa.String(512), nullable=True)
        batch_op.add_column(sa.Column("email", sa.String(320), nullable=True))


def downgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("email")
        batch_op.alter_column("password_verifier", existing_type=sa.String(512), nullable=False)
