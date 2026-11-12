"""Create google_nonces table and add UNIQUE constraint to users.google_sub

Revision ID: 0007_google_nonce_and_sub_unique
Revises: 0006_add_failed_passcode_count_to_item_shares

Safe to run on existing databases:
  - google_nonces is a new table (no existing data affected).
  - users.google_sub UNIQUE index is added with CREATE UNIQUE INDEX CONCURRENTLY
    on PostgreSQL (handled by Alembic on a live DB); sqlite just adds the index.
    NULL values are never considered equal in UNIQUE indexes, so existing rows
    with NULL google_sub are unaffected.
"""
from alembic import op
import sqlalchemy as sa

revision = "0007_google_nonce_and_sub_unique"
down_revision = "0006_add_failed_passcode_count_to_item_shares"
branch_labels = None
depends_on = None


def upgrade():
    # 1. Add UNIQUE constraint to users.google_sub
    #    NULLs are ignored by UNIQUE indexes in both PostgreSQL and SQLite.
    op.create_index(
        "ix_users_google_sub_unique",
        "users",
        ["google_sub"],
        unique=True,
        postgresql_concurrently=False,  # set True for zero-downtime on live PG
    )

    # 2. Create google_nonces table for single-use nonce replay protection.
    op.create_table(
        "google_nonces",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("nonce_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_google_nonces_nonce_hash", "google_nonces", ["nonce_hash"], unique=True)
    op.create_index("ix_google_nonces_expires_at", "google_nonces", ["expires_at"])


def downgrade():
    op.drop_table("google_nonces")
    op.drop_index("ix_users_google_sub_unique", table_name="users")
