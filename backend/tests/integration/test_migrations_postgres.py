"""Run explicitly with SECUREVAULT_TEST_DATABASE_URL set; never substitutes SQLite for PostgreSQL."""
import os
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

pytestmark = pytest.mark.postgres
POSTGRES_URL = os.environ.get("SECUREVAULT_TEST_DATABASE_URL")

@pytest.mark.skipif(not POSTGRES_URL, reason="requires SECUREVAULT_TEST_DATABASE_URL; no SQLite substitution is permitted")
def test_migrations_create_phase3a_tables(monkeypatch):
    url = POSTGRES_URL
    monkeypatch.setenv("SECUREVAULT_DATABASE_URL", url.replace("postgresql://", "postgresql+asyncpg://"))
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    tables = inspect(create_engine(url)).get_table_names()
    assert {"users", "devices", "sessions", "refresh_tokens", "security_events"}.issubset(tables)
