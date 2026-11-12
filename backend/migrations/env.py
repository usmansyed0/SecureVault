from alembic import context
from app.config import get_settings
from app.models import Base
config = context.config
config.set_main_option("sqlalchemy.url", get_settings().database_url.replace("+asyncpg", ""))
target_metadata = Base.metadata
def run_migrations_offline(): context.configure(url=config.get_main_option("sqlalchemy.url"), target_metadata=target_metadata, literal_binds=True); context.run_migrations()
def run_migrations_online():
    from sqlalchemy import create_engine
    with create_engine(config.get_main_option("sqlalchemy.url")).connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction(): context.run_migrations()
if context.is_offline_mode(): run_migrations_offline()
else: run_migrations_online()
