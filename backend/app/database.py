from collections.abc import AsyncIterator
from functools import lru_cache
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from .config import get_settings

@lru_cache(maxsize=4)
def session_factory(database_url: str) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(create_async_engine(database_url, pool_pre_ping=True), expire_on_commit=False)

async def session() -> AsyncIterator[AsyncSession]:
    async with session_factory(get_settings().database_url)() as value:
        yield value
