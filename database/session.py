from __future__ import annotations

from collections.abc import AsyncGenerator
from functools import lru_cache
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from config.loader import load_settings


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    settings = load_settings()
    db_url = settings.get("database", {}).get("url", "sqlite+aiosqlite:///./nr.db")
    echo = bool(settings.get("database", {}).get("echo", False))
    return create_async_engine(db_url, echo=echo, future=True)


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_engine(), expire_on_commit=False, class_=AsyncSession)


class _SessionLocalProxy:
    def __call__(self, *args: Any, **kwargs: Any):
        return get_sessionmaker()(*args, **kwargs)


SessionLocal = _SessionLocalProxy()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        yield session


async def init_db() -> None:
    from database.models.base import Base
    import database.models.entities  # noqa: F401

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def reset_db_state() -> None:
    get_engine.cache_clear()
