from __future__ import annotations

import json
from typing import cast

import asyncpg

from src.config import DatabaseSettings
from src.exceptions import DatabaseError


def connection_kwargs(settings: DatabaseSettings) -> dict:
    if settings.dsn:
        return {"dsn": settings.dsn}
    return {
        "host": settings.host,
        "port": settings.port,
        "user": settings.user,
        "password": settings.password,
        "database": settings.database,
    }


async def _init_connection(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec(
        "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
    )


class DatabaseConnection:
    def __init__(self, settings: DatabaseSettings) -> None:
        self.settings = settings
        self._pool: asyncpg.Pool | None = None

    @property
    def pool(self) -> asyncpg.Pool | None:
        if self._pool is None:
            raise DatabaseError("database pool is not connected")
        return self._pool

    async def connect(self) -> None:
        if self._pool is not None:
            return
        self._pool = cast(
            asyncpg.Pool,
            await asyncpg.create_pool(
                min_size=1,
                max_size=self.settings.pool_size,
                init=_init_connection,
                **connection_kwargs(self.settings),
            ),
        )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
