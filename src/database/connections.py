from __future__ import annotations

import json
from typing import cast

import asyncpg

from src.exceptions import DatabaseError
from src.config import DatabaseSettings


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
        if self.settings.dsn:
            connect_kwargs = {"dsn": self.settings.dsn}
        else:
            connect_kwargs = {
                "host": self.settings.host,
                "port": self.settings.port,
                "user": self.settings.user,
                "password": self.settings.password,
                "database": self.settings.database,
            }
        self._pool = cast(
            asyncpg.Pool,
            await asyncpg.create_pool(
                min_size=1,
                max_size=self.settings.pool_size,
                init=_init_connection,
                **connect_kwargs,
            ),
        )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
