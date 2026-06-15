from __future__ import annotations

import asyncio
from pathlib import Path

import asyncpg

from src.config import get_settings

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "sql" / "schema.sql"


async def main() -> None:
    settings = get_settings().database
    if settings.dsn:
        connect_kwargs = {"dsn": settings.dsn}
    else:
        connect_kwargs = {
            "host": settings.host,
            "port": settings.port,
            "user": settings.user,
            "password": settings.password,
            "database": settings.database,
        }

    conn = await asyncpg.connect(**connect_kwargs)
    try:
        await conn.execute(SCHEMA_PATH.read_text())
        print(f"applied schema from {SCHEMA_PATH}")
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
