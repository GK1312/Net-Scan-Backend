from __future__ import annotations

import asyncio

import asyncpg

from src.config import get_settings
from src.database import repository
from src.database.connections import connection_kwargs


async def main() -> None:
    settings = get_settings().database
    conn = await asyncpg.connect(**connection_kwargs(settings))
    try:
        deleted = await repository.delete_expired_jobs(
            conn, settings.result_retention_time_day
        )
        print(
            f"reap: deleted {deleted} job(s) older than "
            f"{settings.result_retention_time_day} day(s)"
        )
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
