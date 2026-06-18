from __future__ import annotations

import pytest

from src.database import repository


class _FakeConn:
    def __init__(self, result: int) -> None:
        self.result = result
        self.sql: str | None = None
        self.args: tuple = ()

    async def fetchval(self, sql: str, *args):
        self.sql = sql
        self.args = args
        return self.result


@pytest.mark.asyncio
async def test_delete_expired_jobs_query_shape():
    conn = _FakeConn(result=7)
    deleted = await repository.delete_expired_jobs(conn, retention_days=30)

    assert deleted == 7
    assert conn.args == (30,)
    assert "DELETE FROM jobs" in conn.sql
    assert "make_interval(days => $1)" in conn.sql
