from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager

import asyncpg


class NotifyDispatcher:
    def __init__(self, pool: asyncpg.Pool, channel: str) -> None:
        self._pool = pool
        self._channel = channel
        self._conn: asyncpg.pool.PoolConnectionProxy | None = None
        self._subscribers: dict[str, set[asyncio.Event]] = {}

    async def start(self) -> None:
        self._conn = await self._pool.acquire()
        await self._conn.add_listener(self._channel, self._on_notify)

    async def stop(self) -> None:
        if self._conn is None:
            return
        await self._conn.remove_listener(self._channel, self._on_notify)
        await self._pool.release(self._conn)
        self._conn = None

    def _on_notify(self, _conn, _pid, _channel, payload: str) -> None:
        for event in self._subscribers.get(payload, ()):
            event.set()

    @contextmanager
    def subscribe(self, job_id: str) -> Iterator[asyncio.Event]:
        event = asyncio.Event()
        self._subscribers.setdefault(job_id, set()).add(event)
        try:
            yield event
        finally:
            subscribers = self._subscribers.get(job_id)
            if subscribers is not None:
                subscribers.discard(event)
                if not subscribers:
                    self._subscribers.pop(job_id, None)
