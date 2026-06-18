from __future__ import annotations

import time

import pytest

from src.config import Settings, WorkerSettings
from src.queue.consumer import Worker


class _FakeQueue:
    def __init__(self) -> None:
        self.cancelled: str | None = None

    async def cancel(self, tag: str) -> None:
        self.cancelled = tag


class _FakeClosable:
    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class _UnparseableMessage:
    body = b"not json"

    async def reject(self, requeue: bool) -> None:
        pass

    async def ack(self) -> None:
        pass


def _worker(grace: float = 30.0) -> Worker:
    settings = Settings(worker=WorkerSettings(shutdown_grace_seconds=grace))
    worker = Worker(settings)
    worker._queue = _FakeQueue()
    worker._consumer_tag = "ctag"
    worker.queue = _FakeClosable()
    worker.db = _FakeClosable()
    return worker


@pytest.mark.asyncio
async def test_shutdown_when_idle_cancels_and_closes():
    worker = _worker()
    await worker._shutdown()
    assert worker._queue.cancelled == "ctag"
    assert worker.queue.closed and worker.db.closed


@pytest.mark.asyncio
async def test_shutdown_times_out_but_still_closes():
    worker = _worker(grace=0.05)
    worker._inflight = 1
    worker._idle.clear()

    start = time.perf_counter()
    await worker._shutdown()
    elapsed = time.perf_counter() - start

    assert elapsed < 1.0
    assert worker.queue.closed and worker.db.closed


@pytest.mark.asyncio
async def test_inflight_tracking_returns_to_idle():
    worker = _worker()
    assert worker._idle.is_set()
    await worker._on_message(_UnparseableMessage())
    assert worker._inflight == 0
    assert worker._idle.is_set()
