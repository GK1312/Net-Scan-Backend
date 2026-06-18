from __future__ import annotations

import asyncio

from src.config import PhaseTimeouts
from src.core.scan.context import ProbeContext


class _DummyWriter:
    def close(self) -> None:
        pass


async def test_open_connection_bounds_concurrency(monkeypatch):
    current = 0
    peak = 0

    async def fake_open(host, port, **kwargs):
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        try:
            await asyncio.sleep(0.02)
            return object(), _DummyWriter()
        finally:
            current -= 1

    monkeypatch.setattr(
        "src.core.scan.context.asyncio.open_connection", fake_open
    )

    ctx = ProbeContext(
        ip="10.0.0.1", timeouts=PhaseTimeouts(), conn_limit=asyncio.Semaphore(3)
    )
    await asyncio.gather(*(ctx.open_connection(p, 1.0) for p in range(20)))

    assert peak <= 3


async def test_open_connection_unbounded_without_limiter(monkeypatch):
    async def fake_open(host, port, **kwargs):
        return object(), _DummyWriter()

    monkeypatch.setattr(
        "src.core.scan.context.asyncio.open_connection", fake_open
    )

    ctx = ProbeContext(ip="10.0.0.1", timeouts=PhaseTimeouts())  # conn_limit=None
    reader, writer = await ctx.open_connection(80, 1.0)
    assert writer is not None
