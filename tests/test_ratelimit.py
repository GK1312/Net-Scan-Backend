from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from src.api import deps
from src.utils.ratelimit import ClientRateLimiter


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_burst_then_blocks_then_refills():
    clock = _Clock()
    limiter = ClientRateLimiter(rate_per_sec=1.0, burst=3, time_fn=clock)

    assert [limiter.allow("a") for _ in range(3)] == [True, True, True]
    assert limiter.allow("a") is False
    clock.t += 1.0
    assert limiter.allow("a") is True
    assert limiter.allow("a") is False


def test_keys_are_independent():
    clock = _Clock()
    limiter = ClientRateLimiter(rate_per_sec=1.0, burst=1, time_fn=clock)
    assert limiter.allow("a") is True
    assert limiter.allow("a") is False
    assert limiter.allow("b") is True


def test_idle_buckets_evicted_at_capacity():
    clock = _Clock()
    limiter = ClientRateLimiter(
        rate_per_sec=1.0, burst=1, time_fn=clock, idle_evict_seconds=10, max_keys=2
    )
    limiter.allow("a")
    limiter.allow("b")
    clock.t += 100
    limiter.allow("c")
    assert "c" in limiter._buckets
    assert "a" not in limiter._buckets and "b" not in limiter._buckets


def _request(headers: dict[str, str], limiter, client_host="1.2.3.4"):
    client = SimpleNamespace(host=client_host) if client_host else None
    app = SimpleNamespace(state=SimpleNamespace(rate_limiter=limiter))
    return SimpleNamespace(headers=headers, app=app, client=client)


async def test_dependency_disabled_when_no_limiter():
    await deps.enforce_rate_limit(_request({}, limiter=None))


async def test_dependency_raises_429_when_exhausted():
    limiter = ClientRateLimiter(rate_per_sec=0.0, burst=1)
    req = _request({}, limiter=limiter)
    await deps.enforce_rate_limit(req)
    with pytest.raises(HTTPException) as exc:
        await deps.enforce_rate_limit(req)
    assert exc.value.status_code == 429


async def test_dependency_keys_by_api_key_then_ip():
    limiter = ClientRateLimiter(rate_per_sec=0.0, burst=1)

    await deps.enforce_rate_limit(_request({"x-api-key": "k1"}, limiter))
    await deps.enforce_rate_limit(_request({"x-api-key": "k2"}, limiter))
