from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass


class RateLimiter:
    def __init__(self, rate: float, burst: float | None = None) -> None:
        self.rate = float(rate)
        self.capacity = float(burst) if burst is not None else max(self.rate, 1.0)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.rate <= 0:
            return
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self.rate
            await asyncio.sleep(wait)


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


class ClientRateLimiter:
    def __init__(
        self,
        rate_per_sec: float,
        burst: float,
        *,
        idle_evict_seconds: float = 300.0,
        max_keys: int = 100_000,
        time_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self.rate = float(rate_per_sec)
        self.burst = float(burst)
        self._idle_evict = idle_evict_seconds
        self._max_keys = max_keys
        self._time = time_fn
        self._buckets: dict[str, _Bucket] = {}

    def allow(self, key: str) -> bool:
        now = self._time()
        bucket = self._buckets.get(key)
        if bucket is None:
            if len(self._buckets) >= self._max_keys:
                self._evict(now)
            bucket = _Bucket(self.burst, now)
            self._buckets[key] = bucket
        bucket.tokens = min(
            self.burst, bucket.tokens + (now - bucket.updated) * self.rate
        )
        bucket.updated = now
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True
        return False

    def _evict(self, now: float) -> None:
        stale = [
            key
            for key, bucket in self._buckets.items()
            if now - bucket.updated > self._idle_evict
        ]
        for key in stale:
            del self._buckets[key]
