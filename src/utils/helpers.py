from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator, Sequence, TypeVar

T = TypeVar("T")


def chunk(items: Sequence[T], size: int) -> list[list[T]]:
    if size <= 0:
        raise ValueError("size must be positive")
    return [list(items[i : i + size]) for i in range(0, len(items), size)]


@contextmanager
def timed(label: str) -> Iterator[None]:
    start = time.perf_counter()
    yield
    _elapsed = time.perf_counter() - start
