from __future__ import annotations

from collections.abc import Sequence
from typing import TypeVar

T = TypeVar("T")


def chunk(items: Sequence[T], size: int) -> list[list[T]]:
    if size <= 0:
        raise ValueError("size must be positive")
    return [list(items[i : i + size]) for i in range(0, len(items), size)]
