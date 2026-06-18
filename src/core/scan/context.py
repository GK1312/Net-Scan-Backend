from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from src.config import PhaseTimeouts


@dataclass(slots=True)
class ProbeContext:
    ip: str
    timeouts: PhaseTimeouts
    reverse_dns: bool = True
    conn_limit: asyncio.Semaphore | None = None
    shared: dict[str, Any] = field(default_factory=dict)

    async def open_connection(
        self, port: int, timeout: float, **kwargs: Any
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if self.conn_limit is None:
            return await asyncio.wait_for(
                asyncio.open_connection(self.ip, port, **kwargs), timeout
            )
        async with self.conn_limit:
            return await asyncio.wait_for(
                asyncio.open_connection(self.ip, port, **kwargs), timeout
            )
