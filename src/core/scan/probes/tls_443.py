from __future__ import annotations

from src.core.scan.context import ProbeContext
from src.core.scan.models import Tls443Result


async def run(ctx: ProbeContext) -> Tls443Result:
    return Tls443Result()
