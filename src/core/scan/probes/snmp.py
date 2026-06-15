from __future__ import annotations

from src.core.scan.context import ProbeContext
from src.core.scan.models import SnmpResult


async def run(ctx: ProbeContext) -> SnmpResult:
    return SnmpResult()
