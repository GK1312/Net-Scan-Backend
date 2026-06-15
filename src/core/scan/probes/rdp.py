from __future__ import annotations

from src.core.scan.context import ProbeContext
from src.core.scan.models import RdpResult


async def run(ctx: ProbeContext) -> RdpResult:
    return RdpResult()
