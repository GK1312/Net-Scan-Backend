from __future__ import annotations

from src.core.scan.context import ProbeContext
from src.core.scan.models import RtspResult


async def run(ctx: ProbeContext) -> RtspResult:
    return RtspResult()
