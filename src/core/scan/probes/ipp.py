from __future__ import annotations

from src.core.scan.context import ProbeContext
from src.core.scan.models import IppResult


async def run(ctx: ProbeContext) -> IppResult:
    return IppResult()
