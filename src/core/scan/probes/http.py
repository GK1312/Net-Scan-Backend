from __future__ import annotations

from src.core.scan.context import ProbeContext
from src.core.scan.models import HttpResult


async def run(ctx: ProbeContext) -> HttpResult:
    return HttpResult()
