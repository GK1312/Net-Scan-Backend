from __future__ import annotations

from src.core.scan.context import ProbeContext
from src.core.scan.models import UpnpResult


async def run(ctx: ProbeContext) -> UpnpResult:
    return UpnpResult()
