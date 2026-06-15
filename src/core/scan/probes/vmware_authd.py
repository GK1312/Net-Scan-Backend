from __future__ import annotations

from src.core.scan.context import ProbeContext
from src.core.scan.models import VmwareAuthdResult


async def run(ctx: ProbeContext) -> VmwareAuthdResult:
    return VmwareAuthdResult()
