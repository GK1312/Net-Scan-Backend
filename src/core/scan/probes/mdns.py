from __future__ import annotations

from src.core.scan.context import ProbeContext
from src.core.scan.models import MdnsResult


async def run(ctx: ProbeContext) -> MdnsResult:
    return MdnsResult()
