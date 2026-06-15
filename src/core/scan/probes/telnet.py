from __future__ import annotations

from src.core.scan.context import ProbeContext
from src.core.scan.models import TelnetResult


async def run(ctx: ProbeContext) -> TelnetResult:
    return TelnetResult()
