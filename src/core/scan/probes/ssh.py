from __future__ import annotations

from src.core.scan.context import ProbeContext
from src.core.scan.models import SshResult


async def run(ctx: ProbeContext) -> SshResult:
    return SshResult()
