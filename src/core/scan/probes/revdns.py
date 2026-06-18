from __future__ import annotations

import asyncio
import socket

from src.core.scan.context import ProbeContext
from src.core.scan.models import RevDnsResult


async def run(ctx: ProbeContext) -> RevDnsResult:
    if not ctx.reverse_dns:
        return RevDnsResult()
    try:
        name = await asyncio.wait_for(
            asyncio.to_thread(_ptr, ctx.ip),
            timeout=ctx.timeouts.tcp_connect_timeout,
        )
    except (OSError, asyncio.TimeoutError):
        return RevDnsResult()
    return RevDnsResult(hostname=name)


def _ptr(ip: str) -> str | None:
    try:
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
    except OSError:
        return None
    host = host.rstrip(".")
    return host if host and host != ip else None
