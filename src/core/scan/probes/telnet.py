from __future__ import annotations

import asyncio

from src.core.scan.context import ProbeContext
from src.core.scan.models import TelnetResult

TELNET_PORT = 23
_BANNER_BYTES = 512
_BANNER_MAX = 300


async def run(ctx: ProbeContext) -> TelnetResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ctx.ip, TELNET_PORT), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return TelnetResult()

    try:
        raw = await asyncio.wait_for(reader.read(_BANNER_BYTES), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return TelnetResult()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    banner = raw.decode("latin-1", errors="ignore").strip()
    if not banner:
        return TelnetResult()
    return TelnetResult(responded=True, banner=banner[:_BANNER_MAX])
