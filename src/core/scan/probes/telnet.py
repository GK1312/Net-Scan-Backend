from __future__ import annotations

import asyncio

from src.core.scan.constants import TELNET, TELNET_BANNER_BYTES, TELNET_BANNER_MAX
from src.core.scan.context import ProbeContext
from src.core.scan.models import TelnetResult


async def run(ctx: ProbeContext) -> TelnetResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ctx.ip, TELNET), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return TelnetResult()

    try:
        raw = await asyncio.wait_for(reader.read(TELNET_BANNER_BYTES), timeout=timeout)
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
    return TelnetResult(responded=True, banner=banner[:TELNET_BANNER_MAX])
