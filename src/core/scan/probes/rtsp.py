from __future__ import annotations

import asyncio

from src.core.scan.constants import (
    RTSP,
    RTSP_REPLY_BYTES,
    RTSP_OPTIONS_REQUEST,
    RTSP_REPLY_PREFIX,
)
from src.core.scan.context import ProbeContext
from src.core.scan.models import RtspResult


async def run(ctx: ProbeContext) -> RtspResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ctx.ip, RTSP), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return RtspResult()

    try:
        writer.write(RTSP_OPTIONS_REQUEST)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(RTSP_REPLY_BYTES), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return RtspResult()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    reply = raw.decode(errors="ignore")
    if not reply.startswith(RTSP_REPLY_PREFIX):
        return RtspResult()
    return RtspResult(responded=True, banner=reply.split("\r\n")[0])
