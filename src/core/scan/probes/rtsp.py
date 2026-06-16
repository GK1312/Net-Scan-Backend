from __future__ import annotations

import asyncio

from src.core.scan.context import ProbeContext
from src.core.scan.models import RtspResult

RTSP_PORT = 554
_REPLY_BYTES = 256
_RTSP_OPTIONS = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: probe\r\n\r\n"


async def run(ctx: ProbeContext) -> RtspResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ctx.ip, RTSP_PORT), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return RtspResult()

    try:
        writer.write(_RTSP_OPTIONS)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(_REPLY_BYTES), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return RtspResult()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    reply = raw.decode(errors="ignore")
    if not reply.startswith("RTSP/"):
        return RtspResult()
    return RtspResult(responded=True, banner=reply.split("\r\n")[0])
