from __future__ import annotations

import asyncio

from src.core.scan.context import ProbeContext
from src.core.scan.models import RdpResult

RDP_PORT = 3389
_REPLY_BYTES = 256

_RDP_CR = (
    b"\x03\x00\x00\x13"
    b"\x0e"
    b"\xe0"
    b"\x00\x00"
    b"\x00\x00"
    b"\x00"
    b"\x01"
    b"\x00"
    b"\x08\x00"
    b"\x00\x00\x00\x00"
)


async def run(ctx: ProbeContext) -> RdpResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ctx.ip, RDP_PORT), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return RdpResult()

    try:
        writer.write(_RDP_CR)
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(_REPLY_BYTES), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return RdpResult()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    if len(reply) >= 6 and reply[0] == 0x03 and reply[5] == 0xD0:
        return RdpResult(responded=True)
    return RdpResult()
