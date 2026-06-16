from __future__ import annotations

import asyncio

from src.core.scan.constants import (
    RDP,
    RDP_REPLY_BYTES,
    RDP_CONNECTION_REQUEST,
    RDP_CC_MIN_LEN,
    RDP_CC_TPKT_OFFSET,
    RDP_CC_TPKT_VERSION,
    RDP_CC_COTP_OFFSET,
    RDP_CC_COTP_TYPE,
)
from src.core.scan.context import ProbeContext
from src.core.scan.models import RdpResult


async def run(ctx: ProbeContext) -> RdpResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ctx.ip, RDP), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return RdpResult()

    try:
        writer.write(RDP_CONNECTION_REQUEST)
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(RDP_REPLY_BYTES), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return RdpResult()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    if len(reply) >= RDP_CC_MIN_LEN and reply[RDP_CC_TPKT_OFFSET] == RDP_CC_TPKT_VERSION and reply[RDP_CC_COTP_OFFSET] == RDP_CC_COTP_TYPE:
        return RdpResult(responded=True)
    return RdpResult()
