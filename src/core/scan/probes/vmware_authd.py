from __future__ import annotations

import asyncio

from src.core.scan.context import ProbeContext
from src.core.scan.models import VmwareAuthdResult

VMWARE_AUTHD_PORT = 902
_BANNER_BYTES = 256


async def run(ctx: ProbeContext) -> VmwareAuthdResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ctx.ip, VMWARE_AUTHD_PORT), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return VmwareAuthdResult()

    try:
        raw = await asyncio.wait_for(reader.read(_BANNER_BYTES), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return VmwareAuthdResult()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    banner = raw.decode(errors="ignore").strip()
    return VmwareAuthdResult(
        responded="vmware" in banner.lower(),
        banner=banner or None,
    )
