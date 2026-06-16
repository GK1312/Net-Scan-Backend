from __future__ import annotations

import asyncio

from src.core.scan.constants import VMWARE_AUTHD, VMWARE_AUTHD_BANNER_BYTES
from src.core.scan.context import ProbeContext
from src.core.scan.models import VmwareAuthdResult


async def run(ctx: ProbeContext) -> VmwareAuthdResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ctx.ip, VMWARE_AUTHD), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return VmwareAuthdResult()

    try:
        raw = await asyncio.wait_for(reader.read(VMWARE_AUTHD_BANNER_BYTES), timeout=timeout)
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
