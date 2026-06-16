from __future__ import annotations

import asyncio

from src.core.scan.constants import SSH, SSH_BANNER_BYTES
from src.core.scan.context import ProbeContext
from src.core.scan.models import SshResult


async def run(ctx: ProbeContext) -> SshResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ctx.ip, SSH), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return SshResult()

    try:
        raw = await asyncio.wait_for(reader.read(SSH_BANNER_BYTES), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return SshResult()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    banner = raw.decode(errors="ignore").strip()
    if not banner.startswith("SSH"):
        return SshResult()
    return SshResult(responded=True, banner=banner)
