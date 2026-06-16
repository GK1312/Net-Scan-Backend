from __future__ import annotations

import asyncio

from src.core.scan.constants import DEFAULT_SCAN_PORTS
from src.core.scan.context import ProbeContext
from src.core.scan.models import TcpPortsResult


async def run(ctx: ProbeContext) -> TcpPortsResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    states = await asyncio.gather(
        *(_probe_port(ctx.ip, port, timeout) for port in DEFAULT_SCAN_PORTS)
    )
    buckets: dict[str, list[int]] = {"open": [], "filtered": [], "closed": []}
    for port, state in zip(DEFAULT_SCAN_PORTS, states):
        buckets[state].append(port)
    return TcpPortsResult(probed=list(DEFAULT_SCAN_PORTS), **buckets)


async def _probe_port(ip: str, port: int, timeout: float) -> str:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except asyncio.TimeoutError:
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return "filtered"

    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return "open"
