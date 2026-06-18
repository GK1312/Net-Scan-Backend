from __future__ import annotations

import asyncio

from src.core.scan.context import ProbeContext
from src.core.scan.models import TcpPortsResult

DEFAULT_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    80,
    135,
    139,
    161,
    443,
    445,
    548,
    554,
    631,
    902,
    1883,
    3306,
    3389,
    5985,
    7547,
    8080,
    8443,
    9100,
)


async def run(ctx: ProbeContext) -> TcpPortsResult:
    timeout = ctx.timeouts.port_connect_timeout
    states = await probe_ports(ctx, DEFAULT_PORTS, timeout)
    buckets: dict[str, list[int]] = {"open": [], "filtered": [], "closed": []}
    for port in DEFAULT_PORTS:
        buckets[states[port]].append(port)
    return TcpPortsResult(probed=list(DEFAULT_PORTS), **buckets)


async def probe_ports(
    ctx: ProbeContext, ports: tuple[int, ...] | list[int], timeout: float
) -> dict[int, str]:
    states = await asyncio.gather(*(_probe_port(ctx, p, timeout) for p in ports))
    return dict(zip(ports, states, strict=True))


async def _probe_port(ctx: ProbeContext, port: int, timeout: float) -> str:
    try:
        _, writer = await ctx.open_connection(port, timeout)
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
