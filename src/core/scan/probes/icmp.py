from __future__ import annotations

import asyncio
import re
import subprocess
import sys

from src.core.scan.constants import snap_ttl
from src.core.scan.context import ProbeContext
from src.core.scan.models import IcmpResult

_TTL_RE = re.compile(r"ttl[=:](\d+)", re.IGNORECASE)
_RTT_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


async def run(ctx: ProbeContext) -> IcmpResult:
    wait_ms = max(500, int((ctx.timeouts.ping_timeout - 0.5) * 1000))
    out = await _ping(ctx.ip, wait_ms)
    if out is None:
        return IcmpResult()

    ttl_match = _TTL_RE.search(out)
    if ttl_match is None:
        return IcmpResult()

    ttl = int(ttl_match.group(1))
    rtt_match = _RTT_RE.search(out)
    return IcmpResult(
        responded=True,
        ttl_received=ttl,
        ttl_estimated=snap_ttl(ttl),
        rtt_ms=float(rtt_match.group(1)) if rtt_match else None,
    )


def _ping_args(ip: str, wait_ms: int) -> list[str]:
    if sys.platform == "win32":
        return ["ping", "-n", "1", "-w", str(wait_ms), ip]
    if sys.platform == "darwin":
        return ["ping", "-c", "1", "-W", str(wait_ms), ip]  # macOS -W is milliseconds
    return [
        "ping",
        "-c",
        "1",
        "-W",
        str(max(1, round(wait_ms / 1000))),
        ip,
    ]


async def _ping(ip: str, wait_ms: int) -> str | None:
    kwargs: dict = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        proc = await asyncio.create_subprocess_exec(
            *_ping_args(ip, wait_ms),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            **kwargs,
        )
    except (OSError, ValueError):
        return None
    try:
        stdout, _ = await proc.communicate()
    except asyncio.CancelledError:
        proc.kill()
        raise
    return stdout.decode(errors="ignore")

