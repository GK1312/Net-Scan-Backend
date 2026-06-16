from __future__ import annotations

import asyncio
import re
import urllib.request

from src.core.scan.constants import (
    IPP,
    JETDIRECT,
    HTTP_USER_AGENT,
    IPP_HTTP_BODY_BYTES,
    PJL_REPLY_BYTES,
    PJL_INFO_ID_COMMAND,
    PJL_ID_REPLY_PATTERN,
)
from src.core.scan.context import ProbeContext
from src.core.scan.models import IppResult

_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,100})</title>", re.IGNORECASE)
_PJL_ID_RE = re.compile(PJL_ID_REPLY_PATTERN)


async def run(ctx: ProbeContext) -> IppResult:
    open_ports: set[int] = ctx.shared.get("open_ports", set())
    timeout = ctx.timeouts.tcp_connect_timeout

    responded = False
    printer_name: str | None = None
    make_model: str | None = None

    if IPP in open_ports:
        ok, printer_name = await asyncio.to_thread(_fetch_ipp, ctx.ip, timeout)
        responded = responded or ok

    if JETDIRECT in open_ports:
        ok, make_model = await _fetch_jetdirect(ctx.ip, timeout)
        responded = responded or ok

    return IppResult(
        responded=responded, printer_name=printer_name, make_model=make_model
    )


def _fetch_ipp(ip: str, timeout: float) -> tuple[bool, str | None]:
    request = urllib.request.Request(
        f"http://{ip}:{IPP}/", headers={"User-Agent": HTTP_USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(IPP_HTTP_BODY_BYTES).decode(errors="ignore")
    except Exception:
        return False, None
    match = _TITLE_RE.search(body)
    return True, match.group(1).strip() if match else None


async def _fetch_jetdirect(ip: str, timeout: float) -> tuple[bool, str | None]:
    """Send a PJL INFO ID and parse the make/model from the reply."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, JETDIRECT), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return False, None

    try:
        writer.write(PJL_INFO_ID_COMMAND)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(PJL_REPLY_BYTES), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return False, None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    reply = raw.decode(errors="ignore")
    if not reply:
        return False, None
    match = _PJL_ID_RE.search(reply)
    return True, match.group(1).strip() if match else None
