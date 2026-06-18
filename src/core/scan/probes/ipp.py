from __future__ import annotations

import asyncio
import re
import urllib.request

from src.core.scan.context import ProbeContext
from src.core.scan.models import IppResult

IPP_PORT = 631
JETDIRECT_PORT = 9100
_USER_AGENT = "Mozilla/5.0"
_HTTP_BODY_BYTES = 4096
_PJL_REPLY_BYTES = 512
_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,100})</title>", re.IGNORECASE)
_PJL_INFO = b"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X"
_PJL_ID_RE = re.compile(r"@PJL INFO ID\s*\r?\n(.+)")


async def run(ctx: ProbeContext) -> IppResult:
    open_ports: set[int] = ctx.shared.get("open_ports", set())
    timeout = ctx.timeouts.tcp_connect_timeout

    ipp_task = (
        asyncio.to_thread(_fetch_ipp, ctx.ip, timeout)
        if IPP_PORT in open_ports
        else _none_pair()
    )
    jetdirect_task = (
        _fetch_jetdirect(ctx.ip, timeout)
        if JETDIRECT_PORT in open_ports
        else _none_pair()
    )
    (ipp_ok, printer_name), (jd_ok, make_model) = await asyncio.gather(
        ipp_task, jetdirect_task
    )

    return IppResult(
        responded=ipp_ok or jd_ok,
        printer_name=printer_name,
        make_model=make_model,
    )


async def _none_pair() -> tuple[bool, str | None]:
    return False, None


def _fetch_ipp(ip: str, timeout: float) -> tuple[bool, str | None]:
    request = urllib.request.Request(
        f"http://{ip}:{IPP_PORT}/", headers={"User-Agent": _USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(_HTTP_BODY_BYTES).decode(errors="ignore")
    except Exception:
        return False, None
    match = _TITLE_RE.search(body)
    return True, match.group(1).strip() if match else None


async def _fetch_jetdirect(ip: str, timeout: float) -> tuple[bool, str | None]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, JETDIRECT_PORT), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return False, None

    try:
        writer.write(_PJL_INFO)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(_PJL_REPLY_BYTES), timeout=timeout)
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
