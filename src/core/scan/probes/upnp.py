from __future__ import annotations

import asyncio
import re
import ssl
import urllib.request

from src.core.scan.constants import (
    UPNP_CANDIDATES,
    DESCRIPTION_PATHS,
    HTTP_USER_AGENT,
    UPNP_BODY_BYTES,
)
from src.core.scan.context import ProbeContext
from src.core.scan.models import UpnpResult

_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_TLS_CONTEXT.check_hostname = False
_TLS_CONTEXT.verify_mode = ssl.CERT_NONE


async def run(ctx: ProbeContext) -> UpnpResult:
    open_ports: set[int] = ctx.shared.get("open_ports", set())
    timeout = ctx.timeouts.tcp_connect_timeout
    for scheme, port in UPNP_CANDIDATES:
        if port not in open_ports:
            continue
        result = await asyncio.to_thread(
            _fetch_description, ctx.ip, scheme, port, timeout
        )
        if result is not None:
            return result
    return UpnpResult()


def _fetch_description(
    ip: str, scheme: str, port: int, timeout: float
) -> UpnpResult | None:
    base = f"{scheme}://{ip}" if port in (80, 443) else f"{scheme}://{ip}:{port}"
    for path in DESCRIPTION_PATHS:
        body = _get(base + path, scheme, timeout)
        if body is None or ("<root" not in body and "<device" not in body):
            continue
        return UpnpResult(
            responded=True,
            location=path,
            friendly_name=_tag(body, "friendlyName"),
            manufacturer=_tag(body, "manufacturer"),
            model_name=_tag(body, "modelName"),
        )
    return None


def _get(url: str, scheme: str, timeout: float) -> str | None:
    request = urllib.request.Request(url, headers={"User-Agent": HTTP_USER_AGENT})
    kwargs: dict = {"timeout": timeout}
    if scheme == "https":
        kwargs["context"] = _TLS_CONTEXT
    try:
        with urllib.request.urlopen(request, **kwargs) as response:
            return response.read(UPNP_BODY_BYTES).decode(errors="ignore")
    except Exception:
        return None


def _tag(body: str, name: str) -> str | None:
    match = re.search(rf"<{name}[^>]*>([^<]{{1,200}})</{name}>", body, re.IGNORECASE)
    return match.group(1).strip() if match else None
