from __future__ import annotations

import asyncio
import re
import ssl
import urllib.request
from urllib.parse import urlsplit

from src.core.scan.context import ProbeContext
from src.core.scan.models import UpnpResult

_CANDIDATES = (("http", 80), ("http", 8080), ("https", 443), ("https", 8443))
_UPNP_PATHS = (
    "/description.xml",
    "/rootDesc.xml",
    "/",
)
_USER_AGENT = "Mozilla/5.0"
_BODY_BYTES = 8192

_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_TLS_CONTEXT.check_hostname = False
_TLS_CONTEXT.verify_mode = ssl.CERT_NONE


async def run(ctx: ProbeContext) -> UpnpResult:
    open_ports: set[int] = ctx.shared.get("open_ports", set())
    timeout = ctx.timeouts.tcp_connect_timeout

    targets: list[tuple[str, str]] = []  # (scheme, url) in preference order
    for scheme, port in _CANDIDATES:
        if port not in open_ports:
            continue
        base = (
            f"{scheme}://{ctx.ip}"
            if port in (80, 443)
            else f"{scheme}://{ctx.ip}:{port}"
        )
        targets.extend((scheme, base + path) for path in _UPNP_PATHS)
    if not targets:
        return UpnpResult()

    bodies = await asyncio.gather(
        *(asyncio.to_thread(_get, url, scheme, timeout) for scheme, url in targets)
    )
    for (_, url), body in zip(targets, bodies, strict=True):
        if body is None or ("<root" not in body and "<device" not in body):
            continue
        return UpnpResult(
            responded=True,
            location=urlsplit(url).path,
            friendly_name=_tag(body, "friendlyName"),
            manufacturer=_tag(body, "manufacturer"),
            model_name=_tag(body, "modelName"),
        )
    return UpnpResult()


def _get(url: str, scheme: str, timeout: float) -> str | None:
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    kwargs: dict = {"timeout": timeout}
    if scheme == "https":
        kwargs["context"] = _TLS_CONTEXT
    try:
        with urllib.request.urlopen(request, **kwargs) as response:
            return response.read(_BODY_BYTES).decode(errors="ignore")
    except Exception:
        return None


def _tag(body: str, name: str) -> str | None:
    match = re.search(rf"<{name}[^>]*>([^<]{{1,200}})</{name}>", body, re.IGNORECASE)
    return match.group(1).strip() if match else None
