from __future__ import annotations

import asyncio
import re
import ssl
import urllib.error
import urllib.request

from src.core.scan.context import ProbeContext
from src.core.scan.models import HttpResult

_CANDIDATES = (("https", 443), ("https", 8443), ("http", 8080), ("http", 80))
_INTERESTING_HEADERS = {"server", "x-powered-by", "x-aspnet-version", "x-frame-options"}
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_USER_AGENT = "Mozilla/5.0"
_BODY_BYTES = 8192

_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_TLS_CONTEXT.check_hostname = False
_TLS_CONTEXT.verify_mode = ssl.CERT_NONE


async def run(ctx: ProbeContext) -> HttpResult:
    open_ports: set[int] = ctx.shared.get("open_ports", set())
    timeout = ctx.timeouts.tcp_connect_timeout
    for scheme, port in _CANDIDATES:
        if port not in open_ports:
            continue
        result = await asyncio.to_thread(_fetch, ctx.ip, scheme, port, timeout)
        if result is not None:
            return result
    return HttpResult()


def _fetch(ip: str, scheme: str, port: int, timeout: float) -> HttpResult | None:
    url = f"{scheme}://{ip}/" if port in (80, 443) else f"{scheme}://{ip}:{port}/"
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    kwargs: dict = {"timeout": timeout}
    if scheme == "https":
        kwargs["context"] = _TLS_CONTEXT
    try:
        with urllib.request.urlopen(request, **kwargs) as response:
            headers = dict(response.headers)
            body = response.read(_BODY_BYTES).decode(errors="ignore")
        return _build(headers, body)
    except urllib.error.HTTPError as exc:
        return _build(dict(exc.headers), "")
    except Exception:
        return None


def _build(headers: dict[str, str], body: str) -> HttpResult:
    server = next(
        (value for key, value in headers.items() if key.lower() == "server"), None
    )
    title_match = _TITLE_RE.search(body)
    return HttpResult(
        responded=True,
        server=server or None,
        title=title_match.group(1).strip() if title_match else None,
        headers={
            key: value
            for key, value in headers.items()
            if key.lower() in _INTERESTING_HEADERS
        },
    )
