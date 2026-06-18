from __future__ import annotations

import asyncio
import ssl
from typing import Any

from src.core.scan.context import ProbeContext
from src.core.scan.models import Tls443Result

TLS_PORT = 443
_COMMON_NAME_OID = b"\x55\x04\x03"


async def run(ctx: ProbeContext) -> Tls443Result:
    handshake_timeout = min(
        ctx.timeouts.tcp_connect_timeout, (ctx.timeouts.ping_timeout - 0.2) / 2
    )

    cert_dict, cert_der = await _fetch_cert(
        ctx.ip, _verifying_context(), handshake_timeout
    )
    if cert_dict is None and cert_der is None:
        cert_dict, cert_der = await _fetch_cert(
            ctx.ip, _permissive_context(), handshake_timeout
        )

    if cert_dict is None and cert_der is None:
        return Tls443Result()

    if cert_dict:
        return Tls443Result(
            responded=True,
            subject=_rdn_value(cert_dict.get("subject"), "commonName"),
            issuer=_rdn_value(cert_dict.get("issuer"), "commonName"),
            san=[value for _, value in cert_dict.get("subjectAltName", ())],
        )
    return Tls443Result(responded=True, subject=_der_common_name(cert_der))


async def _fetch_cert(
    ip: str, context: ssl.SSLContext, timeout: float
) -> tuple[dict[str, Any] | None, bytes | None]:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, TLS_PORT, ssl=context, server_hostname=ip),
            timeout=timeout,
        )
    except (OSError, ssl.SSLError, asyncio.TimeoutError):
        return None, None

    ssl_object = writer.get_extra_info("ssl_object")
    cert_dict = ssl_object.getpeercert() if ssl_object else None
    cert_der = ssl_object.getpeercert(binary_form=True) if ssl_object else None

    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return (cert_dict or None), cert_der


def _verifying_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    return context


def _permissive_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _rdn_value(rdns: Any, key: str) -> str | None:
    for rdn in rdns or ():
        for name, value in rdn:
            if name == key:
                return value
    return None


def _der_common_name(der: bytes | None) -> str | None:
    if not der:
        return None
    index = der.rfind(_COMMON_NAME_OID)
    if index < 0:
        return None
    pos = index + len(_COMMON_NAME_OID)
    if pos + 2 > len(der):
        return None
    length = der[pos + 1]
    start = pos + 2
    end = start + length
    if end > len(der):
        return None
    return der[start:end].decode(errors="ignore") or None
