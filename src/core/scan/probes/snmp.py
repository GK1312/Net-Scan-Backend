from __future__ import annotations

import asyncio
from collections.abc import Callable

from src.core.scan.context import ProbeContext
from src.core.scan.models import SnmpResult

SNMP_PORT = 161
_COMMUNITY = b"public"
_REPLY_BYTES = 4096

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"

_OCTET_STRING = 0x04
_OBJECT_ID = 0x06


async def run(ctx: ProbeContext) -> SnmpResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    sys_descr, sys_name, sys_object_id = await asyncio.gather(
        _snmp_get(ctx.ip, SYS_DESCR, timeout, _as_text),
        _snmp_get(ctx.ip, SYS_NAME, timeout, _as_text),
        _snmp_get(ctx.ip, SYS_OBJECT_ID, timeout, _as_oid),
    )

    if sys_descr is None and sys_name is None and sys_object_id is None:
        return SnmpResult()
    return SnmpResult(
        responded=True,
        sys_descr=sys_descr,
        sys_name=sys_name,
        sys_object_id=sys_object_id,
    )


class _ResponseProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future) -> None:
        self._future = future

    def datagram_received(self, data: bytes, _addr) -> None:
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(exc)


async def _snmp_get(
    ip: str, oid: str, timeout: float, convert: Callable[[int, bytes], str | None]
) -> str | None:
    loop = asyncio.get_running_loop()
    future: asyncio.Future[bytes] = loop.create_future()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _ResponseProtocol(future), remote_addr=(ip, SNMP_PORT)
        )
    except OSError:
        return None
    try:
        transport.sendto(_build_get(oid))
        data = await asyncio.wait_for(future, timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        transport.close()

    try:
        varbind = _first_varbind(data)
    except (ValueError, IndexError):
        return None
    return convert(*varbind) if varbind is not None else None


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def _integer(n: int) -> bytes:
    body = n.to_bytes((n.bit_length() // 8) + 1, "big")
    return _tlv(0x02, body)


def _encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for arc in parts[2:]:
        chunks = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunks.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body += bytes(reversed(chunks))
    return _tlv(_OBJECT_ID, body)


def _build_get(oid: str, request_id: int = 1) -> bytes:
    varbind = _tlv(0x30, _encode_oid(oid) + _tlv(0x05, b""))
    varbinds = _tlv(0x30, varbind)
    pdu = _tlv(0xA0, _integer(request_id) + _integer(0) + _integer(0) + varbinds)
    return _tlv(0x30, _integer(0) + _tlv(_OCTET_STRING, _COMMUNITY) + pdu)


def _read_tlv(data: bytes, i: int) -> tuple[int, bytes, int]:
    tag = data[i]
    length = data[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[i : i + n], "big")
        i += n
    end = i + length
    if end > len(data):
        raise ValueError("truncated TLV")
    return tag, data[i:end], end


def _first_varbind(data: bytes) -> tuple[int, bytes] | None:
    _, message, _ = _read_tlv(data, 0)
    _, _, i = _read_tlv(message, 0)
    _, _, i = _read_tlv(message, i)
    _, pdu, _ = _read_tlv(message, i)
    _, _, j = _read_tlv(pdu, 0)
    _, error_status, j = _read_tlv(pdu, j)
    if int.from_bytes(error_status, "big") != 0:
        return None
    _, _, j = _read_tlv(pdu, j)
    _, varbinds, _ = _read_tlv(pdu, j)
    _, varbind, _ = _read_tlv(varbinds, 0)
    _, _, k = _read_tlv(varbind, 0)
    tag, value, _ = _read_tlv(varbind, k)
    return tag, value


def _as_text(tag: int, value: bytes) -> str | None:
    if tag != _OCTET_STRING:
        return None
    text = value.decode(errors="ignore").strip()
    return text or None


def _as_oid(tag: int, value: bytes) -> str | None:
    if tag != _OBJECT_ID or not value:
        return None
    arcs = [str(value[0] // 40), str(value[0] % 40)]
    acc = 0
    for byte in value[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(str(acc))
            acc = 0
    return ".".join(arcs)
