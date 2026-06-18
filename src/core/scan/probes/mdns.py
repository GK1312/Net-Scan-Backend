from __future__ import annotations

import asyncio
import struct

from src.core.scan.context import ProbeContext
from src.core.scan.models import MdnsResult

MDNS_PORT = 5353
_REPLY_BYTES = 4096
_PTR = 12
_IN = 1
_QR = 0x8000


class _ResponseProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future) -> None:
        self._future = future

    def datagram_received(self, data: bytes, _addr) -> None:
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(exc)


async def run(ctx: ProbeContext) -> MdnsResult:
    timeout = ctx.timeouts.tcp_connect_timeout

    reverse_query = _reverse_ptr_query(ctx.ip)
    queries = [_udp_query(ctx.ip, _SERVICE_ENUM_QUERY, timeout)]
    if reverse_query is not None:
        queries.append(_udp_query(ctx.ip, reverse_query, timeout))
    responses = await asyncio.gather(*queries)

    services_data = responses[0]
    hostname_data = responses[1] if len(responses) > 1 else None

    responded = False
    services: list[str] = []
    hostname: str | None = None

    if services_data is not None and _is_response(services_data):
        responded = True
        services = _ptr_names(services_data)

    if hostname_data is not None:
        names = _ptr_names(hostname_data)
        if names:
            responded = True
            hostname = names[0]

    if not responded:
        return MdnsResult()
    return MdnsResult(responded=True, services=services, hostname=hostname)


async def _udp_query(ip: str, packet: bytes, timeout: float) -> bytes | None:
    loop = asyncio.get_running_loop()
    future: asyncio.Future[bytes] = loop.create_future()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _ResponseProtocol(future), remote_addr=(ip, MDNS_PORT)
        )
    except OSError:
        return None
    try:
        transport.sendto(packet)
        return await asyncio.wait_for(future, timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        transport.close()


def _dns_ptr_query(labels: list[bytes]) -> bytes:
    qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)  # id, flags, qd=1, an/ns/ar=0
    return header + qname + struct.pack("!HH", _PTR, _IN)


_SERVICE_ENUM_QUERY = _dns_ptr_query([b"_services", b"_dns-sd", b"_udp", b"local"])


def _reverse_ptr_query(ip: str) -> bytes | None:
    if ":" in ip or "." not in ip:  # IPv4 only
        return None
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    return _dns_ptr_query([label.encode() for label in rev.split(".")])


def _is_response(data: bytes) -> bool:
    return len(data) >= 12 and bool(struct.unpack_from("!H", data, 2)[0] & _QR)


def _ptr_names(data: bytes) -> list[str]:
    if len(data) < 12:
        return []
    flags, qdcount, ancount = struct.unpack_from("!HHH", data, 2)
    if not flags & _QR:
        return []

    offset = 12
    for _ in range(qdcount):
        _, offset = _parse_name(data, offset)
        offset += 4  # QTYPE + QCLASS

    names: list[str] = []
    for _ in range(ancount):
        _, offset = _parse_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        if rtype == _PTR:
            name, _ = _parse_name(data, offset)
            name = name.rstrip(".")
            if name:
                names.append(name)
        offset += rdlen
    return names


def _parse_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    pos = offset
    next_offset = offset
    jumped = False
    guard = 0
    while guard < 128 and pos < len(data):
        guard += 1
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                next_offset = pos
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                next_offset = pos + 2
            pos = pointer
            jumped = True
            continue
        pos += 1
        if pos + length > len(data):
            break
        labels.append(data[pos : pos + length].decode("utf-8", errors="ignore"))
        pos += length
    return ".".join(labels), next_offset
