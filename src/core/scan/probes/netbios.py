from __future__ import annotations

import asyncio
import struct

from src.core.scan.context import ProbeContext
from src.core.scan.models import NetbiosResult

NETBIOS_PORT = 137
_REPLY_BYTES = 4096

_NBSTAT_QUERY = (
    b"\xab\xcd"
    b"\x00\x10"
    b"\x00\x01"
    b"\x00\x00\x00\x00\x00\x00"
    b"\x20"
    b"CK" + b"AA" * 15 + b"\x00" + b"\x00\x21" + b"\x00\x01"
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


async def run(ctx: ProbeContext) -> NetbiosResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    loop = asyncio.get_running_loop()
    future: asyncio.Future[bytes] = loop.create_future()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _ResponseProtocol(future), remote_addr=(ctx.ip, NETBIOS_PORT)
        )
    except OSError:
        return NetbiosResult()
    try:
        transport.sendto(_NBSTAT_QUERY)
        data = await asyncio.wait_for(future, timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return NetbiosResult()
    finally:
        transport.close()

    return _parse(data)


def _parse(data: bytes) -> NetbiosResult:
    pos = data.find(b"\x00\x21\x00\x01", 50)
    if pos == -1:
        return NetbiosResult()
    pos += 4  # past type + class
    if pos + 6 > len(data):
        return NetbiosResult()
    pos += 4  # TTL
    pos += 2  # RDLENGTH
    if pos >= len(data):
        return NetbiosResult()

    num_names = data[pos]
    pos += 1

    computer_name: str | None = None
    domain: str | None = None
    for _ in range(num_names):
        if pos + 18 > len(data):
            break
        name = data[pos : pos + 15].decode(errors="ignore").rstrip()
        ntype = data[pos + 15]
        flags = struct.unpack_from(">H", data, pos + 16)[0]
        is_group = bool(flags & 0x8000)
        pos += 18

        if ntype == 0x00 and not is_group and computer_name is None:
            computer_name = name
        elif ntype == 0x00 and is_group and domain is None:
            domain = name

    mac: str | None = None
    if pos + 6 <= len(data):
        mac = ":".join(f"{b:02x}" for b in data[pos : pos + 6])

    return NetbiosResult(
        responded=True, computer_name=computer_name, domain=domain, mac=mac
    )
