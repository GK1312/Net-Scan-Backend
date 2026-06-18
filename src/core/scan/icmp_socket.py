from __future__ import annotations

import asyncio
import os
import socket
import struct
import sys
import time

_ICMP_ECHO_REQUEST = 8
_ICMP_ECHO_REPLY = 0
_PID = os.getpid() & 0xFFFF
_PAYLOAD = b"net-scan-probe"

_IP_RECVTTL = getattr(socket, "IP_RECVTTL", None)
_IP_TTL = getattr(socket, "IP_TTL", None)
_ANC_BUFSIZE = socket.CMSG_SPACE(64) if hasattr(socket, "CMSG_SPACE") else 64

_mode: str | None = None
_seq_counter = 0


def mode() -> str:
    global _mode
    if _mode is not None:
        return _mode
    if sys.platform == "win32":
        _mode = "subprocess"
        return _mode
    for candidate in ("raw", "dgram"):
        try:
            _open_socket(candidate).close()
            _mode = candidate
            return _mode
        except OSError:
            continue
    _mode = "subprocess"
    return _mode


async def ping(ip: str, timeout: float) -> tuple[int | None, float] | None:
    socket_mode = mode()
    if socket_mode == "subprocess":
        return None
    loop = asyncio.get_running_loop()
    seq = _next_seq()
    try:
        sock = _open_socket(socket_mode)
    except OSError:
        return None
    sock.setblocking(False)
    try:
        start = time.perf_counter()
        try:
            sock.sendto(_echo_packet(_PID, seq), (ip, 0))
        except OSError:
            return None
        ttl = await _await_reply(loop, sock, seq, socket_mode, timeout)
        if ttl is _NO_REPLY:
            return None
        return ttl, round((time.perf_counter() - start) * 1000, 3)
    finally:
        sock.close()


_NO_REPLY = object()


async def _await_reply(loop, sock, want_seq, socket_mode, timeout):
    use_recvmsg = socket_mode == "dgram" and _IP_RECVTTL is not None
    future: asyncio.Future = loop.create_future()

    def on_readable() -> None:
        try:
            if use_recvmsg:
                data, ancdata, _flags, _addr = sock.recvmsg(2048, _ANC_BUFSIZE)
            else:
                data, _addr = sock.recvfrom(2048)
                ancdata = ()
        except (BlockingIOError, InterruptedError):
            return
        except OSError as exc:
            if not future.done():
                future.set_exception(exc)
            return
        matched, ip_ttl = _parse_reply(data, want_seq, socket_mode)
        if not matched:
            return
        ttl = ip_ttl if ip_ttl is not None else _ttl_from_ancdata(ancdata)
        if not future.done():
            future.set_result(ttl)

    loop.add_reader(sock.fileno(), on_readable)
    try:
        return await asyncio.wait_for(future, timeout)
    except (asyncio.TimeoutError, OSError):
        return _NO_REPLY
    finally:
        loop.remove_reader(sock.fileno())


def _open_socket(socket_mode: str) -> socket.socket:
    if socket_mode == "raw":
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    if _IP_RECVTTL is not None:
        try:
            sock.setsockopt(socket.IPPROTO_IP, _IP_RECVTTL, 1)
        except OSError:
            pass
    return sock


def _next_seq() -> int:
    global _seq_counter
    _seq_counter = (_seq_counter + 1) & 0xFFFF
    return _seq_counter


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _echo_packet(ident: int, seq: int) -> bytes:
    header = struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    checksum = _checksum(header + _PAYLOAD)
    header = struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, checksum, ident, seq)
    return header + _PAYLOAD


def _parse_reply(
    data: bytes, want_seq: int, socket_mode: str
) -> tuple[bool, int | None]:
    ip_ttl: int | None = None
    if socket_mode == "raw":
        if len(data) < 20:
            return False, None
        ihl = (data[0] & 0x0F) * 4
        ip_ttl = data[8]
        icmp = data[ihl:]
    else:
        icmp = data
    if len(icmp) < 8 or icmp[0] != _ICMP_ECHO_REPLY:
        return False, None
    rid, rseq = struct.unpack("!HH", icmp[4:8])
    if rseq != want_seq:
        return False, None
    if socket_mode == "raw" and rid != _PID:
        return False, None
    return True, ip_ttl


def _ttl_from_ancdata(ancdata) -> int | None:
    for level, anc_type, cdata in ancdata:
        if level == socket.IPPROTO_IP and anc_type == _IP_TTL and cdata:
            if len(cdata) >= 4:
                return struct.unpack("i", cdata[:4])[0]
            return cdata[0]
    return None
