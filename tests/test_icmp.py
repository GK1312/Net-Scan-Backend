from __future__ import annotations

import struct
import sys

import pytest

from src.core.scan import icmp_socket
from src.core.scan.context import ProbeContext
from src.core.scan.probes import icmp


def _make_raw_reply(ident: int, seq: int, ttl: int) -> bytes:
    ip_header = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, ttl, 1, 0, 0]) + bytes(8)
    icmp_msg = struct.pack("!BBHHH", 0, 0, 0, ident, seq) + b"net-scan-probe"
    return ip_header + icmp_msg


def test_checksum_is_self_verifying():
    packet = icmp_socket._echo_packet(0x1234, 7)
    assert icmp_socket._checksum(packet) == 0


def test_echo_packet_fields():
    packet = icmp_socket._echo_packet(0xABCD, 42)
    icmp_type, code, _csum, ident, seq = struct.unpack("!BBHHH", packet[:8])
    assert icmp_type == 8 and code == 0
    assert ident == 0xABCD and seq == 42
    assert packet[8:] == b"net-scan-probe"


def test_parse_raw_reply_matches_id_and_seq():
    reply = _make_raw_reply(icmp_socket._PID, 99, ttl=58)
    matched, ttl = icmp_socket._parse_reply(reply, 99, "raw")
    assert matched and ttl == 58


def test_parse_raw_reply_rejects_wrong_seq_and_id():
    reply = _make_raw_reply(icmp_socket._PID, 99, ttl=58)
    assert icmp_socket._parse_reply(reply, 100, "raw") == (False, None)
    other = _make_raw_reply(icmp_socket._PID ^ 0xFF, 99, ttl=58)
    assert other and icmp_socket._parse_reply(other, 99, "raw") == (False, None)


def test_parse_dgram_reply_has_no_ip_ttl():
    icmp_msg = struct.pack("!BBHHH", 0, 0, 0, 1, 5) + b"x"
    matched, ttl = icmp_socket._parse_reply(icmp_msg, 5, "dgram")
    assert matched and ttl is None


def test_non_echo_reply_rejected():
    icmp_msg = struct.pack("!BBHHH", 3, 0, 0, 1, 5)
    assert icmp_socket._parse_reply(icmp_msg, 5, "dgram") == (False, None)


def test_mode_is_subprocess_on_windows():
    if sys.platform == "win32":
        assert icmp_socket.mode() == "subprocess"
    else:
        assert icmp_socket.mode() in ("raw", "dgram", "subprocess")


@pytest.mark.asyncio
async def test_ping_loopback_when_sockets_available():
    if icmp_socket.mode() == "subprocess":
        pytest.skip("no unprivileged/raw ICMP socket on this host")
    ctx = ProbeContext(ip="127.0.0.1", timeouts=_Timeouts())
    result = await icmp.run(ctx)
    assert result.responded is True
    assert result.rtt_ms is not None


class _Timeouts:
    ping_timeout = 3.0
    tcp_connect_timeout = 2.0
