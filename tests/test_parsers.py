from __future__ import annotations

import struct

from src.core.scan.os_hints import win_version_name
from src.core.scan.probes import mdns, netbios, snmp


def test_win_version_name_shared_build_names_client_and_server():
    assert win_version_name(6, 2, 9200) == "Windows 8 / Server 2012"
    assert win_version_name(10, 0, 14393) == "Windows 10 1607 / Server 2016"
    assert win_version_name(10, 0, 26100) == "Windows 11 24H2 / Server 2025"


def test_win_version_name_legacy_build_carries_service_pack():
    assert win_version_name(6, 1, 7601) == "Windows 7 SP1 / Server 2008 R2 SP1"
    assert win_version_name(6, 1, 7600) == "Windows 7 / Server 2008 R2 (RTM)"
    assert win_version_name(5, 1, 2600) == "Windows XP"
    assert win_version_name(6, 1, 7777) == "Windows 7 / Server 2008 R2"


def test_win_version_name_server_exclusive_and_fallback():
    assert win_version_name(10, 0, 20348) == "Windows Server 2022"  # server-only build
    assert win_version_name(10, 0, 99999) == "Windows 11"  # unknown 10.0, build >= 22000
    assert win_version_name(6, 9, 1234) == "Windows (NT 6.9, build 1234)"


def test_snmp_oid_encode_decode_roundtrip():
    encoded = snmp._encode_oid(snmp.SYS_OBJECT_ID)
    tag, value, _ = snmp._read_tlv(encoded, 0)
    assert snmp._as_oid(tag, value) == snmp.SYS_OBJECT_ID


def test_snmp_parses_octet_string_varbind():
    def tlv(t, v):
        return bytes([t]) + snmp._length(len(v)) + v

    oid = snmp._encode_oid(snmp.SYS_DESCR)
    varbind = tlv(0x30, oid + tlv(0x04, b"Linux router"))
    varbinds = tlv(0x30, varbind)
    pdu = tlv(0xA2, snmp._integer(1) + snmp._integer(0) + snmp._integer(0) + varbinds)
    message = tlv(0x30, snmp._integer(0) + tlv(0x04, b"public") + pdu)

    tag, value = snmp._first_varbind(message)
    assert snmp._as_text(tag, value) == "Linux router"


def test_snmp_error_status_yields_no_varbind():
    def tlv(t, v):
        return bytes([t]) + snmp._length(len(v)) + v

    pdu = tlv(
        0xA2, snmp._integer(1) + snmp._integer(2) + snmp._integer(0) + tlv(0x30, b"")
    )
    message = tlv(0x30, snmp._integer(0) + tlv(0x04, b"public") + pdu)
    assert snmp._first_varbind(message) is None


def _name(labels):
    return b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00"


def _question(labels):
    return _name(labels) + struct.pack("!HH", 12, 1)


def test_mdns_service_enumeration_parsed():
    header = struct.pack("!HHHHHH", 0, 0x8400, 1, 2, 0, 0)
    q = _question(["_services", "_dns-sd", "_udp", "local"])
    answers = b""
    for svc in (["_http", "_tcp", "local"], ["_ipp", "_tcp", "local"]):
        rd = _name(svc)
        answers += b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(rd)) + rd
    packet = header + q + answers
    assert mdns._ptr_names(packet) == ["_http._tcp.local", "_ipp._tcp.local"]


def test_mdns_reverse_ptr_with_compression_pointer():
    header = struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 0)
    q = _question(["5", "1", "168", "192", "in-addr", "arpa"])
    rd = _name(["mydevice", "local"])
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(rd)) + rd
    assert mdns._ptr_names(header + q + answer) == ["mydevice.local"]


def test_mdns_non_response_returns_empty():
    assert mdns._ptr_names(struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)) == []


def test_mdns_reverse_query_ipv4_only():
    assert mdns._reverse_ptr_query("192.168.1.5") is not None
    assert mdns._reverse_ptr_query("fe80::1") is None


def test_netbios_parses_name_table_and_mac():
    def entry(label, ntype, group):
        flags = 0x8000 if group else 0x0000
        return label.ljust(15)[:15].encode() + bytes([ntype]) + struct.pack(">H", flags)

    body = bytes(50)
    body += b"\x00\x21\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00"
    body += bytes([2])
    body += entry("MYPC", 0x00, False)
    body += entry("WORKGROUP", 0x00, True)
    body += bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01])

    result = netbios._parse(body)
    assert result.responded
    assert result.computer_name == "MYPC"
    assert result.domain == "WORKGROUP"
    assert result.mac == "de:ad:be:ef:00:01"


def test_netbios_unparseable_returns_default():
    assert netbios._parse(b"\x00" * 10).responded is False
