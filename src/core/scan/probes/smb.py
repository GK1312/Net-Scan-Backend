from __future__ import annotations

import asyncio
import struct

from src.core.scan.context import ProbeContext
from src.core.scan.models import SmbResult
from src.core.scan.os_hints import win_version_name

SMB_PORT = 445
# One retry: SMB handshakes drop transiently (reset / lost packet) on busy hosts.
# The runner sizes SMB's per-probe budget to cover SMB_ATTEMPTS reads.
SMB_ATTEMPTS = 2

_DIALECTS: dict[int, str] = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
    0x02FF: "SMB 2.x",
}


def _smb2_header(command: int, msg_id: int) -> bytes:
    return (
        b"\xfeSMB"
        + b"\x40\x00"
        + b"\x00\x00"
        + b"\x00\x00\x00\x00"
        + command.to_bytes(2, "little")
        + b"\x1f\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + msg_id.to_bytes(8, "little")
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 8
        + b"\x00" * 16
    )


def _netbios(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


_SMB2_NEG_BODY = (
    b"\x24\x00"
    + b"\x02\x00"
    + b"\x01\x00"
    + b"\x00\x00"
    + b"\x7f\x00\x00\x00"
    + b"\x00" * 16
    + b"\x00" * 8
    + b"\x02\x02"
    + b"\x10\x02"
)

_NTLMSSP_NEG = (
    b"NTLMSSP\x00"
    + b"\x01\x00\x00\x00"
    + b"\x15\x82\x08\x62"
    + b"\x00" * 8
    + b"\x00" * 8
    + b"\x0a\x00\x00\x00\x00\x00\x00\x0f"
)

_NEGOTIATE_PACKET = _netbios(_smb2_header(0x0000, 0) + _SMB2_NEG_BODY)


def _session_setup_packet(ntlmssp: bytes) -> bytes:
    body = (
        b"\x19\x00"
        + b"\x00"
        + b"\x01"
        + b"\x7f\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x58\x00"
        + len(ntlmssp).to_bytes(2, "little")
        + b"\x00" * 8
        + ntlmssp
    )
    return _netbios(_smb2_header(0x0001, 1) + body)


async def run(ctx: ProbeContext) -> SmbResult:
    connect_timeout = ctx.timeouts.tcp_connect_timeout
    read_timeout = ctx.timeouts.smb_timeout
    result = SmbResult()
    for _ in range(SMB_ATTEMPTS):
        result = await _attempt(ctx.ip, connect_timeout, read_timeout)
        # Retry only a failed *connect* (transient). A successful connect is a
        # terminal result whether or not SMB2 answered: a host that ignores the
        # SMB2 negotiate (SMB1-only, e.g. XP/2003) won't answer on a retry either,
        # and retrying would blow the per-probe time budget and lose the signal.
        if result.probed:
            break
    return result


async def _attempt(ip: str, connect_timeout: float, read_timeout: float) -> SmbResult:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, SMB_PORT), timeout=connect_timeout
        )
    except (OSError, asyncio.TimeoutError):
        return SmbResult()  # 445 unreachable this attempt -> a retry may still win
    try:
        return await _negotiate(reader, writer, read_timeout)
    finally:
        writer.close()


async def _negotiate(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float
) -> SmbResult:
    result = SmbResult(probed=True)

    try:
        writer.write(_NEGOTIATE_PACKET)
        await writer.drain()
        resp = await _read_message(reader, timeout)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        return result

    if len(resp) < 74 or resp[4:8] != b"\xfeSMB":
        return result
    result.responded = True
    dialect_val = struct.unpack_from("<H", resp, 72)[0]
    result.dialect = _DIALECTS.get(dialect_val, f"0x{dialect_val:04x}")
    if len(resp) >= 92:
        guid = resp[76:92]
        result.server_guid = guid.hex()
        result.is_samba = guid == b"\x00" * 16

    try:
        writer.write(_session_setup_packet(_NTLMSSP_NEG))
        await writer.drain()
        resp = await _read_message(reader, timeout)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        return result

    pos = resp.find(b"NTLMSSP\x00")
    if pos == -1:
        return result
    ntlmssp = resp[pos:]
    # Must be a CHALLENGE (MessageType 2) with the fixed header through TargetInfo.
    if len(ntlmssp) < 48 or struct.unpack_from("<I", ntlmssp, 8)[0] != 2:
        return result

    # AvPairs are located via the TargetInfo offset, so computer/domain parse
    # whether or not the server included a version block.
    avs = _parse_avpairs(ntlmssp)
    result.computer_name = avs.get("dns_computer_name") or avs.get("computer_name")
    result.domain = avs.get("dns_domain") or avs.get("nb_domain")

    # The version block at offset 48 is only meaningful if the server set
    # NTLMSSP_NEGOTIATE_VERSION (0x02000000); otherwise those bytes are payload.
    flags = struct.unpack_from("<I", ntlmssp, 20)[0]
    if flags & 0x02000000 and len(ntlmssp) >= 56:
        major, minor = ntlmssp[48], ntlmssp[49]
        build = struct.unpack_from("<H", ntlmssp, 50)[0]
        if major:
            result.os_version = f"{major}.{minor}.{build}"
            result.native_os = win_version_name(major, minor, build)

    # Non-Windows SMB (Samba on Linux/Unix, most NAS appliances) sends no Windows
    # version block and an all-zero ServerGUID -> label it from the Samba signal.
    if result.native_os is None and result.is_samba:
        result.native_os = "Samba (Linux/Unix)"
    return result


async def _read_message(reader: asyncio.StreamReader, timeout: float) -> bytes:
    header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    length = min(int.from_bytes(header[1:4], "big"), 0x10000)
    body = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    return header + body


def _parse_avpairs(ntlmssp: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    if len(ntlmssp) < 48:
        return out
    ti_len = struct.unpack_from("<H", ntlmssp, 40)[0]
    ti_offset = struct.unpack_from("<I", ntlmssp, 44)[0]
    if ti_offset + ti_len > len(ntlmssp):
        return out
    avpairs = ntlmssp[ti_offset : ti_offset + ti_len]
    i = 0
    while i + 4 <= len(avpairs):
        av_id = struct.unpack_from("<H", avpairs, i)[0]
        av_len = struct.unpack_from("<H", avpairs, i + 2)[0]
        i += 4
        if av_id == 0x0000:
            break
        if i + av_len > len(avpairs):
            break
        val = avpairs[i : i + av_len].decode("utf-16-le", errors="ignore")
        i += av_len
        if av_id == 0x0001:
            out["computer_name"] = val
        elif av_id == 0x0002:
            out["nb_domain"] = val
        elif av_id == 0x0003:
            out["dns_computer_name"] = val
        elif av_id == 0x0004:
            out["dns_domain"] = val
    return out
