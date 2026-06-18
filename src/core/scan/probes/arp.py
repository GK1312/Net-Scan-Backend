from __future__ import annotations

import asyncio
import re
import socket
import subprocess
import sys
import time

from src.core.scan.context import ProbeContext
from src.core.scan.models import ArpResult
from src.core.scan.oui import is_randomized_mac, lookup_oui, normalize_mac

_MAC_RE = re.compile(
    r"([\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}"
    r"[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2})"
)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_ARP_RESOLVE_DELAY = 0.15
_LOCAL_TTL = 30.0
_local_cache: tuple[float, dict[str, str]] | None = None
_local_lock = asyncio.Lock()


async def run(ctx: ProbeContext) -> ArpResult:
    ip = ctx.ip
    local = await _local_macs()

    if ip in local:
        mac = local[ip]
    elif _on_link(ip, local):
        _poke(ip)
        await asyncio.sleep(_ARP_RESOLVE_DELAY)
        mac = await asyncio.to_thread(_read_arp_entry, ip)
    else:
        return ArpResult()

    if mac is None:
        return ArpResult()

    if is_randomized_mac(mac):
        return ArpResult(mac=mac, randomized=True)

    manufacturer, platform_hint = lookup_oui(mac)
    return ArpResult(
        mac=mac,
        manufacturer=manufacturer,
        platform_hint=platform_hint,
        randomized=False,
    )


def _poke(ip: str) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setblocking(False)
            try:
                sock.sendto(b"", (ip, 9))
            except OSError:
                pass
    except OSError:
        pass


def _on_link(ip: str, local: dict[str, str]) -> bool:
    if not local:
        return False
    target = _net24(ip)
    return any(_net24(local_ip) == target for local_ip in local)


def _net24(ip: str) -> str:
    head, _, _ = ip.rpartition(".")
    return head or ip


def _read_arp_entry(ip: str) -> str | None:
    args = ["arp", "-a", ip] if sys.platform == "win32" else ["ip", "neigh", "show", ip]
    for line in _run(args, timeout=3).splitlines():
        ip_match = _IP_RE.search(line)
        mac_match = _MAC_RE.search(line)
        if ip_match and mac_match and ip_match.group(1) == ip:
            return normalize_mac(mac_match.group(1))
    return None


async def _local_macs() -> dict[str, str]:
    global _local_cache
    if _local_cache and time.monotonic() - _local_cache[0] < _LOCAL_TTL:
        return _local_cache[1]
    async with _local_lock:
        if _local_cache and time.monotonic() - _local_cache[0] < _LOCAL_TTL:
            return _local_cache[1]
        table = await asyncio.to_thread(_read_local_macs)
        _local_cache = (time.monotonic(), table)
        return table


def _read_local_macs() -> dict[str, str]:
    args = ["ipconfig", "/all"] if sys.platform == "win32" else ["ip", "addr"]
    table: dict[str, str] = {}
    current_mac: str | None = None
    for line in _run(args, timeout=5).splitlines():
        lower = line.lower()

        if sys.platform == "win32":
            if line[:1].strip() and line.rstrip().endswith(":"):
                current_mac = None
        elif re.match(r"^\d+:\s", line):
            current_mac = None

        if "physical address" in lower or "link/ether" in lower:
            mac_match = _MAC_RE.search(line)
            if mac_match:
                current_mac = normalize_mac(mac_match.group(1))
            continue

        is_ipv4_line = (
            "ipv4 address" in lower
            or "ip address" in lower
            or line.lstrip().startswith("inet ")
        )
        if current_mac and is_ipv4_line:
            ip_match = _IP_RE.search(line)
            if ip_match:
                table[ip_match.group(1)] = current_mac
    return table


def _run(args: list[str], timeout: float) -> str:
    kwargs: dict = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        out = subprocess.check_output(
            args, timeout=timeout, stderr=subprocess.DEVNULL, **kwargs
        )
        return out.decode(errors="ignore")
    except Exception:
        return ""
