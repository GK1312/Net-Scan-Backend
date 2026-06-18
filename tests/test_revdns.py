from __future__ import annotations

import socket

import pytest

from src.config import PhaseTimeouts
from src.core.scan.context import ProbeContext
from src.core.scan.probes import revdns


def _ctx(reverse_dns: bool = True) -> ProbeContext:
    return ProbeContext(
        ip="192.168.1.117", timeouts=PhaseTimeouts(), reverse_dns=reverse_dns
    )


@pytest.mark.asyncio
async def test_resolves_ptr_hostname(monkeypatch):
    monkeypatch.setattr(
        socket, "gethostbyaddr", lambda ip: ("web01.example.com.", [], [ip])
    )
    result = await revdns.run(_ctx())
    assert result.hostname == "web01.example.com"


@pytest.mark.asyncio
async def test_no_ptr_record_returns_none(monkeypatch):
    def _raise(ip):
        raise socket.herror(1, "Unknown host")

    monkeypatch.setattr(socket, "gethostbyaddr", _raise)
    assert (await revdns.run(_ctx())).hostname is None


@pytest.mark.asyncio
async def test_ptr_echoing_ip_is_dropped(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: (ip, [], [ip]))
    assert (await revdns.run(_ctx())).hostname is None


@pytest.mark.asyncio
async def test_disabled_skips_lookup(monkeypatch):
    def _boom(ip):
        raise AssertionError("resolver must not be called when disabled")

    monkeypatch.setattr(socket, "gethostbyaddr", _boom)
    assert (await revdns.run(_ctx(reverse_dns=False))).hostname is None
