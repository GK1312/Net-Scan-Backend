from __future__ import annotations

from src.config import PhaseTimeouts
from src.core.scan.context import ProbeContext
from src.core.scan.models import SmbResult
from src.core.scan.probes import smb


def _ctx() -> ProbeContext:
    return ProbeContext(ip="192.168.1.103", timeouts=PhaseTimeouts())


async def test_smb_retries_once_on_failed_connect(monkeypatch):
    calls = {"n": 0}

    async def fake_attempt(ip, connect_timeout, read_timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            return SmbResult()  # connect failed (probed=False) -> transient
        return SmbResult(probed=True, responded=True, native_os="Windows 8 / Server 2012")

    monkeypatch.setattr(smb, "_attempt", fake_attempt)
    result = await smb.run(_ctx())

    assert calls["n"] == 2  # retried after the failed connect
    assert result.responded
    assert result.native_os == "Windows 8 / Server 2012"


async def test_smb_does_not_retry_when_connected_but_no_smb2(monkeypatch):
    # SMB1-only host (XP/2003): connect succeeds, SMB2 negotiate ignored. This is
    # terminal -> do NOT retry (retrying would blow the per-probe time budget).
    calls = {"n": 0}

    async def fake_attempt(ip, connect_timeout, read_timeout):
        calls["n"] += 1
        return SmbResult(probed=True)  # connected, responded=False

    monkeypatch.setattr(smb, "_attempt", fake_attempt)
    result = await smb.run(_ctx())

    assert calls["n"] == 1  # connected once -> no retry
    assert result.probed
    assert not result.responded


async def test_smb_does_not_retry_after_success(monkeypatch):
    calls = {"n": 0}

    async def fake_attempt(ip, connect_timeout, read_timeout):
        calls["n"] += 1
        return SmbResult(probed=True, responded=True)

    monkeypatch.setattr(smb, "_attempt", fake_attempt)
    result = await smb.run(_ctx())

    assert calls["n"] == 1  # stopped on first success
    assert result.responded


async def test_smb_gives_up_after_max_attempts(monkeypatch):
    calls = {"n": 0}

    async def fake_attempt(ip, connect_timeout, read_timeout):
        calls["n"] += 1
        return SmbResult()  # never responds

    monkeypatch.setattr(smb, "_attempt", fake_attempt)
    result = await smb.run(_ctx())

    assert calls["n"] == smb.SMB_ATTEMPTS
    assert not result.responded
