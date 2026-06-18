from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.config import PhaseTimeouts
from src.core.scan import runner
from src.core.scan.context import ProbeContext
from src.core.scan.registry import PROBES


def _ctx(open_ports, reverse_dns=True):
    ctx = ProbeContext(ip="10.0.0.1", timeouts=PhaseTimeouts(), reverse_dns=reverse_dns)
    ctx.shared["open_ports"] = set(open_ports)
    return ctx


def test_probe_timeout_gives_smb_and_port_scan_more_budget():
    timeouts = PhaseTimeouts(
        ping_timeout=3.0, smb_timeout=4.0, port_scan_timeout=5.0
    )
    ctx = ProbeContext(ip="10.0.0.1", timeouts=timeouts)
    default = timeouts.ping_timeout

    # gated probes that get skipped when the port scan is cancelled must outlive
    # the generic per-probe cap
    assert runner._probe_timeout("smb", ctx, default) == 4.0 * runner.SMB_ATTEMPTS
    assert runner._probe_timeout("tcp_ports", ctx, default) == 5.0
    assert runner._probe_timeout("icmp", ctx, default) == default


async def test_recover_gate_ports_promotes_filtered_445(monkeypatch):
    from src.core.scan import runner as runner_mod
    from src.core.scan.models import TcpPortsResult

    # 445 (gate for smb) and 7547 (not a gate) both came back filtered.
    results = {
        "tcp_ports": TcpPortsResult(
            probed=[445, 5985, 7547], open=[5985], filtered=[445, 7547]
        )
    }

    async def fake_probe_ports(ctx, ports, timeout):
        assert set(ports) == {445}  # only gate ports get re-probed, not 7547
        return {445: "open"}

    monkeypatch.setattr(runner_mod, "probe_ports", fake_probe_ports)
    await runner_mod._recover_gate_ports(_ctx(set()), results)

    tcp = results["tcp_ports"]
    assert 445 in tcp.open  # recovered -> feeds gating + scoring
    assert 445 not in tcp.filtered
    assert 7547 in tcp.filtered  # non-gate port left alone


async def test_recover_gate_ports_noop_when_still_filtered(monkeypatch):
    from src.core.scan import runner as runner_mod
    from src.core.scan.models import TcpPortsResult

    results = {"tcp_ports": TcpPortsResult(probed=[445], open=[], filtered=[445])}

    async def fake_probe_ports(ctx, ports, timeout):
        return {445: "filtered"}

    monkeypatch.setattr(runner_mod, "probe_ports", fake_probe_ports)
    await runner_mod._recover_gate_ports(_ctx(set()), results)

    assert results["tcp_ports"].open == []
    assert results["tcp_ports"].filtered == [445]


def test_phase_grouping_covers_all_probes():
    all_ports = {22, 80, 443, 445, 1883, 554, 3389, 902, 631, 9100, 23, 8080, 8443}
    phase1 = set(runner._phase(1, set()))
    phase2 = set(runner._phase(2, all_ports))
    phase3 = set(runner._phase(3, all_ports))
    assert phase1 == {"icmp", "tcp_ports", "arp"}
    assert "snmp" in phase3 and "netbios" in phase3 and "mdns" in phase3
    assert phase1 | phase2 | phase3 == set(PROBES)


def test_gated_probe_skipped_when_port_closed():
    assert "smb" not in runner._phase(2, set())
    assert "smb" in runner._phase(2, {445})


def test_enrichment_includes_revdns_when_no_hostname():
    specs = runner._enrichment_specs(_ctx({22}), {}, SimpleNamespace(hostname=None))
    assert "revdns" in specs


def test_enrichment_skips_revdns_when_hostname_known():
    specs = runner._enrichment_specs(_ctx({22}), {}, SimpleNamespace(hostname="host1"))
    assert "revdns" not in specs


def test_enrichment_skips_revdns_when_disabled_or_already_run():
    disabled = runner._enrichment_specs(
        _ctx({22}, reverse_dns=False), {}, SimpleNamespace(hostname=None)
    )
    assert "revdns" not in disabled

    already = runner._enrichment_specs(
        _ctx({22}), {"revdns": object()}, SimpleNamespace(hostname=None)
    )
    assert "revdns" not in already


@pytest.mark.asyncio
async def test_scan_unreachable_host_short_circuits():
    doc = await runner.scan_ip("192.0.2.1")
    assert doc["classification"]["platform"] == "unreachable"
    assert doc["classification"]["reachable"] is False
    assert len(doc["probes"]) == 18
