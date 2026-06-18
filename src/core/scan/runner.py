from __future__ import annotations

import asyncio
import time

from pydantic import BaseModel

from src.config import Settings, get_settings
from src.core.scan.context import ProbeContext
from src.core.scan.models import Probes, ScanResult
from src.core.scan.probes.smb import SMB_ATTEMPTS
from src.core.scan.probes.tcp_ports import probe_ports
from src.core.scan.registry import PROBES, ProbeSpec
from src.core.scan.scoring import Scoring, build_classification, score

_GATE_PORTS: frozenset[int] = frozenset().union(
    *(spec.gate_ports for spec in PROBES.values())
)


async def scan_ip(
        ip: str,
        settings: Settings | None = None,
        conn_limit: asyncio.Semaphore | None = None,
) -> dict:
    settings = settings or get_settings()
    ctx = ProbeContext(
        ip=ip,
        timeouts=settings.timeouts,
        reverse_dns=settings.worker.enable_reverse_dns,
        conn_limit=conn_limit,
    )
    threshold = settings.security.short_circuit_confidence
    timeout = ctx.timeouts.ping_timeout
    start = time.perf_counter()

    results: dict[str, BaseModel] = {}

    results.update(await _gather(_phase(1, set()), ctx, timeout))
    tcp = results.get("tcp_ports")
    open_ports = set(tcp.open) if tcp is not None else set()
    ctx.shared["open_ports"] = open_ports

    if _unreachable(results, open_ports):
        return _finish(ip, results, start, unreachable=True)

    if open_ports:
        await _recover_gate_ports(ctx, results)
        open_ports = set(tcp.open) if tcp is not None else set()
        ctx.shared["open_ports"] = open_ports

    scoring = score(ip, Probes(**results))
    if scoring.confidence >= threshold:
        results.update(await _enrich(ctx, results, scoring, timeout))
        return _finish(ip, results, start)

    results.update(await _gather(_phase(2, open_ports), ctx, timeout))
    scoring = score(ip, Probes(**results))
    if scoring.confidence >= threshold:
        results.update(await _enrich(ctx, results, scoring, timeout))
        return _finish(ip, results, start)

    results.update(await _gather(_phase(3, open_ports), ctx, timeout))
    return _finish(ip, results, start)


def _phase(phase: int, open_ports: set[int]) -> dict[str, ProbeSpec]:
    return {
        name: spec
        for name, spec in PROBES.items()
        if spec.phase == phase and (not spec.gate_ports or spec.gate_ports & open_ports)
    }


async def _recover_gate_ports(ctx: ProbeContext, results: dict[str, BaseModel]) -> None:
    tcp = results.get("tcp_ports")
    if tcp is None:
        return
    candidates = sorted(set(tcp.filtered) & _GATE_PORTS)
    if not candidates:
        return
    states = await probe_ports(ctx, candidates, ctx.timeouts.tcp_connect_timeout)
    recovered = [port for port in candidates if states[port] == "open"]
    if not recovered:
        return
    for port in recovered:
        tcp.filtered.remove(port)
        tcp.open.append(port)
    tcp.open.sort()


def _unreachable(results: dict[str, BaseModel], open_ports: set[int]) -> bool:
    icmp = results.get("icmp")
    arp = results.get("arp")
    icmp_up = bool(icmp and icmp.responded)
    has_mac = bool(arp and arp.mac)
    return not icmp_up and not open_ports and not has_mac


async def _enrich(
        ctx: ProbeContext,
        results: dict[str, BaseModel],
        scoring: Scoring,
        timeout: float,
) -> dict[str, BaseModel]:
    pending = _enrichment_specs(ctx, results, scoring)
    if not pending:
        return {}
    return await _gather(pending, ctx, timeout)


def _enrichment_specs(
        ctx: ProbeContext, results: dict[str, BaseModel], scoring: Scoring
) -> dict[str, ProbeSpec]:
    open_ports: set[int] = ctx.shared.get("open_ports", set())
    pending: dict[str, ProbeSpec] = {}

    if 445 in open_ports and "smb" not in results:
        pending["smb"] = PROBES["smb"]

    netbios = results.get("netbios")
    if open_ports and not scoring.hostname and not (netbios and netbios.responded):
        pending["netbios"] = PROBES["netbios"]

    mdns = results.get("mdns")
    if not scoring.hostname and not (mdns and mdns.hostname):
        pending["mdns"] = PROBES["mdns"]

    if ctx.reverse_dns and not scoring.hostname and "revdns" not in results:
        pending["revdns"] = PROBES["revdns"]

    return pending


def _finish(
        ip: str,
        results: dict[str, BaseModel],
        start: float,
        unreachable: bool = False,
) -> dict:
    probes = Probes(**results)
    scoring = score(ip, probes)
    duration_ms = int((time.perf_counter() - start) * 1000)

    classification = build_classification(ip, probes, scoring, duration_ms)
    if unreachable:
        classification.platform = "unreachable"
        classification.reachable = False

    result = ScanResult(
        classification=classification,
        probes=probes,
        evidence=scoring.evidence,
        score_log=scoring.score_log,
        scores=scoring.scores,
    )
    return result.model_dump(by_alias=True)


async def _gather(
        specs: dict[str, ProbeSpec], ctx: ProbeContext, timeout: float
) -> dict[str, BaseModel]:
    async def run_one(name: str, spec: ProbeSpec) -> tuple[str, BaseModel | None]:
        try:
            budget = _probe_timeout(name, ctx, timeout)
            return name, await asyncio.wait_for(spec.run(ctx), timeout=budget)
        except Exception:
            return name, None

    pairs = await asyncio.gather(*(run_one(n, s) for n, s in specs.items()))
    return {name: res for name, res in pairs if res is not None}


def _probe_timeout(name: str, ctx: ProbeContext, default: float) -> float:
    if name == "smb":
        return max(default, ctx.timeouts.smb_timeout * SMB_ATTEMPTS)
    
    if name == "tcp_ports":
        return max(default, ctx.timeouts.port_scan_timeout)
    return default
