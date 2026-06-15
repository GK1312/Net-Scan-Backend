from __future__ import annotations

import asyncio
import time

from pydantic import BaseModel

from src.config import Settings, get_settings
from src.core.scan.context import ProbeContext
from src.core.scan.models import Probes, ScanResult
from src.core.scan.registry import PROBES, ProbeSpec
from src.core.scan.scoring import build_classification, score


async def scan_ip(ip: str, settings: Settings | None = None) -> dict:
    settings = settings or get_settings()
    ctx = ProbeContext(ip=ip, timeouts=settings.timeouts)

    start = time.perf_counter()
    probe_results = await _run_probes(ctx)
    probes = Probes(**probe_results)
    scoring = score(ip, probes)
    duration_ms = int((time.perf_counter() - start) * 1000)

    result = ScanResult(
        classification=build_classification(ip, probes, scoring, duration_ms),
        probes=probes,
        evidence=scoring.evidence,
        score_log=scoring.score_log,
        scores=scoring.scores,
    )
    return result.model_dump(by_alias=True)


async def _run_probes(ctx: ProbeContext) -> dict[str, BaseModel]:
    """Two-phase, port-gated execution:

    Phase 1 runs the ungated probes (discovery + UDP services), including the TCP
    port scan. Phase 2 then runs each TCP service probe only if one of its gate
    ports is open — so smb/http/ssh/etc. never connect to a closed port. Skipped
    probes are simply absent from the result; `Probes` fills their default.
    """
    timeout = ctx.timeouts.ping_timeout
    results: dict[str, BaseModel] = {}

    ungated = {n: s for n, s in PROBES.items() if not s.gate_ports}
    results.update(await _gather(ungated, ctx, timeout))

    tcp = results.get("tcp_ports")
    open_ports = set(tcp.open) if tcp is not None else set()
    gated = {
        n: s
        for n, s in PROBES.items()
        if s.gate_ports and (s.gate_ports & open_ports)
    }
    results.update(await _gather(gated, ctx, timeout))
    return results


async def _gather(
    specs: dict[str, ProbeSpec], ctx: ProbeContext, timeout: float
) -> dict[str, BaseModel]:
    """Run a set of probes concurrently with per-probe timeout + error isolation."""

    async def run_one(name: str, spec: ProbeSpec) -> tuple[str, BaseModel | None]:
        try:
            return name, await asyncio.wait_for(spec.run(ctx), timeout=timeout)
        except Exception:
            return name, None

    pairs = await asyncio.gather(*(run_one(n, s) for n, s in specs.items()))
    return {name: res for name, res in pairs if res is not None}
