from __future__ import annotations

from dataclasses import dataclass

from src.core.scan.models import Classification, Evidence, Probes, ScoreEntry

PLATFORMS = [
    "windows",
    "linux",
    "macos",
    "vmware_esxi",
    "snmp",
    "network_device",
    "iot",
    "printer",
    "wifi_ap",
    "mobile",
]


@dataclass(slots=True)
class Scoring:
    evidence: Evidence
    score_log: list[ScoreEntry]
    scores: dict[str, float]
    platform: str
    confidence: float
    os_hint: str | None
    hostname: str | None


def score(ip: str, probes: Probes) -> Scoring:
    scores: dict[str, float] = {platform: 0.0 for platform in PLATFORMS}
    score_log: list[ScoreEntry] = []
    evidence = Evidence()

    platform, confidence = _winner(scores)
    hostname = (
            probes.smb.computer_name
            or probes.netbios.computer_name
            or probes.mdns.hostname
    )
    os_hint = probes.smb.native_os
    return Scoring(evidence, score_log, scores, platform, confidence, os_hint, hostname)


def build_classification(
        ip: str, probes: Probes, scoring: Scoring, duration_ms: int
) -> Classification:
    reachable = probes.icmp.responded or bool(probes.tcp_ports.open)
    return Classification(
        ip=ip,
        platform=scoring.platform,
        confidence=scoring.confidence,
        os_hint=scoring.os_hint,
        hostname=scoring.hostname,
        reachable=reachable,
        duration_ms=duration_ms,
    )


def _winner(scores: dict[str, float]) -> tuple[str, float]:
    total = sum(scores.values())
    if total <= 0:
        return "unknown", 0.0
    top = max(scores, key=lambda platform: scores[platform])
    return top, round(scores[top] / total * 100, 1)
