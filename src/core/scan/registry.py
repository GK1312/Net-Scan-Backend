from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from pydantic import BaseModel

from src.core.scan.context import ProbeContext
from src.core.scan.probes import (
    arp,
    http,
    icmp,
    ipp,
    mdns,
    mqtt,
    netbios,
    rdp,
    revdns,
    rtsp,
    smb,
    snmp,
    ssh,
    tcp_ports,
    telnet,
    tls_443,
    upnp,
    vmware_authd,
)

ProbeFn = Callable[[ProbeContext], Awaitable[BaseModel]]


@dataclass(frozen=True)
class ProbeSpec:
    run: ProbeFn
    gate_ports: frozenset[int] = frozenset()
    phase: int = 1


PROBES: dict[str, ProbeSpec] = {
    "icmp": ProbeSpec(icmp.run, phase=1),
    "tcp_ports": ProbeSpec(tcp_ports.run, phase=1),
    "arp": ProbeSpec(arp.run, phase=1),
    "smb": ProbeSpec(smb.run, frozenset({445}), phase=2),
    "ssh": ProbeSpec(ssh.run, frozenset({22}), phase=2),
    "tls_443": ProbeSpec(tls_443.run, frozenset({443}), phase=2),
    "http": ProbeSpec(http.run, frozenset({80, 443, 8080, 8443}), phase=2),
    "upnp": ProbeSpec(upnp.run, frozenset({80, 443, 8080, 8443}), phase=2),
    "mqtt": ProbeSpec(mqtt.run, frozenset({1883}), phase=2),
    "rtsp": ProbeSpec(rtsp.run, frozenset({554}), phase=2),
    "snmp": ProbeSpec(snmp.run, phase=3),
    "netbios": ProbeSpec(netbios.run, phase=3),
    "mdns": ProbeSpec(mdns.run, phase=3),
    "rdp": ProbeSpec(rdp.run, frozenset({3389}), phase=3),
    "vmware_authd": ProbeSpec(vmware_authd.run, frozenset({902}), phase=3),
    "ipp": ProbeSpec(ipp.run, frozenset({631, 9100}), phase=3),
    "telnet": ProbeSpec(telnet.run, frozenset({23}), phase=3),
    "revdns": ProbeSpec(revdns.run, phase=3),
}
