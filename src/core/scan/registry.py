from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable

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
    # TCP ports that gate this probe: it runs only if at least one is open (per the
    # tcp_ports scan). Empty = always run — discovery probes and UDP-based services,
    # whose ports a TCP connect scan can't observe.
    gate_ports: frozenset[int] = frozenset()


PROBES: dict[str, ProbeSpec] = {
    # --- always run: discovery + UDP services ---
    "icmp": ProbeSpec(icmp.run),
    "tcp_ports": ProbeSpec(tcp_ports.run),
    "arp": ProbeSpec(arp.run),
    "snmp": ProbeSpec(snmp.run),      # UDP 161
    "netbios": ProbeSpec(netbios.run),  # UDP 137
    "mdns": ProbeSpec(mdns.run),      # UDP 5353
    "upnp": ProbeSpec(upnp.run),      # UDP 1900
    # --- TCP service probes, gated on their port(s) being open ---
    "smb": ProbeSpec(smb.run, frozenset({445})),
    "ssh": ProbeSpec(ssh.run, frozenset({22})),
    "tls_443": ProbeSpec(tls_443.run, frozenset({443, 8443})),
    "http": ProbeSpec(http.run, frozenset({80, 8080})),
    "rdp": ProbeSpec(rdp.run, frozenset({3389})),
    "vmware_authd": ProbeSpec(vmware_authd.run, frozenset({902})),
    "mqtt": ProbeSpec(mqtt.run, frozenset({1883})),
    "ipp": ProbeSpec(ipp.run, frozenset({631})),
    "rtsp": ProbeSpec(rtsp.run, frozenset({554})),
    "telnet": ProbeSpec(telnet.run, frozenset({23})),
}
