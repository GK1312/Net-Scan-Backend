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
    gate_ports: frozenset[int] = frozenset()


PROBES: dict[str, ProbeSpec] = {
    "icmp": ProbeSpec(icmp.run),
    "tcp_ports": ProbeSpec(tcp_ports.run),
    "arp": ProbeSpec(arp.run),
    "snmp": ProbeSpec(snmp.run),
    "netbios": ProbeSpec(netbios.run),
    "mdns": ProbeSpec(mdns.run),
    "smb": ProbeSpec(smb.run, frozenset({445})),
    "ssh": ProbeSpec(ssh.run, frozenset({22})),
    "tls_443": ProbeSpec(tls_443.run, frozenset({443})),
    "http": ProbeSpec(http.run, frozenset({80, 443, 8080, 8443})),
    "upnp": ProbeSpec(upnp.run, frozenset({80, 443, 8080, 8443})),
    "rdp": ProbeSpec(rdp.run, frozenset({3389})),
    "vmware_authd": ProbeSpec(vmware_authd.run, frozenset({902})),
    "mqtt": ProbeSpec(mqtt.run, frozenset({1883})),
    "ipp": ProbeSpec(ipp.run, frozenset({631, 9100})),
    "rtsp": ProbeSpec(rtsp.run, frozenset({554})),
    "telnet": ProbeSpec(telnet.run, frozenset({23})),
}
