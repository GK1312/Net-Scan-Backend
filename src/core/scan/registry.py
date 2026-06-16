from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable

from pydantic import BaseModel

from src.core.scan.constants import (
    GATE_SMB, GATE_SSH, GATE_TLS, GATE_HTTP, GATE_UPNP,
    GATE_RDP, GATE_VMWARE_AUTHD, GATE_MQTT, GATE_IPP, GATE_RTSP, GATE_TELNET,
)
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
    "smb": ProbeSpec(smb.run, GATE_SMB),
    "ssh": ProbeSpec(ssh.run, GATE_SSH),
    "tls_443": ProbeSpec(tls_443.run, GATE_TLS),
    "http": ProbeSpec(http.run, GATE_HTTP),
    "upnp": ProbeSpec(upnp.run, GATE_UPNP),
    "rdp": ProbeSpec(rdp.run, GATE_RDP),
    "vmware_authd": ProbeSpec(vmware_authd.run, GATE_VMWARE_AUTHD),
    "mqtt": ProbeSpec(mqtt.run, GATE_MQTT),
    "ipp": ProbeSpec(ipp.run, GATE_IPP),
    "rtsp": ProbeSpec(rtsp.run, GATE_RTSP),
    "telnet": ProbeSpec(telnet.run, GATE_TELNET),
}
