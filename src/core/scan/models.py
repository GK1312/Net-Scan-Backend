from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IcmpResult(BaseModel):
    responded: bool = False
    ttl_received: int | None = None
    ttl_estimated: int | None = None
    rtt_ms: float | None = None


class TcpPortsResult(BaseModel):
    probed: list[int] = Field(default_factory=list)
    open: list[int] = Field(default_factory=list)
    filtered: list[int] = Field(default_factory=list)
    closed: list[int] = Field(default_factory=list)


class SmbResult(BaseModel):
    probed: bool = False
    responded: bool = False
    dialect: str | None = None
    os_version: str | None = None
    native_os: str | None = None
    computer_name: str | None = None
    domain: str | None = None
    server_guid: str | None = None
    is_samba: bool | None = None


class SshResult(BaseModel):
    responded: bool = False
    banner: str | None = None


class Tls443Result(BaseModel):
    responded: bool = False
    subject: str | None = None
    issuer: str | None = None
    san: list[str] = Field(default_factory=list)
    ja3: str | None = None


class HttpResult(BaseModel):
    responded: bool = False
    server: str | None = None
    title: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)


class SnmpResult(BaseModel):
    responded: bool = False
    sys_descr: str | None = None
    sys_name: str | None = None
    sys_object_id: str | None = None


class NetbiosResult(BaseModel):
    responded: bool = False
    computer_name: str | None = None
    domain: str | None = None
    mac: str | None = None


class RdpResult(BaseModel):
    responded: bool = False


class VmwareAuthdResult(BaseModel):
    responded: bool = False
    banner: str | None = None


class MdnsResult(BaseModel):
    responded: bool = False
    services: list[str] = Field(default_factory=list)
    hostname: str | None = None


class UpnpResult(BaseModel):
    responded: bool = False
    friendly_name: str | None = None
    manufacturer: str | None = None
    model_name: str | None = None
    location: str | None = None


class MqttResult(BaseModel):
    responded: bool = False


class IppResult(BaseModel):
    responded: bool = False
    printer_name: str | None = None
    make_model: str | None = None


class RtspResult(BaseModel):
    responded: bool = False
    banner: str | None = None


class ArpResult(BaseModel):
    mac: str | None = None
    manufacturer: str | None = None
    platform_hint: str | None = None
    randomized: bool | None = None


class TelnetResult(BaseModel):
    responded: bool = False
    banner: str | None = None


class RevDnsResult(BaseModel):
    hostname: str | None = None


class Probes(BaseModel):
    icmp: IcmpResult = Field(default_factory=IcmpResult)
    tcp_ports: TcpPortsResult = Field(default_factory=TcpPortsResult)
    smb: SmbResult = Field(default_factory=SmbResult)
    ssh: SshResult = Field(default_factory=SshResult)
    tls_443: Tls443Result = Field(default_factory=Tls443Result)
    http: HttpResult = Field(default_factory=HttpResult)
    snmp: SnmpResult = Field(default_factory=SnmpResult)
    netbios: NetbiosResult = Field(default_factory=NetbiosResult)
    rdp: RdpResult = Field(default_factory=RdpResult)
    vmware_authd: VmwareAuthdResult = Field(default_factory=VmwareAuthdResult)
    mdns: MdnsResult = Field(default_factory=MdnsResult)
    upnp: UpnpResult = Field(default_factory=UpnpResult)
    mqtt: MqttResult = Field(default_factory=MqttResult)
    ipp: IppResult = Field(default_factory=IppResult)
    rtsp: RtspResult = Field(default_factory=RtspResult)
    arp: ArpResult = Field(default_factory=ArpResult)
    telnet: TelnetResult = Field(default_factory=TelnetResult)
    revdns: RevDnsResult = Field(default_factory=RevDnsResult)


class Classification(BaseModel):
    ip: str
    platform: str = "unknown"
    confidence: float = 0
    os_hint: str | None = None
    hostname: str | None = None
    reachable: bool = False
    duration_ms: int = 0
    error: str | None = None


class Evidence(BaseModel):
    ttl_rule: dict[str, Any] = Field(default_factory=dict)
    port_rule: dict[str, Any] = Field(default_factory=dict)
    banner_rule: dict[str, Any] = Field(default_factory=dict)
    service_rule: dict[str, Any] = Field(default_factory=dict)
    os_rule: dict[str, Any] = Field(default_factory=dict)
    conflict_resolution: Any | None = None


class ScoreEntry(BaseModel):
    platform: str
    delta: float
    total: float
    signal: str
    reason: str
    value: str


class ScanResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    classification: Classification
    probes: Probes
    evidence: Evidence
    score_log: list[ScoreEntry] = Field(default_factory=list, alias="_score_log")
    scores: dict[str, float] = Field(default_factory=dict, alias="_scores")
