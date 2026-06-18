from __future__ import annotations

import re
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

_PORT_VOTES: dict[int, tuple[str, float]] = {
    135: ("windows", 1.5),
    139: ("windows", 1.5),
    445: ("windows", 2.0),
    3389: ("windows", 2.5),
    5985: ("windows", 1.5),
    22: ("linux", 1.5),
    548: ("macos", 2.0),
    9100: ("printer", 3.0),
    631: ("printer", 2.5),
    554: ("iot", 2.0),
    1883: ("iot", 2.0),
    902: ("vmware_esxi", 3.0),
    161: ("network_device", 1.0),
    7547: ("network_device", 1.5),
}

_CONFIDENCE_SATURATION_SCORE = 5.0

_DEFINITIVE_CONFIDENCE = 90.0

_TLS_VENDOR_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("vmware", "vmware_esxi"),
    ("esxi", "vmware_esxi"),
    ("laserjet", "printer"),
    ("officejet", "printer"),
    ("brother", "printer"),
    ("epson", "printer"),
    ("canon", "printer"),
    ("kyocera", "printer"),
    ("lexmark", "printer"),
    ("cisco", "network_device"),
    ("mikrotik", "network_device"),
    ("fortinet", "network_device"),
    ("fortigate", "network_device"),
    ("sonicwall", "network_device"),
    ("ubiquiti", "wifi_ap"),
    ("unifi", "wifi_ap"),
)

_UPNP_VENDOR_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("netgear", "wifi_ap"),
    ("tp-link", "wifi_ap"),
    ("tplink", "wifi_ap"),
    ("asus", "wifi_ap"),
    ("linksys", "wifi_ap"),
    ("d-link", "wifi_ap"),
    ("dlink", "wifi_ap"),
    ("ubiquiti", "wifi_ap"),
    ("unifi", "wifi_ap"),
    ("mikrotik", "wifi_ap"),
    ("edgerouter", "wifi_ap"),
    ("aruba", "wifi_ap"),
    ("ruckus", "wifi_ap"),
    ("meraki", "wifi_ap"),
    ("fritz", "wifi_ap"),
    ("synology", "linux"),
    ("qnap", "linux"),
    ("hikvision", "iot"),
    ("dahua", "iot"),
    ("axis", "iot"),
    ("sonos", "iot"),
    ("roku", "iot"),
    ("chromecast", "iot"),
    ("samsung", "iot"),
    ("philips hue", "iot"),
    ("ring", "iot"),
    ("nest", "iot"),
    ("ecobee", "iot"),
    ("wemo", "iot"),
    ("belkin", "iot"),
    ("xiaomi", "iot"),
    ("tuya", "iot"),
    ("shelly", "iot"),
    ("tasmota", "iot"),
    ("brother", "printer"),
    ("epson", "printer"),
    ("canon", "printer"),
    ("hewlett", "printer"),
)

_HTTP_SERVER_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("openwrt", "wifi_ap"),
    ("dd-wrt", "wifi_ap"),
    ("tomato", "wifi_ap"),
    ("ubnt", "wifi_ap"),
    ("edgeos", "wifi_ap"),
    ("airos", "wifi_ap"),
    ("routeros", "wifi_ap"),
    ("mikrotik", "wifi_ap"),
    ("miniupnpd", "wifi_ap"),
    ("jcow", "wifi_ap"),
    ("juicejfv", "wifi_ap"),
    ("hikvision", "iot"),
    ("dahua", "iot"),
    ("axis", "iot"),
    ("amcrest", "iot"),
    ("reolink", "iot"),
    ("foscam", "iot"),
    ("vivotek", "iot"),
    ("hanwha", "iot"),
    ("lexmark", "printer"),
    ("ricoh", "printer"),
    ("kyocera", "printer"),
    ("xerox", "printer"),
    ("virata", "printer"),
    ("kojiro", "printer"),
    ("hp-chaiseri", "printer"),
)

_HTTP_TITLE_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("camera", "iot"),
    ("ip cam", "iot"),
    ("dvr", "iot"),
    ("nvr", "iot"),
    ("surveillance", "iot"),
    ("smart home", "iot"),
    ("philips hue", "iot"),
    ("sonos", "iot"),
    ("tuya", "iot"),
    ("homebridge", "iot"),
    ("access point", "wifi_ap"),
    ("router", "wifi_ap"),
    ("gateway", "wifi_ap"),
    ("modem", "wifi_ap"),
    ("tp-link", "wifi_ap"),
    ("netgear", "wifi_ap"),
    ("d-link", "wifi_ap"),
    ("linksys", "wifi_ap"),
    ("unifi", "wifi_ap"),
    ("edgerouter", "wifi_ap"),
    ("laserjet", "printer"),
    ("officejet", "printer"),
    ("print server", "printer"),
    ("printer", "printer"),
    ("epson", "printer"),
    ("canon", "printer"),
    ("brother", "printer"),
    ("xerox", "printer"),
    ("lexmark", "printer"),
)

_DEVICE_IDENTITY: tuple[tuple[str, str, str], ...] = (
    ("rilselfcert", "wifi_ap", "Jio ISP Gateway"),
    ("reliance", "wifi_ap", "Jio ISP Gateway"),
    ("jio", "wifi_ap", "Jio ISP Gateway"),
)

_PLATFORM_OS_HINT: dict[str, str] = {
    "windows": "Windows",
    "linux": "Linux/Unix",
    "macos": "macOS",
    "vmware_esxi": "VMware ESXi",
    "network_device": "Network device",
    "printer": "Printer",
    "wifi_ap": "Wi-Fi access point",
    "iot": "IoT device",
    "mobile": "Android / iOS device",
}

_OPENSSH_RE = re.compile(r"openssh(?:_for_\w+)?[_-](\d+\.\d+)", re.IGNORECASE)

_UBUNTU_VERSIONS: dict[str, str] = {
    "6.6": "Ubuntu 14.04 LTS",
    "7.2": "Ubuntu 16.04 LTS",
    "7.6": "Ubuntu 18.04 LTS",
    "8.2": "Ubuntu 20.04 LTS",
    "8.9": "Ubuntu 22.04 LTS",
    "9.6": "Ubuntu 24.04 LTS",
    "9.7": "Ubuntu 24.10",
    "9.9": "Ubuntu 25.04",
    "10.0": "Ubuntu 25.04",
}

_DEBIAN_VERSIONS: dict[str, str] = {
    "6.7": "Debian 8 (jessie)",
    "7.4": "Debian 9 (stretch)",
    "7.9": "Debian 10 (buster)",
    "8.4": "Debian 11 (bullseye)",
    "9.2": "Debian 12 (bookworm)",
    "9.9": "Debian 13 (trixie)",
}

_FEDORA_VERSIONS: dict[str, str] = {
    "8.8": "Fedora 35",
    "9.0": "Fedora 36/37",
    "9.3": "Fedora 38/39",
    "9.6": "Fedora 40",
    "9.9": "Fedora 41+",
}

_SSH_OS_TOKENS: tuple[tuple[str, str, dict[str, str]], ...] = (
    ("for_windows", "Windows (OpenSSH)", {}),
    ("windows", "Windows (OpenSSH)", {}),
    ("ubuntu", "Ubuntu Linux", _UBUNTU_VERSIONS),
    ("debian", "Debian Linux", _DEBIAN_VERSIONS),
    ("fedora", "Fedora Linux", _FEDORA_VERSIONS),
    ("rocky", "Rocky Linux", {}),
    ("almalinux", "AlmaLinux", {}),
    ("centos", "CentOS", {}),
    ("redhat", "Red Hat Enterprise Linux", {}),
    ("rhel", "Red Hat Enterprise Linux", {}),
    ("raspbian", "Raspberry Pi OS", {}),
    ("amzn", "Amazon Linux", {}),
    ("amazon", "Amazon Linux", {}),
    ("oracle", "Oracle Linux", {}),
    ("sles", "SUSE Linux Enterprise", {}),
    ("suse", "SUSE Linux", {}),
    ("gentoo", "Gentoo Linux", {}),
    ("arch", "Arch Linux", {}),
    ("alpine", "Alpine Linux", {}),
    ("freebsd", "FreeBSD", {}),
    ("openbsd", "OpenBSD", {}),
    ("netbsd", "NetBSD", {}),
    ("dragonfly", "DragonFly BSD", {}),
    ("sun_ssh", "Oracle Solaris", {}),
    ("dropbear", "Embedded Linux (Dropbear)", {}),
    ("cisco", "Cisco network OS", {}),
    ("mikrotik", "MikroTik RouterOS", {}),
    ("rosssh", "MikroTik RouterOS", {}),
)

_BARE_OPENSSH_OS: dict[str, str] = {
    "6.6": "RHEL / CentOS 6",
    "7.4": "RHEL / CentOS / Oracle / Rocky / Alma 7",
    "8.0": "RHEL / AlmaLinux / Rocky / Oracle / CentOS 8",
    "8.7": "RHEL / AlmaLinux / Rocky / Oracle 9",
    "9.9": "RHEL / AlmaLinux / Rocky / Oracle 10",
}

_SNMP_ENTERPRISE: dict[str, str] = {
    "9": "network_device",
    "2636": "network_device",
    "14988": "network_device",
    "12356": "network_device",
    "2435": "printer",
    "1248": "printer",
    "1602": "printer",
    "367": "printer",
    "641": "printer",
    "8072": "linux",
    "311": "windows",
    "6876": "vmware_esxi",
}


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
    scores: dict[str, float] = dict.fromkeys(PLATFORMS, 0.0)
    log: list[ScoreEntry] = []
    evidence = Evidence()
    ttl_hint = _score_ttl(probes, scores, log, evidence)
    _score_ports(probes, scores, log, evidence)
    _score_banners(probes, scores, log, evidence)
    smb_hint = _score_services(probes, scores, log, evidence)
    _score_oui(probes, scores, log, evidence)

    identity = _match_device_identity(probes)
    if identity:
        _add(scores, log, identity[0], 3.0, "identity", "device fingerprint", identity[1])

    platform, confidence, share, saturation = _winner(scores)
    if _has_definitive_signal(probes, platform):
        confidence = max(confidence, _DEFINITIVE_CONFIDENCE)
    _resolve_conflicts(scores, platform, confidence, share, saturation, evidence)

    os_hint = _resolve_os_hint(probes, platform, smb_hint, ttl_hint, identity)

    hostname = (
            (probes.smb.computer_name or None)
            or (probes.netbios.computer_name or None)
            or (probes.mdns.hostname or None)
            or (probes.snmp.sys_name or None)
            or (probes.revdns.hostname or None)
    )
    return Scoring(evidence, log, scores, platform, confidence, os_hint, hostname)


def build_classification(
        ip: str, probes: Probes, scoring: Scoring, duration_ms: int
) -> Classification:
    reachable = (
            probes.icmp.responded
            or bool(probes.tcp_ports.open)
            or probes.arp.mac is not None
    )
    return Classification(
        ip=ip,
        platform=scoring.platform,
        confidence=scoring.confidence,
        os_hint=scoring.os_hint,
        hostname=scoring.hostname,
        reachable=reachable,
        duration_ms=duration_ms,
    )


def _add(
        scores: dict[str, float],
        log: list[ScoreEntry],
        platform: str,
        delta: float,
        signal: str,
        reason: str,
        value: object,
) -> None:
    scores[platform] += delta
    log.append(
        ScoreEntry(
            platform=platform,
            delta=delta,
            total=scores[platform],
            signal=signal,
            reason=reason,
            value=str(value),
        )
    )


def _score_ttl(probes, scores, log, evidence) -> str | None:
    icmp = probes.icmp
    if not icmp.responded or icmp.ttl_estimated is None:
        return None
    ttl = icmp.ttl_estimated
    inference: str | None = None
    os_hint: str | None = None
    if ttl == 128:
        _add(scores, log, "windows", 1.5, "ttl", "initial TTL 128", ttl)
        inference, os_hint = "windows", "Windows"
    elif ttl == 64:
        if probes.arp.randomized:
            _add(scores, log, "mobile", 4.0, "ttl", "randomized MAC + TTL 64", ttl)
            inference = "mobile (randomized MAC)"
        else:
            _add(scores, log, "linux", 1.0, "ttl", "initial TTL 64", ttl)
            _add(scores, log, "macos", 0.5, "ttl", "initial TTL 64", ttl)
            _add(scores, log, "iot", 0.5, "ttl", "initial TTL 64", ttl)
            inference, os_hint = "unix-like", "Linux/Unix"
    elif ttl == 255:
        _add(scores, log, "network_device", 1.5, "ttl", "initial TTL 255", ttl)
        inference, os_hint = "network device", "Network device"
    elif ttl == 32:
        _add(scores, log, "windows", 0.5, "ttl", "initial TTL 32 (legacy)", ttl)
        inference = "legacy windows"
    evidence.ttl_rule = {
        "received": icmp.ttl_received,
        "estimated": ttl,
        "inference": inference,
    }
    return os_hint


def _score_ports(probes, scores, log, evidence) -> None:
    open_ports = probes.tcp_ports.open
    matched: dict[str, float] = {}
    for port in open_ports:
        vote = _PORT_VOTES.get(port)
        if vote is None:
            continue
        platform, weight = vote
        _add(scores, log, platform, weight, "port", f"tcp/{port} open", port)
        matched[str(port)] = weight
    evidence.port_rule = {"open": list(open_ports), "matched": matched}


def _score_banners(probes, scores, log, evidence) -> None:
    rule: dict[str, str] = {}

    if probes.ssh.responded and probes.ssh.banner:
        banner = probes.ssh.banner.lower()
        rule["ssh"] = probes.ssh.banner
        if "ubuntu" in banner or "debian" in banner or "openssh" in banner:
            _add(scores, log, "linux", 1.5, "banner", "ssh banner", probes.ssh.banner)
        if "dropbear" in banner:
            _add(scores, log, "iot", 1.0, "banner", "dropbear ssh", probes.ssh.banner)
        if "cisco" in banner:
            _add(
                scores,
                log,
                "network_device",
                2.0,
                "banner",
                "cisco ssh",
                probes.ssh.banner,
            )

    if probes.telnet.responded and probes.telnet.banner:
        banner = probes.telnet.banner.lower()
        rule["telnet"] = probes.telnet.banner
        nd_keys = (
            "cisco", "juniper", "junos", "mikrotik", "routeros", "huawei",
            "fortinet", "palo alto", "aruba", "procurve", "extreme",
            "edgerouter", "router", "switch", "firewall",
        )
        iot_keys = ("busybox", "openwrt", "dd-wrt", "buildroot", "dropbear", "embedded")
        if any(k in banner for k in nd_keys):
            _add(scores, log, "network_device", 2.0, "banner", "telnet network kw",
                 probes.telnet.banner)
        elif any(k in banner for k in iot_keys):
            _add(scores, log, "iot", 1.5, "banner", "telnet iot kw", probes.telnet.banner)
        else:
            _add(scores, log, "network_device", 1.0, "banner", "telnet generic",
                 probes.telnet.banner)

    if probes.rtsp.responded:
        rule["rtsp"] = probes.rtsp.banner or "responded"
        _add(scores, log, "iot", 2.0, "banner", "rtsp service (camera)", rule["rtsp"])

    if probes.vmware_authd.responded:
        rule["vmware_authd"] = probes.vmware_authd.banner or "responded"
        _add(
            scores,
            log,
            "vmware_esxi",
            3.0,
            "banner",
            "vmware authd",
            rule["vmware_authd"],
        )

    evidence.banner_rule = rule


def _score_services(probes, scores, log, evidence) -> str | None:
    rule: dict[str, str] = {}
    os_hint: str | None = None

    smb = probes.smb
    if smb.responded:
        rule["smb"] = smb.native_os or smb.dialect or "responded"
        if smb.is_samba:
            _add(scores, log, "linux", 2.0, "service", "samba (smb)", rule["smb"])
        else:
            _add(scores, log, "windows", 3.0, "service", "windows smb", rule["smb"])
        if smb.os_version:
            os_hint = smb.native_os
            evidence.os_rule = {
                "source": "smb",
                "os_version": smb.os_version,
                "name": smb.native_os,
            }

    if probes.rdp.responded:
        rule["rdp"] = "responded"
        _add(scores, log, "windows", 2.0, "service", "rdp x.224", "responded")

    if probes.netbios.responded:
        rule["netbios"] = (
                probes.netbios.computer_name or probes.netbios.domain or "responded"
        )
        _add(
            scores,
            log,
            "windows",
            1.5,
            "service",
            "netbios name service",
            rule["netbios"],
        )

    snmp = probes.snmp
    if snmp.responded:
        descr = (snmp.sys_descr or "").lower()
        rule["snmp"] = snmp.sys_descr or "responded"
        _add(scores, log, "network_device", 1.0, "service", "snmp agent", rule["snmp"])
        if any(
                v in descr for v in ("cisco", "mikrotik", "juniper", "routeros", "arista")
        ):
            _add(
                scores,
                log,
                "network_device",
                2.0,
                "service",
                "snmp vendor",
                rule["snmp"],
            )
        elif "windows" in descr:
            _add(scores, log, "windows", 2.0, "service", "snmp windows", rule["snmp"])
        elif "linux" in descr:
            _add(scores, log, "linux", 2.0, "service", "snmp linux", rule["snmp"])
        elif any(v in descr for v in ("jetdirect", "printer", "laserjet")):
            _add(scores, log, "printer", 2.5, "service", "snmp printer", rule["snmp"])
        oid_platform = _snmp_enterprise_platform(snmp.sys_object_id)
        if oid_platform:
            _add(
                scores,
                log,
                oid_platform,
                2.0,
                "service",
                "snmp enterprise oid",
                snmp.sys_object_id,
            )

    tls = probes.tls_443
    if tls.responded:
        ident = " ".join(v for v in (tls.subject, tls.issuer) if v)
        rule["tls"] = ident or "responded"
        vendor = _match_vendor(ident.lower(), _TLS_VENDOR_KEYWORDS)
        if vendor:
            _add(scores, log, vendor, 1.5, "tls", "cert identity", ident)

    http = probes.http
    if http.responded:
        server = (http.server or "").lower()
        title = (http.title or "").lower()
        rule["http"] = http.server or http.title or "responded"
        if _vcenter_web_detected(probes):
            _add(scores, log, "linux", 2.0, "service", "vcenter web ui", rule["http"])
        else:
            srv_platform = _match_vendor(server, _HTTP_SERVER_KEYWORDS)
            if srv_platform:
                _add(scores, log, srv_platform, 3.0, "service", "http server brand", server[:60])
            elif "iis" in server or "microsoft" in server:
                _add(scores, log, "windows", 1.5, "service", "iis server", rule["http"])
            elif "apache" in server or "nginx" in server:
                _add(scores, log, "linux", 0.5, "service", "unix web server", rule["http"])
            title_platform = _match_vendor(title, _HTTP_TITLE_KEYWORDS)
            if title_platform:
                _add(scores, log, title_platform, 1.5, "service", "http title", title[:80])

    if probes.ipp.responded:
        rule["ipp"] = probes.ipp.make_model or probes.ipp.printer_name or "responded"
        _add(scores, log, "printer", 3.0, "service", "ipp/jetdirect", rule["ipp"])

    if probes.mqtt.responded:
        rule["mqtt"] = "responded"
        _add(scores, log, "iot", 2.0, "service", "mqtt broker", "responded")

    services = " ".join(probes.mdns.services).lower()
    if probes.mdns.responded:
        rule["mdns"] = services or probes.mdns.hostname or "responded"
        if (
                "_airplay" in services
                or "_raop" in services
                or "_companion-link" in services
        ):
            _add(scores, log, "macos", 1.5, "service", "apple mdns", rule["mdns"])
        if "_ipp" in services or "_pdl-datastream" in services:
            _add(scores, log, "printer", 2.0, "service", "printer mdns", rule["mdns"])
        if "_googlecast" in services:
            _add(scores, log, "iot", 1.5, "service", "chromecast mdns", rule["mdns"])

    if probes.upnp.responded:
        ident = _upnp_ident(probes.upnp)
        rule["upnp"] = ident or "responded"
        il = ident.lower()
        vendor = _match_vendor(il, _UPNP_VENDOR_KEYWORDS)
        if vendor:
            _add(scores, log, vendor, 1.5, "service", "upnp vendor", ident)
        elif any(k in il for k in ("router", "gateway", "modem", "access point")):
            _add(scores, log, "wifi_ap", 1.5, "service", "upnp router/gateway", ident)
        elif any(k in il for k in ("camera", "nvr", "dvr", "ipcam")):
            _add(scores, log, "iot", 1.5, "service", "upnp camera", ident)
        else:
            _add(scores, log, "iot", 0.5, "service", "upnp device", rule["upnp"])

    evidence.service_rule = rule
    return os_hint


def _match_device_identity(probes) -> tuple[str, str] | None:
    parts: list[str] = []
    tls = probes.tls_443
    if tls.responded:
        parts.extend(v for v in (tls.subject, tls.issuer) if v)
    if probes.revdns.hostname:
        parts.append(probes.revdns.hostname)
    text = " ".join(parts).lower()
    if not text:
        return None
    for keyword, platform, os_hint in _DEVICE_IDENTITY:
        if keyword in text:
            return platform, os_hint
    return None


def _vcenter_web_detected(probes) -> bool:
    http = probes.http
    if not http.responded:
        return False
    text = f"{http.title or ''} {http.server or ''}".lower()
    return any(tok in text for tok in ("id_vc_", "vcenter"))


def _resolve_os_hint(
        probes,
        platform: str,
        smb_hint: str | None,
        ttl_hint: str | None,
        identity: tuple[str, str] | None = None,
) -> str | None:
    if smb_hint:
        return smb_hint
    if identity:
        return identity[1]
    if _vcenter_web_detected(probes):
        return "VMware vCenter Server Appliance (Photon OS)"
    if platform == "vmware_esxi":
        return _PLATFORM_OS_HINT["vmware_esxi"]
    specific = _platform_specific_hint(probes, platform)
    if specific:
        return specific
    if ttl_hint:
        return ttl_hint
    if platform == "unknown":
        return None
    return _PLATFORM_OS_HINT.get(platform)


def _upnp_ident(upnp) -> str:
    return " ".join(
        v for v in (upnp.manufacturer, upnp.model_name, upnp.friendly_name) if v
    )


def _platform_specific_hint(probes, platform: str) -> str | None:
    open_ports = set(probes.tcp_ports.open)
    ssh = probes.ssh
    snmp = probes.snmp
    if platform == "linux":
        if ssh.responded and ssh.banner:
            ssh_hint = _os_hint_from_ssh(ssh.banner)
            if ssh_hint:
                return ssh_hint
        return snmp.sys_descr[:80] if snmp.sys_descr else None
    if platform == "macos":
        if ssh.responded and ssh.banner:
            match = _OPENSSH_RE.search(ssh.banner.lower())
            if match:
                return f"macOS (OpenSSH {match.group(1)})"
        return None
    if platform == "windows":
        if open_ports & {5985, 5986}:
            return "Windows (WinRM)"
        if probes.smb.probed and not probes.smb.responded and 445 in open_ports:
            return "Windows (SMB v1 only — likely XP/Server 2003)"
        return snmp.sys_descr[:80] if snmp.sys_descr else None
    if platform == "network_device":
        return snmp.sys_descr[:80] if snmp.sys_descr else None
    if platform == "printer":
        return probes.ipp.make_model or probes.ipp.printer_name or None
    if platform == "iot":
        if probes.rtsp.responded:
            return "IoT Camera / NVR (RTSP)"
        if probes.mqtt.responded:
            return "IoT Device (MQTT Broker)"
        if probes.upnp.responded and _upnp_ident(probes.upnp):
            return _upnp_ident(probes.upnp)[:80]
        return probes.http.title[:80] if probes.http.title else None
    if platform == "wifi_ap":
        if probes.upnp.responded and _upnp_ident(probes.upnp):
            return _upnp_ident(probes.upnp)[:80]
        if snmp.sys_descr:
            return snmp.sys_descr[:80]
        if probes.http.title:
            return probes.http.title[:80]
        if probes.arp.manufacturer:
            return f"{probes.arp.manufacturer} Router / AP"
        return None
    return None


def _os_hint_from_ssh(banner: str) -> str | None:
    low = banner.lower()
    match = _OPENSSH_RE.search(low)
    version = match.group(1) if match else None
    for token, label, versions in _SSH_OS_TOKENS:
        if token in low:
            return versions.get(version, label) if version else label
    if version:
        return _BARE_OPENSSH_OS.get(version, "Linux/Unix")
    return None


def _match_vendor(text: str, table: tuple[tuple[str, str], ...]) -> str | None:
    for keyword, platform in table:
        if keyword in text:
            return platform
    return None


def _snmp_enterprise_platform(sys_object_id: str | None) -> str | None:
    prefix = "1.3.6.1.4.1."
    if not sys_object_id or not sys_object_id.startswith(prefix):
        return None
    pen = sys_object_id[len(prefix):].split(".", 1)[0]
    return _SNMP_ENTERPRISE.get(pen)


def _score_oui(probes, scores, log, evidence) -> None:
    arp = probes.arp
    if arp.mac is None:
        return
    info = {
        "mac": arp.mac,
        "manufacturer": arp.manufacturer,
        "randomized": arp.randomized,
    }
    evidence.service_rule = {**evidence.service_rule, "oui": info}
    if arp.randomized or not arp.platform_hint:
        return
    _add(
        scores,
        log,
        arp.platform_hint,
        3.0,
        "oui",
        f"mac vendor {arp.manufacturer}",
        arp.mac,
    )


def _resolve_conflicts(
        scores, platform, confidence, share, saturation, evidence
) -> None:
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top = ranked[0]
    runner_up = ranked[1] if len(ranked) > 1 else ("", 0.0)
    evidence.conflict_resolution = {
        "winner": platform,
        "confidence": confidence,
        "share": round(share * 100, 1),
        "saturation": round(saturation, 2),
        "top": {top[0]: top[1]},
        "runner_up": {runner_up[0]: runner_up[1]},
        "contested": bool(top[1]) and (top[1] - runner_up[1]) < 1.0,
    }


def _has_definitive_signal(probes, platform: str) -> bool:
    if platform == "vmware_esxi" and probes.vmware_authd.responded:
        return True
    identity = _match_device_identity(probes)
    return identity is not None and identity[0] == platform


def _winner(scores: dict[str, float]) -> tuple[str, float, float, float]:
    total = sum(scores.values())
    if total <= 0:
        return "unknown", 0.0, 0.0, 0.0
    platform = max(scores, key=lambda p: scores[p])
    top_score = scores[platform]
    share = top_score / total
    saturation = min(1.0, top_score / _CONFIDENCE_SATURATION_SCORE)
    confidence = round(share * saturation * 100, 1)
    return platform, confidence, share, saturation
