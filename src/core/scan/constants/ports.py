from __future__ import annotations

# ── Individual service port numbers ───────────────────────────────────────
FTP            = 21
SSH            = 22
TELNET         = 23
SMTP           = 25
DNS            = 53
HTTP           = 80
KERBEROS       = 88
POP3           = 110
IDENT          = 113
IMAP           = 143
SNMP           = 161    # UDP — always-run probe, not TCP-gated
NETBIOS_NS     = 137    # UDP — NetBIOS Name Service
NETBIOS_DGM    = 138    # UDP — NetBIOS Datagram Service
NETBIOS_SSN    = 139    # TCP — NetBIOS Session Service (legacy SMB)
LDAP           = 389
HTTPS          = 443
SMB            = 445    # Direct-hosted SMB (preferred over NetBIOS)
AFP            = 548    # Apple Filing Protocol
RTSP           = 554    # Real Time Streaming Protocol
IPP            = 631    # Internet Printing Protocol
WINRM_HTTP     = 5985   # Windows Remote Management (HTTP)
WINRM_HTTPS    = 5986   # Windows Remote Management (HTTPS)
TR069          = 7547   # CPE WAN Management Protocol (ISP remote management)
HTTP_ALT       = 8080
HTTPS_ALT      = 8443
JETDIRECT      = 9100   # HP JetDirect / raw printing (JetDirect/AppSocket)
VMWARE_AUTHD   = 902    # VMware Authentication Daemon
MQTT           = 1883   # MQTT (unencrypted)
MQTT_TLS       = 8883   # MQTT over TLS
RDP            = 3389   # Remote Desktop Protocol
MYSQL          = 3306
MSSQL          = 1433
POSTGRESQL     = 5432
REDIS          = 6379
ELASTICSEARCH  = 9200
MEMCACHED      = 11211
MONGODB        = 27017
MDNS           = 5353   # UDP — mDNS / DNS-SD (Bonjour)
UPNP_SSDP      = 1900   # UDP — UPnP SSDP discovery
SYSLOG         = 514    # UDP
NTP            = 123    # UDP
DHCP_SERVER    = 67     # UDP
DHCP_CLIENT    = 68     # UDP
TFTP           = 69     # UDP
VNC            = 5900
X11            = 6000
DOCKER_API     = 2375
KUBERNETES_API = 6443
ETCD           = 2379
CONSUL         = 8500

# ── TCP port scan defaults (probed by the tcp_ports probe) ────────────────
# Order does not matter — all are probed concurrently.
DEFAULT_SCAN_PORTS: tuple[int, ...] = (
    FTP,            # 21
    SSH,            # 22
    TELNET,         # 23
    HTTP,           # 80
    NETBIOS_SSN,    # 139
    SNMP,           # 161  (listed for gate logic; UDP probe handles actual scan)
    HTTPS,          # 443
    SMB,            # 445
    AFP,            # 548
    RTSP,           # 554
    IPP,            # 631
    VMWARE_AUTHD,   # 902
    MQTT,           # 1883
    MYSQL,          # 3306
    RDP,            # 3389
    WINRM_HTTP,     # 5985
    TR069,          # 7547
    HTTP_ALT,       # 8080
    HTTPS_ALT,      # 8443
    JETDIRECT,      # 9100
)

# ── Per-probe gate port sets (mirrors registry.PROBES gate_ports) ─────────
# A probe only runs in phase 2 if at least one of its gate ports is open.
GATE_SMB:           frozenset[int] = frozenset({SMB})
GATE_SSH:           frozenset[int] = frozenset({SSH})
GATE_TLS:           frozenset[int] = frozenset({HTTPS})
GATE_HTTP:          frozenset[int] = frozenset({HTTP, HTTPS, HTTP_ALT, HTTPS_ALT})
GATE_UPNP:          frozenset[int] = frozenset({HTTP, HTTPS, HTTP_ALT, HTTPS_ALT})
GATE_RDP:           frozenset[int] = frozenset({RDP})
GATE_VMWARE_AUTHD:  frozenset[int] = frozenset({VMWARE_AUTHD})
GATE_MQTT:          frozenset[int] = frozenset({MQTT})
GATE_IPP:           frozenset[int] = frozenset({IPP, JETDIRECT})
GATE_RTSP:          frozenset[int] = frozenset({RTSP})
GATE_TELNET:        frozenset[int] = frozenset({TELNET})

# ── Human-readable port → service name (for display / logging) ────────────
PORT_NAMES: dict[int, str] = {
    FTP:            "FTP",
    SSH:            "SSH",
    TELNET:         "Telnet",
    SMTP:           "SMTP",
    DNS:            "DNS",
    HTTP:           "HTTP",
    KERBEROS:       "Kerberos",
    POP3:           "POP3",
    IDENT:          "Ident",
    IMAP:           "IMAP",
    SNMP:           "SNMP",
    NETBIOS_NS:     "NetBIOS-NS",
    NETBIOS_DGM:    "NetBIOS-DGM",
    NETBIOS_SSN:    "NetBIOS-SSN",
    LDAP:           "LDAP",
    HTTPS:          "HTTPS",
    SMB:            "SMB",
    AFP:            "AFP",
    RTSP:           "RTSP",
    IPP:            "IPP",
    WINRM_HTTP:     "WinRM-HTTP",
    WINRM_HTTPS:    "WinRM-HTTPS",
    TR069:          "TR-069",
    HTTP_ALT:       "HTTP-alt",
    HTTPS_ALT:      "HTTPS-alt",
    JETDIRECT:      "JetDirect",
    VMWARE_AUTHD:   "VMware-AuthD",
    MQTT:           "MQTT",
    MQTT_TLS:       "MQTT-TLS",
    RDP:            "RDP",
    MYSQL:          "MySQL",
    MSSQL:          "MSSQL",
    POSTGRESQL:     "PostgreSQL",
    REDIS:          "Redis",
    ELASTICSEARCH:  "Elasticsearch",
    MEMCACHED:      "Memcached",
    MONGODB:        "MongoDB",
    MDNS:           "mDNS",
    UPNP_SSDP:      "UPnP-SSDP",
    VNC:            "VNC",
    X11:            "X11",
    DOCKER_API:     "Docker-API",
    KUBERNETES_API: "Kubernetes-API",
    ETCD:           "etcd",
    CONSUL:         "Consul",
}
