from __future__ import annotations

# Central re-export for the constants package.
# Probes and scoring rules import from here instead of from individual modules.
#
# Usage examples:
#   from src.core.scan.constants import SSH, SMB, DEFAULT_SCAN_PORTS
#   from src.core.scan.constants import TTL_OS_HINT, snap_ttl
#   from src.core.scan.constants import SERVER_HINTS, SSH_PREFIX_HINTS
#   from src.core.scan.constants import ENTERPRISE_HINTS, SYSDESCR_HINTS
#   from src.core.scan.constants import SERVICE_TYPE_HINTS, DEVICE_TYPE_HINTS
#   from src.core.scan.constants import RDP_CONNECTION_REQUEST, MQTT_CONNECT_PACKET
#   from src.core.scan.constants import SSH_BANNER_BYTES, TELNET_BANNER_BYTES


# ── Port numbers & gate sets ──────────────────────────────────────────────
from src.core.scan.constants.ports import (
    FTP, SSH, TELNET, SMTP, DNS, HTTP, KERBEROS, POP3, IDENT, IMAP,
    SNMP, NETBIOS_NS, NETBIOS_DGM, NETBIOS_SSN, LDAP, HTTPS, SMB, AFP,
    RTSP, IPP, WINRM_HTTP, WINRM_HTTPS, TR069, HTTP_ALT, HTTPS_ALT,
    JETDIRECT, VMWARE_AUTHD, MQTT, MQTT_TLS, RDP, MYSQL, MSSQL,
    POSTGRESQL, REDIS, ELASTICSEARCH, MEMCACHED, MONGODB, MDNS,
    UPNP_SSDP, SYSLOG, NTP, DHCP_SERVER, DHCP_CLIENT, TFTP, VNC, X11,
    DOCKER_API, KUBERNETES_API, ETCD, CONSUL,
    DEFAULT_SCAN_PORTS,
    GATE_SMB, GATE_SSH, GATE_TLS, GATE_HTTP, GATE_UPNP, GATE_RDP,
    GATE_VMWARE_AUTHD, GATE_MQTT, GATE_IPP, GATE_RTSP, GATE_TELNET,
    PORT_NAMES,
)

# ── TTL fingerprinting ────────────────────────────────────────────────────
from src.core.scan.constants.ttl import (
    TTL_BOUNDARIES,
    TTL_INITIAL,
    TTL_OS_HINT,
    snap_ttl,
)

# ── SMB / NTLM protocol constants ────────────────────────────────────────
from src.core.scan.constants.smb_hints import (
    SMB2_DIALECTS,
    SMB1_DIALECTS,
    DIALECT_OS_MAP,
    SMB3_MIN_VERSION,
    NTLMSSP_FLAGS,
    NTLMSSP_NEGOTIATE_VERSION_FLAG,
    NTLM_AV_PAIR_IDS,
    SAMBA_NULL_GUID,
    SAMBA_BANNERS,
    SMB_FEATURE_MIN_DIALECT,
)

# ── SSH banner fingerprints ───────────────────────────────────────────────
from src.core.scan.constants.ssh_hints import (
    SSH_PROTO_2,
    SSH_PROTO_1,
    SSH_PROTO_199,
    PREFIX_HINTS as SSH_PREFIX_HINTS,
    SUBSTRING_HINTS as SSH_SUBSTRING_HINTS,
)

# ── HTTP / web fingerprints ───────────────────────────────────────────────
from src.core.scan.constants.http_hints import (
    HTTP_CANDIDATES,
    UPNP_CANDIDATES,
    INTERESTING_HEADERS,
    HTTP_USER_AGENT,
    SERVER_HINTS,
    XPOWERED_HINTS,
    TITLE_HINTS,
)

# ── SNMP OID fingerprints ────────────────────────────────────────────────
from src.core.scan.constants.snmp_oids import (
    ENTERPRISE_HINTS,
    SYSDESCR_HINTS,
)

# ── mDNS service fingerprints ─────────────────────────────────────────────
from src.core.scan.constants.mdns_hints import (
    SERVICE_TYPE_HINTS,
    HOSTNAME_HINTS as MDNS_HOSTNAME_HINTS,
)

# ── UPnP device fingerprints ──────────────────────────────────────────────
from src.core.scan.constants.upnp_hints import (
    DESCRIPTION_PATHS,
    DEVICE_TYPE_HINTS,
    MANUFACTURER_HINTS as UPNP_MANUFACTURER_HINTS,
    FRIENDLY_NAME_HINTS,
)

# ── NetBIOS name service constants ────────────────────────────────────────
from src.core.scan.constants.netbios_hints import (
    NAME_SUFFIX_HINTS,
    NODE_TYPE,
    SUFFIX_COMBO_HINTS,
    NBSTAT_QUERY,
    NBSTAT_PORT,
    NBSTAT_TIMEOUT,
    NBSTAT_BUFSIZE,
)

# ── Buffer / read sizes ───────────────────────────────────────────────────
from src.core.scan.constants.buffer_sizes import (
    SSH_BANNER_BYTES,
    VMWARE_AUTHD_BANNER_BYTES,
    RDP_REPLY_BYTES,
    RTSP_REPLY_BYTES,
    MQTT_CONNACK_BYTES,
    TELNET_BANNER_BYTES,
    TELNET_BANNER_MAX,
    HTTP_BODY_BYTES,
    UPNP_BODY_BYTES,
    IPP_HTTP_BODY_BYTES,
    PJL_REPLY_BYTES,
    SNMP_REPLY_BYTES,
    NETBIOS_NBSTAT_BYTES,
    MDNS_REPLY_BYTES,
    ARP_RESOLVE_DELAY_S,
    ARP_LOCAL_CACHE_TTL_S,
)

# ── Wire-protocol byte sequences ──────────────────────────────────────────
from src.core.scan.constants.wire import (
    RDP_CONNECTION_REQUEST,
    RDP_CC_TPKT_VERSION,
    RDP_CC_COTP_TYPE,
    RDP_CC_TPKT_OFFSET,
    RDP_CC_COTP_OFFSET,
    RDP_CC_MIN_LEN,
    MQTT_CONNECT_PACKET,
    MQTT5_CONNECT_PACKET,
    MQTT_CONNACK_BYTE0,
    MQTT_CONNACK_BYTE1,
    RTSP_OPTIONS_REQUEST,
    RTSP_REPLY_PREFIX,
    PJL_INFO_ID_COMMAND,
    PJL_ID_REPLY_PATTERN,
    TLS_OID_COMMON_NAME,
    TLS_OID_ORG_NAME,
    TLS_OID_ORG_UNIT,
    TLS_OID_COUNTRY,
    TLS_OID_STATE,
    TLS_OID_LOCALITY,
    TLS_OID_EMAIL,
    TLS_OID_SAN,
    SNMP_GET_SYSDESCR,
    SNMP_GET_SYSOBJECTID,
    SNMP_GET_SYSNAME,
    SNMP_TAG_INTEGER,
    SNMP_TAG_OCTET_STRING,
    SNMP_TAG_OID,
    SNMP_TAG_NULL,
    SNMP_TAG_SEQUENCE,
    SNMP_TAG_GET_RESPONSE,
    SNMP_COMMUNITY_STRINGS,
    MDNS_SERVICES_QUERY,
    MDNS_MULTICAST_ADDR,
    MDNS_PORT,
    SSDP_MSEARCH,
    SSDP_MULTICAST_ADDR,
    SSDP_PORT,
)

# ── Telnet fingerprints ───────────────────────────────────────────────────
from src.core.scan.constants.telnet_hints import (
    BANNER_HINTS as TELNET_BANNER_HINTS,
    PROMPT_HINTS as TELNET_PROMPT_HINTS,
    TELNET_IAC,
    TELNET_WILL, TELNET_WONT, TELNET_DO, TELNET_DONT,
    TELNET_SB, TELNET_SE,
    TELNET_OPT_ECHO, TELNET_OPT_SUPPRESS_GA, TELNET_OPT_TERMINAL,
    TELNET_OPT_WINDOW_SIZE, TELNET_OPT_LINEMODE,
)

# ── RTSP fingerprints ────────────────────────────────────────────────────
from src.core.scan.constants.rtsp_hints import (
    RTSP_ALT_PORT,
    SERVER_HINTS as RTSP_SERVER_HINTS,
    STATUS_HINTS as RTSP_STATUS_HINTS,
    STREAM_PATHS as RTSP_STREAM_PATHS,
)

# ── TLS / X.509 certificate fingerprints ─────────────────────────────────
from src.core.scan.constants.tls_hints import (
    CN_HINTS as TLS_CN_HINTS,
    ISSUER_HINTS as TLS_ISSUER_HINTS,
    SAN_HINTS as TLS_SAN_HINTS,
    TLS_VERSION_HINTS,
    SELF_SIGNED_PLATFORM_BOOST,
)

# ── VMware authd fingerprints ────────────────────────────────────────────
from src.core.scan.constants.vmware_hints import (
    BANNER_KEYWORDS as VMWARE_BANNER_KEYWORDS,
    GREETING_PATTERNS as VMWARE_GREETING_PATTERNS,
    DAEMON_VERSION_RE as VMWARE_DAEMON_VERSION_RE,
    DAEMON_VERSION_TO_ESXI,
    ESXI_VERSIONS,
    PORT_902_FALLBACK_HINT,
    VMWARE_VM_OUI_PREFIXES,
)
