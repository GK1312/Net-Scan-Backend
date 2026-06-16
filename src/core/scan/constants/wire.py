from __future__ import annotations

# Wire-protocol byte sequences sent by probes.
#
# Each constant is the exact bytes written to the socket to elicit a response.
# Keeping them here (rather than inline in probes) makes it easy to review
# protocol correctness in one place.


# ── RDP — COTP Connection Request (ISO 8073 / X.224) ─────────────────────
# Sent to port 3389 to check if Remote Desktop is listening.
# A valid server replies with a COTP Connection Confirm (0x03 … 0xD0).
#
# Structure:
#   [TPKT header]  03 00 00 13   — version=3, length=19
#   [TPKT payload] 0e            — TPKT data length (14)
#                  e0            — COTP PDU type: Connection Request (CR)
#                  00 00         — DST-REF: 0
#                  00 00         — SRC-REF: 0
#                  00            — Class: 0
#                  01 00         — Variable part: type=0x01 (TPDU size), length=1
#                  08 00         — TPDU size = 256 (2^8)
#                  00 00 00 00   — padding
RDP_CONNECTION_REQUEST: bytes = (
    b"\x03\x00\x00\x13"   # TPKT: version=3, reserved=0, length=19
    b"\x0e"               # TPKT data length
    b"\xe0"               # COTP CR PDU
    b"\x00\x00"           # DST-REF
    b"\x00\x00"           # SRC-REF
    b"\x00"               # Class
    b"\x01"               # Variable part type: TPDU-size
    b"\x00"               # Variable part length
    b"\x08\x00"           # TPDU size = 256
    b"\x00\x00\x00\x00"   # padding
)

# Expected byte offsets in a valid COTP Connection Confirm reply:
#   reply[0] == 0x03  (TPKT version)
#   reply[5] == 0xD0  (COTP CC PDU type)
RDP_CC_TPKT_VERSION  = 0x03
RDP_CC_COTP_TYPE     = 0xD0
RDP_CC_TPKT_OFFSET   = 0        # reply[0]
RDP_CC_COTP_OFFSET   = 5        # reply[5]
RDP_CC_MIN_LEN       = 6        # Minimum valid reply length


# ── MQTT — CONNECT packet (protocol level 4 = MQTT 3.1.1) ─────────────────
# Sent to port 1883 to check if an MQTT broker is listening.
# A valid broker replies with a CONNACK (first byte 0x20, second byte 0x02).
#
# Byte breakdown:
#   10       — Fixed header: CONNECT (type=1), flags=0
#   12       — Remaining length: 18 bytes
#   00 04    — Protocol name length: 4
#   4D 51 54 54  — "MQTT"
#   04       — Protocol level: 4 (MQTT 3.1.1)
#   00       — Connect flags: clean session=0, no will, no username/password
#   00 3C    — Keep-alive: 60 seconds
#   00 06    — Client ID length: 6
#   70 72 6F 62 65 31  — Client ID: "probe1"
MQTT_CONNECT_PACKET: bytes = bytes([
    0x10, 0x12,               # Fixed header + remaining length
    0x00, 0x04,               # Protocol name length
    0x4D, 0x51, 0x54, 0x54,  # "MQTT"
    0x04,                     # Protocol level: 3.1.1
    0x00,                     # Connect flags
    0x00, 0x3C,               # Keep-alive: 60 s
    0x00, 0x06,               # Client ID length
    0x70, 0x72, 0x6F,         # "pro"
    0x62, 0x65, 0x31,         # "be1"
])

# CONNACK fixed header bytes:
MQTT_CONNACK_BYTE0 = 0x20   # Packet type = CONNACK
MQTT_CONNACK_BYTE1 = 0x02   # Remaining length = 2


# ── MQTT — CONNECT packet for MQTT 5.0 (protocol level 5) ─────────────────
# Useful to distinguish MQTT 5.0 brokers (they return CONNACK with reason code).
#
#   10       — CONNECT
#   15       — Remaining length: 21
#   00 04 4D 51 54 54  — "MQTT"
#   05       — Protocol level: 5
#   00       — Connect flags
#   00 3C    — Keep-alive: 60 s
#   00       — Properties length: 0
#   00 06    — Client ID length: 6
#   70 72 6F 62 65 31  — "probe1"
MQTT5_CONNECT_PACKET: bytes = bytes([
    0x10, 0x15,
    0x00, 0x04,
    0x4D, 0x51, 0x54, 0x54,
    0x05,
    0x00,
    0x00, 0x3C,
    0x00,           # Properties length
    0x00, 0x06,
    0x70, 0x72, 0x6F, 0x62, 0x65, 0x31,
])


# ── RTSP — OPTIONS request ────────────────────────────────────────────────
# Sent to port 554 (and sometimes 8554) to check for RTSP cameras/streamers.
# A valid server replies with "RTSP/1.0 200 OK\r\n…" or similar status line.
RTSP_OPTIONS_REQUEST: bytes = (
    b"OPTIONS * RTSP/1.0\r\n"
    b"CSeq: 1\r\n"
    b"User-Agent: probe\r\n"
    b"\r\n"
)

# A valid RTSP reply starts with this prefix:
RTSP_REPLY_PREFIX = "RTSP/"


# ── HP PJL — INFO ID command (JetDirect / AppSocket port 9100) ───────────
# Sent over a raw TCP connection to port 9100 to query printer make/model.
# The printer replies with:
#   @PJL INFO ID
#   <make/model string>
#   \x0c  (form feed)
#
# The escape sequence \x1b%-12345X is the PJL Universal Exit Language (UEL)
# command that switches the printer into PJL mode from any current PDL.
PJL_INFO_ID_COMMAND: bytes = (
    b"\x1b%-12345X"       # UEL: enter PJL mode
    b"@PJL INFO ID\r\n"  # PJL INFO ID request
    b"\x1b%-12345X"       # UEL: exit PJL mode
)

# Regex pattern (as a raw string for re.compile) to parse the reply:
PJL_ID_REPLY_PATTERN = r"@PJL INFO ID\s*\r?\n(.+)"


# ── TLS — X.509 ASN.1 OIDs used in certificate parsing ───────────────────
# OID 2.5.4.3 = commonName (CN) in DER encoding.
# Used to extract the certificate subject CN from raw DER bytes when the
# Python ssl module cannot return a parsed cert dict (CERT_NONE mode).
TLS_OID_COMMON_NAME: bytes = b"\x55\x04\x03"  # OID 2.5.4.3 — commonName
TLS_OID_ORG_NAME:   bytes = b"\x55\x04\x0a"  # OID 2.5.4.10 — organizationName
TLS_OID_ORG_UNIT:   bytes = b"\x55\x04\x0b"  # OID 2.5.4.11 — organizationalUnitName
TLS_OID_COUNTRY:    bytes = b"\x55\x04\x06"  # OID 2.5.4.6 — countryName
TLS_OID_STATE:      bytes = b"\x55\x04\x08"  # OID 2.5.4.8 — stateOrProvinceName
TLS_OID_LOCALITY:   bytes = b"\x55\x04\x07"  # OID 2.5.4.7 — localityName
TLS_OID_EMAIL:      bytes = b"\x55\x04\x31"  # OID 2.5.4.49 — emailAddress (legacy)
TLS_OID_SAN:        bytes = b"\x55\x1d\x11"  # OID 2.5.29.17 — subjectAltName


# ── SNMP — GetRequest PDU (v1, community "public") ────────────────────────
# Each packet requests one OID via SNMPv1 GetRequest.
# Destination: UDP port 161.
#
# SNMPv1 GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0)
SNMP_GET_SYSDESCR: bytes = bytes([
    0x30, 0x26,             # SEQUENCE, length=38
    0x02, 0x01, 0x00,       # INTEGER version=0 (SNMPv1)
    0x04, 0x06,             # OCTET STRING, length=6
    0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # "public"
    0xa0, 0x19,             # GetRequest-PDU, length=25
    0x02, 0x01, 0x01,       # INTEGER request-id=1
    0x02, 0x01, 0x00,       # INTEGER error-status=0
    0x02, 0x01, 0x00,       # INTEGER error-index=0
    0x30, 0x0e,             # SEQUENCE (VarBindList), length=14
    0x30, 0x0c,             # SEQUENCE (VarBind), length=12
    0x06, 0x08,             # OID, length=8
    0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # 1.3.6.1.2.1.1.1.0
    0x05, 0x00,             # NULL value
])

# SNMPv1 GetRequest for sysObjectID.0 (1.3.6.1.2.1.1.2.0)
SNMP_GET_SYSOBJECTID: bytes = bytes([
    0x30, 0x26,
    0x02, 0x01, 0x00,
    0x04, 0x06,
    0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
    0xa0, 0x19,
    0x02, 0x01, 0x02,       # request-id=2
    0x02, 0x01, 0x00,
    0x02, 0x01, 0x00,
    0x30, 0x0e,
    0x30, 0x0c,
    0x06, 0x08,
    0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00,  # 1.3.6.1.2.1.1.2.0
    0x05, 0x00,
])

# SNMPv1 GetRequest for sysName.0 (1.3.6.1.2.1.1.5.0)
SNMP_GET_SYSNAME: bytes = bytes([
    0x30, 0x26,
    0x02, 0x01, 0x00,
    0x04, 0x06,
    0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
    0xa0, 0x19,
    0x02, 0x01, 0x03,       # request-id=3
    0x02, 0x01, 0x00,
    0x02, 0x01, 0x00,
    0x30, 0x0e,
    0x30, 0x0c,
    0x06, 0x08,
    0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00,  # 1.3.6.1.2.1.1.5.0
    0x05, 0x00,
])

# SNMPv1 ASN.1 type tags
SNMP_TAG_INTEGER        = 0x02
SNMP_TAG_OCTET_STRING   = 0x04
SNMP_TAG_OID            = 0x06
SNMP_TAG_NULL           = 0x05
SNMP_TAG_SEQUENCE       = 0x30
SNMP_TAG_GET_RESPONSE   = 0xa2   # GetResponse-PDU

# SNMP community strings to try in order (probe tries each until one responds)
SNMP_COMMUNITY_STRINGS: tuple[str, ...] = (
    "public",
    "private",
    "community",
    "admin",
    "monitor",
    "manager",
    "snmpd",
    "cisco",
    "router",
    "switch",
    "IOLAN",
    "apc",
    "mngt",
    "default",
    "read",
    "guest",
)


# ── mDNS — service discovery query ────────────────────────────────────────
# Sent to 224.0.0.251:5353 (UDP multicast) to enumerate DNS-SD services.
#
# DNS query for PTR record: _services._dns-sd._udp.local
# Enumerates all advertised service types on the local link.
MDNS_SERVICES_QUERY: bytes = bytes([
    0x00, 0x00,             # ID: 0 (mDNS uses 0)
    0x00, 0x00,             # Flags: standard query
    0x00, 0x01,             # QDCOUNT: 1
    0x00, 0x00,             # ANCOUNT: 0
    0x00, 0x00,             # NSCOUNT: 0
    0x00, 0x00,             # ARCOUNT: 0
    # Question: _services._dns-sd._udp.local PTR IN
    0x09,                   # label length: 9
    0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,  # "_services"
    0x07,                   # label length: 7
    0x5f, 0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64,              # "_dns-sd"
    0x04,                   # label length: 4
    0x5f, 0x75, 0x64, 0x70,                                  # "_udp"
    0x05,                   # label length: 5
    0x6c, 0x6f, 0x63, 0x61, 0x6c,                           # "local"
    0x00,                   # root label
    0x00, 0x0c,             # QTYPE: PTR
    0x80, 0x01,             # QCLASS: IN | QU (unicast-response request bit)
])

MDNS_MULTICAST_ADDR = "224.0.0.251"
MDNS_PORT           = 5353


# ── UPnP / SSDP — M-SEARCH discovery ─────────────────────────────────────
# Sent to 239.255.255.250:1900 (UDP multicast) to discover UPnP devices.
SSDP_MSEARCH: bytes = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\n'
    b"MX: 3\r\n"
    b"ST: upnp:rootdevice\r\n"
    b"\r\n"
)

SSDP_MULTICAST_ADDR = "239.255.255.250"
SSDP_PORT           = 1900
