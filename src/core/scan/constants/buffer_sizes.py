from __future__ import annotations

# Per-probe read buffer sizes.
#
# All sizes are in bytes. "Banner" probes read a fixed initial chunk to capture
# the server greeting; "body" probes read a larger chunk for document parsing.
# Keeping sizes here means one place to tune without touching probe logic.


# ── Banner read sizes (small — just enough to identify the service) ────────

SSH_BANNER_BYTES        = 256   # First SSH version string (e.g. "SSH-2.0-OpenSSH_9.x")
VMWARE_AUTHD_BANNER_BYTES = 256 # VMware Authentication Daemon greeting
RDP_REPLY_BYTES         = 256   # RDP COTP Connection Confirm PDU
RTSP_REPLY_BYTES        = 256   # RTSP/1.0 response status + first headers
MQTT_CONNACK_BYTES      = 64    # MQTT CONNACK is exactly 4 bytes; 64 gives headroom

# ── Telnet — larger because the IAC negotiation + banner can be verbose ────
TELNET_BANNER_BYTES     = 512   # Raw read including IAC bytes
TELNET_BANNER_MAX       = 300   # Max chars kept in the stored banner (strip IAC noise)

# ── HTTP / web probes — enough to parse headers + page title ──────────────
HTTP_BODY_BYTES         = 8192  # Covers headers + <title> for most pages
UPNP_BODY_BYTES         = 8192  # UPnP description XML is typically < 4 KB
IPP_HTTP_BODY_BYTES     = 4096  # Printer web UI — smaller than a full page
PJL_REPLY_BYTES         = 512   # HP PJL INFO ID reply is always tiny

# ── TLS — cert is read by the SSL layer; no manual buffer needed ───────────
# The asyncio SSL transport handles TLS framing internally.
# We do not define a buffer size for tls_443.

# ── SNMP — UDP, reply bounded by MTU ──────────────────────────────────────
SNMP_REPLY_BYTES        = 1472  # Max safe UDP payload (Ethernet MTU 1500 − IP/UDP headers)

# ── NetBIOS NBSTAT ────────────────────────────────────────────────────────
NETBIOS_NBSTAT_BYTES    = 1024  # NBSTAT response is usually < 500 bytes

# ── mDNS — UDP multicast response ─────────────────────────────────────────
MDNS_REPLY_BYTES        = 4096  # DNS message max is 65535, but mDNS replies are small

# ── ARP ───────────────────────────────────────────────────────────────────
ARP_RESOLVE_DELAY_S     = 0.15  # Seconds to wait after poking before reading ARP table
ARP_LOCAL_CACHE_TTL_S   = 30.0  # Seconds to cache the local interface MAC table
