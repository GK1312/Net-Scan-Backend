from __future__ import annotations

# NetBIOS name service fingerprint tables.
#
# The NetBIOS Name Service (NBNS) runs on UDP/TCP port 137.
# Each entry in a node's name table has a 1-byte "type" suffix (0x00–0xFF)
# appended to the 15-character padded name.
#
# Reading the name table from a NBSTAT response reveals what services the
# node is running and allows platform disambiguation.
#
# References:
#   RFC 1001 / RFC 1002 — NetBIOS over TCP/IP
#   [MS-BRWS]  — Common Internet File System Browser Protocol
#   [MS-NRPC]  — Netlogon Remote Protocol


# ── NetBIOS name suffix codes ──────────────────────────────────────────────
# Format: suffix_byte → (service_name, description, platform_hint)
NAME_SUFFIX_HINTS: dict[int, tuple[str, str, str | None]] = {
    # ── Node / workstation name (first entry, always present) ─────────────
    0x00: ("WORKSTATION",     "Registered by the Workstation Service",          "windows"),
    # ── Messenger service ─────────────────────────────────────────────────
    0x03: ("MESSENGER",       "Messenger Service (WinPopup / net send)",         "windows"),
    # ── RAS / Remote Access Server ────────────────────────────────────────
    0x06: ("RAS_SERVER",      "Remote Access Server Service",                   "windows"),
    # ── Samba registration ────────────────────────────────────────────────
    0x08: ("SAMBA_PROXY",     "Samba NetBEUI name-server proxy",               "linux"),
    0x09: ("SAMBA_PROXY_OB",  "Samba NetBEUI name-server proxy (OB)",          "linux"),
    # ── NetDDE ────────────────────────────────────────────────────────────
    0x0A: ("NETDDE",          "Net DDE service (legacy)",                       "windows"),
    0x0B: ("NETDDE_SERVER",   "Net DDE server (legacy)",                        "windows"),
    # ── File and Printer sharing (Server service) ─────────────────────────
    0x20: ("FILE_SERVER",     "File Server / Server Service (SMB hosting)",     "windows"),
    # ── Domain master browser ─────────────────────────────────────────────
    0x1B: ("DOMAIN_MASTER",   "Domain Master Browser — usually a DC",           "windows"),
    # ── Domain name (group) ───────────────────────────────────────────────
    0x1C: ("DOMAIN_NAME",     "Domain name (group) — appears on DCs",          "windows"),
    # ── Master browser ────────────────────────────────────────────────────
    0x1D: ("MASTER_BROWSER",  "Local Master Browser",                           "windows"),
    # ── Browser elections ─────────────────────────────────────────────────
    0x1E: ("BROWSER_ELECT",   "Browser Election Service (group)",               "windows"),
    # ── Global browser group ──────────────────────────────────────────────
    0x01: ("BROWSER_GROUP",   "__MSBROWSE__ Master Browser Announcement",       "windows"),
    # ── Modem sharing ─────────────────────────────────────────────────────
    0x30: ("MODEM_SERVER",    "Modem Sharing Server Service",                   "windows"),
    0x31: ("MODEM_CLIENT",    "Modem Sharing Client Service",                   "windows"),
    # ── SMS / SCCM client ────────────────────────────────────────────────
    0x43: ("SMS_CLIENT",      "SMS Clients Remote Control",                     "windows"),
    0x44: ("SMS_ADMIN",       "SMS Administrators Remote Control Tool",         "windows"),
    0x45: ("SMS_CLIENT2",     "SMS Clients Remote Chat",                        "windows"),
    0x46: ("SMS_CLIENT3",     "SMS Clients Remote Transfer",                    "windows"),
    # ── DEC PATHWORKS (legacy) ────────────────────────────────────────────
    0x4C: ("PATHWORKS_A",     "DEC Pathworks TCP/IP service (A)",               None),
    0x52: ("PATHWORKS_B",     "DEC Pathworks TCP/IP service (B)",               None),
    # ── Exchange / Lotus Notes ────────────────────────────────────────────
    0x42: ("SNA_SERVER",      "SNA Server Service",                             "windows"),
    0x4B: ("NOTES_MGR",       "Lotus Notes MultiCast (manager)",                None),
    0x6A: ("NOTES_DISP",      "Lotus Notes dispatch",                           None),
    0x87: ("NOTES_COMM",      "Lotus Notes communication",                      None),
    0x2B: ("NOTES_CLIENT",    "Lotus Notes client service",                     None),
    0x2F: ("NOTES_SERVER",    "Lotus Notes server",                             None),
    # ── Network Monitor ───────────────────────────────────────────────────
    0xBE: ("NETMON_AGENT",    "Network Monitor Agent",                          "windows"),
    0xBF: ("NETMON_APP",      "Network Monitor Application",                    "windows"),
    # ── Quarantine ────────────────────────────────────────────────────────
    0x05: ("QUARANTINE",      "Quarantine service (rare)",                      "windows"),
    # ── IIS / HTTP ────────────────────────────────────────────────────────
    0x07: ("HTTP",            "Internet Information Services (IIS) proxy",      "windows"),
    # ── Routing and Remote Access ─────────────────────────────────────────
    0x77: ("RRAS",            "Routing and Remote Access (RRAS)",               "windows"),
    # ── Exchange Server ───────────────────────────────────────────────────
    0x00: ("EXCHANGE_MTA",    "Exchange MTA / Workstation (overloaded 0x00)",   "windows"),
    # ── Anti-Virus / Security agents ─────────────────────────────────────
    0x83: ("AV_QUARANTINE",   "Anti-virus quarantine agent (vendor-specific)",  None),
}

# ── Node type flags (in NBSTAT NAME_FLAGS field) ──────────────────────────
# Bits 15–14 of the 16-bit flags word in each NAME_FLAGS entry.
NODE_TYPE: dict[int, str] = {
    0b00: "B-node (broadcast)",   # Only uses broadcasts; no NBNS
    0b01: "P-node (peer-peer)",   # Uses NBNS; no broadcasts
    0b10: "M-node (mixed)",       # Broadcasts first, then NBNS
    0b11: "H-node (hybrid)",      # NBNS first, then broadcast (default modern Windows)
}

# ── Platform hints from name table contents ────────────────────────────────
# The presence of certain suffixes strongly implies a platform / role.
#
# Format: frozenset of suffix bytes → (platform, role_hint)
# Check if ALL suffixes in the set are present in the node's name table.
SUFFIX_COMBO_HINTS: dict[frozenset, tuple[str, str]] = {
    # Domain Controller: has 0x1B (Domain Master Browser) + 0x1C (Domain Name)
    frozenset({0x1B, 0x1C}): ("windows", "Windows Domain Controller (DC)"),
    # File server: has 0x00 (Workstation) + 0x20 (File Server)
    frozenset({0x00, 0x20}): ("windows", "Windows file server (SMB)"),
    # Master browser: 0x1D present
    frozenset({0x1D}):        ("windows", "Windows Master Browser"),
    # Samba on Linux: typically registers 0x20 (File Server) without 0x03 (Messenger)
    frozenset({0x20}):        ("linux",   "Samba file server (Linux/Unix)"),
}

# ── NetBIOS NBSTAT reply constants ────────────────────────────────────────
# Query packet to send to port 137 UDP for a NBSTAT (Node Status) request.
# Format: [transaction_id(2)] [flags(2)] [qdcount(2)] [ancount(2)]
#         [nscount(2)] [arcount(2)] [name(34)] [qtype(2)] [qclass(2)]
NBSTAT_QUERY: bytes = (
    b"\x00\x00"          # Transaction ID
    b"\x00\x00"          # Flags: standard query
    b"\x00\x01"          # QDCOUNT: 1 question
    b"\x00\x00"          # ANCOUNT
    b"\x00\x00"          # NSCOUNT
    b"\x00\x00"          # ARCOUNT
    b"\x20"              # Name length: 32 (encoded)
    b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # Wildcard name "*" (encoded)
    b"\x00"              # Name terminator
    b"\x00\x21"          # QTYPE: NBSTAT (0x0021)
    b"\x00\x01"          # QCLASS: IN
)

NBSTAT_PORT    = 137
NBSTAT_TIMEOUT = 2.0    # seconds
NBSTAT_BUFSIZE = 1024
