from __future__ import annotations

# SMB protocol constants and fingerprint tables.
#
# References:
#   [MS-SMB2]: Server Message Block (SMB) Protocol Version 2 and 3
#   [MS-CIFS]: Common Internet File System (CIFS) Protocol
#   [MS-NLMP]:  NT LAN Manager (NTLM) Authentication Protocol


# ── SMB2/3 negotiated dialect codes ──────────────────────────────────────
# Returned in the SMB2 NEGOTIATE response (offset 72, 2 bytes LE).
SMB2_DIALECTS: dict[int, str] = {
    # SMB 2.x family
    0x0202: "SMB 2.0.2",    # Windows Vista / Server 2008 RTM
    0x0210: "SMB 2.1",      # Windows 7 / Server 2008 R2
    0x02FF: "SMB 2.x",      # Multi-protocol negotiate wildcard response
    # SMB 3.x family
    0x0300: "SMB 3.0",      # Windows 8 / Server 2012
    0x0302: "SMB 3.0.2",    # Windows 8.1 / Server 2012 R2
    0x0311: "SMB 3.1.1",    # Windows 10 / Server 2016 / Server 2019 / Server 2022+
}

# SMB1 dialect strings (sent as ASCII in the NEGOTIATE request body).
# Servers respond with their highest mutually-supported dialect.
SMB1_DIALECTS: list[str] = [
    "PC NETWORK PROGRAM 1.0",  # Original IBM LAN Manager 1.0 (DOS era, ~1987)
    "MICROSOFT NETWORKS 1.03", # MS LAN Manager 1.0 extension
    "MICROSOFT NETWORKS 3.0",  # MS LAN Manager 2.0
    "LANMAN1.0",               # LAN Manager 1.0
    "LM1.2X002",               # LAN Manager 1.2
    "LANMAN2.1",               # LAN Manager 2.1
    "DOS LANMAN2.1",           # DOS LAN Manager 2.1
    "DOS LM1.2X002",           # DOS LAN Manager 1.2
    "Windows for Workgroups 3.1a",  # Windows 3.1 / WfW (historical)
    "NT LM 0.12",              # NT LAN Manager 0.12 — the canonical SMB1 (NT-dialect)
    "SMB 2.???",               # SMB2 upgrade signal (some Win7+ servers)
    "SMB 2.002",               # SMB 2.0.2 upgrade signal
]

# ── Dialect → Windows version that introduced it ─────────────────────────
# (dialect_code_or_string, first_windows_client, first_windows_server)
DIALECT_OS_MAP: dict[str, tuple[str, str]] = {
    "SMB 2.0.2":  ("Windows Vista",       "Windows Server 2008"),
    "SMB 2.1":    ("Windows 7",           "Windows Server 2008 R2"),
    "SMB 2.x":    ("Windows 7+",          "Windows Server 2008 R2+"),
    "SMB 3.0":    ("Windows 8",           "Windows Server 2012"),
    "SMB 3.0.2":  ("Windows 8.1",         "Windows Server 2012 R2"),
    "SMB 3.1.1":  ("Windows 10 (1507)",   "Windows Server 2016"),
}

# SMB 3.1.1 is the minimum dialect that supports:
#   - Pre-authentication integrity (SHA-512)
#   - Encryption via AES-128-GCM or AES-256-GCM
#   - Cluster dialect fencing
SMB3_MIN_VERSION = "SMB 3.1.1"

# ── NTLMSSP flags (NEGOTIATE_FLAGS field at offset 20 in CHALLENGE message) ──
# Bit definitions from [MS-NLMP] section 2.2.2.5.
NTLMSSP_FLAGS: dict[str, int] = {
    "NTLMSSP_NEGOTIATE_UNICODE":              0x00000001,
    "NTLMSSP_NEGOTIATE_OEM":                  0x00000002,
    "NTLMSSP_REQUEST_TARGET":                 0x00000004,
    "NTLMSSP_NEGOTIATE_SIGN":                 0x00000010,
    "NTLMSSP_NEGOTIATE_SEAL":                 0x00000020,
    "NTLMSSP_NEGOTIATE_DATAGRAM":             0x00000040,
    "NTLMSSP_NEGOTIATE_LM_KEY":              0x00000080,
    "NTLMSSP_NEGOTIATE_NTLM":                0x00000200,
    "NTLMSSP_ANONYMOUS":                      0x00000800,
    "NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED":  0x00001000,
    "NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED": 0x00002000,
    "NTLMSSP_NEGOTIATE_ALWAYS_SIGN":          0x00008000,
    "NTLMSSP_TARGET_TYPE_DOMAIN":             0x00010000,
    "NTLMSSP_TARGET_TYPE_SERVER":             0x00020000,
    "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY": 0x00080000,
    "NTLMSSP_NEGOTIATE_IDENTIFY":             0x00100000,
    "NTLMSSP_REQUEST_NON_NT_SESSION_KEY":     0x00400000,
    "NTLMSSP_NEGOTIATE_TARGET_INFO":          0x00800000,
    "NTLMSSP_NEGOTIATE_VERSION":              0x02000000,  # Version block present
    "NTLMSSP_NEGOTIATE_128":                  0x20000000,  # 128-bit session key
    "NTLMSSP_NEGOTIATE_KEY_EXCH":             0x40000000,
    "NTLMSSP_NEGOTIATE_56":                   0x80000000,  # 56-bit DES
}

# Flag that signals the 8-byte version block is valid at offset 48.
NTLMSSP_NEGOTIATE_VERSION_FLAG = NTLMSSP_FLAGS["NTLMSSP_NEGOTIATE_VERSION"]

# ── NTLMSSP AvPair IDs (MsvAvId values in TargetInfo) ─────────────────────
# [MS-NLMP] section 2.2.2.1
NTLM_AV_PAIR_IDS: dict[int, str] = {
    0x0000: "MsvAvEOL",               # End of list
    0x0001: "MsvAvNbComputerName",    # NetBIOS computer name
    0x0002: "MsvAvNbDomainName",      # NetBIOS domain name
    0x0003: "MsvAvDnsComputerName",   # DNS computer name (FQDN)
    0x0004: "MsvAvDnsDomainName",     # DNS domain name (FQDN)
    0x0005: "MsvAvDnsTreeName",       # DNS tree name (forest)
    0x0006: "MsvAvFlags",             # Flags
    0x0007: "MsvAvTimestamp",         # FILETIME timestamp
    0x0008: "MsvAvSingleHost",        # Single-host data
    0x0009: "MsvAvTargetName",        # Target name (UPN / SPN)
    0x000A: "MsvAvChannelBindings",   # Channel bindings hash
}

# ── Samba signal ──────────────────────────────────────────────────────────
# Samba (Linux / Unix) typically returns an all-zero ServerGUID in the
# NEGOTIATE response body.  This is a reliable heuristic.
SAMBA_NULL_GUID: bytes = b"\x00" * 16

# ── Known Samba version banner substrings ─────────────────────────────────
# Appear in sysDescr (SNMP) or sometimes HTTP Server headers on NAS devices.
SAMBA_BANNERS: list[str] = [
    "samba",
    "smbd",
    "cifs",
]

# ── SMB signing / encryption matrix ──────────────────────────────────────
# Minimum dialect required for each security feature.
SMB_FEATURE_MIN_DIALECT: dict[str, str] = {
    "signing_required":       "NT LM 0.12",  # Supported from NT-dialect SMB1
    "encryption":             "SMB 3.0",     # SMB3 added AES-128-CCM encryption
    "pre_auth_integrity":     "SMB 3.1.1",   # SHA-512 pre-auth hash (Win10+)
    "compression":            "SMB 3.1.1",   # LZ77 / LZ77+Huffman / LZNT1
    "rdma":                   "SMB 3.0",     # SMB Direct / RDMA transport
    "multichannel":           "SMB 3.0",     # Multiple network paths
    "persistent_handles":     "SMB 3.0",     # Transparent failover
    "directory_leasing":      "SMB 2.1",
    "large_mtu":              "SMB 2.1",
}
