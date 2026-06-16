from __future__ import annotations

# VMware Authentication Daemon (vmware-authd) fingerprint tables.
#
# vmware-authd listens on TCP port 902. After a connection it immediately
# sends a greeting banner, then waits for authentication.
#
# Two signals:
#   BANNER_KEYWORDS  — substrings in the banner that confirm VMware
#   VERSION_PATTERN  — regex pattern (as raw string) to extract the ESXi version
#
# Reference: VMware ESXi greeting format:
#   "220 VMware Authentication Daemon Version 1.10: SSL Required, …"
#   "220 VMware Authentication Daemon Version 1.00 …"


# ── Banner keywords (presence of any → vmware_esxi) ───────────────────────
BANNER_KEYWORDS: tuple[str, ...] = (
    "vmware",
    "vmware authentication daemon",
    "esx",
    "esxi",
    "vmauthd",
    "vcenter",
    "vsphere",
)

# ── Known greeting formats and version strings ─────────────────────────────
# Format: (greeting_prefix, esxi_generation)
GREETING_PATTERNS: list[tuple[str, str]] = [
    ("220 vmware authentication daemon version 1.10", "ESXi 5.0+"),
    ("220 vmware authentication daemon version 1.00", "ESXi 4.x"),
    ("220 vmware authentication daemon",              "VMware ESXi (version unknown)"),
    ("220 esx",                                       "VMware ESX / ESXi"),
    ("220 esxi",                                      "VMware ESXi"),
]

# ── Regex (raw string) to extract version from banner ─────────────────────
# Captures the daemon version number, e.g. "1.10" from the greeting above.
DAEMON_VERSION_RE = r"version\s+([\d.]+)"

# ── ESXi release history (daemon version → ESXi release) ──────────────────
# Maps the vmware-authd daemon version to the ESXi product version.
DAEMON_VERSION_TO_ESXI: dict[str, str] = {
    "1.00": "ESXi 4.0 / 4.1",
    "1.10": "ESXi 5.0 / 5.1 / 5.5 / 6.0 / 6.5 / 6.7 / 7.0 / 8.0",
}

# ── ESXi version history ───────────────────────────────────────────────────
# Format: (build_range_description, product_version, release_year)
ESXI_VERSIONS: list[tuple[str, str, str]] = [
    ("ESXi 8.0",   "vSphere 8",   "2022"),
    ("ESXi 7.0",   "vSphere 7",   "2020"),
    ("ESXi 6.7",   "vSphere 6.7", "2018"),
    ("ESXi 6.5",   "vSphere 6.5", "2016"),
    ("ESXi 6.0",   "vSphere 6.0", "2015"),
    ("ESXi 5.5",   "vSphere 5.5", "2013"),
    ("ESXi 5.1",   "vSphere 5.1", "2012"),
    ("ESXi 5.0",   "vSphere 5.0", "2011"),
    ("ESXi 4.1",   "vSphere 4.1", "2010"),
    ("ESXi 4.0",   "vSphere 4.0", "2009"),
    ("ESXi 3.5",   "VI 3.5",      "2007"),
]

# ── Port 902 protocol notes ────────────────────────────────────────────────
# Port 902 is used for:
#   - vmware-authd (VMware Authentication Daemon) — TCP, server sends banner
#   - VMware vSphere API (alternative) — HTTPS, used in newer ESXi
#   - IANA registered name: "iss-realsecure" — ignore this; in practice it's VMware
#
# If the banner does NOT contain VMware keywords but the port is 902,
# fall back to a weaker "possibly VMware" signal.
PORT_902_FALLBACK_HINT = "possibly VMware (port 902)"

# ── VMware MAC address OUI prefixes ───────────────────────────────────────
# Virtual machines created by VMware get MAC addresses in these ranges.
# Seeing one of these OUIs via ARP means the host is a VM guest, not ESXi itself.
VMWARE_VM_OUI_PREFIXES: tuple[str, ...] = (
    "00:05:69",  # VMware (legacy)
    "00:0C:29",  # VMware (most common VM range)
    "00:1C:14",  # VMware
    "00:50:56",  # VMware vSphere / Workstation (static MAC range)
)
