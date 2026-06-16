from __future__ import annotations

# SSH banner fingerprint tables.
#
# The SSH banner is the first line sent by the server during the protocol
# version exchange, e.g.:
#   "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3"
#
# Two-stage lookup (applied in order):
#   1. PREFIX_HINTS  — exact lowercased prefix match (fastest)
#   2. SUBSTRING_HINTS — ordered substring scan of the lowercased banner
#
# Each entry resolves to (platform, os_hint).
# platform must be one of the PLATFORMS list in scoring.py.


# ── Protocol version strings ───────────────────────────────────────────────
SSH_PROTO_2   = "SSH-2.0-"
SSH_PROTO_1   = "SSH-1.5-"
SSH_PROTO_199 = "SSH-1.99-"   # Server supports both SSHv1 and SSHv2

# ── Prefix → (platform, os_hint) ─────────────────────────────────────────
# Key is the lowercased prefix of the banner string.
# Matched before SUBSTRING_HINTS for speed and precision.
PREFIX_HINTS: dict[str, tuple[str, str]] = {
    # ── OpenSSH for Windows (bundled with Windows 10 1809+ / Server 2019+) ─
    "ssh-2.0-openssh_for_windows":       ("windows",        "Windows OpenSSH"),
    "ssh-2.0-openssh_for_windows_":      ("windows",        "Windows OpenSSH"),
    # ── Bitvise SSH Server (Windows) ──────────────────────────────────────
    "ssh-2.0-bitvise":                   ("windows",        "Bitvise SSH Server (Windows)"),
    # ── WeOnlyDo (Windows) ────────────────────────────────────────────────
    "ssh-2.0-weonlydo":                  ("windows",        "WeOnlyDo SSH Server (Windows)"),
    # ── Cerberus FTP (Windows) ────────────────────────────────────────────
    "ssh-2.0-cerberus_ftp":              ("windows",        "Cerberus FTP Server (Windows)"),
    # ── Rebex (Windows .NET) ──────────────────────────────────────────────
    "ssh-2.0-rebex":                     ("windows",        "Rebex SSH (Windows .NET)"),
    # ── CompleteFTP (Windows) ─────────────────────────────────────────────
    "ssh-2.0-completeftp":               ("windows",        "CompleteFTP (Windows)"),
    # ── Dropbear — embedded Linux (routers, NAS, IoT, Android) ───────────
    "ssh-2.0-dropbear":                  ("linux",          "Dropbear SSH (embedded Linux)"),
    "ssh-1.99-dropbear":                 ("linux",          "Dropbear SSH (embedded Linux)"),
    # ── Cisco IOS / IOS-XE / IOS-XR ──────────────────────────────────────
    "ssh-1.99-cisco-":                   ("network_device", "Cisco IOS"),
    "ssh-2.0-cisco-":                    ("network_device", "Cisco IOS / IOS-XE"),
    "ssh-1.99-cisco_":                   ("network_device", "Cisco IOS"),
    "ssh-2.0-cisco_":                    ("network_device", "Cisco IOS"),
    # ── Cisco ASA ─────────────────────────────────────────────────────────
    "ssh-2.0-cisco_asa":                 ("network_device", "Cisco ASA"),
    # ── Cisco NX-OS ───────────────────────────────────────────────────────
    "ssh-2.0-cisco_nx":                  ("network_device", "Cisco NX-OS"),
    # ── Juniper JunOS ─────────────────────────────────────────────────────
    "ssh-2.0-openssh_junos":             ("network_device", "Juniper JunOS"),
    "ssh-2.0-junos":                     ("network_device", "Juniper JunOS"),
    # ── MikroTik RouterOS ─────────────────────────────────────────────────
    "ssh-2.0-mpssh":                     ("network_device", "MikroTik RouterOS"),
    "ssh-2.0-mpssh_":                    ("network_device", "MikroTik RouterOS"),
    # ── Fortinet FortiGate ────────────────────────────────────────────────
    "ssh-2.0-fortissh":                  ("network_device", "Fortinet FortiGate"),
    # ── Palo Alto PAN-OS ──────────────────────────────────────────────────
    "ssh-2.0-panos":                     ("network_device", "Palo Alto PAN-OS"),
    # ── Huawei VRP ───────────────────────────────────────────────────────
    "ssh-2.0-huawei-":                   ("network_device", "Huawei VRP"),
    "ssh-1.99-huawei-":                  ("network_device", "Huawei VRP"),
    # ── HP ProCurve / Aruba ArubaOS ──────────────────────────────────────
    "ssh-2.0-hpbsd":                     ("network_device", "HP ProCurve / Aruba"),
    "ssh-2.0-hp-":                       ("network_device", "HP ProCurve"),
    # ── Zyxel ─────────────────────────────────────────────────────────────
    "ssh-2.0-zssh":                      ("network_device", "Zyxel"),
    # ── Arista EOS ────────────────────────────────────────────────────────
    "ssh-2.0-arista_":                   ("network_device", "Arista EOS"),
    # ── Ubiquiti AirOS / EdgeOS ───────────────────────────────────────────
    "ssh-2.0-openssh_ubnt":              ("wifi_ap",        "Ubiquiti AirOS"),
    # ── Ubiquiti UniFi AP ─────────────────────────────────────────────────
    "ssh-2.0-openssh_unifi":             ("wifi_ap",        "Ubiquiti UniFi"),
    # ── VMware ESXi ───────────────────────────────────────────────────────
    "ssh-2.0-openssh_esxi":              ("vmware_esxi",    "VMware ESXi"),
    # ── libssh ────────────────────────────────────────────────────────────
    "ssh-2.0-libssh_":                   ("linux",          "libssh"),
    "ssh-2.0-libssh2":                   ("linux",          "libssh2"),
    "ssh-0.0-libssh":                    ("linux",          "libssh (pre-release)"),
    # ── AsyncSSH (Python) ─────────────────────────────────────────────────
    "ssh-2.0-asyncssh_":                 ("linux",          "AsyncSSH (Python)"),
    # ── Paramiko (Python) ─────────────────────────────────────────────────
    "ssh-2.0-paramiko_":                 ("linux",          "Paramiko (Python)"),
    # ── Go golang.org/x/crypto/ssh ────────────────────────────────────────
    "ssh-2.0-go":                        ("linux",          "Go crypto/ssh"),
    # ── Twisted (Python) ──────────────────────────────────────────────────
    "ssh-2.0-twisted_":                  ("linux",          "Twisted SSH (Python)"),
    # ── Apache MINA sshd (Java) ───────────────────────────────────────────
    "ssh-2.0-apache-sshd-":              ("linux",          "Apache MINA SSHd (Java)"),
    # ── Jsch (Java) ───────────────────────────────────────────────────────
    "ssh-2.0-jsch-":                     ("linux",          "JSch (Java)"),
    # ── OpenSSH (generic — refined by SUBSTRING_HINTS distro suffix) ──────
    "ssh-2.0-openssh_":                  ("linux",          "OpenSSH"),
    "ssh-1.99-openssh_":                 ("linux",          "OpenSSH (SSH1/2 compat)"),
    # ── Legacy protocol versions ──────────────────────────────────────────
    "ssh-1.5-":                          ("linux",          "SSH-1 server (legacy)"),
    "ssh-1.99-":                         ("linux",          "SSH-1/2 compatible server (legacy)"),
}

# ── Substring hints — ordered; first match wins ───────────────────────────
# Applied (case-insensitively) to the full banner string after PREFIX_HINTS fails.
SUBSTRING_HINTS: list[tuple[str, str, str]] = [
    # Windows-specific strings
    ("for_windows",          "windows",        "Windows OpenSSH"),
    ("bitvise",              "windows",        "Bitvise SSH Server (Windows)"),
    ("weonlydo",             "windows",        "WeOnlyDo SSH Server (Windows)"),
    ("cerberus",             "windows",        "Cerberus FTP (Windows)"),
    ("completeftp",          "windows",        "CompleteFTP (Windows)"),
    ("cygwin",               "windows",        "Cygwin SSH (Windows)"),
    # Linux distro suffixes (OpenSSH appends these in the version string)
    ("ubuntu",               "linux",          "Ubuntu Linux"),
    ("debian",               "linux",          "Debian Linux"),
    ("raspbian",             "linux",          "Raspberry Pi OS (Raspbian)"),
    ("raspberrypi",          "linux",          "Raspberry Pi OS"),
    ("fedora",               "linux",          "Fedora Linux"),
    ("centos",               "linux",          "CentOS Linux"),
    ("rhel",                 "linux",          "Red Hat Enterprise Linux"),
    ("redhat",               "linux",          "Red Hat Enterprise Linux"),
    ("amzn",                 "linux",          "Amazon Linux"),
    ("amazon",               "linux",          "Amazon Linux"),
    ("alpine",               "linux",          "Alpine Linux"),
    ("archlinux",            "linux",          "Arch Linux"),
    ("gentoo",               "linux",          "Gentoo Linux"),
    ("suse",                 "linux",          "SUSE Linux"),
    ("opensuse",             "linux",          "openSUSE"),
    ("slackware",            "linux",          "Slackware Linux"),
    ("void",                 "linux",          "Void Linux"),
    ("nixos",                "linux",          "NixOS"),
    ("kali",                 "linux",          "Kali Linux"),
    ("parrot",               "linux",          "Parrot OS"),
    ("mint",                 "linux",          "Linux Mint"),
    ("manjaro",              "linux",          "Manjaro Linux"),
    ("pop_os",               "linux",          "Pop!_OS"),
    ("zorin",                "linux",          "Zorin OS"),
    ("elementary",           "linux",          "elementary OS"),
    # BSD / Darwin
    ("freebsd",              "linux",          "FreeBSD"),
    ("openbsd",              "linux",          "OpenBSD"),
    ("netbsd",               "linux",          "NetBSD"),
    ("dragonfly",            "linux",          "DragonFly BSD"),
    ("darwin",               "macos",          "macOS (Darwin)"),
    ("macos",                "macos",          "macOS"),
    ("ios",                  "mobile",         "Apple iOS"),
    # Network equipment vendor keywords
    ("cisco",                "network_device", "Cisco"),
    ("junos",                "network_device", "Juniper JunOS"),
    ("juniper",              "network_device", "Juniper"),
    ("routeros",             "network_device", "MikroTik RouterOS"),
    ("mikrotik",             "network_device", "MikroTik"),
    ("mpssh",                "network_device", "MikroTik RouterOS"),
    ("fortissh",             "network_device", "Fortinet FortiGate"),
    ("fortigate",            "network_device", "Fortinet FortiGate"),
    ("fortios",              "network_device", "Fortinet FortiOS"),
    ("panos",                "network_device", "Palo Alto PAN-OS"),
    ("zyxel",                "network_device", "Zyxel"),
    ("huawei",               "network_device", "Huawei"),
    ("vrp",                  "network_device", "Huawei VRP"),
    ("procurve",             "network_device", "HP ProCurve"),
    ("arubaos",              "network_device", "Aruba ArubaOS"),
    ("arista",               "network_device", "Arista EOS"),
    ("extreme",              "network_device", "Extreme Networks"),
    ("sonicwall",            "network_device", "SonicWall"),
    ("airos",                "wifi_ap",        "Ubiquiti AirOS"),
    ("ubnt",                 "wifi_ap",        "Ubiquiti"),
    ("unifi",                "wifi_ap",        "Ubiquiti UniFi"),
    ("edgeos",               "wifi_ap",        "Ubiquiti EdgeOS"),
    # VMware
    ("vmware",               "vmware_esxi",    "VMware ESXi"),
    ("esxi",                 "vmware_esxi",    "VMware ESXi"),
    # Embedded / IoT
    ("dropbear",             "linux",          "Dropbear SSH (embedded Linux)"),
    ("synology",             "linux",          "Synology NAS"),
    ("qnap",                 "linux",          "QNAP NAS"),
    ("hikvision",            "iot",            "Hikvision"),
    ("dahua",                "iot",            "Dahua"),
    ("axis",                 "iot",            "Axis"),
    # Generic "windows" keyword last (low priority)
    ("windows",              "windows",        "Windows"),
]
