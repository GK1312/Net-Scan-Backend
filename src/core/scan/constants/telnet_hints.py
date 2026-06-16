from __future__ import annotations

# Telnet banner fingerprint tables.
#
# Telnet (port 23) servers send a banner immediately after the TCP connection
# is established, before any login prompt. The raw bytes include IAC (0xFF)
# negotiation sequences mixed with ASCII text.
#
# Two signals:
#   BANNER_HINTS  — substring search in the stripped banner → (platform, os_hint)
#   PROMPT_HINTS  — login / shell prompt patterns → (platform, os_hint)
#
# All matches are case-insensitive. First match wins.


# ── Banner substrings → (platform, os_hint) ───────────────────────────────
# Matched against the decoded banner text (IAC bytes stripped / ignored).
BANNER_HINTS: list[tuple[str, str, str]] = [
    # ── Cisco IOS / IOS-XE / IOS-XR ──────────────────────────────────────
    ("cisco ios xe",            "network_device", "Cisco IOS-XE"),
    ("cisco ios xr",            "network_device", "Cisco IOS-XR"),
    ("cisco ios",               "network_device", "Cisco IOS"),
    ("cisco",                   "network_device", "Cisco"),
    ("user access verification","network_device", "Cisco (login banner)"),
    # ── Juniper JunOS ────────────────────────────────────────────────────
    ("junos",                   "network_device", "Juniper JunOS"),
    ("juniper",                 "network_device", "Juniper"),
    # ── Huawei VRP ───────────────────────────────────────────────────────
    ("huawei",                  "network_device", "Huawei VRP"),
    ("vrp software",            "network_device", "Huawei VRP"),
    # ── MikroTik RouterOS ────────────────────────────────────────────────
    ("mikrotik",                "network_device", "MikroTik RouterOS"),
    ("routeros",                "network_device", "MikroTik RouterOS"),
    # ── Zyxel ────────────────────────────────────────────────────────────
    ("zyxel",                   "network_device", "Zyxel"),
    ("zywall",                  "network_device", "Zyxel ZyWALL"),
    # ── HP ProCurve / Aruba ──────────────────────────────────────────────
    ("hp procurve",             "network_device", "HP ProCurve switch"),
    ("procurve",                "network_device", "HP ProCurve switch"),
    ("aruba",                   "wifi_ap",        "Aruba Networks"),
    # ── Fortinet ─────────────────────────────────────────────────────────
    ("fortigate",               "network_device", "Fortinet FortiGate"),
    ("fortios",                 "network_device", "Fortinet FortiOS"),
    ("fortinet",                "network_device", "Fortinet"),
    # ── D-Link ────────────────────────────────────────────────────────────
    ("d-link",                  "wifi_ap",        "D-Link device"),
    # ── TP-Link ───────────────────────────────────────────────────────────
    ("tp-link",                 "wifi_ap",        "TP-Link device"),
    # ── Netgear ───────────────────────────────────────────────────────────
    ("netgear",                 "wifi_ap",        "Netgear device"),
    # ── Linux distributions ───────────────────────────────────────────────
    ("ubuntu",                  "linux",          "Ubuntu Linux"),
    ("debian",                  "linux",          "Debian Linux"),
    ("centos",                  "linux",          "CentOS Linux"),
    ("red hat",                 "linux",          "Red Hat Enterprise Linux"),
    ("fedora",                  "linux",          "Fedora Linux"),
    ("suse",                    "linux",          "SUSE Linux"),
    ("alpine",                  "linux",          "Alpine Linux"),
    ("raspbian",                "linux",          "Raspberry Pi OS"),
    ("raspberry pi",            "iot",            "Raspberry Pi"),
    ("openwrt",                 "wifi_ap",        "OpenWrt router"),
    ("dd-wrt",                  "wifi_ap",        "DD-WRT router"),
    ("busybox",                 "linux",          "BusyBox (embedded Linux)"),
    ("linux",                   "linux",          "Linux"),
    # ── macOS / Darwin ────────────────────────────────────────────────────
    ("darwin",                  "macos",          "macOS"),
    ("mac os x",                "macos",          "macOS (Mac OS X)"),
    # ── Windows ───────────────────────────────────────────────────────────
    ("microsoft windows",       "windows",        "Windows Telnet server"),
    ("windows",                 "windows",        "Windows"),
    # ── FreeBSD / BSD ─────────────────────────────────────────────────────
    ("freebsd",                 "linux",          "FreeBSD"),
    ("openbsd",                 "linux",          "OpenBSD"),
    ("netbsd",                  "linux",          "NetBSD"),
    # ── Solaris ───────────────────────────────────────────────────────────
    ("solaris",                 "linux",          "Oracle Solaris"),
    ("sunos",                   "linux",          "SunOS / Oracle Solaris"),
    # ── VMware ────────────────────────────────────────────────────────────
    ("vmware",                  "vmware_esxi",    "VMware ESXi"),
    ("esxi",                    "vmware_esxi",    "VMware ESXi"),
    # ── NAS devices ───────────────────────────────────────────────────────
    ("synology",                "linux",          "Synology NAS"),
    ("qnap",                    "linux",          "QNAP NAS"),
    # ── IP cameras / IoT ──────────────────────────────────────────────────
    ("hikvision",               "iot",            "Hikvision IP camera"),
    ("dahua",                   "iot",            "Dahua IP camera"),
    ("axis",                    "iot",            "Axis device"),
    ("ip camera",               "iot",            "IP camera"),
    # ── Printers ──────────────────────────────────────────────────────────
    ("jetdirect",               "printer",        "HP JetDirect"),
    ("hp laserjet",             "printer",        "HP LaserJet"),
    ("epson",                   "printer",        "Epson printer"),
    ("brother",                 "printer",        "Brother printer"),
    # ── SCADA / industrial ────────────────────────────────────────────────
    ("scada",                   "iot",            "SCADA / ICS device"),
    ("plc",                     "iot",            "PLC (industrial controller)"),
    ("siemens",                 "iot",            "Siemens industrial device"),
    ("schneider",               "iot",            "Schneider Electric device"),
    ("rockwell",                "iot",            "Rockwell Automation device"),
]

# ── Login / shell prompt patterns → (platform, os_hint) ───────────────────
# These appear after the banner, when the server awaits input.
# Matched as substrings (case-insensitive).
PROMPT_HINTS: list[tuple[str, str, str]] = [
    # Cisco
    ("username:",               "network_device", "Cisco-style login"),
    ("password:",               "network_device", "Network device login"),
    (">",                       "network_device", "Cisco user EXEC prompt"),
    ("#",                       "network_device", "Cisco privileged EXEC prompt"),
    # Unix / Linux
    ("$ ",                      "linux",          "Unix/Linux shell prompt"),
    ("# ",                      "linux",          "Unix/Linux root shell prompt"),
    ("login:",                  "linux",          "Unix/Linux login prompt"),
    ("% ",                      "macos",          "Zsh / csh prompt (macOS/BSD)"),
    # Windows
    ("c:\\",                    "windows",        "Windows command prompt"),
    ("c:/",                     "windows",        "Windows command prompt"),
    # MikroTik
    ("[admin@",                 "network_device", "MikroTik RouterOS prompt"),
    # JunOS
    ("root@",                   "network_device", "JunOS root shell"),
    # FortiGate
    ("fortigate",               "network_device", "FortiGate prompt"),
]

# ── Telnet IAC (Interpret As Command) byte ────────────────────────────────
# IAC sequences precede option negotiation. Strip these when parsing the banner.
TELNET_IAC     = 0xFF   # IAC byte
TELNET_WILL    = 0xFB   # WILL option
TELNET_WONT    = 0xFC   # WON'T option
TELNET_DO      = 0xFD   # DO option
TELNET_DONT    = 0xFE   # DON'T option
TELNET_SB      = 0xFA   # Subnegotiation Begin
TELNET_SE      = 0xF0   # Subnegotiation End

# Common Telnet options negotiated during connection
TELNET_OPT_ECHO        = 0x01
TELNET_OPT_SUPPRESS_GA = 0x03
TELNET_OPT_STATUS      = 0x05
TELNET_OPT_TIMING_MARK = 0x06
TELNET_OPT_TERMINAL    = 0x18   # Terminal Type
TELNET_OPT_WINDOW_SIZE = 0x1F   # NAWS
TELNET_OPT_SPEED       = 0x20   # Terminal Speed
TELNET_OPT_FLOW        = 0x21   # Remote Flow Control
TELNET_OPT_LINEMODE    = 0x22
TELNET_OPT_ENV         = 0x24   # Environment Variables
TELNET_OPT_AUTH        = 0x25   # Authentication Option
TELNET_OPT_NEW_ENV     = 0x27   # New Environment Option
