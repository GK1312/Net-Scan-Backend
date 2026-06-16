from __future__ import annotations

# SNMP fingerprint tables.
#
# Two signals:
#   ENTERPRISE_HINTS — sysObjectID enterprise number → (platform, manufacturer)
#   SYSDESCR_HINTS   — sysDescr substring → (platform, os_hint)
#
# sysObjectID format: 1.3.6.1.4.1.<enterprise>.<model>...
# Extract enterprise with: int(oid.split(".")[6])
#
# Reference: https://www.iana.org/assignments/enterprise-numbers/


# ── Enterprise number → (platform, manufacturer_hint) ─────────────────────
ENTERPRISE_HINTS: dict[int, tuple[str, str]] = {
    # ── Major networking vendors ───────────────────────────────────────────
    2:     ("linux",          "IBM"),
    9:     ("network_device", "Cisco"),                  # Cisco Systems
    11:    ("printer",        "HP"),                     # HP / Hewlett-Packard
    25:    ("network_device", "Cabletron / Enterasys"),
    36:    ("network_device", "DEC / Compaq"),
    42:    ("linux",          "Sun Microsystems / Oracle"),
    43:    ("network_device", "3Com"),
    49:    ("network_device", "Proteon"),
    94:    ("network_device", "Wellfleet / Bay Networks / Nortel"),
    111:   ("linux",          "Oracle / Sun"),
    116:   ("network_device", "Xyplex"),
    171:   ("wifi_ap",        "D-Link"),
    207:   ("network_device", "Allied Telesis / Allied Telesyn"),
    232:   ("printer",        "Compaq / HP Servers"),
    244:   ("iot",            "Lantronix"),
    253:   ("printer",        "Xerox"),
    311:   ("windows",        "Microsoft"),
    318:   ("iot",            "APC / Schneider Electric (UPS)"),
    333:   ("network_device", "Xylan / Alcatel"),
    334:   ("network_device", "Alcatel-Lucent"),
    343:   ("network_device", "Ascend Communications / Lucent"),
    351:   ("network_device", "Fujitsu"),
    362:   ("network_device", "IBM / Cisco"),
    367:   ("printer",        "Ricoh"),
    368:   ("iot",            "Axis Communications"),        # Axis IP cameras
    534:   ("iot",            "Eaton (UPS)"),
    674:   ("network_device", "Dell Networking"),
    890:   ("network_device", "Zyxel"),
    1004:  ("network_device", "Allied Telesis"),
    1008:  ("iot",            "Dahua Technology"),
    1011:  ("network_device", "Cabletron Systems"),
    1119:  ("linux",          "Stratus Technologies"),
    1248:  ("printer",        "Seiko Epson"),
    1347:  ("printer",        "Kyocera"),
    1369:  ("printer",        "Lexmark"),
    1466:  ("network_device", "Bintec"),
    1588:  ("network_device", "Brocade Communications"),
    1602:  ("printer",        "Canon"),
    1637:  ("network_device", "Netopia / Motorola"),
    1795:  ("linux",          "FreeBSD Project"),
    1811:  ("iot",            "Raritan (KVM / PDU)"),
    1916:  ("network_device", "Extreme Networks"),
    1935:  ("linux",          "OpenBSD Project"),
    1978:  ("network_device", "Netscout"),
    2011:  ("network_device", "Huawei Technologies"),
    2232:  ("network_device", "Avocent / Vertiv (KVM)"),
    2312:  ("linux",          "Red Hat"),
    2435:  ("printer",        "Brother Industries"),
    2544:  ("network_device", "Packeteer"),
    2636:  ("network_device", "Juniper Networks"),
    2699:  ("network_device", "Dell Force10"),
    2925:  ("linux",          "Debian Project"),
    3076:  ("linux",          "Novell"),
    3224:  ("network_device", "Fortinet"),                  # FortiGate
    3375:  ("network_device", "F5 Networks"),               # BIG-IP / TMOS
    3764:  ("network_device", "TP-Link Technologies"),
    3955:  ("wifi_ap",        "Linksys / Cisco-Linksys"),
    4113:  ("network_device", "Motorola Solutions"),
    4526:  ("wifi_ap",        "Netgear"),
    4562:  ("linux",          "Mandriva / Mageia Linux"),
    4874:  ("network_device", "Foundry Networks / Brocade"),
    5624:  ("network_device", "Enterasys Networks"),
    5771:  ("printer",        "Zebra Technologies"),        # Label printers
    6027:  ("network_device", "Force10 Networks / Dell"),
    6141:  ("printer",        "Lexmark International"),
    6486:  ("network_device", "Alcatel-Lucent Enterprise"),
    6574:  ("linux",          "Synology"),                  # DSM NAS
    6876:  ("vmware_esxi",    "VMware"),
    7745:  ("network_device", "Avaya"),
    7779:  ("network_device", "Meru Networks"),
    8072:  ("linux",          "Net-SNMP"),                  # Most Linux/Unix via net-snmp
    9148:  ("network_device", "Check Point Software"),
    9694:  ("network_device", "Palo Alto Networks"),
    11863: ("network_device", "Ruckus Wireless"),
    12356: ("network_device", "Fortinet"),                  # Alternate enterprise
    14179: ("wifi_ap",        "Cisco / Airespace WLC"),
    14529: ("linux",          "SUSE Linux"),
    14823: ("wifi_ap",        "Aruba Networks / HPE"),
    14988: ("network_device", "MikroTik"),
    17163: ("network_device", "Aerohive Networks"),
    17551: ("linux",          "Oracle Linux"),
    18334: ("printer",        "Konica Minolta"),
    20301: ("linux",          "Amazon Web Services"),
    24681: ("linux",          "QNAP Systems"),
    25053: ("wifi_ap",        "Ruckus Networks"),
    25461: ("network_device", "Palo Alto Networks"),
    30065: ("network_device", "Arista Networks"),
    38369: ("wifi_ap",        "Ubiquiti Networks"),
    41112: ("wifi_ap",        "Ubiquiti Networks (alt)"),
    50001: ("iot",            "Hikvision Digital Technology"),
}

# ── sysDescr substrings → (platform, os_hint) ─────────────────────────────
# Case-insensitive substring match; first match wins.
SYSDESCR_HINTS: list[tuple[str, str, str]] = [
    # ── Windows ───────────────────────────────────────────────────────────
    ("windows server 2025",   "windows",        "Windows Server 2025"),
    ("windows server 2022",   "windows",        "Windows Server 2022"),
    ("windows server 2019",   "windows",        "Windows Server 2019"),
    ("windows server 2016",   "windows",        "Windows Server 2016"),
    ("windows server 2012",   "windows",        "Windows Server 2012 / R2"),
    ("windows server 2008",   "windows",        "Windows Server 2008 / R2"),
    ("windows server 2003",   "windows",        "Windows Server 2003"),
    ("windows server 2000",   "windows",        "Windows Server 2000"),
    ("windows 11",            "windows",        "Windows 11"),
    ("windows 10",            "windows",        "Windows 10"),
    ("windows 8",             "windows",        "Windows 8 / 8.1"),
    ("windows 7",             "windows",        "Windows 7"),
    ("windows vista",         "windows",        "Windows Vista"),
    ("windows xp",            "windows",        "Windows XP"),
    ("windows 2000",          "windows",        "Windows 2000"),
    ("windows nt",            "windows",        "Windows NT"),
    ("microsoft",             "windows",        "Microsoft Windows"),
    ("windows",               "windows",        "Windows"),
    # ── Cisco ─────────────────────────────────────────────────────────────
    ("cisco ios xr",          "network_device", "Cisco IOS-XR"),
    ("cisco ios-xe",          "network_device", "Cisco IOS-XE"),
    ("cisco ios xe",          "network_device", "Cisco IOS-XE"),
    ("cisco nx-os",           "network_device", "Cisco NX-OS"),
    ("cisco nxos",            "network_device", "Cisco NX-OS"),
    ("cisco asa",             "network_device", "Cisco ASA"),
    ("cisco fxos",            "network_device", "Cisco FX-OS"),
    ("cisco ios",             "network_device", "Cisco IOS"),
    ("cisco",                 "network_device", "Cisco"),
    # ── Juniper ───────────────────────────────────────────────────────────
    ("junos",                 "network_device", "Juniper JunOS"),
    ("juniper",               "network_device", "Juniper"),
    # ── Palo Alto ─────────────────────────────────────────────────────────
    ("pan-os",                "network_device", "Palo Alto PAN-OS"),
    ("panos",                 "network_device", "Palo Alto PAN-OS"),
    # ── Fortinet ──────────────────────────────────────────────────────────
    ("fortigate",             "network_device", "Fortinet FortiGate"),
    ("fortios",               "network_device", "Fortinet FortiOS"),
    ("fortinet",              "network_device", "Fortinet"),
    # ── F5 ────────────────────────────────────────────────────────────────
    ("big-ip",                "network_device", "F5 BIG-IP"),
    ("tmos",                  "network_device", "F5 TMOS"),
    # ── Check Point ───────────────────────────────────────────────────────
    ("gaia",                  "network_device", "Check Point Gaia"),
    ("check point",           "network_device", "Check Point"),
    # ── HP ProCurve / Aruba ───────────────────────────────────────────────
    ("hp procurve",           "network_device", "HP ProCurve"),
    ("procurve",              "network_device", "HP ProCurve"),
    ("arubaos",               "wifi_ap",        "Aruba ArubaOS"),
    ("aruba",                 "wifi_ap",        "Aruba Networks"),
    # ── MikroTik ──────────────────────────────────────────────────────────
    ("routeros",              "network_device", "MikroTik RouterOS"),
    ("mikrotik",              "network_device", "MikroTik"),
    # ── Ubiquiti ──────────────────────────────────────────────────────────
    ("airos",                 "wifi_ap",        "Ubiquiti AirOS"),
    ("ubiquiti",              "wifi_ap",        "Ubiquiti"),
    ("unifi",                 "wifi_ap",        "Ubiquiti UniFi"),
    # ── Zyxel ─────────────────────────────────────────────────────────────
    ("zyxel",                 "network_device", "Zyxel"),
    ("zywall",                "network_device", "Zyxel ZyWALL"),
    # ── Huawei ────────────────────────────────────────────────────────────
    ("huawei vrp",            "network_device", "Huawei VRP"),
    ("huawei",                "network_device", "Huawei"),
    # ── VMware ────────────────────────────────────────────────────────────
    ("vmware esxi",           "vmware_esxi",    "VMware ESXi"),
    ("esxi",                  "vmware_esxi",    "VMware ESXi"),
    ("vmware",                "vmware_esxi",    "VMware"),
    # ── Linux distros ─────────────────────────────────────────────────────
    ("ubuntu",                "linux",          "Ubuntu Linux"),
    ("debian",                "linux",          "Debian Linux"),
    ("centos",                "linux",          "CentOS Linux"),
    ("red hat",               "linux",          "Red Hat Enterprise Linux"),
    ("rhel",                  "linux",          "Red Hat Enterprise Linux"),
    ("fedora",                "linux",          "Fedora Linux"),
    ("suse",                  "linux",          "SUSE / openSUSE Linux"),
    ("oracle linux",          "linux",          "Oracle Linux"),
    ("amazon linux",          "linux",          "Amazon Linux"),
    ("arch linux",            "linux",          "Arch Linux"),
    ("alpine",                "linux",          "Alpine Linux"),
    ("freebsd",               "linux",          "FreeBSD"),
    ("openbsd",               "linux",          "OpenBSD"),
    ("netbsd",                "linux",          "NetBSD"),
    ("linux",                 "linux",          "Linux"),
    # ── macOS / Darwin ────────────────────────────────────────────────────
    ("darwin",                "macos",          "macOS (Darwin)"),
    ("macos",                 "macos",          "macOS"),
    ("mac os x",              "macos",          "macOS (Mac OS X)"),
    # ── Net-SNMP (generic Linux/Unix agent) ──────────────────────────────
    ("net-snmp",              "linux",          "Net-SNMP agent (Linux/Unix)"),
    # ── NAS ───────────────────────────────────────────────────────────────
    ("synology",              "linux",          "Synology NAS (DSM)"),
    ("qnap",                  "linux",          "QNAP NAS (QTS)"),
    ("freenas",               "linux",          "FreeNAS"),
    ("truenas",               "linux",          "TrueNAS"),
    # ── Printers ──────────────────────────────────────────────────────────
    ("hp laserjet",           "printer",        "HP LaserJet"),
    ("hp officejet",          "printer",        "HP OfficeJet"),
    ("hp color laserjet",     "printer",        "HP Color LaserJet"),
    ("jetdirect",             "printer",        "HP JetDirect"),
    ("epson",                 "printer",        "Epson Printer"),
    ("brother",               "printer",        "Brother Printer"),
    ("canon",                 "printer",        "Canon Printer"),
    ("ricoh",                 "printer",        "Ricoh Printer"),
    ("xerox",                 "printer",        "Xerox Printer"),
    ("kyocera",               "printer",        "Kyocera Printer"),
    ("konica minolta",        "printer",        "Konica Minolta Printer"),
    ("lexmark",               "printer",        "Lexmark Printer"),
    ("zebra",                 "printer",        "Zebra Label Printer"),
    # ── IP cameras ────────────────────────────────────────────────────────
    ("hikvision",             "iot",            "Hikvision IP Camera"),
    ("dahua",                 "iot",            "Dahua IP Camera"),
    ("axis",                  "iot",            "Axis IP Camera"),
    # ── UPS / power ───────────────────────────────────────────────────────
    ("apc",                   "iot",            "APC UPS"),
    ("eaton",                 "iot",            "Eaton UPS"),
    ("cyberpower",            "iot",            "CyberPower UPS"),
    # ── Other embedded / IoT ──────────────────────────────────────────────
    ("android",               "mobile",         "Android"),
]
