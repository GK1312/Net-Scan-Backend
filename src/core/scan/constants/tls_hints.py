from __future__ import annotations

# TLS / X.509 certificate fingerprint tables.
#
# Three signals derived from TLS certificate fields:
#   CN_HINTS       — certificate Subject commonName → (platform, device_hint)
#   ISSUER_HINTS   — certificate Issuer commonName / O → (platform, org_hint)
#   SAN_HINTS      — Subject Alternative Name patterns → (platform, device_hint)
#
# All matches are case-insensitive substring matches. First match wins.


# ── Subject commonName substrings → (platform, device_hint) ───────────────
# The CN is what the server calls itself. Self-signed certs often contain
# device/product names that are strong fingerprinting signals.
CN_HINTS: list[tuple[str, str, str]] = [
    # ── Network equipment ─────────────────────────────────────────────────
    ("cisco",                   "network_device", "Cisco device"),
    ("cisco-asa",               "network_device", "Cisco ASA"),
    ("cisco asa",               "network_device", "Cisco ASA"),
    ("cisco firepower",         "network_device", "Cisco Firepower"),
    ("cisco meraki",            "wifi_ap",        "Cisco Meraki"),
    ("juniper",                 "network_device", "Juniper device"),
    ("junos",                   "network_device", "Juniper JunOS"),
    ("fortigate",               "network_device", "Fortinet FortiGate"),
    ("fortinet",                "network_device", "Fortinet"),
    ("palo alto",               "network_device", "Palo Alto Networks"),
    ("paloalto",                "network_device", "Palo Alto Networks"),
    ("panos",                   "network_device", "Palo Alto PAN-OS"),
    ("checkpoint",              "network_device", "Check Point"),
    ("check point",             "network_device", "Check Point"),
    ("f5-bigip",                "network_device", "F5 BIG-IP"),
    ("big-ip",                  "network_device", "F5 BIG-IP"),
    ("sonicwall",               "network_device", "SonicWall"),
    ("watchguard",              "network_device", "WatchGuard"),
    ("mikrotik",                "network_device", "MikroTik"),
    ("routeros",                "network_device", "MikroTik RouterOS"),
    ("zyxel",                   "network_device", "Zyxel"),
    ("barracuda",               "network_device", "Barracuda Networks"),
    ("huawei",                  "network_device", "Huawei"),
    ("netscaler",               "network_device", "Citrix NetScaler / ADC"),
    ("citrix",                  "network_device", "Citrix"),
    ("arista",                  "network_device", "Arista Networks"),
    ("extreme",                 "network_device", "Extreme Networks"),
    # ── Wi-Fi APs ─────────────────────────────────────────────────────────
    ("ubiquiti",                "wifi_ap",        "Ubiquiti device"),
    ("unifi",                   "wifi_ap",        "Ubiquiti UniFi"),
    ("airos",                   "wifi_ap",        "Ubiquiti AirOS"),
    ("netgear",                 "wifi_ap",        "Netgear"),
    ("tp-link",                 "wifi_ap",        "TP-Link"),
    ("asus",                    "wifi_ap",        "ASUS"),
    # ── VMware ────────────────────────────────────────────────────────────
    ("vmware",                  "vmware_esxi",    "VMware"),
    ("esxi",                    "vmware_esxi",    "VMware ESXi"),
    ("vcenter",                 "vmware_esxi",    "VMware vCenter"),
    ("vsphere",                 "vmware_esxi",    "VMware vSphere"),
    ("horizon",                 "vmware_esxi",    "VMware Horizon"),
    # ── Windows / Microsoft ───────────────────────────────────────────────
    ("windows",                 "windows",        "Windows"),
    ("microsoft",               "windows",        "Microsoft"),
    ("exchange",                "windows",        "Microsoft Exchange"),
    ("sharepoint",              "windows",        "Microsoft SharePoint"),
    ("outlook",                 "windows",        "Microsoft Outlook Web"),
    ("lync",                    "windows",        "Microsoft Lync / Skype for Business"),
    ("skype for business",      "windows",        "Microsoft Skype for Business"),
    ("iis",                     "windows",        "IIS (Windows)"),
    # ── Linux ─────────────────────────────────────────────────────────────
    ("ubuntu",                  "linux",          "Ubuntu Linux"),
    ("debian",                  "linux",          "Debian Linux"),
    ("centos",                  "linux",          "CentOS Linux"),
    ("fedora",                  "linux",          "Fedora Linux"),
    ("red hat",                 "linux",          "Red Hat Enterprise Linux"),
    # ── macOS ─────────────────────────────────────────────────────────────
    ("apple",                   "macos",          "Apple"),
    ("macos",                   "macos",          "macOS"),
    # ── NAS ───────────────────────────────────────────────────────────────
    ("synology",                "linux",          "Synology NAS"),
    ("qnap",                    "linux",          "QNAP NAS"),
    ("truenas",                 "linux",          "TrueNAS"),
    ("freenas",                 "linux",          "FreeNAS"),
    ("western digital",         "linux",          "Western Digital NAS"),
    # ── Printers ──────────────────────────────────────────────────────────
    ("hp laserjet",             "printer",        "HP LaserJet"),
    ("hp officejet",            "printer",        "HP OfficeJet"),
    ("hewlett",                 "printer",        "HP printer"),
    ("epson",                   "printer",        "Epson printer"),
    ("canon",                   "printer",        "Canon printer"),
    ("brother",                 "printer",        "Brother printer"),
    ("ricoh",                   "printer",        "Ricoh printer"),
    ("xerox",                   "printer",        "Xerox printer"),
    ("kyocera",                 "printer",        "Kyocera printer"),
    ("konica",                  "printer",        "Konica Minolta printer"),
    ("lexmark",                 "printer",        "Lexmark printer"),
    # ── IP cameras ────────────────────────────────────────────────────────
    ("hikvision",               "iot",            "Hikvision IP camera"),
    ("dahua",                   "iot",            "Dahua IP camera"),
    ("axis",                    "iot",            "Axis IP camera"),
    ("reolink",                 "iot",            "Reolink IP camera"),
    ("amcrest",                 "iot",            "Amcrest IP camera"),
    ("camera",                  "iot",            "IP camera"),
    ("ipcam",                   "iot",            "IP camera"),
    # ── IoT / embedded ────────────────────────────────────────────────────
    ("esp32",                   "iot",            "ESP32 device"),
    ("espressif",               "iot",            "Espressif (ESP32/ESP8266)"),
    ("raspberry",               "iot",            "Raspberry Pi"),
    ("shelly",                  "iot",            "Shelly IoT device"),
    ("homeassistant",           "iot",            "Home Assistant"),
    ("home assistant",          "iot",            "Home Assistant"),
    ("tasmota",                 "iot",            "Tasmota firmware"),
    # ── Web hosting / CDNs (these are NOT strong platform signals) ────────
    # Listed last because they indicate the cert is issued by a CA for a domain,
    # not a device-specific self-signed cert.
    ("cloudflare",              "linux",          "Cloudflare CDN"),
    ("amazon",                  "linux",          "Amazon AWS"),
    ("google",                  "linux",          "Google Cloud"),
    ("azure",                   "windows",        "Microsoft Azure"),
    ("digitalocean",            "linux",          "DigitalOcean"),
    ("linode",                  "linux",          "Linode / Akamai Cloud"),
    ("vultr",                   "linux",          "Vultr cloud"),
    ("hetzner",                 "linux",          "Hetzner cloud"),
]

# ── Issuer commonName / Organization → (platform, org_hint) ───────────────
# What CA or vendor signed this certificate?
# Self-signed certs from devices typically show the vendor name as issuer.
ISSUER_HINTS: list[tuple[str, str, str]] = [
    # ── Well-known public CAs → not a strong platform signal ──────────────
    ("let's encrypt",           "linux",          "Let's Encrypt (likely Linux server)"),
    ("digicert",                "linux",          "DigiCert CA"),
    ("comodo",                  "linux",          "Comodo / Sectigo CA"),
    ("sectigo",                 "linux",          "Sectigo CA"),
    ("globalsign",              "linux",          "GlobalSign CA"),
    ("geotrust",                "linux",          "GeoTrust CA"),
    ("entrust",                 "linux",          "Entrust CA"),
    ("godaddy",                 "linux",          "GoDaddy CA"),
    ("amazon",                  "linux",          "Amazon ACM CA"),
    ("google trust",            "linux",          "Google Trust Services CA"),
    ("microsoft",               "windows",        "Microsoft CA (likely Windows)"),
    ("verisign",                "linux",          "VeriSign CA"),
    ("thawte",                  "linux",          "Thawte CA"),
    # ── Vendor self-signed CAs (strong device fingerprint) ────────────────
    ("cisco",                   "network_device", "Cisco self-signed CA"),
    ("juniper",                 "network_device", "Juniper self-signed CA"),
    ("fortinet",                "network_device", "Fortinet self-signed CA"),
    ("fortigate",               "network_device", "FortiGate self-signed CA"),
    ("palo alto",               "network_device", "Palo Alto self-signed CA"),
    ("sonicwall",               "network_device", "SonicWall self-signed CA"),
    ("checkpoint",              "network_device", "Check Point self-signed CA"),
    ("f5",                      "network_device", "F5 self-signed CA"),
    ("bigip",                   "network_device", "F5 BIG-IP self-signed CA"),
    ("mikrotik",                "network_device", "MikroTik self-signed CA"),
    ("ubiquiti",                "wifi_ap",        "Ubiquiti self-signed CA"),
    ("vmware",                  "vmware_esxi",    "VMware self-signed CA"),
    ("synology",                "linux",          "Synology self-signed CA"),
    ("qnap",                    "linux",          "QNAP self-signed CA"),
    ("hikvision",               "iot",            "Hikvision self-signed CA"),
    ("dahua",                   "iot",            "Dahua self-signed CA"),
    ("axis",                    "iot",            "Axis self-signed CA"),
    ("hp",                      "printer",        "HP self-signed CA"),
    ("hewlett",                 "printer",        "HP self-signed CA"),
    ("brother",                 "printer",        "Brother self-signed CA"),
    ("epson",                   "printer",        "Epson self-signed CA"),
    ("canon",                   "printer",        "Canon self-signed CA"),
    ("ricoh",                   "printer",        "Ricoh self-signed CA"),
    ("xerox",                   "printer",        "Xerox self-signed CA"),
    ("kyocera",                 "printer",        "Kyocera self-signed CA"),
    ("konica",                  "printer",        "Konica Minolta self-signed CA"),
    ("lexmark",                 "printer",        "Lexmark self-signed CA"),
]

# ── Subject Alternative Name (SAN) patterns → (platform, device_hint) ────
# SANs are checked as case-insensitive substring matches against each SAN entry.
SAN_HINTS: list[tuple[str, str, str]] = [
    # Device-specific SANs (common in self-signed certs)
    ("hikvision",               "iot",            "Hikvision device"),
    ("dahua",                   "iot",            "Dahua device"),
    ("axis",                    "iot",            "Axis device"),
    ("camera",                  "iot",            "IP camera"),
    ("unifi",                   "wifi_ap",        "Ubiquiti UniFi"),
    ("ubnt",                    "wifi_ap",        "Ubiquiti"),
    ("vmware",                  "vmware_esxi",    "VMware"),
    ("esxi",                    "vmware_esxi",    "VMware ESXi"),
    ("synology",                "linux",          "Synology NAS"),
    ("qnap",                    "linux",          "QNAP NAS"),
    ("fortigate",               "network_device", "Fortinet FortiGate"),
    ("cisco",                   "network_device", "Cisco device"),
    ("mikrotik",                "network_device", "MikroTik"),
    ("pfsense",                 "network_device", "pfSense"),
    ("opnsense",                "network_device", "OPNsense"),
    ("homeassistant",           "iot",            "Home Assistant"),
    # IP address SANs are common in device certs — no platform signal
    # Domain name SANs from public CAs are also not useful here
]

# ── TLS protocol version → security posture ───────────────────────────────
# Older TLS versions are weak signals for older/embedded devices.
TLS_VERSION_HINTS: dict[str, str] = {
    "SSLv2":   "Very old / misconfigured — likely legacy embedded device",
    "SSLv3":   "Old — POODLE-vulnerable; likely legacy embedded device",
    "TLSv1":   "Old (2000) — likely embedded IoT or legacy server",
    "TLSv1.1": "Old (2006) — likely embedded IoT or legacy server",
    "TLSv1.2": "Modern — widely supported",
    "TLSv1.3": "Latest — modern server or recent firmware",
}

# ── Self-signed certificate heuristic ─────────────────────────────────────
# If subject == issuer (and neither is a known CA), the cert is self-signed.
# Self-signed certs are a strong signal for embedded devices, IoT, and
# network equipment — they almost never appear on managed servers with
# properly issued TLS certificates.
SELF_SIGNED_PLATFORM_BOOST = 0.3   # Score bump for "is self-signed" signal
