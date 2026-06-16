from __future__ import annotations

# UPnP device fingerprint tables.
#
# A UPnP description document (fetched from the URL in the SSDP Location header
# or from well-known paths like /description.xml) contains:
#   <deviceType>   — a URN identifying the device class
#   <manufacturer> — free-text manufacturer name
#   <modelName>    — free-text model name
#   <friendlyName> — human-readable device name
#
# Three signals (applied in order, first match wins within each):
#   DEVICE_TYPE_HINTS    — exact deviceType URN → (platform, device_hint)
#   MANUFACTURER_HINTS   — manufacturer substring → (platform, manufacturer_hint)
#   FRIENDLY_NAME_HINTS  — friendlyName substring → (platform, device_hint)
#
# Common description XML paths tried by the UPnP probe:
DESCRIPTION_PATHS: tuple[str, ...] = (
    "/description.xml",
    "/rootDesc.xml",
    "/igd.xml",
    "/upnp/desc.html",
    "/setup.xml",
    "/device.xml",
    "/desc.xml",
    "/upnp/BasicDevice.xml",
    "/MediaServer.xml",
    "/gatedesc.xml",
    "/upnphost/udhisapi.dll",  # Windows UPnP host
    "/",
)


# ── Device type URN → (platform, device_hint) ─────────────────────────────
# Exact match against the <deviceType> element (case-sensitive per spec,
# but compare lowercased in practice for robustness).
DEVICE_TYPE_HINTS: dict[str, tuple[str, str]] = {
    # ── Internet Gateway Devices (home routers) ───────────────────────────
    "urn:schemas-upnp-org:device:internetgatewaydevice:1":  ("network_device", "Internet Gateway Device v1 (router)"),
    "urn:schemas-upnp-org:device:internetgatewaydevice:2":  ("network_device", "Internet Gateway Device v2 (router)"),
    "urn:schemas-upnp-org:device:wandevice:1":              ("network_device", "WAN Device"),
    "urn:schemas-upnp-org:device:wanconnectiondevice:1":    ("network_device", "WAN Connection Device"),
    "urn:schemas-upnp-org:device:wanconnectiondevice:2":    ("network_device", "WAN Connection Device v2"),
    "urn:schemas-upnp-org:device:landevice:1":              ("network_device", "LAN Device"),
    # ── Media rendering (TVs, speakers, streaming sticks) ─────────────────
    "urn:schemas-upnp-org:device:mediarenderer:1":          ("iot",            "UPnP Media Renderer v1"),
    "urn:schemas-upnp-org:device:mediarenderer:2":          ("iot",            "UPnP Media Renderer v2"),
    "urn:schemas-upnp-org:device:mediarenderer:3":          ("iot",            "UPnP Media Renderer v3"),
    # ── Media servers (NAS, PC, Plex, etc.) ───────────────────────────────
    "urn:schemas-upnp-org:device:mediaserver:1":            ("linux",          "UPnP Media Server v1"),
    "urn:schemas-upnp-org:device:mediaserver:2":            ("linux",          "UPnP Media Server v2"),
    "urn:schemas-upnp-org:device:mediaserver:3":            ("linux",          "UPnP Media Server v3"),
    "urn:schemas-upnp-org:device:mediaserver:4":            ("linux",          "UPnP Media Server v4"),
    # ── Printers ──────────────────────────────────────────────────────────
    "urn:schemas-upnp-org:device:printbasic:1":             ("printer",        "UPnP Basic Printer"),
    "urn:schemas-upnp-org:device:printenhanced:1":          ("printer",        "UPnP Enhanced Printer"),
    "urn:schemas-upnp-org:device:printbasic:2":             ("printer",        "UPnP Basic Printer v2"),
    # ── Basic device (generic) ────────────────────────────────────────────
    "urn:schemas-upnp-org:device:basicdevice:1":            ("iot",            "UPnP Basic Device"),
    # ── Smart TVs ─────────────────────────────────────────────────────────
    "urn:dial-multiscreen-org:device:dial:1":               ("iot",            "DIAL Smart TV / streaming stick"),
    "urn:dial-multiscreen-org:device:dial:2":               ("iot",            "DIAL Smart TV v2"),
    "urn:schemas-upnp-org:device:tvdevice:1":               ("iot",            "UPnP TV Device"),
    # ── Sonos ─────────────────────────────────────────────────────────────
    "urn:schemas-upnp-org:device:zoneplayer:1":             ("iot",            "Sonos ZonePlayer"),
    # ── Belkin WeMo ───────────────────────────────────────────────────────
    "urn:belkin-com:device:controllee:1":                   ("iot",            "Belkin WeMo smart plug"),
    "urn:belkin-com:device:light:1":                        ("iot",            "Belkin WeMo smart light"),
    "urn:belkin-com:device:sensor:1":                       ("iot",            "Belkin WeMo motion sensor"),
    "urn:belkin-com:device:insight:1":                      ("iot",            "Belkin WeMo Insight"),
    "urn:belkin-com:device:bridge:1":                       ("iot",            "Belkin WeMo bridge"),
    # ── Samsung (TVs, cameras) ────────────────────────────────────────────
    "urn:samsung-com:device:remotecontrolreceiver:1":       ("iot",            "Samsung Smart TV"),
    "urn:samsung-com:device:remotecontrolreceiver:2":       ("iot",            "Samsung Smart TV"),
    "urn:samsung.com:device:ipcamera:1":                    ("iot",            "Samsung IP camera"),
    "urn:schemas-upnp-org:device:avtransport:1":            ("iot",            "UPnP AV Transport"),
    # ── LG Smart TV ───────────────────────────────────────────────────────
    "urn:lge-com:device:netcast.tv-2.0:1":                  ("iot",            "LG NetCast Smart TV"),
    "urn:lge-com:device:netcast.tv-3.0:1":                  ("iot",            "LG Smart TV (webOS)"),
    # ── Sony Bravia / PlayStation ─────────────────────────────────────────
    "urn:schemas-sony-com:device:scalarwebapi:1":           ("iot",            "Sony Bravia TV / PlayStation"),
    "urn:schemas-upnp-org:device:scalarwebapi:1":           ("iot",            "Sony device"),
    # ── Microsoft (Windows Media Center / Xbox) ───────────────────────────
    "urn:microsoft-com:device:mediacenter:1":               ("windows",        "Windows Media Center"),
    "urn:microsoft-com:device:dial:1":                      ("windows",        "Windows DIAL device"),
    "urn:microsoft-com:device:xbox:1":                      ("windows",        "Microsoft Xbox"),
    "urn:microsoft-com:device:xbox360:1":                   ("windows",        "Microsoft Xbox 360"),
    "urn:microsoft-com:device:xboxone:1":                   ("windows",        "Microsoft Xbox One"),
    # ── Roku ──────────────────────────────────────────────────────────────
    "urn:roku-com:device:player:1-0":                       ("iot",            "Roku streaming device"),
    # ── Amazon Fire TV ────────────────────────────────────────────────────
    "urn:amazon-com:device:amzn-firetv:1":                  ("iot",            "Amazon Fire TV"),
    # ── Philips Hue ───────────────────────────────────────────────────────
    "urn:schemas-upnp-org:device:basic:1":                  ("iot",            "UPnP Basic Device (likely IoT)"),
    # ── D-Link IP cameras ─────────────────────────────────────────────────
    "urn:dlink-com:device:ipcam:1":                         ("iot",            "D-Link IP Camera"),
    # ── Netgear ───────────────────────────────────────────────────────────
    "urn:netgear-com:device:basicdevice:1":                 ("wifi_ap",        "Netgear device"),
    # ── TP-Link ───────────────────────────────────────────────────────────
    "urn:tplink-com:device:basicdevice:1":                  ("wifi_ap",        "TP-Link device"),
}

# ── Manufacturer substring → (platform, manufacturer_hint) ────────────────
# Case-insensitive substring match against the <manufacturer> field.
# First match wins.
MANUFACTURER_HINTS: list[tuple[str, str, str]] = [
    # Windows / Microsoft
    ("microsoft",         "windows",        "Microsoft"),
    ("xbox",              "windows",        "Microsoft Xbox"),
    # Apple
    ("apple",             "macos",          "Apple"),
    # Network devices
    ("cisco",             "network_device", "Cisco"),
    ("juniper",           "network_device", "Juniper Networks"),
    ("palo alto",         "network_device", "Palo Alto Networks"),
    ("fortinet",          "network_device", "Fortinet"),
    ("check point",       "network_device", "Check Point"),
    ("f5 networks",       "network_device", "F5 Networks"),
    ("sonicwall",         "network_device", "SonicWall"),
    ("arista",            "network_device", "Arista Networks"),
    ("extreme",           "network_device", "Extreme Networks"),
    ("brocade",           "network_device", "Brocade"),
    ("huawei",            "network_device", "Huawei"),
    ("zte",               "network_device", "ZTE"),
    ("h3c",               "network_device", "H3C / HPE FlexFabric"),
    # Wi-Fi APs / SOHO routers
    ("netgear",           "wifi_ap",        "Netgear"),
    ("tp-link",           "wifi_ap",        "TP-Link"),
    ("tp link",           "wifi_ap",        "TP-Link"),
    ("tplink",            "wifi_ap",        "TP-Link"),
    ("d-link",            "wifi_ap",        "D-Link"),
    ("asus",              "wifi_ap",        "ASUS"),
    ("linksys",           "wifi_ap",        "Linksys"),
    ("belkin",            "wifi_ap",        "Belkin"),
    ("ubiquiti",          "wifi_ap",        "Ubiquiti Networks"),
    ("ubnt",              "wifi_ap",        "Ubiquiti"),
    ("mikrotik",          "network_device", "MikroTik"),
    ("zyxel",             "network_device", "Zyxel"),
    ("aruba",             "wifi_ap",        "Aruba Networks / HPE"),
    ("ruckus",            "wifi_ap",        "Ruckus Networks"),
    ("aerohive",          "wifi_ap",        "Aerohive / Extreme Networks"),
    ("meraki",            "wifi_ap",        "Cisco Meraki"),
    ("cambium",           "wifi_ap",        "Cambium Networks"),
    ("motorola",          "wifi_ap",        "Motorola Solutions"),
    ("hewlett-packard",   "network_device", "HP / Hewlett-Packard"),
    ("hewlett packard",   "network_device", "HP / Hewlett-Packard"),
    # IoT / smart home
    ("sonos",             "iot",            "Sonos"),
    ("philips",           "iot",            "Philips"),
    ("belkin",            "iot",            "Belkin WeMo"),
    ("amazon",            "iot",            "Amazon"),
    ("google",            "iot",            "Google"),
    ("roku",              "iot",            "Roku"),
    ("samsung",           "iot",            "Samsung"),
    ("sony",              "iot",            "Sony"),
    ("lg electronics",    "iot",            "LG Electronics"),
    ("sharp",             "iot",            "Sharp"),
    ("pioneer",           "iot",            "Pioneer"),
    ("denon",             "iot",            "Denon"),
    ("yamaha",            "iot",            "Yamaha"),
    ("onkyo",             "iot",            "Onkyo"),
    ("harman",            "iot",            "Harman / JBL"),
    ("bose",              "iot",            "Bose"),
    ("xiaomi",            "iot",            "Xiaomi"),
    ("oppo",              "iot",            "OPPO"),
    ("tcl",               "iot",            "TCL"),
    ("hisense",           "iot",            "Hisense"),
    ("panasonic",         "iot",            "Panasonic"),
    ("toshiba",           "iot",            "Toshiba"),
    ("espressif",         "iot",            "Espressif (ESP32/ESP8266)"),
    ("raspberry pi",      "iot",            "Raspberry Pi Foundation"),
    ("shelly",            "iot",            "Allterco / Shelly"),
    # NAS
    ("synology",          "linux",          "Synology"),
    ("qnap",              "linux",          "QNAP"),
    ("western digital",   "linux",          "Western Digital"),
    ("wd",                "linux",          "Western Digital"),
    ("seagate",           "linux",          "Seagate"),
    ("buffalo",           "linux",          "Buffalo Technology"),
    ("asustor",           "linux",          "ASUSTOR NAS"),
    ("terramaster",       "linux",          "TerraMaster"),
    # Printers
    ("hewlett",           "printer",        "HP"),
    ("hp inc",            "printer",        "HP Inc."),
    ("epson",             "printer",        "Seiko Epson"),
    ("canon",             "printer",        "Canon"),
    ("brother",           "printer",        "Brother Industries"),
    ("ricoh",             "printer",        "Ricoh"),
    ("xerox",             "printer",        "Xerox"),
    ("kyocera",           "printer",        "Kyocera"),
    ("konica",            "printer",        "Konica Minolta"),
    ("lexmark",           "printer",        "Lexmark"),
    ("oki",               "printer",        "OKI Electric"),
    ("sharp",             "printer",        "Sharp (MFP)"),
    ("zebra",             "printer",        "Zebra Technologies"),
    # VMware
    ("vmware",            "vmware_esxi",    "VMware"),
    # Cameras
    ("hikvision",         "iot",            "Hikvision"),
    ("dahua",             "iot",            "Dahua Technology"),
    ("axis",              "iot",            "Axis Communications"),
    ("vivotek",           "iot",            "Vivotek"),
    ("reolink",           "iot",            "Reolink"),
    ("amcrest",           "iot",            "Amcrest"),
    ("bosch",             "iot",            "Bosch Security Systems"),
    ("hanwha",            "iot",            "Hanwha Vision"),
    ("foscam",            "iot",            "Foscam"),
]

# ── Friendly name substrings → (platform, device_hint) ────────────────────
# Lower-priority signal; applied when device type + manufacturer both miss.
FRIENDLY_NAME_HINTS: list[tuple[str, str, str]] = [
    ("router",            "network_device", "Router"),
    ("gateway",           "network_device", "Gateway"),
    ("modem",             "network_device", "Modem"),
    ("access point",      "wifi_ap",        "Access point"),
    ("nas",               "linux",          "NAS device"),
    ("printer",           "printer",        "Printer"),
    ("camera",            "iot",            "IP camera"),
    ("tv",                "iot",            "Smart TV"),
    ("speaker",           "iot",            "Smart speaker"),
    ("echo",              "iot",            "Amazon Echo"),
    ("chromecast",        "iot",            "Google Chromecast"),
    ("roku",              "iot",            "Roku"),
    ("xbox",              "windows",        "Microsoft Xbox"),
    ("playstation",       "iot",            "Sony PlayStation"),
    ("iphone",            "mobile",         "Apple iPhone"),
    ("ipad",              "mobile",         "Apple iPad"),
    ("mac",               "macos",          "Apple Mac"),
]
