from __future__ import annotations

# mDNS / DNS-SD service type fingerprint tables.
#
# mDNS (RFC 6762) + DNS-SD (RFC 6763) allow devices to announce services
# on the local link via multicast UDP port 5353.
#
# Service type format: "_<service>._<protocol>.local"
#   protocol is "tcp" or "udp"
#
# Two signals:
#   SERVICE_TYPE_HINTS  — exact service type → (platform, device_hint)
#   HOSTNAME_HINTS      — mDNS hostname substring → (platform, os_hint)
#
# References:
#   http://www.dns-sd.org/ServiceTypes.html
#   https://developer.apple.com/bonjour/printing-specification/bonjourprinting-1.2.1.pdf


# ── Service type → (platform, device_hint) ────────────────────────────────
SERVICE_TYPE_HINTS: dict[str, tuple[str, str]] = {
    # ── Apple-exclusive / Apple-primary services ──────────────────────────
    "_airplay._tcp":              ("macos",          "Apple AirPlay (Apple TV / HomePod / Mac)"),
    "_raop._tcp":                 ("macos",          "Apple AirPlay Audio (RAOP)"),
    "_appletv-v2._tcp":           ("iot",            "Apple TV 2nd gen+"),
    "_appletv-pair._tcp":         ("iot",            "Apple TV pairing"),
    "_apple-mobdev2._tcp":        ("mobile",         "Apple iOS / iPadOS device"),
    "_companion-link._tcp":       ("mobile",         "Apple Handoff / Continuity"),
    "_afpovertcp._tcp":           ("macos",          "macOS AFP file sharing"),
    "_adisk._tcp":                ("macos",          "macOS Time Machine / AFP disk"),
    "_sleep-proxy._udp":          ("macos",          "macOS Bonjour Sleep Proxy"),
    "_homekit._tcp":              ("iot",            "Apple HomeKit"),
    "_hap._tcp":                  ("iot",            "Apple HomeKit Accessory Protocol"),
    "_apple-pairable._tcp":       ("mobile",         "Apple pairable device"),
    "_presence._tcp":             ("macos",          "Bonjour Presence (iChat / Messages)"),
    "_touch-able._tcp":           ("mobile",         "Apple Remote (iOS)"),
    "_net-assistant._tcp":        ("macos",          "Apple Remote Desktop"),
    "_acp-sync._tcp":             ("iot",            "AirPort Base Station sync"),
    "_airport._tcp":              ("wifi_ap",        "Apple AirPort base station"),
    "_daap._tcp":                 ("macos",          "iTunes Music Sharing (DAAP)"),
    "_home-sharing._tcp":         ("macos",          "iTunes Home Sharing"),
    "_itunes-satip._tcp":         ("macos",          "iTunes SATIP"),
    "_appletv._tcp":              ("iot",            "Apple TV (legacy)"),
    "_apple-midi._udp":           ("macos",          "Apple MIDI (RTP-MIDI)"),
    # ── Printing ──────────────────────────────────────────────────────────
    "_ipp._tcp":                  ("printer",        "IPP printer"),
    "_ipps._tcp":                 ("printer",        "IPPS (IPP over TLS) printer"),
    "_printer._tcp":              ("printer",        "LPD / LPR printer"),
    "_pdl-datastream._tcp":       ("printer",        "PDL / HP JetDirect printer"),
    "_ptp._tcp":                  ("printer",        "PTP / MTP device"),
    "_riousbprint._tcp":          ("printer",        "HP USB print server"),
    "_uscan._tcp":                ("printer",        "Network scanner (eSCL)"),
    "_uscans._tcp":               ("printer",        "Network scanner TLS (eSCL)"),
    "_scanner._tcp":              ("printer",        "Network scanner"),
    "_canon-bjnp1._tcp":          ("printer",        "Canon BJNP printer"),
    "_canon-bjnp2._tcp":          ("printer",        "Canon BJNP printer"),
    "_brother._tcp":              ("printer",        "Brother printer"),
    "_brprintsvc._tcp":           ("printer",        "Brother print service"),
    "_xerox-svcprxy._tcp":        ("printer",        "Xerox printer proxy"),
    "_fax-ipp._tcp":              ("printer",        "IPP fax"),
    "_print-caps._tcp":           ("printer",        "Print capabilities service"),
    # ── File sharing / storage ────────────────────────────────────────────
    "_smb._tcp":                  ("windows",        "SMB file sharing (Windows / Samba)"),
    "_cifs._tcp":                 ("linux",          "CIFS / Samba file sharing"),
    "_nfs._tcp":                  ("linux",          "NFS network file system"),
    "_webdav._tcp":               ("linux",          "WebDAV server"),
    "_webdavs._tcp":              ("linux",          "WebDAV over TLS"),
    "_tftp._udp":                 ("network_device", "TFTP server"),
    # ── Linux / Unix workstations ─────────────────────────────────────────
    "_workstation._tcp":          ("linux",          "Avahi workstation (Linux)"),
    "_ssh._tcp":                  ("linux",          "SSH server"),
    "_sftp-ssh._tcp":             ("linux",          "SFTP server"),
    "_rfb._tcp":                  ("linux",          "VNC (Remote Frame Buffer)"),
    "_ftp._tcp":                  ("linux",          "FTP server"),
    "_telnet._tcp":               ("linux",          "Telnet server"),
    "_http._tcp":                 ("linux",          "HTTP server"),
    "_https._tcp":                ("linux",          "HTTPS server"),
    "_http-alt._tcp":             ("linux",          "HTTP alt port server"),
    "_mqtt._tcp":                 ("iot",            "MQTT broker"),
    "_mqtt._udp":                 ("iot",            "MQTT broker (UDP)"),
    "_xmpp-client._tcp":          ("linux",          "XMPP messaging server"),
    "_xmpp-server._tcp":          ("linux",          "XMPP server federation"),
    "_matrix._tcp":               ("linux",          "Matrix homeserver"),
    # ── IoT / streaming / smart home ─────────────────────────────────────
    "_googlecast._tcp":           ("iot",            "Google Cast (Chromecast / Google Home)"),
    "_googlerpc._tcp":            ("iot",            "Google Cast RPC"),
    "_spotify-connect._tcp":      ("iot",            "Spotify Connect speaker"),
    "_sonos._tcp":                ("iot",            "Sonos speaker"),
    "_hue._tcp":                  ("iot",            "Philips Hue bridge"),
    "_miio._udp":                 ("iot",            "Xiaomi Mi IO device"),
    "_axis-video._tcp":           ("iot",            "Axis IP camera"),
    "_axis-video._udp":           ("iot",            "Axis IP camera (UDP)"),
    "_nvstream._tcp":             ("iot",            "NVIDIA GameStream / Shield"),
    "_nvstream._udp":             ("iot",            "NVIDIA GameStream / Shield (UDP)"),
    "_roku._tcp":                 ("iot",            "Roku streaming device"),
    "_ecp._tcp":                  ("iot",            "Roku ECP API"),
    "_androidtvremote2._tcp":     ("iot",            "Android TV remote"),
    "_androidtvremote._tcp":      ("iot",            "Android TV remote (legacy)"),
    "_android._tcp":              ("mobile",         "Android device"),
    "_amzn-wplay._tcp":           ("iot",            "Amazon Fire TV / Echo"),
    "_amazon-alexa._tcp":         ("iot",            "Amazon Echo / Alexa"),
    "_tivo-mindrpc._tcp":         ("iot",            "TiVo DVR"),
    "_esphomelib._tcp":           ("iot",            "ESPHome (ESP32/ESP8266)"),
    "_esphome._tcp":              ("iot",            "ESPHome"),
    "_shelly._tcp":               ("iot",            "Shelly IoT device"),
    "_tasmota._tcp":              ("iot",            "Tasmota firmware"),
    "_octoprint._tcp":            ("iot",            "OctoPrint (3D printer)"),
    "_klipper._tcp":              ("iot",            "Klipper (3D printer firmware)"),
    "_homeassistant._tcp":        ("iot",            "Home Assistant"),
    "_home-assistant._tcp":       ("iot",            "Home Assistant"),
    "_openhab._tcp":              ("linux",          "openHAB home automation"),
    "_domoticz._tcp":             ("linux",          "Domoticz home automation"),
    "_nodered._tcp":              ("iot",            "Node-RED"),
    "_zigbee2mqtt._tcp":          ("iot",            "Zigbee2MQTT"),
    "_matter._tcp":               ("iot",            "Matter smart home"),
    "_matter._udp":               ("iot",            "Matter smart home (UDP)"),
    "_hap-pairing._tcp":          ("iot",            "HomeKit pairing"),
    # ── NAS / storage services ────────────────────────────────────────────
    "_afpovertcp._udp":           ("linux",          "AFP (Apple Filing Protocol) UDP"),
    "_timemachine._tcp":          ("linux",          "Time Machine backup service"),
    "_xsan-admin._tcp":           ("macos",          "Apple Xsan admin"),
    # ── Media servers ─────────────────────────────────────────────────────
    "_plex._tcp":                 ("linux",          "Plex Media Server"),
    "_plexmediasvr._tcp":         ("linux",          "Plex Media Server"),
    "_jellyfin._tcp":             ("linux",          "Jellyfin media server"),
    "_emby._tcp":                 ("linux",          "Emby media server"),
    "_dlna._tcp":                 ("iot",            "DLNA media server"),
    "_upnp._tcp":                 ("iot",            "UPnP device"),
    # ── Network management ────────────────────────────────────────────────
    "_snmp._udp":                 ("network_device", "SNMP agent"),
    "_router._tcp":               ("network_device", "Router admin"),
    "_ntp._udp":                  ("network_device", "NTP server"),
    "_domain._udp":               ("network_device", "DNS server"),
    "_dns-sd._udp":               ("network_device", "DNS Service Discovery"),
    "_mikrotik-neighbor._udp":    ("network_device", "MikroTik Neighbor Discovery"),
    "_unifi._tcp":                ("wifi_ap",        "Ubiquiti UniFi controller"),
    # ── Windows-specific ──────────────────────────────────────────────────
    "_wdp._tcp":                  ("windows",        "Windows Device Portal"),
    "_ms-wbt-server._tcp":        ("windows",        "Windows Remote Desktop (WBT)"),
    "_microsoft-ds._tcp":         ("windows",        "Microsoft-DS / SMB"),
    "_hyper-v._tcp":              ("windows",        "Hyper-V"),
    "_rdp._tcp":                  ("windows",        "Remote Desktop Protocol"),
}

# ── mDNS hostname substrings → (platform, os_hint) ───────────────────────
# Matched case-insensitively against the resolved mDNS hostname.
# Apple devices often broadcast predictable hostname patterns.
HOSTNAME_HINTS: list[tuple[str, str, str]] = [
    # Apple product naming conventions
    ("iphone",          "mobile",         "Apple iPhone"),
    ("ipad",            "mobile",         "Apple iPad"),
    ("ipod",            "mobile",         "Apple iPod"),
    ("apple-tv",        "iot",            "Apple TV"),
    ("appletv",         "iot",            "Apple TV"),
    ("macbook",         "macos",          "Apple MacBook"),
    ("imac",            "macos",          "Apple iMac"),
    ("mac-mini",        "macos",          "Apple Mac Mini"),
    ("mac-pro",         "macos",          "Apple Mac Pro"),
    ("mac-studio",      "macos",          "Apple Mac Studio"),
    ("homepod",         "iot",            "Apple HomePod"),
    ("airpods",         "mobile",         "Apple AirPods"),
    ("apple-watch",     "mobile",         "Apple Watch"),
    # Android
    ("android",         "mobile",         "Android device"),
    ("pixel",           "mobile",         "Google Pixel"),
    ("samsung",         "mobile",         "Samsung device"),
    # Printers
    ("printer",         "printer",        "Network printer"),
    ("laserjet",        "printer",        "HP LaserJet"),
    ("officejet",       "printer",        "HP OfficeJet"),
    ("epson",           "printer",        "Epson printer"),
    ("brother",         "printer",        "Brother printer"),
    ("canon",           "printer",        "Canon printer"),
    # Network gear
    ("router",          "network_device", "Router"),
    ("gateway",         "network_device", "Gateway"),
    ("mikrotik",        "network_device", "MikroTik"),
    ("ubnt",            "wifi_ap",        "Ubiquiti"),
    ("unifi",           "wifi_ap",        "Ubiquiti UniFi"),
    # IoT
    ("raspberry",       "iot",            "Raspberry Pi"),
    ("raspberrypi",     "iot",            "Raspberry Pi"),
    ("esp32",           "iot",            "ESP32"),
    ("esp8266",         "iot",            "ESP8266"),
    ("arduino",         "iot",            "Arduino"),
    ("shelly",          "iot",            "Shelly IoT"),
    ("sonos",           "iot",            "Sonos speaker"),
    ("chromecast",      "iot",            "Google Chromecast"),
    ("roku",            "iot",            "Roku"),
    ("firetv",          "iot",            "Amazon Fire TV"),
    ("echo",            "iot",            "Amazon Echo"),
    ("hue",             "iot",            "Philips Hue"),
    ("xiaomi",          "iot",            "Xiaomi IoT"),
    ("camera",          "iot",            "IP camera"),
    ("hikvision",       "iot",            "Hikvision camera"),
    ("dahua",           "iot",            "Dahua camera"),
    # NAS
    ("synology",        "linux",          "Synology NAS"),
    ("qnap",            "linux",          "QNAP NAS"),
    ("nas",             "linux",          "NAS device"),
    # Windows
    ("desktop",         "windows",        "Windows Desktop"),
    ("laptop",          "windows",        "Windows Laptop"),
]
