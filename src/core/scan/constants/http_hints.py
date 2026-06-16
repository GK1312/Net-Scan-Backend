from __future__ import annotations

# HTTP response fingerprint tables.
#
# Three independent signals, each yielding (platform, os_hint):
#   SERVER_HINTS     — "Server:" response header (substring match, ordered)
#   XPOWERED_HINTS   — "X-Powered-By:" response header (substring match, ordered)
#   TITLE_HINTS      — HTML <title> element (substring match, ordered)
#
# All matches are case-insensitive. First match wins within each table.


# ── Common HTTP candidates (scheme, port) tried in order by the http probe ──
HTTP_CANDIDATES: tuple[tuple[str, int], ...] = (
    ("https", 443),
    ("https", 8443),
    ("http",  8080),
    ("http",  80),
)

# Same order for UPnP (HTTP only — UPnP rarely runs over TLS)
UPNP_CANDIDATES: tuple[tuple[str, int], ...] = (
    ("http",  80),
    ("http",  8080),
    ("https", 443),
    ("https", 8443),
)

# ── Response headers worth collecting for fingerprinting ──────────────────
INTERESTING_HEADERS: frozenset[str] = frozenset({
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-frame-options",
    "x-generator",
    "x-content-type-options",
    "x-drupal-cache",
    "x-wp-nonce",
    "x-pingback",
    "x-runtime",                # Ruby on Rails
    "x-version",
    "x-application-context",    # Spring Boot
    "x-envoy-upstream-service-time",  # Envoy / Istio
    "via",
    "www-authenticate",
})

# ── User-Agent string used for all HTTP probes ────────────────────────────
HTTP_USER_AGENT = "Mozilla/5.0 (compatible; NetScan/1.0)"

# ── Server header → (platform, os_hint) ──────────────────────────────────
# Substring match (case-insensitive) against the "Server:" header value.
# First match wins.
SERVER_HINTS: list[tuple[str, str, str]] = [
    # ── Microsoft IIS (strongest Windows signal) ──────────────────────────
    ("microsoft-iis/10",              "windows",        "IIS 10 — Windows Server 2016 / 2019 / 2022 / 2025 or Windows 10/11"),
    ("microsoft-iis/8.5",             "windows",        "IIS 8.5 — Windows Server 2012 R2 / Windows 8.1"),
    ("microsoft-iis/8.0",             "windows",        "IIS 8.0 — Windows Server 2012 / Windows 8"),
    ("microsoft-iis/7.5",             "windows",        "IIS 7.5 — Windows Server 2008 R2 / Windows 7"),
    ("microsoft-iis/7.0",             "windows",        "IIS 7.0 — Windows Server 2008 / Windows Vista"),
    ("microsoft-iis/6.0",             "windows",        "IIS 6.0 — Windows Server 2003"),
    ("microsoft-iis/5.1",             "windows",        "IIS 5.1 — Windows XP Professional"),
    ("microsoft-iis/5.0",             "windows",        "IIS 5.0 — Windows 2000 Server"),
    ("microsoft-iis/4.0",             "windows",        "IIS 4.0 — Windows NT 4.0 Option Pack"),
    ("microsoft-iis",                 "windows",        "Microsoft IIS (Windows)"),
    # ── ASP.NET / .NET embedded Kestrel ───────────────────────────────────
    ("microsoft-httpapi",             "windows",        "Microsoft HTTP API (Windows)"),
    ("kestrel",                       "windows",        "ASP.NET Core Kestrel"),
    # ── Apache HTTP Server ────────────────────────────────────────────────
    ("apache/2.4",                    "linux",          "Apache 2.4"),
    ("apache/2.2",                    "linux",          "Apache 2.2"),
    ("apache/2.0",                    "linux",          "Apache 2.0"),
    ("apache/1",                      "linux",          "Apache 1.x (legacy)"),
    ("apache",                        "linux",          "Apache HTTP Server"),
    # ── nginx ─────────────────────────────────────────────────────────────
    ("nginx/",                        "linux",          "nginx"),
    ("nginx",                         "linux",          "nginx"),
    # ── OpenResty (nginx + LuaJIT) ────────────────────────────────────────
    ("openresty",                     "linux",          "OpenResty (nginx + Lua)"),
    # ── Tengine (Alibaba nginx fork) ──────────────────────────────────────
    ("tengine",                       "linux",          "Tengine (Alibaba nginx fork)"),
    # ── lighttpd ──────────────────────────────────────────────────────────
    ("lighttpd",                      "linux",          "lighttpd"),
    # ── Caddy ─────────────────────────────────────────────────────────────
    ("caddy",                         "linux",          "Caddy"),
    # ── Traefik ───────────────────────────────────────────────────────────
    ("traefik",                       "linux",          "Traefik reverse proxy"),
    # ── HAProxy ───────────────────────────────────────────────────────────
    ("haproxy",                       "linux",          "HAProxy"),
    # ── Cherokee ──────────────────────────────────────────────────────────
    ("cherokee",                      "linux",          "Cherokee"),
    # ── Hiawatha ──────────────────────────────────────────────────────────
    ("hiawatha",                      "linux",          "Hiawatha"),
    # ── Jetty (Java) ──────────────────────────────────────────────────────
    ("jetty",                         "linux",          "Eclipse Jetty (Java)"),
    # ── Apache Tomcat ─────────────────────────────────────────────────────
    ("apache-coyote",                 "linux",          "Apache Tomcat (Java, Coyote connector)"),
    ("tomcat",                        "linux",          "Apache Tomcat (Java)"),
    # ── JBoss / WildFly ───────────────────────────────────────────────────
    ("jboss-",                        "linux",          "JBoss AS (Java)"),
    ("wildfly",                       "linux",          "WildFly (Java)"),
    # ── GlassFish ─────────────────────────────────────────────────────────
    ("glassfish",                     "linux",          "GlassFish (Java)"),
    # ── Undertow ──────────────────────────────────────────────────────────
    ("undertow",                      "linux",          "Undertow (Java / Quarkus)"),
    # ── Vert.x ────────────────────────────────────────────────────────────
    ("vert.x",                        "linux",          "Vert.x (Java)"),
    # ── Gunicorn (Python WSGI) ────────────────────────────────────────────
    ("gunicorn",                      "linux",          "Gunicorn (Python WSGI)"),
    # ── uWSGI ─────────────────────────────────────────────────────────────
    ("uwsgi",                         "linux",          "uWSGI (Python WSGI)"),
    # ── Python BaseHTTPServer / http.server ───────────────────────────────
    ("basehttp",                      "linux",          "Python BaseHTTPServer"),
    ("python/",                       "linux",          "Python HTTP server"),
    # ── Go net/http ───────────────────────────────────────────────────────
    ("go http",                       "linux",          "Go net/http"),
    # ── Node.js / Express ─────────────────────────────────────────────────
    ("node.js",                       "linux",          "Node.js HTTP server"),
    ("express",                       "linux",          "Express.js (Node.js)"),
    # ── Perl / Dancer / Mojolicious ───────────────────────────────────────
    ("perl",                          "linux",          "Perl HTTP server"),
    # ── Ruby / WEBrick / Thin / Puma ─────────────────────────────────────
    ("webrick",                       "linux",          "Ruby WEBrick"),
    ("puma",                          "linux",          "Puma (Ruby)"),
    ("thin",                          "linux",          "Thin (Ruby)"),
    ("unicorn",                       "linux",          "Unicorn (Ruby)"),
    # ── PHP built-in server ───────────────────────────────────────────────
    ("php",                           "linux",          "PHP built-in HTTP server"),
    # ── Tornado (Python async) ────────────────────────────────────────────
    ("tornado",                       "linux",          "Tornado (Python async)"),
    # ── Uvicorn / Starlette / FastAPI ─────────────────────────────────────
    ("uvicorn",                       "linux",          "Uvicorn (Python ASGI)"),
    # ── Nginx Unit ────────────────────────────────────────────────────────
    ("unit/",                         "linux",          "NGINX Unit"),
    # ── Network equipment embedded HTTP ───────────────────────────────────
    ("cisco",                         "network_device", "Cisco embedded HTTP"),
    ("mikrotik",                      "network_device", "MikroTik RouterOS web"),
    ("mini_httpd",                    "network_device", "mini_httpd (embedded device)"),
    ("mini-httpd",                    "network_device", "mini_httpd (embedded device)"),
    ("uc-httpd",                      "network_device", "uc-httpd (embedded device)"),
    ("goahead",                       "network_device", "GoAhead embedded HTTP"),
    ("allegro-software-rompager",     "network_device", "RomPager (modem/router)"),
    ("rompager",                      "network_device", "RomPager (modem/router)"),
    ("dnvrs-webs",                    "wifi_ap",        "D-Link embedded HTTP"),
    ("wireless-ap",                   "wifi_ap",        "Wireless AP admin page"),
    ("netgear",                       "wifi_ap",        "Netgear"),
    ("tp-link",                       "wifi_ap",        "TP-Link"),
    ("zyxel",                         "network_device", "Zyxel"),
    ("fortinet",                      "network_device", "Fortinet"),
    ("palo alto",                     "network_device", "Palo Alto Networks"),
    ("huawei",                        "network_device", "Huawei"),
    ("ubiquiti",                      "wifi_ap",        "Ubiquiti"),
    ("airos",                         "wifi_ap",        "Ubiquiti AirOS"),
    # ── VMware ────────────────────────────────────────────────────────────
    ("vmware",                        "vmware_esxi",    "VMware ESXi / vSphere"),
    # ── Synology NAS ──────────────────────────────────────────────────────
    ("synology",                      "linux",          "Synology DSM"),
    # ── QNAP ─────────────────────────────────────────────────────────────
    ("qnap",                          "linux",          "QNAP QTS"),
    # ── Printers ──────────────────────────────────────────────────────────
    ("hp http server",                "printer",        "HP JetDirect"),
    ("jetdirect",                     "printer",        "HP JetDirect"),
    ("epson",                         "printer",        "Epson Printer"),
    ("canon",                         "printer",        "Canon Printer"),
    ("brother",                       "printer",        "Brother Printer"),
    ("xerox",                         "printer",        "Xerox Printer"),
    ("ricoh",                         "printer",        "Ricoh Printer"),
    ("kyocera",                       "printer",        "Kyocera Printer"),
    ("konica",                        "printer",        "Konica Minolta Printer"),
    ("lexmark",                       "printer",        "Lexmark Printer"),
    ("sharp",                         "printer",        "Sharp Printer"),
    ("oki",                           "printer",        "OKI Printer"),
    ("samsung",                       "printer",        "Samsung Printer"),
    ("dell",                          "printer",        "Dell Printer"),
    # ── IP cameras ────────────────────────────────────────────────────────
    ("hikvision",                     "iot",            "Hikvision IP Camera"),
    ("dahua",                         "iot",            "Dahua IP Camera"),
    ("axis",                          "iot",            "Axis IP Camera"),
    ("bosch security",                "iot",            "Bosch IP Camera"),
    ("hanwha",                        "iot",            "Hanwha / Samsung IP Camera"),
    ("vivotek",                       "iot",            "Vivotek IP Camera"),
    ("foscam",                        "iot",            "Foscam IP Camera"),
    ("reolink",                       "iot",            "Reolink IP Camera"),
    ("amcrest",                       "iot",            "Amcrest IP Camera"),
    ("dvr web server",                "iot",            "DVR/NVR"),
    # ── IoT / smart home ──────────────────────────────────────────────────
    ("espressif",                     "iot",            "Espressif (ESP32/ESP8266)"),
    ("particle",                      "iot",            "Particle IoT"),
    ("shelly",                        "iot",            "Shelly IoT device"),
    ("tasmota",                       "iot",            "Tasmota firmware"),
    ("esphome",                       "iot",            "ESPHome"),
    ("homeassistant",                 "iot",            "Home Assistant"),
    ("home assistant",                "iot",            "Home Assistant"),
]

# ── X-Powered-By / X-AspNet-Version → (platform, os_hint) ────────────────
XPOWERED_HINTS: list[tuple[str, str, str]] = [
    ("asp.net",                       "windows",        "ASP.NET (Windows)"),
    ("asp",                           "windows",        "Classic ASP (Windows)"),
    ("mono",                          "linux",          "Mono / .NET on Linux"),
    ("php/5",                         "linux",          "PHP 5.x"),
    ("php/7",                         "linux",          "PHP 7.x"),
    ("php/8",                         "linux",          "PHP 8.x"),
    ("php",                           "linux",          "PHP"),
    ("express",                       "linux",          "Node.js / Express"),
    ("next.js",                       "linux",          "Next.js (Node.js)"),
    ("nuxt.js",                       "linux",          "Nuxt.js (Node.js)"),
    ("rails",                         "linux",          "Ruby on Rails"),
    ("django",                        "linux",          "Django (Python)"),
    ("flask",                         "linux",          "Flask (Python)"),
    ("fastapi",                       "linux",          "FastAPI (Python)"),
    ("laravel",                       "linux",          "Laravel (PHP)"),
    ("symfony",                       "linux",          "Symfony (PHP)"),
    ("codeigniter",                   "linux",          "CodeIgniter (PHP)"),
    ("wordpress",                     "linux",          "WordPress (PHP)"),
    ("joomla",                        "linux",          "Joomla! (PHP)"),
    ("drupal",                        "linux",          "Drupal (PHP)"),
    ("spring",                        "linux",          "Spring Boot (Java)"),
    ("grails",                        "linux",          "Grails (Java/Groovy)"),
    ("plesk",                         "linux",          "Plesk control panel"),
    ("cpanel",                        "linux",          "cPanel control panel"),
    ("directadmin",                   "linux",          "DirectAdmin control panel"),
]

# ── HTML <title> substrings → (platform, os_hint) ─────────────────────────
TITLE_HINTS: list[tuple[str, str, str]] = [
    # ── Windows / Microsoft ───────────────────────────────────────────────
    ("windows server",                "windows",        "Windows Server"),
    ("iis",                           "windows",        "IIS (Windows)"),
    ("remote desktop",                "windows",        "Windows Remote Desktop"),
    ("windows",                       "windows",        "Windows"),
    ("sharepoint",                    "windows",        "SharePoint (Windows)"),
    ("exchange",                      "windows",        "Microsoft Exchange (Windows)"),
    ("outlook web",                   "windows",        "Outlook Web App (Windows)"),
    # ── Network devices / routers ─────────────────────────────────────────
    ("router",                        "network_device", "Router admin page"),
    ("gateway",                       "network_device", "Gateway admin page"),
    ("firewall",                      "network_device", "Firewall admin page"),
    ("switch",                        "network_device", "Switch admin page"),
    ("web management",                "network_device", "Web management interface"),
    ("management console",            "network_device", "Management console"),
    ("dsl modem",                     "network_device", "DSL modem"),
    ("adsl",                          "network_device", "ADSL modem/router"),
    ("vdsl",                          "network_device", "VDSL modem/router"),
    ("home hub",                      "network_device", "ISP home hub"),
    ("pfsense",                       "network_device", "pfSense firewall"),
    ("opnsense",                      "network_device", "OPNsense firewall"),
    ("mikrotik",                      "network_device", "MikroTik RouterOS"),
    ("cisco",                         "network_device", "Cisco device"),
    ("juniper",                       "network_device", "Juniper device"),
    ("fortigate",                     "network_device", "Fortinet FortiGate"),
    ("sonicwall",                     "network_device", "SonicWall"),
    ("watchguard",                    "network_device", "WatchGuard Firebox"),
    ("barracuda",                     "network_device", "Barracuda Networks"),
    ("checkpoint",                    "network_device", "Check Point"),
    # ── Wi-Fi APs ─────────────────────────────────────────────────────────
    ("tp-link",                       "wifi_ap",        "TP-Link"),
    ("tplink",                        "wifi_ap",        "TP-Link"),
    ("netgear",                       "wifi_ap",        "Netgear"),
    ("asus router",                   "wifi_ap",        "ASUS router"),
    ("asus wireless",                 "wifi_ap",        "ASUS wireless router"),
    ("dd-wrt",                        "wifi_ap",        "DD-WRT router"),
    ("openwrt",                       "wifi_ap",        "OpenWrt router"),
    ("luci",                          "wifi_ap",        "OpenWrt (LuCI UI)"),
    ("gargoyle",                      "wifi_ap",        "Gargoyle router"),
    ("tomato",                        "wifi_ap",        "Tomato router firmware"),
    ("unifi",                         "wifi_ap",        "Ubiquiti UniFi"),
    ("airmax",                        "wifi_ap",        "Ubiquiti AirMax"),
    ("edgeos",                        "wifi_ap",        "Ubiquiti EdgeOS"),
    ("linksys",                       "wifi_ap",        "Linksys"),
    ("belkin",                        "wifi_ap",        "Belkin router"),
    ("d-link",                        "wifi_ap",        "D-Link"),
    ("netis",                         "wifi_ap",        "Netis router"),
    ("tenda",                         "wifi_ap",        "Tenda router"),
    ("mercusys",                      "wifi_ap",        "Mercusys (TP-Link sub-brand)"),
    ("xiaomi router",                 "wifi_ap",        "Xiaomi router"),
    ("mi router",                     "wifi_ap",        "Xiaomi Mi Router"),
    # ── VMware ────────────────────────────────────────────────────────────
    ("esxi",                          "vmware_esxi",    "VMware ESXi"),
    ("vmware",                        "vmware_esxi",    "VMware"),
    ("vsphere",                       "vmware_esxi",    "VMware vSphere"),
    ("vcenter",                       "vmware_esxi",    "VMware vCenter"),
    # ── Printers ──────────────────────────────────────────────────────────
    ("printer",                       "printer",        "Printer"),
    ("print server",                  "printer",        "Print server"),
    ("hp laserjet",                   "printer",        "HP LaserJet"),
    ("hp officejet",                  "printer",        "HP OfficeJet"),
    ("hp deskjet",                    "printer",        "HP DeskJet"),
    ("hp photosmart",                 "printer",        "HP Photosmart"),
    ("hp color laserjet",             "printer",        "HP Color LaserJet"),
    ("hp designjet",                  "printer",        "HP DesignJet (plotter)"),
    ("epson",                         "printer",        "Epson printer"),
    ("brother",                       "printer",        "Brother printer"),
    ("canon",                         "printer",        "Canon printer"),
    ("ricoh",                         "printer",        "Ricoh printer"),
    ("xerox",                         "printer",        "Xerox printer"),
    ("kyocera",                       "printer",        "Kyocera printer"),
    ("konica minolta",                "printer",        "Konica Minolta printer"),
    ("lexmark",                       "printer",        "Lexmark printer"),
    ("dell printer",                  "printer",        "Dell printer"),
    ("sharp mx",                      "printer",        "Sharp MFP"),
    ("oki",                           "printer",        "OKI printer"),
    ("zebra",                         "printer",        "Zebra label printer"),
    # ── NAS / storage ─────────────────────────────────────────────────────
    ("synology",                      "linux",          "Synology NAS (DSM)"),
    ("qnap",                          "linux",          "QNAP NAS (QTS)"),
    ("freenas",                       "linux",          "FreeNAS"),
    ("truenas",                       "linux",          "TrueNAS"),
    ("openmediavault",                "linux",          "OpenMediaVault (OMV)"),
    ("western digital",               "linux",          "Western Digital NAS"),
    ("wd my cloud",                   "linux",          "WD My Cloud"),
    ("buffalo",                       "linux",          "Buffalo NAS"),
    ("netgear readynas",              "linux",          "Netgear ReadyNAS"),
    ("terramaster",                   "linux",          "TerraMaster NAS"),
    ("nas",                           "linux",          "NAS device"),
    # ── IP cameras / CCTV ─────────────────────────────────────────────────
    ("camera",                        "iot",            "IP camera"),
    ("ip camera",                     "iot",            "IP camera"),
    ("nvr",                           "iot",            "NVR/DVR"),
    ("dvr",                           "iot",            "DVR"),
    ("cctv",                          "iot",            "CCTV system"),
    ("hikvision",                     "iot",            "Hikvision camera"),
    ("dahua",                         "iot",            "Dahua camera"),
    ("axis",                          "iot",            "Axis camera"),
    ("reolink",                       "iot",            "Reolink camera"),
    ("amcrest",                       "iot",            "Amcrest camera"),
    ("foscam",                        "iot",            "Foscam camera"),
    # ── IoT / smart home ──────────────────────────────────────────────────
    ("home assistant",                "iot",            "Home Assistant"),
    ("homeassistant",                 "iot",            "Home Assistant"),
    ("node-red",                      "iot",            "Node-RED"),
    ("openhab",                       "iot",            "openHAB"),
    ("domoticz",                      "iot",            "Domoticz"),
    ("hass.io",                       "iot",            "Hass.io (Home Assistant OS)"),
    ("tasmota",                       "iot",            "Tasmota firmware"),
    ("esphome",                       "iot",            "ESPHome"),
    ("shelly",                        "iot",            "Shelly IoT"),
    ("raspberry pi",                  "iot",            "Raspberry Pi"),
    ("pi-hole",                       "linux",          "Pi-hole"),
    ("octoprint",                     "iot",            "OctoPrint (3D printer)"),
    ("ender",                         "iot",            "Creality Ender 3D printer"),
    ("prusa",                         "iot",            "Prusa 3D printer"),
    ("smart home",                    "iot",            "Smart home device"),
    # ── Linux servers / general ────────────────────────────────────────────
    ("ubuntu",                        "linux",          "Ubuntu"),
    ("debian",                        "linux",          "Debian"),
    ("centos",                        "linux",          "CentOS"),
    ("fedora",                        "linux",          "Fedora"),
    ("proxmox",                       "linux",          "Proxmox VE"),
    ("cockpit",                       "linux",          "Cockpit (Linux admin)"),
    ("webmin",                        "linux",          "Webmin"),
    ("cpanel",                        "linux",          "cPanel"),
    ("directadmin",                   "linux",          "DirectAdmin"),
    ("plesk",                         "linux",          "Plesk"),
    ("phpmyadmin",                    "linux",          "phpMyAdmin"),
    ("nextcloud",                     "linux",          "Nextcloud"),
    ("owncloud",                      "linux",          "ownCloud"),
    ("gitlab",                        "linux",          "GitLab"),
    ("gitea",                         "linux",          "Gitea"),
    ("jenkins",                       "linux",          "Jenkins CI/CD"),
    ("grafana",                       "linux",          "Grafana"),
    ("kibana",                        "linux",          "Kibana"),
    ("portainer",                     "linux",          "Portainer (Docker)"),
    ("traefik",                       "linux",          "Traefik proxy"),
    ("plex",                          "linux",          "Plex Media Server"),
    ("jellyfin",                      "linux",          "Jellyfin media server"),
    ("emby",                          "linux",          "Emby media server"),
    ("pihole",                        "linux",          "Pi-hole"),
    ("vaultwarden",                   "linux",          "Vaultwarden (Bitwarden)"),
    ("bitwarden",                     "linux",          "Bitwarden"),
]
