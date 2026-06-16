from __future__ import annotations

# TTL fingerprinting reference tables.
#
# Each OS / firmware stack has a fixed *initial* TTL it stamps on outgoing
# packets.  By the time a packet reaches the scanner, routers have decremented
# it by 1 per hop.  We snap the received value up to the nearest boundary to
# reconstruct the initial TTL, then map that to a likely OS family.
#
# Usage:
#   estimated = snap_ttl(received_ttl)        # e.g. 118 → 128
#   hint      = TTL_OS_HINT[estimated]        # "windows"


# ── Snap boundaries ───────────────────────────────────────────────────────
# Standard initial TTL values used across all known OS/firmware families.
TTL_BOUNDARIES: tuple[int, ...] = (32, 64, 128, 255)


def snap_ttl(received: int) -> int:
    """Round a received TTL up to the nearest boundary (reconstructs initial TTL)."""
    for boundary in TTL_BOUNDARIES:
        if received <= boundary:
            return boundary
    return 255


# ── Initial TTL by OS / environment ───────────────────────────────────────
# (platform_key, environment) → initial TTL
TTL_INITIAL: dict[str, int] = {
    # ── Windows ───────────────────────────────────────────────────────────
    "windows":                  128,   # Windows XP / Vista / 7 / 8 / 10 / 11
    "windows_server_2003":      128,
    "windows_server_2008":      128,
    "windows_server_2012":      128,
    "windows_server_2016":      128,
    "windows_server_2019":      128,
    "windows_server_2022":      128,
    "windows_server_2025":      128,
    "windows_9x":                32,   # Windows 95 / 98 / ME (rare)
    "windows_nt_3":              32,   # Windows NT 3.1 / 3.5
    "windows_nt_4":             128,   # Windows NT 4.0
    "windows_2000":             128,
    # ── Linux ─────────────────────────────────────────────────────────────
    "linux":                     64,   # Linux kernel 2.x+ default
    "ubuntu":                    64,
    "debian":                    64,
    "centos":                    64,
    "rhel":                      64,   # Red Hat Enterprise Linux
    "fedora":                    64,
    "arch":                      64,
    "alpine":                    64,
    "gentoo":                    64,
    "suse":                      64,
    "opensuse":                  64,
    "nixos":                     64,
    "slackware":                 64,
    "void":                      64,
    "kali":                      64,
    "parrot":                    64,
    "raspberry_pi_os":           64,
    "android":                   64,   # Android (Linux kernel)
    "wsl1":                      64,   # Windows Subsystem for Linux 1
    "wsl2":                      64,   # Windows Subsystem for Linux 2
    "docker":                    64,   # Linux containers
    "lxc":                       64,   # LXC containers
    "podman":                    64,
    "kubernetes_pod":            64,
    "aws_ec2_linux":             64,
    "gcp_compute_linux":         64,
    "azure_linux":               64,
    # ── macOS / Darwin ────────────────────────────────────────────────────
    "macos":                     64,   # macOS 10.x and later
    "macos_ventura":             64,   # macOS 13
    "macos_sonoma":              64,   # macOS 14
    "macos_sequoia":             64,   # macOS 15
    "macos_monterey":            64,   # macOS 12
    "macos_big_sur":             64,   # macOS 11
    "macos_catalina":            64,   # macOS 10.15
    "macos_mojave":              64,   # macOS 10.14
    "macos_high_sierra":         64,   # macOS 10.13
    "ios":                       64,   # iPhone / iPad (Darwin kernel)
    "ipados":                    64,
    "tvos":                      64,   # Apple TV
    "watchos":                   64,
    "visionos":                  64,   # Apple Vision Pro
    # ── BSD family ────────────────────────────────────────────────────────
    "freebsd":                   64,   # FreeBSD 5+
    "freebsd_4":                255,   # FreeBSD 4.x and earlier
    "openbsd":                   64,   # OpenBSD
    "netbsd":                    64,
    "dragonflybsd":              64,
    "pfsense":                   64,   # pfSense (FreeBSD-based)
    "opnsense":                  64,   # OPNsense (FreeBSD-based)
    "truenas":                   64,   # TrueNAS (FreeBSD-based)
    "freenas":                   64,
    # ── Solaris / illumos / legacy Unix ───────────────────────────────────
    "solaris":                  255,   # Oracle Solaris 2.x – 11
    "openindiana":              255,   # illumos / OpenIndiana
    "omnios":                   255,
    "aix":                      255,   # IBM AIX
    "hp_ux":                    255,   # HP-UX
    "irix":                     255,   # SGI IRIX
    "tru64":                    255,   # HP Tru64 UNIX
    "nextstep":                  30,   # NeXTSTEP (historical)
    # ── Networking equipment — Cisco ──────────────────────────────────────
    "cisco_ios":                255,   # Cisco IOS
    "cisco_ios_xe":             255,   # Cisco IOS-XE
    "cisco_ios_xr":             255,   # Cisco IOS-XR
    "cisco_nx_os":               64,   # Cisco NX-OS (Linux-based)
    "cisco_asa":                255,   # Cisco ASA firewall
    "cisco_fxos":               255,   # Cisco FX-OS (Firepower)
    "cisco_wlc":                255,   # Cisco WLC
    # ── Networking equipment — other ──────────────────────────────────────
    "juniper_junos":             64,   # Juniper JunOS (FreeBSD-derived)
    "mikrotik_routeros":         64,   # MikroTik RouterOS (Linux-based)
    "palo_alto_panos":          255,   # Palo Alto PAN-OS
    "fortinet_fortios":         255,   # Fortinet FortiOS
    "fortinet_fortigate":       255,
    "zyxel":                    255,
    "huawei_vrp":               255,   # Huawei VRP
    "aruba_arubaos":            255,   # Aruba ArubaOS
    "ruckus":                    64,   # Ruckus SmartZone (Linux-based)
    "checkpoint":               255,   # Check Point Gaia
    "barracuda":                 64,   # Barracuda (Linux-based)
    "sonicwall":                255,   # SonicWall SonicOS
    "watchguard":               255,
    "extreme_exos":              64,   # Extreme Networks EXOS (Linux-based)
    "brocade_fabricos":         255,   # Brocade FabricOS
    "allied_telesis_aw+":       255,
    "openwrt":                   64,   # OpenWrt (Linux)
    "dd_wrt":                    64,   # DD-WRT (Linux)
    "tomato":                    64,   # Tomato firmware (Linux)
    "gargoyle":                  64,   # Gargoyle (OpenWrt-based)
    # ── Wi-Fi APs ─────────────────────────────────────────────────────────
    "ubiquiti_airos":           255,   # Ubiquiti AirOS (varies; often 255)
    "ubiquiti_unifi":            64,   # UniFi AP (Linux-based)
    "ubiquiti_edgeos":           64,   # EdgeOS (Linux-based)
    "tp_link_tplink_os":         64,   # TP-Link router firmware (Linux)
    "netgear_firmware":         255,
    "asus_asuswrt":              64,   # ASUS-WRT (Linux-based)
    "linksys_firmware":         255,
    # ── VMware ────────────────────────────────────────────────────────────
    "vmware_esxi":               64,   # VMware ESXi (Linux-derived hypervisor)
    "vmware_vcenter":            64,   # vCenter (Linux appliance)
    "vmware_horizon":           128,   # Horizon VDI client (usually Windows guest)
    # ── Printers ──────────────────────────────────────────────────────────
    "hp_jetdirect":             255,   # HP JetDirect firmware
    "hp_laserjet":              255,
    "hp_officejet":             255,
    "canon_print":               64,   # Canon (Linux-based firmware)
    "epson_print":               64,
    "brother_print":             64,
    "ricoh_print":              255,
    "xerox_print":               64,
    "kyocera_print":            255,
    "konica_minolta":            64,
    # ── IoT / embedded ────────────────────────────────────────────────────
    "embedded_linux":            64,   # Generic embedded Linux (OpenWrt, Buildroot…)
    "vxworks":                   64,   # Wind River VxWorks RTOS
    "threadx":                  255,   # Azure RTOS ThreadX
    "freertos":                 255,   # FreeRTOS (no TCP/IP default; lwIP used)
    "lwip":                     255,   # lwIP TCP/IP stack (ESP32, STM32, etc.)
    "contiki":                  255,   # Contiki OS
    "riot_os":                  255,
    "zephyr":                   255,
    "esp_idf":                  255,   # Espressif ESP-IDF (ESP32 / ESP8266)
    "arduino_ethernet":         255,   # Arduino with Wiznet W5x00 stack
    "synology_dsm":              64,   # Synology DSM (Linux)
    "qnap_qts":                  64,   # QNAP QTS (Linux)
    "hikvision":                 64,   # Hikvision camera (Linux)
    "dahua":                     64,   # Dahua camera (Linux)
    "axis":                      64,   # Axis camera (Linux)
    "roku":                      64,   # Roku (Linux)
    "google_cast":               64,   # Chromecast (Linux)
    "amazon_fire":               64,   # Fire OS (Android/Linux)
    "samsung_tizen":             64,   # Samsung Tizen OS (Linux)
    "lg_webos":                  64,   # LG webOS (Linux)
    # ── Game consoles ─────────────────────────────────────────────────────
    "xbox":                     128,   # Xbox (Windows-based OS)
    "xbox_360":                 128,
    "xbox_one":                 128,
    "xbox_series":              128,
    "playstation_3":            255,
    "playstation_4":             64,   # PS4 (FreeBSD-derived)
    "playstation_5":             64,   # PS5 (FreeBSD-derived)
    "nintendo_switch":           64,   # Switch (Linux-derived)
    "nintendo_wii":             255,
}

# ── Snapped TTL → scoring hint ────────────────────────────────────────────
# Maps the *estimated* (snapped) initial TTL to a probability-weighted hint.
# Use as a *weak* signal (S1) — combine with TCP/banner/SMB signals.
#
# Format: estimated_ttl → {"platform": str, "os_hint": str, "weight": float}
TTL_OS_HINT: dict[int, dict] = {
    32:  {
        "platform": "windows",
        "os_hint":  "Windows 95/98/ME or NT 3.x (very old)",
        "weight":   0.2,   # Very rare; low confidence
    },
    64:  {
        "platform": "linux",
        "os_hint":  "Linux / macOS / BSD / modern networking gear",
        "weight":   0.4,   # Common; ambiguous (Linux + macOS both use 64)
    },
    128: {
        "platform": "windows",
        "os_hint":  "Windows (XP and later)",
        "weight":   0.7,   # Strong Windows signal
    },
    255: {
        "platform": "network_device",
        "os_hint":  "Cisco IOS / Solaris / HP JetDirect / lwIP / embedded",
        "weight":   0.5,   # Moderately strong; covers several families
    },
}
