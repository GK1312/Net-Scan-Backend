import sys
import json
import socket
import subprocess
import re
import ssl
import struct
import time
import argparse
import ipaddress
import threading
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

_stdout_lock = threading.Lock()  # prevents interleaved JSONL lines
_VERBOSE = False  # set True automatically for single-IP scans
_DEFAULT_GATEWAYS: set[str] = set()  # this host's default-gateway IP(s)


def _vprint(tag: str, msg: str):
    if _VERBOSE:
        print(f"  [{tag:<16}] {msg}", file=sys.stderr, flush=True)


def _print_debug(result: dict):
    c = result["classification"]
    sc = result.get("_scores", {})
    score_log = result.get("_score_log", [])
    ev = result.get("evidence", {})

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"  Scan result: {c['ip']}", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    # ── Step-by-step scoring trace ────────────────────────────────────────
    if score_log:
        hdr = f"  {'#':<4} {'Signal':<18} {'Platform':<16} {'Delta':>7}  {'Running Total':>13}"
        print(f"\n  -- Step-by-step scoring trace --", file=sys.stderr)
        print(hdr, file=sys.stderr)
        print(f"  {'-'*90}", file=sys.stderr)
        for i, e in enumerate(score_log, 1):
            val = f"  [{e['value'][:55]}]" if e.get("value") else ""
            print(
                f"  {i:<4} {e['signal']:<18} {e['platform']:<16} "
                f"{e['delta']*100:>+6.1f}%  {e['total']*100:>11.1f}%  "
                f"{e['reason']}{val}",
                file=sys.stderr,
            )
    else:
        print(
            f"\n  (no scoring signals fired — host unreachable or short-circuited before classify)",
            file=sys.stderr,
        )

    # ── Score board ───────────────────────────────────────────────────────
    print(f"\n  -- Score board --", file=sys.stderr)
    for pl, raw in sorted(sc.items(), key=lambda x: x[1], reverse=True):
        pct = raw * 100
        bar = "#" * min(int(raw * 20), 20)
        marker = "  <-- WINNER" if pl == c["platform"] else ""
        status = f"{pct:5.1f}%" if pct > 0 else "  0.0%  (no signals fired)"
        print(f"    {pl:<16}  {status}  [{bar:<20}]{marker}", file=sys.stderr)

    # ── Conflict resolution (only if it happened) ─────────────────────────
    if ev.get("conflict_resolution"):
        cr = ev["conflict_resolution"]
        print(f"\n  -- Conflict resolution --", file=sys.stderr)
        print(f"    conflict:    {sorted(cr['conflict'])}", file=sys.stderr)
        print(f"    resolved by: {cr['resolved_by']}", file=sys.stderr)
        print(f"    winner:      {cr['winner']}", file=sys.stderr)
        print(f"    scores:      {cr['scores']}", file=sys.stderr)

    # ── Final result ──────────────────────────────────────────────────────
    print(f"\n  -- Result --", file=sys.stderr)
    print(f"    platform:    {c['platform']}", file=sys.stderr)
    print(f"    confidence:  {c['confidence']}%", file=sys.stderr)
    print(f"    os_hint:     {c['os_hint'] or '(none)'}", file=sys.stderr)
    print(f"    hostname:    {c['hostname'] or '(none)'}", file=sys.stderr)
    print(f"    duration:    {c['duration_ms']} ms", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TIMEOUT = 4  # TCP connect + read timeout (seconds)
UDP_TIMEOUT = 2.0  # UDP probes (SNMP, NetBIOS) — respond fast or not at all
CONNECT_TIMEOUT = 3.0  # TCP connect phase only; banner read uses full TIMEOUT
SHORT_CIRCUIT = 85  # stop probing if any platform reaches this (percent)
MIN_CONFIDENCE = 0.50  # below this → "unknown"
PROBE_PORTS = [
    21,
    22,
    23,
    80,
    135,
    139,
    161,
    443,
    445,
    548,
    554,
    631,
    902,
    1883,
    3306,
    3389,
    5985,
    7547,
    8080,
    8443,
    9100,
]
PLATFORMS = [
    "windows",
    "linux",
    "macos",
    "vmware_esxi",
    "snmp",
    "network_device",
    "iot",
    "printer",
    "wifi_ap",
    "mobile",
]

# ---------------------------------------------------------------------------
# OUI → (manufacturer, platform_hint) — first 3 MAC bytes, upper-case XX:XX:XX
# ---------------------------------------------------------------------------
_OUI_TABLE: dict[str, tuple[str, str]] = {
    # ── Espressif (ESP8266 / ESP32 — vast majority of DIY/cheap IoT) ──────
    "18:FE:34": ("Espressif", "iot"),
    "24:0A:C4": ("Espressif", "iot"),
    "24:6F:28": ("Espressif", "iot"),
    "2C:F4:32": ("Espressif", "iot"),
    "30:AE:A4": ("Espressif", "iot"),
    "3C:61:05": ("Espressif", "iot"),
    "3C:71:BF": ("Espressif", "iot"),
    "40:F5:20": ("Espressif", "iot"),
    "48:3F:DA": ("Espressif", "iot"),
    "4C:11:AE": ("Espressif", "iot"),
    "50:02:91": ("Espressif", "iot"),
    "54:43:B2": ("Espressif", "iot"),
    "58:BF:25": ("Espressif", "iot"),
    "5C:CF:7F": ("Espressif", "iot"),
    "60:01:94": ("Espressif", "iot"),
    "64:B7:08": ("Espressif", "iot"),
    "68:C6:3A": ("Espressif", "iot"),
    "70:03:9F": ("Espressif", "iot"),
    "78:21:84": ("Espressif", "iot"),
    "7C:9E:BD": ("Espressif", "iot"),
    "80:7D:3A": ("Espressif", "iot"),
    "84:0D:8E": ("Espressif", "iot"),
    "84:CC:A8": ("Espressif", "iot"),
    "84:F3:EB": ("Espressif", "iot"),
    "8C:AA:B5": ("Espressif", "iot"),
    "90:97:D5": ("Espressif", "iot"),
    "94:B5:55": ("Espressif", "iot"),
    "98:F4:AB": ("Espressif", "iot"),
    "A0:20:A6": ("Espressif", "iot"),
    "A4:7B:9D": ("Espressif", "iot"),
    "A4:CF:12": ("Espressif", "iot"),
    "AC:67:B2": ("Espressif", "iot"),
    "B4:E6:2D": ("Espressif", "iot"),
    "BC:DD:C2": ("Espressif", "iot"),
    "C4:4F:33": ("Espressif", "iot"),
    "C8:2B:96": ("Espressif", "iot"),
    "D8:A0:1D": ("Espressif", "iot"),
    "DC:4F:22": ("Espressif", "iot"),
    "E0:98:06": ("Espressif", "iot"),
    "E8:DB:84": ("Espressif", "iot"),
    "EC:FA:BC": ("Espressif", "iot"),
    "F0:08:D1": ("Espressif", "iot"),
    "F4:CF:A2": ("Espressif", "iot"),
    # ── Raspberry Pi ──────────────────────────────────────────────────────
    "B8:27:EB": ("Raspberry Pi", "iot"),
    "DC:A6:32": ("Raspberry Pi", "iot"),
    "E4:5F:01": ("Raspberry Pi", "iot"),
    # ── VMware ────────────────────────────────────────────────────────────
    "00:05:69": ("VMware", "vmware_esxi"),
    "00:0C:29": ("VMware", "vmware_esxi"),
    "00:1C:14": ("VMware", "vmware_esxi"),
    "00:50:56": ("VMware", "vmware_esxi"),
    # ── Cisco ─────────────────────────────────────────────────────────────
    "00:00:0C": ("Cisco", "network_device"),
    "00:1A:A1": ("Cisco", "network_device"),
    "00:1B:54": ("Cisco", "network_device"),
    "00:1C:57": ("Cisco", "network_device"),
    "58:AC:78": ("Cisco", "network_device"),
    "68:86:A7": ("Cisco", "network_device"),
    "A0:EC:F9": ("Cisco Meraki", "network_device"),
    "88:F0:31": ("Cisco", "network_device"),
    "CC:D8:C1": ("Cisco", "network_device"),
    # ── Juniper ───────────────────────────────────────────────────────────
    "00:10:DB": ("Juniper", "network_device"),
    "00:12:1E": ("Juniper", "network_device"),
    "2C:6B:F5": ("Juniper", "network_device"),
    "28:8A:1C": ("Juniper", "network_device"),
    # ── MikroTik ──────────────────────────────────────────────────────────
    "00:0C:42": ("MikroTik", "network_device"),
    "18:FD:74": ("MikroTik", "network_device"),
    "2C:C8:1B": ("MikroTik", "network_device"),
    "48:8F:5A": ("MikroTik", "network_device"),
    "4C:5E:0C": ("MikroTik", "network_device"),
    "6C:3B:6B": ("MikroTik", "network_device"),
    "74:4D:28": ("MikroTik", "network_device"),
    "B8:69:F4": ("MikroTik", "network_device"),
    "CC:2D:E0": ("MikroTik", "network_device"),
    "D4:CA:6D": ("MikroTik", "network_device"),
    "E4:8D:8C": ("MikroTik", "network_device"),
    # ── TP-Link ───────────────────────────────────────────────────────────
    "18:D6:C7": ("TP-Link", "wifi_ap"),
    "50:C7:BF": ("TP-Link", "wifi_ap"),
    "64:70:02": ("TP-Link", "wifi_ap"),
    "98:DA:C4": ("TP-Link", "wifi_ap"),
    "AC:84:C6": ("TP-Link", "wifi_ap"),
    "B4:B0:24": ("TP-Link", "wifi_ap"),
    "EC:08:6B": ("TP-Link", "wifi_ap"),
    "F8:1A:67": ("TP-Link", "wifi_ap"),
    "54:AF:97": ("TP-Link", "wifi_ap"),
    "C4:E9:84": ("TP-Link", "wifi_ap"),
    "50:D4:F7": ("TP-Link", "wifi_ap"),
    "30:DE:4B": ("TP-Link", "wifi_ap"),
    # ── Netgear ───────────────────────────────────────────────────────────
    "00:09:5B": ("Netgear", "wifi_ap"),
    "00:14:6C": ("Netgear", "wifi_ap"),
    "00:1B:2F": ("Netgear", "wifi_ap"),
    "00:1E:2A": ("Netgear", "wifi_ap"),
    "00:22:3F": ("Netgear", "wifi_ap"),
    "20:E5:2A": ("Netgear", "wifi_ap"),
    "28:C6:8E": ("Netgear", "wifi_ap"),
    "44:94:FC": ("Netgear", "wifi_ap"),
    "84:1B:5E": ("Netgear", "wifi_ap"),
    "A0:04:60": ("Netgear", "wifi_ap"),
    "C0:3F:0E": ("Netgear", "wifi_ap"),
    "2C:30:33": ("Netgear", "wifi_ap"),
    # ── ASUS ──────────────────────────────────────────────────────────────
    "00:0C:6E": ("ASUS", "wifi_ap"),
    "00:11:2F": ("ASUS", "wifi_ap"),
    "00:1A:92": ("ASUS", "wifi_ap"),
    "04:D4:C4": ("ASUS", "wifi_ap"),
    "08:60:6E": ("ASUS", "wifi_ap"),
    "10:BF:48": ("ASUS", "wifi_ap"),
    "14:DD:A9": ("ASUS", "wifi_ap"),
    "2C:FD:A1": ("ASUS", "wifi_ap"),
    "30:5A:3A": ("ASUS", "wifi_ap"),
    "38:2C:4A": ("ASUS", "wifi_ap"),
    "50:46:5D": ("ASUS", "wifi_ap"),
    "54:04:A6": ("ASUS", "wifi_ap"),
    "74:D0:2B": ("ASUS", "wifi_ap"),
    "88:D7:F6": ("ASUS", "wifi_ap"),
    "AC:22:0B": ("ASUS", "wifi_ap"),
    "BC:AE:C5": ("ASUS", "wifi_ap"),
    "F8:32:E4": ("ASUS", "wifi_ap"),
    "90:E6:BA": ("ASUS", "wifi_ap"),
    # ── Ubiquiti ──────────────────────────────────────────────────────────
    "00:15:6D": ("Ubiquiti", "wifi_ap"),
    "00:27:22": ("Ubiquiti", "wifi_ap"),
    "04:18:D6": ("Ubiquiti", "wifi_ap"),
    "0C:80:63": ("Ubiquiti", "wifi_ap"),
    "18:E8:29": ("Ubiquiti", "wifi_ap"),
    "24:A4:3C": ("Ubiquiti", "wifi_ap"),
    "44:D9:E7": ("Ubiquiti", "wifi_ap"),
    "68:72:51": ("Ubiquiti", "wifi_ap"),
    "74:83:C2": ("Ubiquiti", "wifi_ap"),
    "78:8A:20": ("Ubiquiti", "wifi_ap"),
    "80:2A:A8": ("Ubiquiti", "wifi_ap"),
    "B4:FB:E4": ("Ubiquiti", "wifi_ap"),
    "DC:9F:DB": ("Ubiquiti", "wifi_ap"),
    "E0:63:DA": ("Ubiquiti", "wifi_ap"),
    "F0:9F:C2": ("Ubiquiti", "wifi_ap"),
    "FC:EC:DA": ("Ubiquiti", "wifi_ap"),
    # ── D-Link ────────────────────────────────────────────────────────────
    "00:05:5D": ("D-Link", "wifi_ap"),
    "00:0D:88": ("D-Link", "wifi_ap"),
    "00:11:95": ("D-Link", "wifi_ap"),
    "00:15:E9": ("D-Link", "wifi_ap"),
    "00:17:9A": ("D-Link", "wifi_ap"),
    "00:19:5B": ("D-Link", "wifi_ap"),
    "00:1B:11": ("D-Link", "wifi_ap"),
    "00:1C:F0": ("D-Link", "wifi_ap"),
    "00:1E:58": ("D-Link", "wifi_ap"),
    "1C:7E:E5": ("D-Link", "wifi_ap"),
    "28:10:7B": ("D-Link", "wifi_ap"),
    "5C:D9:98": ("D-Link", "wifi_ap"),
    "84:C9:B2": ("D-Link", "wifi_ap"),
    "C8:BE:19": ("D-Link", "wifi_ap"),
    # ── Apple (macOS / iOS — disambiguated by open ports in classify) ──────
    "00:03:93": ("Apple", "macos"),
    "00:0A:27": ("Apple", "macos"),
    "00:0A:95": ("Apple", "macos"),
    "00:11:24": ("Apple", "macos"),
    "00:14:51": ("Apple", "macos"),
    "00:16:CB": ("Apple", "macos"),
    "00:17:F2": ("Apple", "macos"),
    "00:19:E3": ("Apple", "macos"),
    "00:1B:63": ("Apple", "macos"),
    "00:1C:B3": ("Apple", "macos"),
    "00:1D:4F": ("Apple", "macos"),
    "00:1E:52": ("Apple", "macos"),
    "00:1F:5B": ("Apple", "macos"),
    "00:1F:F3": ("Apple", "macos"),
    "00:21:E9": ("Apple", "macos"),
    "00:22:41": ("Apple", "macos"),
    "00:23:12": ("Apple", "macos"),
    "00:25:00": ("Apple", "macos"),
    "00:25:BC": ("Apple", "macos"),
    "00:26:BB": ("Apple", "macos"),
    "04:26:65": ("Apple", "mobile"),
    "04:4B:ED": ("Apple", "mobile"),
    "04:D3:CF": ("Apple", "mobile"),
    "08:70:45": ("Apple", "mobile"),
    "0C:3E:9F": ("Apple", "mobile"),
    "0C:74:C2": ("Apple", "mobile"),
    "0C:BC:9F": ("Apple", "mobile"),
    "10:40:F3": ("Apple", "mobile"),
    "18:AF:61": ("Apple", "mobile"),
    "1C:91:48": ("Apple", "mobile"),
    "20:76:93": ("Apple", "mobile"),
    "28:37:37": ("Apple", "mobile"),
    "34:12:98": ("Apple", "mobile"),
    "34:C0:59": ("Apple", "mobile"),
    "38:66:F0": ("Apple", "mobile"),
    "3C:15:C2": ("Apple", "mobile"),
    "40:30:04": ("Apple", "mobile"),
    "40:D3:2D": ("Apple", "mobile"),
    "4C:57:CA": ("Apple", "mobile"),
    "58:55:CA": ("Apple", "mobile"),
    "5C:96:9D": ("Apple", "mobile"),
    "60:F8:1D": ("Apple", "mobile"),
    "6C:40:08": ("Apple", "mobile"),
    "70:EC:E4": ("Apple", "mobile"),
    "78:4F:43": ("Apple", "mobile"),
    "7C:FA:DF": ("Apple", "mobile"),
    "80:BE:05": ("Apple", "mobile"),
    "84:B1:53": ("Apple", "mobile"),
    "8C:7C:92": ("Apple", "mobile"),
    "90:72:40": ("Apple", "mobile"),
    "94:E9:6A": ("Apple", "mobile"),
    "98:01:A7": ("Apple", "mobile"),
    "9C:F3:87": ("Apple", "mobile"),
    "A4:B1:97": ("Apple", "mobile"),
    "A8:51:AB": ("Apple", "mobile"),
    "AC:BC:32": ("Apple", "mobile"),
    "B0:35:9F": ("Apple", "mobile"),
    "B4:F0:AB": ("Apple", "mobile"),
    "BC:9F:EF": ("Apple", "mobile"),
    "C0:63:94": ("Apple", "mobile"),
    "C8:2A:14": ("Apple", "mobile"),
    "CC:44:63": ("Apple", "mobile"),
    "D0:03:4B": ("Apple", "mobile"),
    "D4:DC:CD": ("Apple", "mobile"),
    "D8:96:95": ("Apple", "mobile"),
    "DC:2B:2A": ("Apple", "mobile"),
    "E0:B5:2D": ("Apple", "mobile"),
    "E4:CE:8F": ("Apple", "mobile"),
    "E8:04:0B": ("Apple", "mobile"),
    "EC:35:86": ("Apple", "mobile"),
    "F0:D1:A9": ("Apple", "mobile"),
    "F4:1B:A1": ("Apple", "mobile"),
    "F8:1E:DF": ("Apple", "mobile"),
    # ── Samsung ───────────────────────────────────────────────────────────
    "00:12:47": ("Samsung", "mobile"),
    "00:15:99": ("Samsung", "mobile"),
    "00:16:32": ("Samsung", "mobile"),
    "00:17:C9": ("Samsung", "mobile"),
    "00:1A:8A": ("Samsung", "mobile"),
    "00:1B:98": ("Samsung", "mobile"),
    "00:1C:43": ("Samsung", "mobile"),
    "00:1D:25": ("Samsung", "mobile"),
    "00:1E:7D": ("Samsung", "mobile"),
    "00:21:19": ("Samsung", "mobile"),
    "00:23:39": ("Samsung", "mobile"),
    "00:24:54": ("Samsung", "mobile"),
    "00:E3:B2": ("Samsung", "mobile"),
    "04:18:0F": ("Samsung", "mobile"),
    "04:1B:BA": ("Samsung", "mobile"),
    "08:D4:2B": ("Samsung", "mobile"),
    "0C:14:20": ("Samsung", "mobile"),
    "14:49:BC": ("Samsung", "mobile"),
    "20:13:E0": ("Samsung", "mobile"),
    "28:98:7B": ("Samsung", "mobile"),
    "34:31:C4": ("Samsung", "mobile"),
    "40:0E:85": ("Samsung", "mobile"),
    "48:44:F7": ("Samsung", "mobile"),
    "50:01:BB": ("Samsung", "mobile"),
    "54:88:0E": ("Samsung", "mobile"),
    "5C:49:79": ("Samsung", "mobile"),
    "60:A1:0A": ("Samsung", "mobile"),
    "68:27:37": ("Samsung", "mobile"),
    "6C:F3:73": ("Samsung", "mobile"),
    "78:40:E4": ("Samsung", "mobile"),
    "84:25:DB": ("Samsung", "mobile"),
    "8C:77:12": ("Samsung", "mobile"),
    "94:35:0A": ("Samsung", "mobile"),
    "98:52:B1": ("Samsung", "mobile"),
    "A8:06:00": ("Samsung", "mobile"),
    "B0:72:BF": ("Samsung", "mobile"),
    "C0:BD:D1": ("Samsung", "mobile"),
    "CC:07:AB": ("Samsung", "mobile"),
    "D0:22:BE": ("Samsung", "mobile"),
    "E4:92:FB": ("Samsung", "mobile"),
    "F4:42:8F": ("Samsung", "mobile"),
    # ── Xiaomi ────────────────────────────────────────────────────────────
    "00:9E:C8": ("Xiaomi", "mobile"),
    "04:CF:8C": ("Xiaomi", "iot"),
    "14:F6:5A": ("Xiaomi", "mobile"),
    "18:59:36": ("Xiaomi", "mobile"),
    "20:82:C0": ("Xiaomi", "mobile"),
    "28:6C:07": ("Xiaomi", "mobile"),
    "34:80:B3": ("Xiaomi", "iot"),
    "38:A4:ED": ("Xiaomi", "mobile"),
    "3C:BD:D8": ("Xiaomi", "mobile"),
    "50:64:2B": ("Xiaomi", "mobile"),
    "58:44:98": ("Xiaomi", "mobile"),
    "5C:E8:EB": ("Xiaomi", "mobile"),
    "64:09:80": ("Xiaomi", "mobile"),
    "64:B4:73": ("Xiaomi", "iot"),
    "68:DF:DD": ("Xiaomi", "mobile"),
    "78:02:F8": ("Xiaomi", "mobile"),
    "90:C7:92": ("Xiaomi", "iot"),
    "98:FA:E3": ("Xiaomi", "mobile"),
    "A0:86:C6": ("Xiaomi", "mobile"),
    "AC:C1:EE": ("Xiaomi", "mobile"),
    "CC:2D:83": ("Xiaomi", "iot"),
    "F0:B4:29": ("Xiaomi", "mobile"),
    # ── Google (Chromecast / Nest / Pixel) ────────────────────────────────
    "00:1A:11": ("Google", "iot"),
    "1C:F2:9A": ("Google", "iot"),
    "20:DF:B9": ("Google", "iot"),
    "48:D6:D5": ("Google", "iot"),
    "54:60:09": ("Google", "iot"),
    "58:6D:8F": ("Google", "iot"),
    "6C:AD:F8": ("Google", "iot"),
    "94:95:A0": ("Google", "iot"),
    "A4:77:33": ("Google", "iot"),
    "C8:FF:28": ("Google/Nest", "iot"),
    "E4:F0:42": ("Google", "iot"),
    "F4:F5:D8": ("Google", "iot"),
    # ── Amazon (Echo / Fire / Ring) ───────────────────────────────────────
    "00:BB:3A": ("Amazon", "iot"),
    "10:AE:60": ("Amazon", "iot"),
    "18:74:2E": ("Amazon", "iot"),
    "28:EF:01": ("Amazon", "iot"),
    "34:D2:70": ("Amazon", "iot"),
    "38:F7:3D": ("Amazon", "iot"),
    "40:B4:CD": ("Amazon", "iot"),
    "50:DC:E7": ("Amazon", "iot"),
    "68:37:E9": ("Amazon", "iot"),
    "74:C2:46": ("Amazon", "iot"),
    "84:D6:D0": ("Amazon", "iot"),
    "A0:02:DC": ("Amazon", "iot"),
    "AC:63:BE": ("Amazon", "iot"),
    "B4:7C:9C": ("Amazon", "iot"),
    "CC:9E:A2": ("Amazon", "iot"),
    "F0:27:2D": ("Amazon", "iot"),
    "F0:4F:7C": ("Amazon", "iot"),
    "FC:A1:83": ("Amazon", "iot"),
    "B0:09:DA": ("Ring/Amazon", "iot"),
    # ── Philips Hue ───────────────────────────────────────────────────────
    "00:17:88": ("Philips Hue", "iot"),
    "EC:B5:FA": ("Philips Hue", "iot"),
    # ── Sonos ─────────────────────────────────────────────────────────────
    "00:0E:58": ("Sonos", "iot"),
    "34:7E:5C": ("Sonos", "iot"),
    "48:A6:B8": ("Sonos", "iot"),
    "54:2A:1B": ("Sonos", "iot"),
    "78:28:CA": ("Sonos", "iot"),
    "94:9F:3E": ("Sonos", "iot"),
    "B8:E9:37": ("Sonos", "iot"),
    # ── Hikvision / Dahua (IP cameras) ───────────────────────────────────
    "44:19:B6": ("Hikvision", "iot"),
    "4C:BD:8F": ("Hikvision", "iot"),
    "54:C4:15": ("Hikvision", "iot"),
    "A0:AC:22": ("Hikvision", "iot"),
    "C0:56:E3": ("Hikvision", "iot"),
    "90:02:A9": ("Dahua", "iot"),
    "E4:24:6C": ("Dahua", "iot"),
    # ── HP (printers & ProCurve switches) ─────────────────────────────────
    "00:01:E6": ("HP", "printer"),
    "00:01:E7": ("HP", "printer"),
    "00:08:02": ("HP", "printer"),
    "00:11:0A": ("HP", "printer"),
    "00:12:79": ("HP", "printer"),
    "00:13:21": ("HP", "printer"),
    "00:14:38": ("HP", "printer"),
    "00:17:08": ("HP", "printer"),
    "00:18:71": ("HP", "printer"),
    "00:1A:4B": ("HP", "printer"),
    "00:1B:78": ("HP", "printer"),
    "00:1C:C4": ("HP", "printer"),
    "00:1E:0B": ("HP", "printer"),
    "00:1F:29": ("HP", "printer"),
    "00:21:5A": ("HP", "printer"),
    "00:22:64": ("HP", "printer"),
    "00:23:7D": ("HP", "printer"),
    "00:25:B3": ("HP", "printer"),
    "00:30:C1": ("HP", "printer"),
    "28:92:4A": ("HP", "printer"),
    # ── Epson ─────────────────────────────────────────────────────────────
    "00:04:AC": ("Epson", "printer"),
    "00:26:AB": ("Epson", "printer"),
    "44:D2:44": ("Epson", "printer"),
    "64:EB:8C": ("Epson", "printer"),
    "AC:18:26": ("Epson", "printer"),
    # ── Canon ─────────────────────────────────────────────────────────────
    "00:00:85": ("Canon", "printer"),
    "00:1E:8F": ("Canon", "printer"),
    "14:C2:13": ("Canon", "printer"),
    "68:26:F2": ("Canon", "printer"),
    # ── Brother ───────────────────────────────────────────────────────────
    "00:1B:A9": ("Brother", "printer"),
    "00:80:77": ("Brother", "printer"),
    "28:84:FA": ("Brother", "printer"),
    # ── Xerox ─────────────────────────────────────────────────────────────
    "00:00:AA": ("Xerox", "printer"),
    "00:00:51": ("Xerox", "printer"),
}


# ---------------------------------------------------------------------------
# Result skeleton
# ---------------------------------------------------------------------------
def _build_result() -> dict:
    return {
        "classification": {
            "ip": None,
            "platform": "",
            "confidence": 0.0,
            "os_hint": None,
            "hostname": None,
            "reachable": False,
            "duration_ms": 0,
            "error": None,
        },
        "probes": {
            "icmp": {
                "responded": False,
                "ttl_received": None,
                "ttl_estimated": None,
                "rtt_ms": None,
            },
            "tcp_ports": {
                "probed": PROBE_PORTS,
                "open": [],
                "filtered": [],
                "closed": [],
            },
            "smb": {
                "probed": False,  # True once signalThree has run
                "responded": False,
                "dialect": None,
                "os_version": None,
                "native_os": None,
                "computer_name": None,
                "domain": None,
                "server_guid": None,  # zero → Samba; non-zero → genuine Windows
                "is_samba": None,  # True / False / None (unknown)
            },
            "ssh": {
                "responded": False,
                "banner": None,
            },
            "tls_443": {
                "responded": False,
                "subject": None,
                "issuer": None,
                "san": [],
                "ja3": None,
            },
            "http": {
                "responded": False,
                "server": None,
                "title": None,
                "headers": {},
            },
            "snmp": {
                "responded": False,
                "sys_descr": None,
                "sys_name": None,
                "sys_object_id": None,
            },
            "netbios": {
                "responded": False,
                "computer_name": None,
                "domain": None,
                "mac": None,
            },
            "rdp": {
                "responded": False,
            },
            "vmware_authd": {
                "responded": False,
                "banner": None,
            },
            "mdns": {
                "responded": False,
                "services": [],
                "hostname": None,
            },
            "upnp": {
                "responded": False,
                "friendly_name": None,
                "manufacturer": None,
                "model_name": None,
                "location": None,
            },
            "mqtt": {
                "responded": False,
            },
            "ipp": {
                "responded": False,
                "printer_name": None,
                "make_model": None,
            },
            "rtsp": {
                "responded": False,
                "banner": None,
            },
            "arp": {
                "mac": None,
                "manufacturer": None,
                "platform_hint": None,
                "randomized": None,  # True = LAA bit set (iOS/Android MAC randomization)
            },
            "telnet": {
                "responded": False,
                "banner": None,
            },
        },
        "evidence": {
            "ttl_rule": {},
            "port_rule": {},
            "banner_rule": {},
            "service_rule": {},
            "os_rule": {},
            "conflict_resolution": None,
        },
    }


# ---------------------------------------------------------------------------
# Windows version table
# ---------------------------------------------------------------------------
_WIN_VERSIONS: dict[str, str] = {
    "10.0.26100": "Windows 11 24H2",
    "10.0.22631": "Windows 11 23H2",
    "10.0.22621": "Windows 11 22H2",
    "10.0.22000": "Windows 11 21H2",
    "10.0.26080": "Windows Server 2025",
    "10.0.20348": "Windows Server 2022",
    "10.0.19045": "Windows 10 22H2",
    "10.0.19044": "Windows 10 21H2",
    "10.0.19043": "Windows 10 21H1",
    "10.0.19042": "Windows 10 20H2",
    "10.0.19041": "Windows 10 2004",
    "10.0.18363": "Windows 10 1909",
    "10.0.18362": "Windows 10 1903",
    "10.0.17763": "Windows Server 2019 / Windows 10 1809",
    "10.0.17134": "Windows 10 1803",
    "10.0.16299": "Windows 10 1709",
    "10.0.15063": "Windows 10 1703",
    "10.0.14393": "Windows Server 2016 / Windows 10 1607",
    "10.0.10586": "Windows 10 1511",
    "10.0.10240": "Windows 10 1507",
    "6.3.9600": "Windows 8.1 / Server 2012 R2",
    "6.2.9200": "Windows 8 / Server 2012",
    "6.1.7601": "Windows 7 SP1 / Server 2008 R2 SP1",
    "6.1.7600": "Windows 7 RTM",
    "6.0.6002": "Windows Vista SP2 / Server 2008 SP2",
    "6.0.6001": "Windows Vista SP1 / Server 2008",
    "6.0.6000": "Windows Vista RTM",
    "5.2.3790": "Windows Server 2003 / XP x64",
    "5.1.2600": "Windows XP",
}


def _win_version_name(major: int, minor: int, build: int) -> str:
    key = f"{major}.{minor}.{build}"
    return _WIN_VERSIONS.get(key, f"Windows {major}.{minor} (build {build})")


# ---------------------------------------------------------------------------
# SSH OS hint tables + parser
# ---------------------------------------------------------------------------
# OpenSSH default version shipped with each Ubuntu LTS (major.minor key)
_UBUNTU_BY_OPENSSH: dict[str, str] = {
    "10.0": "Ubuntu 25.04 (Plucky)",
    "9.9": "Ubuntu 25.04 (Plucky)",
    "9.7": "Ubuntu 24.10 (Oracular)",
    "9.6": "Ubuntu 24.04 LTS (Noble)",
    "8.9": "Ubuntu 22.04 LTS (Jammy)",
    "8.2": "Ubuntu 20.04 LTS (Focal)",
    "7.6": "Ubuntu 18.04 LTS (Bionic)",
    "7.2": "Ubuntu 16.04 LTS (Xenial)",
    "6.6": "Ubuntu 14.04 LTS (Trusty)",
}

# OpenSSH default version shipped with each Debian release
_DEBIAN_BY_OPENSSH: dict[str, str] = {
    "9.9": "Debian 13 (Trixie)",
    "9.2": "Debian 12 (Bookworm)",
    "8.4": "Debian 11 (Bullseye)",
    "7.9": "Debian 10 (Buster)",
    "7.4": "Debian 9 (Stretch)",
    "6.7": "Debian 8 (Jessie)",
}

# OpenSSH default version shipped with each RHEL/CentOS/AlmaLinux/Rocky release
_RHEL_BY_OPENSSH: dict[str, str] = {
    "8.7": "RHEL / AlmaLinux / Rocky 9",
    "8.0": "RHEL / CentOS 8",
    "7.4": "RHEL / CentOS 7",
    "6.6": "RHEL / CentOS 6",
}

# OpenSSH version shipped with each Fedora release
_FEDORA_BY_OPENSSH: dict[str, str] = {
    "9.9": "Fedora 41+",
    "9.6": "Fedora 40",
    "9.3": "Fedora 38/39",
    "9.0": "Fedora 36/37",
    "8.8": "Fedora 35",
}

__SSH_BANNER_RE = re.compile(
    r"SSH-\d+\.\d+-OpenSSH_(\d+\.\d+)[^\s]*(?:\s+(.+))?$", re.IGNORECASE
)
__UBUNTU_COMMENT_RE = re.compile(r"Ubuntu", re.IGNORECASE)
__DEBIAN_COMMENT_RE = re.compile(r"Debian", re.IGNORECASE)
__RASPBIAN_COMMENT_RE = re.compile(r"Raspbian", re.IGNORECASE)
__RHEL_COMMENT_RE = re.compile(
    r"(Red\s*Hat|RHEL|CentOS|AlmaLinux|Rocky)", re.IGNORECASE
)
__FEDORA_COMMENT_RE = re.compile(r"Fedora", re.IGNORECASE)
__FREEBSD_COMMENT_RE = re.compile(r"FreeBSD", re.IGNORECASE)


def _parse_ssh_os_hint(banner: str) -> str:
    """Return a human-readable OS name derived from an SSH banner string."""
    m = __SSH_BANNER_RE.match(banner.strip())
    if not m:
        return banner
    ver_str = m.group(1)  # e.g. "8.9"
    comment = (m.group(2) or "").strip()

    # Helper: look up a table by major.minor key
    def _lookup(table: dict[str, str]) -> str | None:
        return table.get(ver_str)

    # --- Distro detected from comment field --------------------------------
    if __UBUNTU_COMMENT_RE.search(comment):
        return _lookup(_UBUNTU_BY_OPENSSH) or f"Ubuntu (OpenSSH {ver_str})"

    if __RASPBIAN_COMMENT_RE.search(comment):
        return f"Raspbian / Raspberry Pi OS (OpenSSH {ver_str})"

    if __DEBIAN_COMMENT_RE.search(comment):
        return _lookup(_DEBIAN_BY_OPENSSH) or f"Debian (OpenSSH {ver_str})"

    if __RHEL_COMMENT_RE.search(comment):
        return _lookup(_RHEL_BY_OPENSSH) or f"RHEL/CentOS (OpenSSH {ver_str})"

    if __FEDORA_COMMENT_RE.search(comment):
        return _lookup(_FEDORA_BY_OPENSSH) or f"Fedora (OpenSSH {ver_str})"

    if __FREEBSD_COMMENT_RE.search(comment):
        return f"FreeBSD (OpenSSH {ver_str})"

    # --- No distro in comment: try version-table heuristics ----------------
    ubuntu = _lookup(_UBUNTU_BY_OPENSSH)
    if ubuntu:
        return ubuntu

    debian = _lookup(_DEBIAN_BY_OPENSSH)
    if debian:
        return debian

    rhel = _lookup(_RHEL_BY_OPENSSH)
    if rhel:
        return rhel

    # Fallback: just show the OpenSSH version cleanly
    return f"Linux (OpenSSH {ver_str})"


# ---------------------------------------------------------------------------
# ARP MAC lookup + OUI identification
# ---------------------------------------------------------------------------
_MAC_RE = re.compile(
    r"([\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}"
    r"[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2})"
)


def _get_mac_from_arp(ip: str) -> str | None:
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(
                ["arp", "-a", ip], timeout=3, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
        else:
            out = subprocess.check_output(
                ["arp", "-n", ip], timeout=3, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
        # Only accept a MAC from the line that contains the target IP
        for line in out.splitlines():
            if ip in line:
                m = _MAC_RE.search(line)
                if m:
                    return m.group(1).upper().replace("-", ":")
    except Exception:
        pass
    return None


def _is_randomized_mac(mac: str) -> bool:
    """True when the locally-administered (LAA) bit is set — iOS/Android MAC randomization."""
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except Exception:
        return False


def signalZero(ip: str, result: dict):
    """Run after phase-1 so the OS ARP cache is already populated."""
    mac = _get_mac_from_arp(ip)
    if not mac:
        return
    oui = mac[:8]
    entry = _OUI_TABLE.get(oui)
    randomized = _is_randomized_mac(mac)
    result["probes"]["arp"].update(
        {
            "mac": mac,
            "manufacturer": entry[0] if entry else None,
            "platform_hint": entry[1] if (entry and not randomized) else None,
            "randomized": randomized,
        }
    )


# ---------------------------------------------------------------------------
# Signal 1 — ICMP ping (reachability + TTL)
# ---------------------------------------------------------------------------
def _estimate_ttl(received: int) -> int:
    if received <= 32:
        return 32
    if received <= 64:
        return 64
    if received <= 128:
        return 128
    return 255


def signalOne(ip: str, result: dict):
    try:
        out = subprocess.check_output(
            ["ping", "-n", "2", "-w", "4000", ip], stderr=subprocess.DEVNULL, timeout=12
        ).decode(errors="ignore")

        ttl_m = re.search(r"TTL=(\d+)", out, re.IGNORECASE)
        rtt_m = re.search(r"time[=<](\d+)ms", out, re.IGNORECASE)

        if ttl_m:
            ttl = int(ttl_m.group(1))
            est = _estimate_ttl(ttl)
            result["probes"]["icmp"].update(
                {
                    "responded": True,
                    "ttl_received": ttl,
                    "ttl_estimated": est,
                    "rtt_ms": int(rtt_m.group(1)) if rtt_m else None,
                }
            )
    except subprocess.CalledProcessError:
        pass
    except Exception as exc:
        result["classification"]["error"] = str(exc)


# ---------------------------------------------------------------------------
# Signal 2 — TCP port scan
# ---------------------------------------------------------------------------
def _probe_port(ip: str, port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect((ip, port))
        return port, "open"
    except socket.timeout:
        return port, "filtered"
    except ConnectionRefusedError:
        return port, "closed"
    except OSError:
        return port, "filtered"
    finally:
        s.close()


def signalTwo(ip: str, result: dict):
    with ThreadPoolExecutor(max_workers=len(PROBE_PORTS)) as ex:
        for port, state in (
            f.result()
            for f in as_completed(
                {ex.submit(_probe_port, ip, p): p for p in PROBE_PORTS}
            )
        ):
            result["probes"]["tcp_ports"][state].append(port)


# ---------------------------------------------------------------------------
# Signal 3 — SMB negotiate + SESSION_SETUP (NTLMSSP version + AvPairs)
# ---------------------------------------------------------------------------
def _smb2_header(command: int, msg_id: int) -> bytes:
    return (
        b"\xfeSMB"
        + b"\x40\x00"
        + b"\x00\x00"
        + b"\x00\x00\x00\x00"
        + command.to_bytes(2, "little")
        + b"\x1f\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + msg_id.to_bytes(8, "little")
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 8
        + b"\x00" * 16
    )


def _netbios(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


_SMB2_NEG_BODY = (
    b"\x24\x00"
    + b"\x02\x00"
    + b"\x01\x00"
    + b"\x00\x00"
    + b"\x7f\x00\x00\x00"
    + b"\x00" * 16
    + b"\x00" * 8
    + b"\x02\x02"
    + b"\x10\x02"
)

# NTLMSSP_NEGOTIATE with NTLMSSP_NEGOTIATE_VERSION flag → server includes OS build
_NTLMSSP_NEG = (
    b"NTLMSSP\x00"
    + b"\x01\x00\x00\x00"
    + b"\x15\x82\x08\x62"  # NegotiateFlags
    + b"\x00" * 8  # DomainNameFields
    + b"\x00" * 8  # WorkstationFields
    + b"\x0a\x00\x00\x00\x00\x00\x00\x0f"  # Version (10.0, build 0, rev 15)
)


def _smb2_session_setup_packet(ntlmssp: bytes) -> bytes:
    body = (
        b"\x19\x00"
        + b"\x00"
        + b"\x01"
        + b"\x7f\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x58\x00"
        + len(ntlmssp).to_bytes(2, "little")
        + b"\x00" * 8
        + ntlmssp
    )
    return _netbios(_smb2_header(0x0001, 1) + body)


def _parse_ntlmssp_avpairs(ntlmssp: bytes) -> dict:
    """Extract computer_name and domain from NTLMSSP CHALLENGE AvPairs."""
    result: dict = {}
    if len(ntlmssp) < 48:
        return result
    ti_len = struct.unpack_from("<H", ntlmssp, 40)[0]
    ti_offset = struct.unpack_from("<I", ntlmssp, 44)[0]
    if ti_offset + ti_len > len(ntlmssp):
        return result
    avpairs = ntlmssp[ti_offset : ti_offset + ti_len]
    i = 0
    while i + 4 <= len(avpairs):
        av_id = struct.unpack_from("<H", avpairs, i)[0]
        av_len = struct.unpack_from("<H", avpairs, i + 2)[0]
        i += 4
        if av_id == 0x0000:
            break
        if i + av_len > len(avpairs):
            break
        raw = avpairs[i : i + av_len]
        i += av_len
        try:
            val = raw.decode("utf-16-le", errors="ignore")
        except Exception:
            continue
        if av_id == 0x0001:
            result["computer_name"] = val
        elif av_id == 0x0002:
            result["nb_domain"] = val
        elif av_id == 0x0003:
            result["dns_computer_name"] = val
        elif av_id == 0x0004:
            result["dns_domain"] = val
    return result


def signalThree(ip: str, result: dict):
    if 445 not in result["probes"]["tcp_ports"]["open"]:
        return
    result["probes"]["smb"]["probed"] = True
    neg_packet = _netbios(_smb2_header(0x0000, 0) + _SMB2_NEG_BODY)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, 445))
        s.sendall(neg_packet)
        resp1 = s.recv(4096)

        # DialectRevision: NetBIOS(4) + SMB2 hdr(64) + body[2:4] = offset 72
        if len(resp1) < 74 or resp1[4:8] != b"\xfeSMB":
            s.close()
            return

        result["probes"]["smb"]["responded"] = True
        dialect_val = struct.unpack_from("<H", resp1, 72)[0]
        result["probes"]["smb"]["dialect"] = {
            0x0202: "SMB 2.0.2",
            0x0210: "SMB 2.1",
            0x0300: "SMB 3.0",
            0x0302: "SMB 3.0.2",
            0x0311: "SMB 3.1.1",
            0x02FF: "SMB 2.x",
        }.get(dialect_val, f"0x{dialect_val:04x}")

        # ServerGuid: body offset 8 → packet offset 4+64+8 = 76, length 16
        # Windows always sets a non-zero GUID; Samba leaves it all-zeros
        if len(resp1) >= 92:
            guid = resp1[76:92]
            result["probes"]["smb"]["server_guid"] = guid.hex()
            result["probes"]["smb"]["is_samba"] = guid == b"\x00" * 16

        # SESSION_SETUP → NTLMSSP CHALLENGE contains OS version + AvPairs
        s.sendall(_smb2_session_setup_packet(_NTLMSSP_NEG))
        resp2 = s.recv(4096)
        s.close()

        pos = resp2.find(b"NTLMSSP\x00")
        if pos == -1:
            return
        ntlmssp = resp2[pos:]

        # Must be MessageType 2 (CHALLENGE) with ≥56 bytes for version
        if len(ntlmssp) < 56 or struct.unpack_from("<I", ntlmssp, 8)[0] != 2:
            return

        major = ntlmssp[48]
        minor = ntlmssp[49]
        build = struct.unpack_from("<H", ntlmssp, 50)[0]
        ver_str = f"{major}.{minor}.{build}"
        ver_name = _win_version_name(major, minor, build)
        result["probes"]["smb"]["os_version"] = ver_str
        result["probes"]["smb"]["native_os"] = ver_name

        avs = _parse_ntlmssp_avpairs(ntlmssp)
        result["probes"]["smb"]["computer_name"] = avs.get(
            "dns_computer_name"
        ) or avs.get("computer_name")
        result["probes"]["smb"]["domain"] = avs.get("dns_domain") or avs.get(
            "nb_domain"
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Signal 4 — SSH banner grab
# ---------------------------------------------------------------------------
def signalFour(ip: str, result: dict):
    if 22 not in result["probes"]["tcp_ports"]["open"]:
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        s.connect((ip, 22))
        s.settimeout(TIMEOUT)  # banner may take longer to arrive
        banner = s.recv(256).decode(errors="ignore").strip()
        s.close()
        if banner.startswith("SSH"):
            result["probes"]["ssh"].update({"responded": True, "banner": banner})
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Signal 5 — TLS/443 certificate
# ---------------------------------------------------------------------------
def _cn_from_der(der: bytes) -> str | None:
    cn_oid = b"\x55\x04\x03"
    pos = der.rfind(cn_oid)
    if pos == -1:
        return None
    j = pos + 3
    if j + 2 > len(der):
        return None
    tag, n = der[j], der[j + 1]
    if tag in (0x0C, 0x13, 0x16, 0x1A) and not (n & 0x80):
        return der[j + 2 : j + 2 + n].decode(errors="ignore")
    return None


def _ou_from_der(der: bytes) -> str | None:
    """Extract last OU value from DER (OID 2.5.4.11 = 55 04 0b)."""
    ou_oid = b"\x55\x04\x0b"
    pos = der.rfind(ou_oid)
    if pos == -1:
        return None
    j = pos + 3
    if j + 2 > len(der):
        return None
    tag, n = der[j], der[j + 1]
    if tag in (0x0C, 0x13, 0x16, 0x1A) and not (n & 0x80):
        return der[j + 2 : j + 2 + n].decode(errors="ignore")
    return None


def signalFive(ip: str, result: dict):
    if 443 not in result["probes"]["tcp_ports"]["open"]:
        return

    def _connect(verify: bool):
        if verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                return ssock.getpeercert(), ssock.getpeercert(binary_form=True)

    cert_dict, cert_der = None, None
    try:
        cert_dict, cert_der = _connect(verify=True)
    except Exception:
        try:
            _, cert_der = _connect(verify=False)
        except Exception:
            pass

    if cert_dict is None and cert_der is None:
        return

    result["probes"]["tls_443"]["responded"] = True

    if cert_dict:
        subject = dict(x[0] for x in cert_dict.get("subject", []))
        issuer = dict(x[0] for x in cert_dict.get("issuer", []))
        san = [v for _, v in cert_dict.get("subjectAltName", [])]
        result["probes"]["tls_443"].update(
            {"subject": subject, "issuer": issuer, "san": san}
        )
    elif cert_der:
        cn = _cn_from_der(cert_der)
        ou = _ou_from_der(cert_der)
        result["probes"]["tls_443"]["subject"] = {
            "commonName": cn,
            "organizationalUnitName": ou,
        }


# ---------------------------------------------------------------------------
# Signal 6 — HTTP/HTTPS server header + title
# ---------------------------------------------------------------------------
def signalSix(ip: str, result: dict):
    _ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    open_p = set(result["probes"]["tcp_ports"]["open"])
    for scheme, port in [("https", 443), ("https", 8443), ("http", 8080), ("http", 80)]:
        if port not in open_p:
            continue
        try:
            req = urllib.request.Request(
                (
                    f"{scheme}://{ip}/"
                    if port in (80, 443)
                    else f"{scheme}://{ip}:{port}/"
                ),
                headers={"User-Agent": "Mozilla/5.0"},
            )
            kw: dict = {"timeout": TIMEOUT}
            if scheme == "https":
                kw["context"] = _ctx
            with urllib.request.urlopen(req, **kw) as resp:
                hdrs = dict(resp.headers)
                srv = hdrs.get("Server") or hdrs.get("server") or ""
                body = resp.read(8192).decode(errors="ignore")
                title_m = re.search(
                    r"<title[^>]*>([^<]{1,200})</title>", body, re.IGNORECASE
                )
                title = title_m.group(1).strip() if title_m else None
                result["probes"]["http"].update(
                    {
                        "responded": True,
                        "server": srv or None,
                        "title": title,
                        "headers": {
                            k: v
                            for k, v in hdrs.items()
                            if k.lower()
                            in {
                                "server",
                                "x-powered-by",
                                "x-aspnet-version",
                                "x-frame-options",
                            }
                        },
                    }
                )
            break
        except urllib.error.HTTPError as e:
            srv = e.headers.get("Server") or ""
            if srv:
                result["probes"]["http"].update({"responded": True, "server": srv})
            break
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Signal 7 — SNMP v1 GET  (sysDescr / sysName / sysObjectID)
# ---------------------------------------------------------------------------
def _snmp_packet(oid_bytes: bytes, req_id: int = 1) -> bytes:
    def tlv(tag: int, val: bytes) -> bytes:
        n = len(val)
        if n < 128:
            return bytes([tag, n]) + val
        if n < 256:
            return bytes([tag, 0x81, n]) + val
        return bytes([tag, 0x82, n >> 8, n & 0xFF]) + val

    varbind = tlv(0x30, tlv(0x06, oid_bytes) + b"\x05\x00")
    rid = req_id.to_bytes(max(1, (req_id.bit_length() + 7) // 8), "big")
    pdu = tlv(
        0xA0,
        tlv(0x02, rid) + tlv(0x02, b"\x00") + tlv(0x02, b"\x00") + tlv(0x30, varbind),
    )
    return tlv(0x30, tlv(0x02, b"\x00") + tlv(0x04, b"public") + pdu)


def _snmp_str(data: bytes) -> str | None:
    i = 0
    while i < len(data) - 2:
        if data[i] == 0x04:
            n = data[i + 1]
            if not (n & 0x80) and i + 2 + n <= len(data):
                val = data[i + 2 : i + 2 + n]
                if val not in (b"public", b""):
                    return val.decode(errors="ignore")
        i += 1
    return None


def signalSeven(ip: str, result: dict):
    OIDS = {
        "sys_descr": bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]),
        "sys_name": bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00]),
        "sys_object_id": bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00]),
    }

    def udp_get(oid: bytes, retries: int = 2) -> bytes | None:
        for _ in range(retries):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(UDP_TIMEOUT)
            try:
                s.sendto(_snmp_packet(oid), (ip, 161))
                return s.recv(4096)
            except Exception:
                pass
            finally:
                s.close()
        return None

    resp = udp_get(OIDS["sys_descr"])
    if not resp:
        return
    descr = _snmp_str(resp)
    if not descr:
        return

    result["probes"]["snmp"]["responded"] = True
    result["probes"]["snmp"]["sys_descr"] = descr

    r2 = udp_get(OIDS["sys_name"])
    if r2:
        result["probes"]["snmp"]["sys_name"] = _snmp_str(r2)

    r3 = udp_get(OIDS["sys_object_id"])
    if r3:
        idx = r3.find(b"\x06", 20)
        if idx != -1 and idx + 1 < len(r3):
            n = r3[idx + 1]
            raw = r3[idx + 2 : idx + 2 + n]
            if raw:
                first = raw[0]
                parts = [str(first // 40), str(first % 40)]
                i, acc = 1, 0
                while i < len(raw):
                    if raw[i] & 0x80:
                        acc = (acc << 7) | (raw[i] & 0x7F)
                    else:
                        acc = (acc << 7) | raw[i]
                        parts.append(str(acc))
                        acc = 0
                    i += 1
                result["probes"]["snmp"]["sys_object_id"] = ".".join(parts)


# ---------------------------------------------------------------------------
# Signal 8 — NetBIOS Name Service (UDP 137)
# ---------------------------------------------------------------------------
# NBSTAT query for '*' (wildcard) — L2-encoded name + type 0x0021
_NBSTAT_QUERY = (
    b"\xab\xcd"  # Transaction ID
    + b"\x00\x10"  # Flags: NBSTAT
    + b"\x00\x01"  # Questions: 1
    + b"\x00\x00\x00\x00\x00\x00"  # Answer/Auth/Additional
    + b"\x20"  # Name length = 32
    + b"CK"
    + b"AA" * 15  # L2-encoded '*\x00×15' (32 bytes)
    + b"\x00"  # Null terminator
    + b"\x00\x21"  # Type: NBSTAT
    + b"\x00\x01"  # Class: IN
)


def signalEight(ip: str, result: dict):
    # ── NetBIOS NBSTAT (UDP 137) ───────────────────────────────────────────
    nb_data = None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(UDP_TIMEOUT)
    try:
        s.sendto(_NBSTAT_QUERY, (ip, 137))
        nb_data = s.recvfrom(4096)[0]
    except Exception:
        pass
    finally:
        s.close()

    if nb_data is None:
        return

    if nb_data is not None:
        pos = nb_data.find(b"\x00\x21\x00\x01", 50)
        if pos != -1:
            pos += 4
            if pos + 6 <= len(nb_data):
                pos += 4
                pos += 2
                if pos < len(nb_data):
                    num_names = nb_data[pos]
                    pos += 1
                    result["probes"]["netbios"]["responded"] = True

                    for _ in range(num_names):
                        if pos + 18 > len(nb_data):
                            break
                        name = nb_data[pos : pos + 15].decode(errors="ignore").rstrip()
                        ntype = nb_data[pos + 15]
                        flags = struct.unpack_from(">H", nb_data, pos + 16)[0]
                        is_group = bool(flags & 0x8000)
                        pos += 18

                        if (
                            ntype == 0x00
                            and not is_group
                            and not result["probes"]["netbios"]["computer_name"]
                        ):
                            result["probes"]["netbios"]["computer_name"] = name
                        if (
                            ntype == 0x00
                            and is_group
                            and not result["probes"]["netbios"]["domain"]
                        ):
                            result["probes"]["netbios"]["domain"] = name

                    if pos + 6 <= len(nb_data):
                        mac = nb_data[pos : pos + 6]
                        result["probes"]["netbios"]["mac"] = ":".join(
                            f"{b:02x}" for b in mac
                        )


# ---------------------------------------------------------------------------
# Signal 9 — RDP X.224 Connection Request (port 3389)
# ---------------------------------------------------------------------------
# TPKT(4) + LI(1) + CR PDU(6) + RDP Neg Request(8) = 19 bytes total
_RDP_CR = (
    b"\x03\x00\x00\x13"  # TPKT: version=3, len=19
    + b"\x0e"  # LI = 14
    + b"\xe0"  # PDU type: Connection Request
    + b"\x00\x00"  # DST-REF
    + b"\x00\x00"  # SRC-REF
    + b"\x00"  # Class 0
    + b"\x01"  # RDP Negotiation Request type
    + b"\x00"  # Flags
    + b"\x08\x00"  # Length = 8 (LE)
    + b"\x00\x00\x00\x00"  # Requested protocols: RDP only
)


def signalNine(ip: str, result: dict):
    if 3389 not in result["probes"]["tcp_ports"]["open"]:
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, 3389))
        s.sendall(_RDP_CR)
        resp = s.recv(256)
        s.close()
        if len(resp) >= 6 and resp[0] == 0x03 and resp[5] == 0xD0:
            result["probes"]["rdp"]["responded"] = True
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Signal 10 — VMware authd banner (port 902)
# ---------------------------------------------------------------------------
def signalTen(ip: str, result: dict):
    if 902 not in result["probes"]["tcp_ports"]["open"]:
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, 902))
        banner = s.recv(256).decode(errors="ignore").strip()
        s.close()
        result["probes"]["vmware_authd"]["banner"] = banner or None
        if "vmware" in banner.lower():
            result["probes"]["vmware_authd"]["responded"] = True
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Signal 11 — mDNS unicast query (UDP 5353)
# ---------------------------------------------------------------------------
def _parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a (possibly compression-pointer) DNS name from `data` at `offset`.

    Returns (dotted_name, offset_just_past_the_name_in_the_record_stream).
    """
    labels: list[str] = []
    pos = offset
    next_offset = offset
    jumped = False
    guard = 0
    while guard < 128 and pos < len(data):
        guard += 1
        length = data[pos]
        if length == 0:  # root → end of name
            pos += 1
            if not jumped:
                next_offset = pos
            break
        if (length & 0xC0) == 0xC0:  # compression pointer
            if pos + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                next_offset = pos + 2
            pos = pointer
            jumped = True
            continue
        pos += 1
        if pos + length > len(data):
            break
        labels.append(data[pos : pos + length].decode("utf-8", errors="ignore"))
        pos += length
    return ".".join(labels), next_offset


def _mdns_reverse_hostname(ip: str) -> str | None:
    """Ask the host (unicast mDNS, UDP 5353) for the PTR of its reverse IP.

    Avahi/Bonjour reply with the device's `<hostname>.local` name — the most
    reliable way to learn a Linux/macOS hostname on a LAN with no DNS PTRs.
    """
    try:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        labels = rev.split(".")
        qname = b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00"
        # header (id=0, qd=1) + question (QTYPE=PTR=12, QCLASS=IN=1)
        packet = (
            struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + qname + struct.pack("!HH", 12, 1)
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(UDP_TIMEOUT)
        try:
            s.sendto(packet, (ip, 5353))
            data = s.recvfrom(4096)[0]
        finally:
            s.close()
    except Exception:
        return None

    if len(data) < 12:
        return None
    flags = struct.unpack("!H", data[2:4])[0]
    qdcount = struct.unpack("!H", data[4:6])[0]
    ancount = struct.unpack("!H", data[6:8])[0]
    if not (flags & 0x8000) or ancount == 0:
        return None

    # Skip header + question section
    offset = 12
    for _ in range(qdcount):
        _, offset = _parse_dns_name(data, offset)
        offset += 4  # QTYPE + QCLASS

    # Walk answers; return the first PTR target
    for _ in range(ancount):
        _, offset = _parse_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if rtype == 12:  # PTR
            name, _ = _parse_dns_name(data, offset)
            name = name.rstrip(".")
            return name or None
        offset += rdlen
    return None


def signalEleven(ip: str, result: dict):
    # Service enumeration — establishes mDNS presence (feeds classification)
    try:
        labels = [b"_services", b"_dns-sd", b"_udp", b"local"]
        name = b"".join(bytes([len(l)]) + l for l in labels) + b"\x00"
        packet = (
            struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + name + struct.pack("!HH", 12, 1)
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(UDP_TIMEOUT)
        try:
            s.sendto(packet, (ip, 5353))
            data = s.recvfrom(4096)[0]
            if data and len(data) > 12:
                flags = struct.unpack("!H", data[2:4])[0]
                if flags & 0x8000:
                    result["probes"]["mdns"]["responded"] = True
        except Exception:
            pass
        finally:
            s.close()
    except Exception:
        pass

    # Reverse PTR lookup — pulls the `<hostname>.local` name (Linux/macOS)
    hostname = _mdns_reverse_hostname(ip)
    if hostname:
        result["probes"]["mdns"]["responded"] = True
        result["probes"]["mdns"]["hostname"] = hostname


# ---------------------------------------------------------------------------
# Signal 12 — UPnP device description (HTTP GET /description.xml etc.)
# ---------------------------------------------------------------------------
_UPNP_PATHS = [
    "/description.xml",
    "/rootDesc.xml",
    "/upnp/description.xml",
    "/tr064/desc.xml",
    "/gateway.xml",
]


def signalTwelve(ip: str, result: dict):
    open_p = set(result["probes"]["tcp_ports"]["open"])
    _ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    for scheme, port in [("http", 80), ("http", 8080), ("https", 443), ("https", 8443)]:
        if port not in open_p:
            continue
        base = f"{scheme}://{ip}" if port in (80, 443) else f"{scheme}://{ip}:{port}"
        for path in _UPNP_PATHS:
            try:
                req = urllib.request.Request(
                    base + path,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                kw: dict = {"timeout": TIMEOUT}
                if scheme == "https":
                    kw["context"] = _ctx
                with urllib.request.urlopen(req, **kw) as resp:
                    body = resp.read(8192).decode(errors="ignore")
                    if "<root" not in body and "<device" not in body:
                        continue
                    result["probes"]["upnp"]["responded"] = True
                    result["probes"]["upnp"]["location"] = path

                    def _tag(tag: str) -> str | None:
                        m = re.search(
                            rf"<{tag}[^>]*>([^<]{{1,200}})</{tag}>", body, re.IGNORECASE
                        )
                        return m.group(1).strip() if m else None

                    result["probes"]["upnp"]["friendly_name"] = _tag("friendlyName")
                    result["probes"]["upnp"]["manufacturer"] = _tag("manufacturer")
                    result["probes"]["upnp"]["model_name"] = _tag("modelName")
                    return
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Signal 13 — MQTT CONNECT probe (TCP 1883)
# ---------------------------------------------------------------------------
_MQTT_CONNECT = bytes(
    [
        0x10,
        0x12,  # CONNECT, remaining=18
        0x00,
        0x04,
        0x4D,
        0x51,
        0x54,
        0x54,  # Protocol: "MQTT"
        0x04,
        0x00,  # Level 4, no flags
        0x00,
        0x3C,  # Keep-alive: 60 s
        0x00,
        0x06,
        0x70,
        0x72,
        0x6F,
        0x62,
        0x65,
        0x31,  # Client ID: "probe1"
    ]
)


def signalThirteen(ip: str, result: dict):
    if 1883 not in result["probes"]["tcp_ports"]["open"]:
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, 1883))
        s.sendall(_MQTT_CONNECT)
        resp = s.recv(64)
        s.close()
        if len(resp) >= 2 and resp[0] == 0x20 and resp[1] == 0x02:
            result["probes"]["mqtt"]["responded"] = True
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Signal 14 — IPP (TCP 631) + JetDirect (TCP 9100)
# ---------------------------------------------------------------------------
_PJL_INFO = b"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X"


def signalFourteen(ip: str, result: dict):
    open_p = set(result["probes"]["tcp_ports"]["open"])

    if 631 in open_p:
        try:
            req = urllib.request.Request(
                f"http://{ip}:631/",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body = resp.read(4096).decode(errors="ignore")
                result["probes"]["ipp"]["responded"] = True
                t = re.search(r"<title[^>]*>([^<]{1,100})</title>", body, re.IGNORECASE)
                if t:
                    result["probes"]["ipp"]["printer_name"] = t.group(1).strip()
        except Exception:
            pass

    if 9100 in open_p:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((ip, 9100))
            s.sendall(_PJL_INFO)
            resp = s.recv(512).decode(errors="ignore")
            s.close()
            if resp:
                result["probes"]["ipp"]["responded"] = True
                m = re.search(r"@PJL INFO ID\s*\r?\n(.+)", resp)
                if m:
                    result["probes"]["ipp"]["make_model"] = m.group(1).strip()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Signal 15 — RTSP OPTIONS (TCP 554)
# ---------------------------------------------------------------------------
_RTSP_OPTIONS = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: probe\r\n\r\n"


def signalFifteen(ip: str, result: dict):
    if 554 not in result["probes"]["tcp_ports"]["open"]:
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, 554))
        s.sendall(_RTSP_OPTIONS)
        resp = s.recv(256).decode(errors="ignore")
        s.close()
        if resp.startswith("RTSP/"):
            result["probes"]["rtsp"]["responded"] = True
            result["probes"]["rtsp"]["banner"] = resp.split("\r\n")[0]
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Signal 16 — Telnet banner (TCP 23)
# ---------------------------------------------------------------------------
def signalSixteen(ip: str, result: dict):
    if 23 not in result["probes"]["tcp_ports"]["open"]:
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, 23))
        s.settimeout(TIMEOUT)
        banner = s.recv(512).decode(errors="ignore", encoding="latin-1").strip()
        s.close()
        if banner:
            result["probes"]["telnet"].update(
                {"responded": True, "banner": banner[:300]}
            )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Conflict resolution (§4.3)
# ---------------------------------------------------------------------------

_DISTRO_KEYWORDS = frozenset(
    {
        "ubuntu",
        "debian",
        "rhel",
        "centos",
        "suse",
        "fedora",
        "rocky",
        "almalinux",
        "arch",
        "gentoo",
    }
)


def _resolve_conflict(
    ranked: list[tuple[str, float]],
    p: dict,
    ev: dict,
) -> str | None:
    """
    Called when ≥2 platforms both scored ≥ MIN_CONFIDENCE.

    ranked  — [(platform, score), ...] sorted descending by score
    p       — result["probes"]
    ev      — result["evidence"]  (writes conflict_resolution key)

    Returns the winning platform name, or None → classify as "unknown".
    """
    platforms = {pl for pl, _ in ranked}
    ssh_banner = (p["ssh"].get("banner") or "").lower()

    def record(conflict, method, winner):
        ev["conflict_resolution"] = {
            "conflict": sorted(conflict),
            "resolved_by": method,
            "winner": winner,
            "scores": {pl: round(sc, 2) for pl, sc in ranked if pl in conflict},
        }
        return winner

    # ── Linux vs Windows (Samba / OpenSSH-for-Windows) ────────────────────
    if {"linux", "windows"} <= platforms:
        if any(d in ssh_banner for d in _DISTRO_KEYWORDS):
            return record({"linux", "windows"}, "ssh_banner_distro", "linux")

        if "openssh_for_windows" in ssh_banner or (
            "windows" in ssh_banner and "openssh" in ssh_banner
        ):
            return record({"linux", "windows"}, "ssh_banner_windows", "windows")

        if p["smb"].get("is_samba") is True:
            return record({"linux", "windows"}, "smb_server_guid_zero", "linux")

        if p["smb"].get("is_samba") is False:
            return record({"linux", "windows"}, "smb_server_guid_nonzero", "windows")

        # No decisive signal — higher score wins
        winner = ranked[0][0]
        return record({"linux", "windows"}, "higher_score", winner)

    # ── Linux vs macOS ─────────────────────────────────────────────────────
    if {"linux", "macos"} <= platforms:
        open_p = set(p["tcp_ports"]["open"])

        if 548 in open_p:  # AFP is macOS-only
            return record({"linux", "macos"}, "afp_port_548", "macos")

        # SSH no-suffix case already split 0.20/0.20 — check for Apple hint
        if "apple" in ssh_banner or "darwin" in ssh_banner:
            return record({"linux", "macos"}, "ssh_banner_apple", "macos")

        # No macOS-specific signal fired → safer to call Linux
        return record({"linux", "macos"}, "no_macos_specific_signal", "linux")

    # ── Windows vs network_device ──────────────────────────────────────────
    if {"windows", "network_device"} <= platforms:
        smb_ok = p["smb"]["responded"]
        snmp_ok = p["snmp"]["responded"]

        if smb_ok and not snmp_ok:
            return record({"windows", "network_device"}, "smb_no_snmp", "windows")
        if snmp_ok and not smb_ok:
            return record(
                {"windows", "network_device"}, "snmp_no_smb", "network_device"
            )

        # Both (or neither) responded — check margin
        win_sc = next((sc for pl, sc in ranked if pl == "windows"), 0.0)
        nd_sc = next((sc for pl, sc in ranked if pl == "network_device"), 0.0)

        if abs(win_sc - nd_sc) < 0.05:  # effectively tied → unknown
            ev["conflict_resolution"] = {
                "conflict": ["windows", "network_device"],
                "resolved_by": "tied_scores",
                "winner": None,
                "scores": {
                    "windows": round(win_sc, 2),
                    "network_device": round(nd_sc, 2),
                },
            }
            return None

        winner = "windows" if win_sc > nd_sc else "network_device"
        return record({"windows", "network_device"}, "higher_score", winner)

    # ── mobile vs linux / macos / iot ─────────────────────────────────────
    if "mobile" in platforms:
        others = platforms - {"mobile"}
        # If any real server service fired, it's not a phone
        server_fired = (
            p["smb"]["responded"]
            or p["ssh"]["responded"]
            or p["http"]["responded"]
            or p["snmp"]["responded"]
            or bool(set(p["tcp_ports"]["open"]) & {22, 80, 443, 445, 8080})
        )
        if server_fired:
            non_mobile = [pl for pl, _ in ranked if pl != "mobile"]
            if non_mobile:
                winner = non_mobile[0]
                return record(platforms, "server_service_beats_mobile", winner)
        # No server services — mobile wins
        return record(platforms, "no_server_services", "mobile")

    # ── iot vs linux ──────────────────────────────────────────────────────
    if {"iot", "linux"} <= platforms:
        if p["mqtt"]["responded"] or p["rtsp"].get("responded"):
            return record({"iot", "linux"}, "mqtt_or_rtsp", "iot")
        if (
            p["ssh"]["responded"]
            and not p["upnp"]["responded"]
            and not p["mdns"]["responded"]
        ):
            return record({"iot", "linux"}, "ssh_no_iot_signals", "linux")
        return record({"iot", "linux"}, "higher_score", ranked[0][0])

    # ── printer vs linux ──────────────────────────────────────────────────
    if {"printer", "linux"} <= platforms:
        if p["ipp"]["responded"]:
            return record({"printer", "linux"}, "ipp_confirmed", "printer")
        return record({"printer", "linux"}, "higher_score", ranked[0][0])

    # ── wifi_ap vs network_device ─────────────────────────────────────────
    if {"wifi_ap", "network_device"} <= platforms:
        if p["upnp"]["responded"]:
            return record({"wifi_ap", "network_device"}, "upnp_confirmed", "wifi_ap")
        if p["snmp"]["responded"] and p["mdns"]["responded"]:
            return record({"wifi_ap", "network_device"}, "snmp_and_mdns", "wifi_ap")
        return record({"wifi_ap", "network_device"}, "higher_score", ranked[0][0])

    # ── Any other combination — highest score wins ─────────────────────────
    winner = ranked[0][0]
    return record(platforms, "highest_score", winner)


# ---------------------------------------------------------------------------
# Classify — spec-accurate weights for all 10 signals
# ---------------------------------------------------------------------------
def classify(result: dict):
    p = result["probes"]
    ev = result["evidence"]
    open_p = set(p["tcp_ports"]["open"])

    scores: dict[str, float] = {pl: 0.0 for pl in PLATFORMS}
    score_log: list[dict] = []  # ordered trace of every score increment

    def bump(platform: str, delta: float, signal: str, reason: str, value: str = ""):
        scores[platform] += delta
        score_log.append(
            {
                "platform": platform,
                "delta": round(delta, 3),
                "total": round(scores[platform], 3),
                "signal": signal,
                "reason": reason,
                "value": value,
            }
        )

    # ── Signal 1: TTL ──────────────────────────────────────────────────────
    icmp = p["icmp"]
    if icmp["responded"]:
        est = icmp["ttl_estimated"]
        ttl_val = f"received={icmp['ttl_received']} estimated={est}"
        if est == 64:
            bump("linux", 0.20, "S1/TTL", "TTL<=64 suggests Linux/macOS", ttl_val)
            bump("macos", 0.15, "S1/TTL", "TTL<=64 suggests Linux/macOS", ttl_val)
            ev["ttl_rule"] = {
                "ttl": icmp["ttl_received"],
                "estimated": 64,
                "suggests": ["linux", "macos"],
            }
        elif est == 128:
            bump("windows", 0.30, "S1/TTL", "TTL<=128 suggests Windows", ttl_val)
            ev["ttl_rule"] = {
                "ttl": icmp["ttl_received"],
                "estimated": 128,
                "suggests": "windows",
            }
        elif est == 255:
            bump(
                "network_device",
                0.40,
                "S1/TTL",
                "TTL=255 suggests network device",
                ttl_val,
            )
            ev["ttl_rule"] = {
                "ttl": icmp["ttl_received"],
                "estimated": 255,
                "suggests": "network_device",
            }
        elif est == 32:
            bump("windows", 0.10, "S1/TTL", "TTL<=32 suggests old Windows", ttl_val)
            ev["ttl_rule"] = {
                "ttl": icmp["ttl_received"],
                "estimated": 32,
                "suggests": "windows_old",
            }

    # ── Signal 2: TCP port patterns ────────────────────────────────────────
    port_ev: dict = {}

    if 445 in open_p and (135 in open_p or 139 in open_p):
        ports = sorted(open_p & {135, 139, 445})
        bump(
            "windows",
            0.30,
            "S2/TCP",
            "SMB cluster (445+135/139) — Windows file sharing",
            f"ports={ports}",
        )
        port_ev["smb_cluster"] = {"ports": ports, "suggests": "windows", "weight": 0.30}

    if 3389 in open_p:
        bump(
            "windows",
            0.20,
            "S2/TCP",
            "RDP port 3389 open — Windows Remote Desktop",
            "port=3389",
        )
        port_ev["rdp"] = {"port": 3389, "suggests": "windows", "weight": 0.20}

    if open_p & {5985, 5986}:
        ports = sorted(open_p & {5985, 5986})
        bump(
            "windows",
            0.55,
            "S2/TCP",
            "WinRM port open — Windows-exclusive service",
            f"ports={ports}",
        )
        port_ev["winrm"] = {"ports": ports, "suggests": "windows", "weight": 0.55}

    if 22 in open_p and not (open_p & {135, 445}):
        bump(
            "linux",
            0.20,
            "S2/TCP",
            "SSH open, no SMB/RPC — likely Linux or macOS",
            "port=22",
        )
        bump(
            "macos",
            0.15,
            "S2/TCP",
            "SSH open, no SMB/RPC — likely Linux or macOS",
            "port=22",
        )
        port_ev["ssh_only"] = {"suggests": ["linux", "macos"], "weight": 0.20}

    if 548 in open_p:
        bump(
            "macos",
            0.25,
            "S2/TCP",
            "AFP port 548 — macOS file sharing exclusive",
            "port=548",
        )
        port_ev["afp"] = {"port": 548, "suggests": "macos", "weight": 0.25}

    if 902 in open_p and 443 in open_p:
        bump(
            "vmware_esxi",
            0.30,
            "S2/TCP",
            "VMware authd (902) + HTTPS (443) combo",
            "ports=[443,902]",
        )
        port_ev["vmware_ports"] = {
            "ports": [443, 902],
            "suggests": "vmware_esxi",
            "weight": 0.30,
        }

    if 161 in open_p and not (open_p & {22, 80, 135, 139, 443, 445, 3389}):
        bump(
            "snmp",
            0.20,
            "S2/TCP",
            "SNMP-only host — no common OS ports open",
            "port=161",
        )
        port_ev["snmp_only"] = {"port": 161, "suggests": "snmp", "weight": 0.20}

    if 9100 in open_p:
        bump(
            "printer",
            0.50,
            "S2/TCP",
            "JetDirect port 9100 — network printer",
            "port=9100",
        )
        port_ev["jetdirect"] = {"port": 9100, "suggests": "printer", "weight": 0.50}

    if 631 in open_p:
        bump(
            "printer",
            0.30,
            "S2/TCP",
            "IPP port 631 — Internet Printing Protocol",
            "port=631",
        )
        port_ev["ipp"] = {"port": 631, "suggests": "printer", "weight": 0.30}

    if open_p & {1883, 8883}:
        ports = sorted(open_p & {1883, 8883})
        bump(
            "iot",
            0.30,
            "S2/TCP",
            "MQTT port open — IoT message broker",
            f"ports={ports}",
        )
        port_ev["mqtt_ports"] = {"ports": ports, "suggests": "iot", "weight": 0.30}

    if 554 in open_p:
        bump("iot", 0.25, "S2/TCP", "RTSP port 554 — IP camera / NVR", "port=554")
        port_ev["rtsp"] = {"port": 554, "suggests": "iot_camera", "weight": 0.25}

    if 7547 in open_p:
        bump(
            "wifi_ap",
            0.35,
            "S2/TCP",
            "TR-069 port 7547 — ISP-managed CPE/router",
            "port=7547",
        )
        port_ev["tr069"] = {"port": 7547, "suggests": "wifi_ap_isp", "weight": 0.35}

    if 23 in open_p and not (open_p & {135, 445}):
        bump(
            "network_device",
            0.15,
            "S2/TCP",
            "Telnet open without SMB — network device",
            "port=23",
        )
        port_ev["telnet"] = {"port": 23, "suggests": "network_device", "weight": 0.15}

    if port_ev:
        ev["port_rule"] = port_ev

    # ── Signal 3: SMB ──────────────────────────────────────────────────────
    smb = p["smb"]
    if smb["responded"]:
        is_samba = smb.get("is_samba")

        if is_samba is True:
            bump(
                "linux",
                0.30,
                "S3/SMB",
                "ServerGUID=zero → Samba on Linux",
                f"dialect={smb['dialect']} guid={smb['server_guid']}",
            )
            ev["service_rule"]["smb"] = {
                "dialect": smb["dialect"],
                "server_guid": smb["server_guid"],
                "suggests": "samba_linux",
                "weight": 0.30,
            }
        elif is_samba is False:
            if smb.get("os_version"):
                bump(
                    "windows",
                    0.50,
                    "S3/SMB",
                    "Non-zero GUID + OS version → genuine Windows SMB",
                    f"dialect={smb['dialect']} os={smb['os_version']} guid={smb['server_guid']}",
                )
                ev["service_rule"]["smb"] = {
                    "dialect": smb["dialect"],
                    "os_version": smb["os_version"],
                    "server_guid": smb["server_guid"],
                    "suggests": "windows",
                    "weight": 0.50,
                }
            else:
                bump(
                    "windows",
                    0.30,
                    "S3/SMB",
                    "Non-zero GUID → genuine Windows SMB (no OS version)",
                    f"dialect={smb['dialect']} guid={smb['server_guid']}",
                )
                ev["service_rule"]["smb"] = {
                    "dialect": smb["dialect"],
                    "server_guid": smb["server_guid"],
                    "suggests": "windows",
                    "weight": 0.30,
                }
        else:
            w = 0.35 if smb.get("os_version") else 0.20
            bump(
                "windows",
                w,
                "S3/SMB",
                "SMB responded but GUID not captured (short response)",
                f"dialect={smb['dialect']} os={smb.get('os_version')}",
            )
            ev["service_rule"]["smb"] = {
                "dialect": smb["dialect"],
                "suggests": "windows_unconfirmed",
                "weight": w,
            }

    # ── Signal 4: SSH banner ───────────────────────────────────────────────
    ssh = p["ssh"]
    if ssh["responded"] and ssh["banner"]:
        bl = ssh["banner"].lower()
        _DISTRO = {
            "ubuntu",
            "debian",
            "rhel",
            "centos",
            "suse",
            "fedora",
            "rocky",
            "almalinux",
            "arch",
            "gentoo",
        }
        _NET = {"cisco", "juniper", "fortinet", "palo alto"}

        if any(d in bl for d in _DISTRO):
            matched = next(d for d in _DISTRO if d in bl)
            bump(
                "linux",
                0.40,
                "S4/SSH",
                f"SSH banner contains distro keyword '{matched}'",
                ssh["banner"],
            )
            ev["banner_rule"]["ssh"] = {
                "banner": ssh["banner"],
                "suggests": "linux",
                "weight": 0.40,
            }
        elif "openssh_for_windows" in bl or ("windows" in bl and "openssh" in bl):
            bump(
                "windows",
                0.40,
                "S4/SSH",
                "SSH banner indicates OpenSSH for Windows",
                ssh["banner"],
            )
            ev["banner_rule"]["ssh"] = {
                "banner": ssh["banner"],
                "suggests": "windows",
                "weight": 0.40,
            }
        elif "vmware" in bl:
            bump(
                "vmware_esxi",
                0.20,
                "S4/SSH",
                "SSH banner contains 'vmware'",
                ssh["banner"],
            )
            ev["banner_rule"]["ssh"] = {
                "banner": ssh["banner"],
                "suggests": "vmware_esxi",
                "weight": 0.20,
            }
        elif any(n in bl for n in _NET):
            matched = next(n for n in _NET if n in bl)
            bump(
                "network_device",
                0.50,
                "S4/SSH",
                f"SSH banner contains network vendor '{matched}'",
                ssh["banner"],
            )
            ev["banner_rule"]["ssh"] = {
                "banner": ssh["banner"],
                "suggests": "network_device",
                "weight": 0.50,
            }
        elif "dropbear" in bl:
            bump(
                "network_device",
                0.30,
                "S4/SSH",
                "Dropbear SSH — embedded/network device",
                ssh["banner"],
            )
            ev["banner_rule"]["ssh"] = {
                "banner": ssh["banner"],
                "suggests": "network_device",
                "weight": 0.30,
            }
        else:
            bump(
                "linux",
                0.20,
                "S4/SSH",
                "SSH banner present but no distro/OS keyword — ambiguous",
                ssh["banner"],
            )
            bump(
                "macos",
                0.20,
                "S4/SSH",
                "SSH banner present but no distro/OS keyword — ambiguous",
                ssh["banner"],
            )
            ev["banner_rule"]["ssh"] = {
                "banner": ssh["banner"],
                "suggests": ["linux", "macos"],
                "weight": 0.20,
            }

    # ── Signal 5: TLS certificate ──────────────────────────────────────────
    tls = p["tls_443"]
    if tls["responded"]:
        subj = tls.get("subject") or {}
        issuer = tls.get("issuer") or {}
        subj_str = (
            " ".join(str(v) for v in subj.values()).lower()
            if isinstance(subj, dict)
            else ""
        )
        issuer_str = (
            " ".join(str(v) for v in issuer.values()).lower()
            if isinstance(issuer, dict)
            else ""
        )

        if "vmware engineering" in subj_str or "vmware" in issuer_str:
            bump(
                "vmware_esxi",
                0.60,
                "S5/TLS",
                "TLS cert subject/issuer contains VMware",
                f"subject={subj_str[:60]}",
            )
            ev["service_rule"]["tls"] = {
                "subject": subj_str,
                "suggests": "vmware_esxi",
                "weight": 0.60,
            }
        elif "localhost.localdomain" in subj_str and 902 in open_p:
            bump(
                "vmware_esxi",
                0.50,
                "S5/TLS",
                "Self-signed localhost cert + port 902 open → ESXi",
                f"subject={subj_str[:60]}",
            )
            ev["service_rule"]["tls"] = {
                "subject": subj_str,
                "suggests": "vmware_esxi",
                "weight": 0.50,
            }
        elif "big-ip" in subj_str or "f5" in issuer_str or "f5" in subj_str:
            bump(
                "network_device",
                0.50,
                "S5/TLS",
                "TLS cert indicates F5 BIG-IP",
                f"subject={subj_str[:60]}",
            )
            ev["service_rule"]["tls"] = {
                "subject": subj_str,
                "suggests": "network_device_f5",
                "weight": 0.50,
            }
        elif "palo alto" in subj_str:
            bump(
                "network_device",
                0.50,
                "S5/TLS",
                "TLS cert subject contains 'Palo Alto'",
                f"subject={subj_str[:60]}",
            )
            ev["service_rule"]["tls"] = {
                "subject": subj_str,
                "suggests": "network_device_palo",
                "weight": 0.50,
            }
        elif "cisco" in subj_str:
            bump(
                "network_device",
                0.40,
                "S5/TLS",
                "TLS cert subject contains 'Cisco'",
                f"subject={subj_str[:60]}",
            )
            ev["service_rule"]["tls"] = {
                "subject": subj_str,
                "suggests": "network_device_cisco",
                "weight": 0.40,
            }
        elif "microsoft corporation" in issuer_str:
            bump(
                "windows",
                0.10,
                "S5/TLS",
                "TLS cert issued by Microsoft Corporation",
                f"issuer={issuer_str[:60]}",
            )
            ev["service_rule"]["tls"] = {
                "issuer": issuer_str,
                "suggests": "windows",
                "weight": 0.10,
            }

    # ── Signal 6: HTTP Server header ───────────────────────────────────────
    http = p["http"]
    if http["responded"]:
        srv = (http.get("server") or "").lower()
        if "microsoft-iis" in srv:
            bump("windows", 0.30, "S6/HTTP", "Server: Microsoft-IIS", srv)
            ev["banner_rule"]["http"] = {
                "server": srv,
                "suggests": "windows",
                "weight": 0.30,
            }
        elif "microsoft-httpapi" in srv:
            bump("windows", 0.25, "S6/HTTP", "Server: Microsoft-HTTPAPI", srv)
            ev["banner_rule"]["http"] = {
                "server": srv,
                "suggests": "windows",
                "weight": 0.25,
            }
        elif "vmware" in srv:
            bump("vmware_esxi", 0.30, "S6/HTTP", "Server header contains 'vmware'", srv)
            ev["banner_rule"]["http"] = {
                "server": srv,
                "suggests": "vmware_esxi",
                "weight": 0.30,
            }
        elif "apache" in srv and "(ubuntu)" in srv:
            bump("linux", 0.30, "S6/HTTP", "Server: Apache with Ubuntu tag", srv)
            ev["banner_rule"]["http"] = {
                "server": srv,
                "suggests": "linux_ubuntu",
                "weight": 0.30,
            }
        elif "apache" in srv and any(x in srv for x in ("red hat", "rhel", "centos")):
            bump("linux", 0.30, "S6/HTTP", "Server: Apache with RHEL/CentOS tag", srv)
            ev["banner_rule"]["http"] = {
                "server": srv,
                "suggests": "linux_rhel",
                "weight": 0.30,
            }
        elif "apache" in srv or "nginx" in srv:
            bump(
                "linux",
                0.10,
                "S6/HTTP",
                "Server: Apache/nginx — generic Linux hint",
                srv,
            )
            ev["banner_rule"]["http"] = {
                "server": srv,
                "suggests": "linux",
                "weight": 0.10,
            }
        elif any(
            x in srv for x in ("boa/", "uhttpd", "mini_httpd", "rompager", "allegro")
        ):
            matched = next(
                x
                for x in ("boa/", "uhttpd", "mini_httpd", "rompager", "allegro")
                if x in srv
            )
            bump(
                "wifi_ap",
                0.50,
                "S6/HTTP",
                f"Server: embedded web server '{matched}' — router/CPE",
                srv,
            )
            ev["banner_rule"]["http"] = {
                "server": srv,
                "suggests": "wifi_ap_embedded",
                "weight": 0.50,
            }

    # ── Signal 7: SNMP sysDescr ────────────────────────────────────────────
    snmp = p["snmp"]
    if snmp["responded"] and snmp.get("sys_descr"):
        dl = snmp["sys_descr"].lower()
        descr_short = snmp["sys_descr"][:80]
        if "cisco ios" in dl:
            bump(
                "network_device",
                0.70,
                "S7/SNMP",
                "sysDescr contains 'Cisco IOS'",
                descr_short,
            )
            ev["os_rule"]["snmp"] = {
                "sys_descr": descr_short,
                "suggests": "network_device_cisco",
                "weight": 0.70,
            }
        elif "vmware esxi" in dl:
            bump(
                "vmware_esxi",
                0.70,
                "S7/SNMP",
                "sysDescr contains 'VMware ESXi'",
                descr_short,
            )
            ev["os_rule"]["snmp"] = {
                "sys_descr": descr_short,
                "suggests": "vmware_esxi",
                "weight": 0.70,
            }
        elif "junos" in dl:
            bump(
                "network_device",
                0.70,
                "S7/SNMP",
                "sysDescr contains 'JunOS'",
                descr_short,
            )
            ev["os_rule"]["snmp"] = {
                "sys_descr": descr_short,
                "suggests": "network_device_juniper",
                "weight": 0.70,
            }
        elif "linux" in dl:
            bump("linux", 0.60, "S7/SNMP", "sysDescr contains 'Linux'", descr_short)
            ev["os_rule"]["snmp"] = {
                "sys_descr": descr_short,
                "suggests": "linux",
                "weight": 0.60,
            }
        elif "windows" in dl:
            bump("windows", 0.60, "S7/SNMP", "sysDescr contains 'Windows'", descr_short)
            ev["os_rule"]["snmp"] = {
                "sys_descr": descr_short,
                "suggests": "windows",
                "weight": 0.60,
            }
        elif any(
            k in dl
            for k in (
                "printer",
                "laserjet",
                "officejet",
                "epson",
                "canon",
                "brother",
                "xerox",
                "lexmark",
                "hp jetdirect",
            )
        ):
            matched = next(
                k
                for k in (
                    "printer",
                    "laserjet",
                    "officejet",
                    "epson",
                    "canon",
                    "brother",
                    "xerox",
                    "lexmark",
                    "hp jetdirect",
                )
                if k in dl
            )
            bump(
                "printer",
                0.60,
                "S7/SNMP",
                f"sysDescr contains printer keyword '{matched}'",
                descr_short,
            )
            ev["os_rule"]["snmp"] = {
                "sys_descr": descr_short,
                "suggests": "printer",
                "weight": 0.60,
            }
        elif any(
            k in dl
            for k in (
                "access point",
                "wireless ap",
                "aironet",
                "unifi",
                "airmax",
                "airport",
                "wifi",
                "wlan",
            )
        ):
            matched = next(
                k
                for k in (
                    "access point",
                    "wireless ap",
                    "aironet",
                    "unifi",
                    "airmax",
                    "airport",
                    "wifi",
                    "wlan",
                )
                if k in dl
            )
            bump(
                "wifi_ap",
                0.60,
                "S7/SNMP",
                f"sysDescr contains AP keyword '{matched}'",
                descr_short,
            )
            ev["os_rule"]["snmp"] = {
                "sys_descr": descr_short,
                "suggests": "wifi_ap",
                "weight": 0.60,
            }
        elif "hp ethernet" in dl:
            ev["os_rule"]["snmp"] = {
                "sys_descr": descr_short,
                "suggests": "printer_unknown",
                "weight": 0.0,
            }

    # ── Signal 8: NetBIOS ──────────────────────────────────────────────────
    netbios = p["netbios"]
    if netbios["responded"]:
        bump(
            "windows",
            0.20,
            "S8/NetBIOS",
            "NetBIOS NBSTAT responded — Windows workstation/server",
            f"computer={netbios.get('computer_name')} domain={netbios.get('domain')}",
        )
        ev["service_rule"]["netbios"] = {
            "computer_name": netbios.get("computer_name"),
            "suggests": "windows",
            "weight": 0.20,
        }

    # ── Signal 9: RDP ──────────────────────────────────────────────────────
    rdp = p["rdp"]
    if rdp["responded"]:
        bump(
            "windows",
            0.25,
            "S9/RDP",
            "RDP Connection Confirm received — Windows Remote Desktop",
            "port=3389",
        )
        ev["service_rule"]["rdp"] = {"suggests": "windows", "weight": 0.25}

    # ── Signal 10: VMware authd ────────────────────────────────────────────
    vauth = p["vmware_authd"]
    if vauth["responded"]:
        bump(
            "vmware_esxi",
            0.50,
            "S10/VMware",
            "VMware authd banner confirmed on port 902",
            vauth.get("banner") or "",
        )
        ev["service_rule"]["vmware_authd"] = {
            "banner": vauth.get("banner"),
            "suggests": "vmware_esxi",
            "weight": 0.50,
        }

    # ── Signal 11: mDNS ───────────────────────────────────────────────────
    mdns = p["mdns"]
    if mdns["responded"]:
        bump(
            "iot",
            0.20,
            "S11/mDNS",
            "mDNS responded on UDP 5353 — IoT/embedded device",
            "port=5353",
        )
        ev["service_rule"]["mdns"] = {"suggests": "iot", "weight": 0.20}

    # ── Signal 12: UPnP ───────────────────────────────────────────────────
    upnp = p["upnp"]
    if upnp["responded"]:
        _combined = " ".join(
            filter(
                None,
                [
                    upnp.get("manufacturer") or "",
                    upnp.get("friendly_name") or "",
                    upnp.get("model_name") or "",
                ],
            )
        ).lower()
        _AP_BRANDS = {
            "tp-link",
            "netgear",
            "asus",
            "d-link",
            "linksys",
            "ubiquiti",
            "unifi",
            "mikrotik",
            "edgerouter",
            "aruba",
            "ruckus",
            "meraki",
            "fritz",
            "fritzbox",
        }
        _IOT_BRANDS = {
            "philips hue",
            "sonos",
            "ring",
            "nest",
            "ecobee",
            "wemo",
            "belkin",
            "xiaomi",
            "tuya",
            "shelly",
            "tasmota",
        }
        upnp_val = f"manufacturer={upnp.get('manufacturer')} model={upnp.get('model_name')} name={upnp.get('friendly_name')}"
        if any(b in _combined for b in _AP_BRANDS):
            matched = next(b for b in _AP_BRANDS if b in _combined)
            bump(
                "wifi_ap",
                0.60,
                "S12/UPnP",
                f"UPnP device matches AP brand '{matched}'",
                upnp_val,
            )
            ev["service_rule"]["upnp"] = {
                "manufacturer": upnp.get("manufacturer"),
                "friendly_name": upnp.get("friendly_name"),
                "suggests": "wifi_ap",
                "weight": 0.60,
            }
        elif any(b in _combined for b in _IOT_BRANDS):
            matched = next(b for b in _IOT_BRANDS if b in _combined)
            bump(
                "iot",
                0.60,
                "S12/UPnP",
                f"UPnP device matches IoT brand '{matched}'",
                upnp_val,
            )
            ev["service_rule"]["upnp"] = {
                "manufacturer": upnp.get("manufacturer"),
                "friendly_name": upnp.get("friendly_name"),
                "suggests": "iot",
                "weight": 0.60,
            }
        elif any(k in _combined for k in ("router", "gateway", "modem")):
            matched = next(k for k in ("router", "gateway", "modem") if k in _combined)
            bump(
                "wifi_ap",
                0.50,
                "S12/UPnP",
                f"UPnP friendlyName contains '{matched}'",
                upnp_val,
            )
            ev["service_rule"]["upnp"] = {
                "friendly_name": upnp.get("friendly_name"),
                "suggests": "wifi_ap",
                "weight": 0.50,
            }
        elif any(k in _combined for k in ("camera", "nvr", "dvr", "ipcam")):
            matched = next(
                k for k in ("camera", "nvr", "dvr", "ipcam") if k in _combined
            )
            bump(
                "iot",
                0.55,
                "S12/UPnP",
                f"UPnP friendlyName contains '{matched}'",
                upnp_val,
            )
            ev["service_rule"]["upnp"] = {
                "friendly_name": upnp.get("friendly_name"),
                "suggests": "iot_camera",
                "weight": 0.55,
            }
        else:
            bump(
                "iot",
                0.25,
                "S12/UPnP",
                "UPnP responded but no brand/keyword matched",
                upnp_val,
            )
            ev["service_rule"]["upnp"] = {
                "friendly_name": upnp.get("friendly_name"),
                "suggests": "iot",
                "weight": 0.25,
            }

    # ── Signal 13: MQTT ───────────────────────────────────────────────────
    mqtt = p["mqtt"]
    if mqtt["responded"]:
        bump(
            "iot",
            0.50,
            "S13/MQTT",
            "MQTT CONNACK received — IoT message broker",
            "port=1883",
        )
        ev["service_rule"]["mqtt"] = {"suggests": "iot_mqtt_broker", "weight": 0.50}

    # ── Signal 14: IPP / JetDirect ────────────────────────────────────────
    ipp = p["ipp"]
    if ipp["responded"]:
        bump(
            "printer",
            0.70,
            "S14/IPP",
            "IPP/JetDirect responded — network printer confirmed",
            f"name={ipp.get('printer_name')} model={ipp.get('make_model')}",
        )
        ev["service_rule"]["ipp"] = {
            "printer_name": ipp.get("printer_name"),
            "make_model": ipp.get("make_model"),
            "suggests": "printer",
            "weight": 0.70,
        }

    # ── Signal 15: RTSP ───────────────────────────────────────────────────
    rtsp = p["rtsp"]
    if rtsp["responded"]:
        bump(
            "iot",
            0.60,
            "S15/RTSP",
            "RTSP OPTIONS responded — IP camera / NVR",
            rtsp.get("banner") or "",
        )
        ev["service_rule"]["rtsp"] = {
            "banner": rtsp.get("banner"),
            "suggests": "iot_camera",
            "weight": 0.60,
        }

    # ── HTTP title + server brand detection (IoT / Printer / WiFi-AP) ─────
    if http["responded"]:
        srv_l = (http.get("server") or "").lower()
        title_l = (http.get("title") or "").lower()

        _IOT_SERVERS = {
            "hikvision",
            "dahua",
            "axis",
            "amcrest",
            "reolink",
            "foscam",
            "vivotek",
            "hanwha",
            "bosch security",
        }
        _ROUTER_SERVERS = {
            "openwrt",
            "dd-wrt",
            "tomato",
            "ubnt",
            "edgeos",
            "airos",
            "tp-link",
            "dlink",
            "mikrotik",
            "miniupnpd",
            "jcow",
            "juicejfv",
        }
        _PRINTER_SERVERS = {
            "virata",
            "kojiro",
            "lexmark",
            "hp-chaiseri",
            "ricoh",
            "kyocera",
            "xerox",
        }

        _AP_TITLES = {
            "router",
            "gateway",
            "modem",
            "access point",
            "tp-link",
            "netgear",
            "asus router",
            "d-link",
            "linksys",
            "unifi",
            "mikrotik",
            "edgerouter",
            "management console",
            "admin",
        }
        _IOT_TITLES = {
            "camera",
            "ip cam",
            "dvr",
            "nvr",
            "surveillance",
            "smart home",
            "philips hue",
            "sonos",
            "tuya",
            "homebridge",
        }
        _PRINTER_TITLES = {
            "printer",
            "print server",
            "laserjet",
            "officejet",
            "epson",
            "canon",
            "brother",
            "xerox",
            "lexmark",
        }

        if any(b in srv_l for b in _IOT_SERVERS):
            matched = next(b for b in _IOT_SERVERS if b in srv_l)
            bump(
                "iot",
                0.60,
                "S6b/HTTP-server",
                f"Server header matches IoT camera brand '{matched}'",
                srv_l[:60],
            )
            ev["banner_rule"]["http_iot_server"] = {
                "server": srv_l[:60],
                "suggests": "iot_camera",
                "weight": 0.60,
            }
        elif any(b in srv_l for b in _ROUTER_SERVERS):
            matched = next(b for b in _ROUTER_SERVERS if b in srv_l)
            bump(
                "wifi_ap",
                0.60,
                "S6b/HTTP-server",
                f"Server header matches router firmware '{matched}'",
                srv_l[:60],
            )
            ev["banner_rule"]["http_ap_server"] = {
                "server": srv_l[:60],
                "suggests": "wifi_ap",
                "weight": 0.60,
            }
        elif any(b in srv_l for b in _PRINTER_SERVERS):
            matched = next(b for b in _PRINTER_SERVERS if b in srv_l)
            bump(
                "printer",
                0.60,
                "S6b/HTTP-server",
                f"Server header matches printer brand '{matched}'",
                srv_l[:60],
            )
            ev["banner_rule"]["http_printer_server"] = {
                "server": srv_l[:60],
                "suggests": "printer",
                "weight": 0.60,
            }

        if any(k in title_l for k in _IOT_TITLES):
            matched = next(k for k in _IOT_TITLES if k in title_l)
            bump(
                "iot",
                0.40,
                "S6c/HTTP-title",
                f"Page title contains IoT keyword '{matched}'",
                title_l[:80],
            )
            ev["banner_rule"]["http_iot_title"] = {
                "title": title_l[:80],
                "suggests": "iot",
                "weight": 0.40,
            }
        elif any(k in title_l for k in _AP_TITLES):
            matched = next(k for k in _AP_TITLES if k in title_l)
            bump(
                "wifi_ap",
                0.40,
                "S6c/HTTP-title",
                f"Page title contains AP keyword '{matched}'",
                title_l[:80],
            )
            ev["banner_rule"]["http_ap_title"] = {
                "title": title_l[:80],
                "suggests": "wifi_ap",
                "weight": 0.40,
            }
        elif any(k in title_l for k in _PRINTER_TITLES):
            matched = next(k for k in _PRINTER_TITLES if k in title_l)
            bump(
                "printer",
                0.50,
                "S6c/HTTP-title",
                f"Page title contains printer keyword '{matched}'",
                title_l[:80],
            )
            ev["banner_rule"]["http_printer_title"] = {
                "title": title_l[:80],
                "suggests": "printer",
                "weight": 0.50,
            }

    # ── Hostname / FQDN hints ─────────────────────────────────────────────
    _fqdn = (result["classification"].get("hostname") or "").lower()
    if _fqdn and ("reliance" in _fqdn or _fqdn.endswith(".jio")):
        bump(
            "wifi_ap",
            0.40,
            "S0/Hostname",
            "Hostname contains Reliance/Jio ISP domain",
            _fqdn,
        )
        ev["service_rule"]["hostname_isp"] = {
            "hostname": _fqdn,
            "suggests": "wifi_ap_jio",
            "weight": 0.40,
        }

    # ── Default gateway → router / AP ──────────────────────────────────────
    if result["classification"]["ip"] in _DEFAULT_GATEWAYS:
        bump(
            "wifi_ap",
            0.60,
            "S0/Gateway",
            "IP is this host's default gateway → router/AP",
            result["classification"]["ip"],
        )
        ev["service_rule"]["default_gateway"] = {
            "ip": result["classification"]["ip"],
            "suggests": "wifi_ap",
            "weight": 0.60,
        }

    # ── ARP / OUI ──────────────────────────────────────────────────────────
    _OUI_WEIGHTS: dict[str, float] = {
        "vmware_esxi": 0.70,
        "mobile": 0.62,
        "iot": 0.58,
        "wifi_ap": 0.58,
        "printer": 0.58,
        "network_device": 0.55,
        "macos": 0.40,
        "linux": 0.35,
        "windows": 0.35,
    }
    arp = p["arp"]
    if arp.get("platform_hint"):
        hint = arp["platform_hint"]
        mfr = arp.get("manufacturer") or ""
        if hint == "macos":
            if open_p & {22, 445, 548, 5985}:
                w = _OUI_WEIGHTS["macos"]
                bump(
                    "macos",
                    w,
                    "S0/ARP-OUI",
                    f"Apple OUI + server ports open → macOS",
                    f"mac={arp.get('mac')} manufacturer={mfr}",
                )
                hint_used = "macos"
            else:
                w = _OUI_WEIGHTS["mobile"]
                bump(
                    "mobile",
                    w,
                    "S0/ARP-OUI",
                    f"Apple OUI + no server ports → iOS mobile",
                    f"mac={arp.get('mac')} manufacturer={mfr}",
                )
                hint_used = "mobile"
        elif hint in _OUI_WEIGHTS:
            w = _OUI_WEIGHTS[hint]
            bump(
                hint,
                w,
                "S0/ARP-OUI",
                f"MAC OUI identifies manufacturer as '{mfr}' → {hint}",
                f"mac={arp.get('mac')} manufacturer={mfr}",
            )
            hint_used = hint
        else:
            w = 0.45
            hint_used = hint
        ev["service_rule"]["oui"] = {
            "mac": arp.get("mac"),
            "manufacturer": mfr,
            "suggests": hint_used,
            "weight": w,
        }

    # ── Randomized MAC (LAA bit) → strong mobile signal ───────────────────
    if arp.get("randomized") is True:
        bump(
            "mobile",
            0.55,
            "S0/ARP-OUI",
            "LAA bit set → MAC randomization → iOS/Android mobile",
            f"mac={arp.get('mac')}",
        )
        ev["service_rule"]["randomized_mac"] = {
            "mac": arp.get("mac"),
            "suggests": "mobile",
            "weight": 0.55,
        }

    # ── TTL + no open ports → mobile hint ─────────────────────────────────
    if icmp["responded"] and not open_p and not snmp["responded"]:
        bump(
            "mobile",
            0.30,
            "S1/TTL",
            "Host responds to ping but has no open TCP ports → mobile/firewalled",
            f"ttl={icmp['ttl_received']}",
        )
        ev["ttl_rule"]["silent_host"] = {
            "ttl": icmp["ttl_received"],
            "no_open_ports": True,
            "suggests": "mobile",
            "weight": 0.30,
        }

    # ── Telnet banner ──────────────────────────────────────────────────────
    telnet = p["telnet"]
    if telnet["responded"] and telnet.get("banner"):
        bl = telnet["banner"].lower()
        _ND_KEYS = {
            "cisco",
            "juniper",
            "mikrotik",
            "huawei",
            "junos",
            "ios",
            "router",
            "switch",
            "firewall",
            "fortinet",
            "palo alto",
            "edgerouter",
            "procurve",
            "aruba",
            "extreme",
        }
        _IOT_KEYS = {
            "busybox",
            "openwrt",
            "dd-wrt",
            "buildroot",
            "embedded",
            "linux",
            "dropbear",
        }
        if any(k in bl for k in _ND_KEYS):
            matched = next(k for k in _ND_KEYS if k in bl)
            bump(
                "network_device",
                0.50,
                "S16/Telnet",
                f"Telnet banner contains network keyword '{matched}'",
                bl[:80],
            )
            ev["banner_rule"]["telnet"] = {
                "banner": bl[:80],
                "suggests": "network_device",
                "weight": 0.50,
            }
        elif any(k in bl for k in _IOT_KEYS):
            matched = next(k for k in _IOT_KEYS if k in bl)
            bump(
                "iot",
                0.35,
                "S16/Telnet",
                f"Telnet banner contains IoT keyword '{matched}'",
                bl[:80],
            )
            ev["banner_rule"]["telnet"] = {
                "banner": bl[:80],
                "suggests": "iot",
                "weight": 0.35,
            }
        else:
            bump(
                "network_device",
                0.20,
                "S16/Telnet",
                "Telnet responded — generic network device hint",
                bl[:80],
            )
            ev["banner_rule"]["telnet"] = {
                "banner": bl[:80],
                "suggests": "network_device",
                "weight": 0.20,
            }

    result["_score_log"] = score_log

    # ── Reachability ───────────────────────────────────────────────────────
    # A resolved ARP MAC proves the host answered at layer 2 → it is alive,
    # even when ICMP/TCP/SNMP all time out on a high-latency network.
    reachable = (
        icmp["responded"] or bool(open_p) or snmp["responded"] or bool(arp.get("mac"))
    )
    result["classification"]["reachable"] = reachable

    if not reachable:
        result["classification"]["platform"] = "unreachable"
        result["classification"]["confidence"] = 0
        result["_scores"] = {pl: 0 for pl in PLATFORMS}
        return

    # ── Decision ───────────────────────────────────────────────────────────
    # Collect every platform that crossed the confidence threshold
    in_play = sorted(
        [(pl, sc) for pl, sc in scores.items() if sc >= MIN_CONFIDENCE],
        key=lambda x: x[1],
        reverse=True,
    )

    result["_scores"] = {pl: round(sc, 3) for pl, sc in scores.items()}

    if not in_play:
        # Nothing reached threshold — output best guess as "unknown"
        top_platform = max(scores, key=lambda k: scores[k])
        result["classification"]["platform"] = "unknown"
        result["classification"]["confidence"] = round(scores[top_platform] * 100)
        return

    if len(in_play) == 1:
        top_platform, top_score = in_play[0]
    else:
        # Two or more platforms above threshold — resolve the conflict
        resolved = _resolve_conflict(in_play, p, ev)
        if resolved is None:
            # Genuinely ambiguous (tied Windows vs network_device, etc.)
            result["classification"]["platform"] = "unknown"
            result["classification"]["confidence"] = round(in_play[0][1] * 100)
            return
        top_platform = resolved
        top_score = scores[resolved]

    result["classification"]["platform"] = top_platform
    result["classification"]["confidence"] = round(min(top_score, 1.0) * 100)

    # ── OS hint ────────────────────────────────────────────────────────────
    if top_platform == "windows":
        if smb.get("native_os"):
            result["classification"]["os_hint"] = smb["native_os"]
        elif smb.get("dialect"):
            result["classification"]["os_hint"] = f"Windows (SMB {smb['dialect']})"
        elif snmp.get("sys_descr"):
            result["classification"]["os_hint"] = snmp["sys_descr"][:80]
        elif smb["probed"] and not smb["responded"] and 445 in open_p:
            # signalThree ran but got no SMB2 response → SMB1-only host
            result["classification"][
                "os_hint"
            ] = "Windows (SMB v1 only — likely XP/Server 2003)"
        elif open_p & {5985, 5986}:
            result["classification"]["os_hint"] = "Windows (WinRM)"
        else:
            result["classification"]["os_hint"] = "Windows"
    elif top_platform == "linux":
        if ssh.get("banner"):
            result["classification"]["os_hint"] = _parse_ssh_os_hint(ssh["banner"])
        elif snmp.get("sys_descr"):
            result["classification"]["os_hint"] = snmp["sys_descr"][:80]
    elif top_platform == "macos":
        if ssh.get("banner"):
            ver_m = re.search(r"OpenSSH_(\d+\.\d+)", ssh["banner"])
            result["classification"]["os_hint"] = (
                f"macOS (OpenSSH {ver_m.group(1)})" if ver_m else "macOS"
            )
        else:
            result["classification"]["os_hint"] = "macOS"
    elif top_platform == "vmware_esxi":
        result["classification"]["os_hint"] = (
            vauth.get("banner") or (snmp.get("sys_descr") or "")[:80] or "VMware ESXi"
        )
    elif top_platform == "network_device":
        if snmp.get("sys_descr"):
            result["classification"]["os_hint"] = snmp["sys_descr"][:80]
    elif top_platform == "iot":
        if rtsp.get("responded"):
            result["classification"]["os_hint"] = "IoT Camera / NVR (RTSP)"
        elif mqtt.get("responded"):
            result["classification"]["os_hint"] = "IoT Device (MQTT Broker)"
        elif upnp.get("responded"):
            parts = [
                upnp.get("manufacturer") or "",
                upnp.get("model_name") or "",
                upnp.get("friendly_name") or "",
            ]
            result["classification"]["os_hint"] = (
                " ".join(filter(None, parts))[:80] or "IoT Device"
            )
        elif http.get("title"):
            result["classification"]["os_hint"] = http["title"][:80]
        else:
            result["classification"]["os_hint"] = "IoT Device"
    elif top_platform == "printer":
        mm = ipp.get("make_model") or ipp.get("printer_name")
        result["classification"]["os_hint"] = mm or "Network Printer"
    elif top_platform == "wifi_ap":
        _srv_l = (http.get("server") or "").lower()
        _host = (result["classification"].get("hostname") or "").lower()
        # Jio ISP gateway: firmware string "jcow*/juicejfv-*"
        if (
            "juicejfv" in _srv_l
            or "jcow" in _srv_l
            or "reliance" in _host
            or _host.endswith(".jio")
        ):
            _fw_m = re.search(r"juicejfv-(\S+)", _srv_l, re.IGNORECASE)
            _fw = _fw_m.group(1) if _fw_m else ""
            result["classification"]["os_hint"] = (
                f"Jio ISP Gateway (fw {_fw})" if _fw else "Jio ISP Gateway"
            )
        elif upnp.get("responded"):
            parts = [
                upnp.get("manufacturer") or "",
                upnp.get("model_name") or "",
                upnp.get("friendly_name") or "",
            ]
            result["classification"]["os_hint"] = (
                " ".join(filter(None, parts))[:80] or "WiFi AP / Router"
            )
        elif snmp.get("sys_descr"):
            result["classification"]["os_hint"] = snmp["sys_descr"][:80]
        elif http.get("title"):
            result["classification"]["os_hint"] = http["title"][:80]
        else:
            mfr = p["arp"].get("manufacturer") or ""
            srv = http.get("server") or ""
            if mfr:
                result["classification"]["os_hint"] = f"{mfr} Router / AP"
            elif srv:
                result["classification"]["os_hint"] = f"Router / AP ({srv})"
            else:
                result["classification"]["os_hint"] = "WiFi AP / Router"
    elif top_platform == "mobile":
        mfr = p["arp"].get("manufacturer") or ""
        est = p["icmp"].get("ttl_estimated")
        os_guess = ""
        if mfr in ("Apple",):
            os_guess = "iPhone / iPad (iOS)"
        elif mfr in ("Samsung", "Xiaomi", "OnePlus", "Huawei", "OPPO", "Vivo"):
            os_guess = f"{mfr} Android"
        elif est == 64:
            os_guess = "Android / iOS device"
        elif est == 128:
            os_guess = "Windows Mobile / Surface"
        result["classification"]["os_hint"] = os_guess or "Mobile / Tablet"

    # ── Hostname: SMB > NetBIOS > mDNS > SNMP > (reverse DNS set earlier) ───
    if smb.get("computer_name"):
        result["classification"]["hostname"] = smb["computer_name"]
    elif netbios.get("computer_name") and not result["classification"]["hostname"]:
        result["classification"]["hostname"] = netbios["computer_name"]
    elif mdns.get("hostname") and not result["classification"]["hostname"]:
        result["classification"]["hostname"] = mdns["hostname"]
    elif snmp.get("sys_name") and not result["classification"]["hostname"]:
        result["classification"]["hostname"] = snmp["sys_name"]


# ---------------------------------------------------------------------------
# Identity enrichment — run cheap name/version probes before a short-circuit
# ---------------------------------------------------------------------------
def _enrich_identity(ip: str, result: dict):
    """Fill in os_hint / hostname before a confident short-circuit return.

    The classifier can reach SHORT_CIRCUIT confidence in phase 1 — e.g. a
    Windows box exposing WinRM (0.55) + the SMB port cluster (0.30) + TTL
    (0.30) = 1.15 — before the probes that actually carry identity have run.
    Those probes don't change the verdict, but skipping them leaves os_hint
    and hostname empty, so run the cheap ones here whenever their port is open.
    """
    open_p = set(result["probes"]["tcp_ports"]["open"])
    if 445 in open_p and not result["probes"]["smb"]["probed"]:
        signalThree(ip, result)  # SMB → Windows build + computer name
    if (
        open_p
        and not result["classification"]["hostname"]
        and not result["probes"]["netbios"]["responded"]
    ):
        signalEight(ip, result)  # NetBIOS NBSTAT → hostname fallback
    # mDNS reverse lookup — cheap single UDP query; the only hostname source
    # for Linux/macOS boxes (which expose neither SMB nor NetBIOS)
    if (
        not result["classification"]["hostname"]
        and not result["probes"]["mdns"]["hostname"]
    ):
        hostname = _mdns_reverse_hostname(ip)
        if hostname:
            result["probes"]["mdns"]["responded"] = True
            result["probes"]["mdns"]["hostname"] = hostname


# ---------------------------------------------------------------------------
# Fingerprint — phased parallel execution
# ---------------------------------------------------------------------------
def fingerprint(ip: str) -> dict:
    start = time.time()
    result = _build_result()
    result["classification"]["ip"] = ip

    # Reverse DNS (best-effort, overridden later by SMB/NetBIOS)
    # Only store if getfqdn returned a real name, not just the IP back
    try:
        fqdn = socket.getfqdn(ip)
        if fqdn != ip:
            result["classification"]["hostname"] = fqdn
    except Exception:
        pass

    # ── Phase 1: ICMP + TCP port scan (parallel) ───────────────────────────
    with ThreadPoolExecutor(max_workers=2) as ex:
        futs = [ex.submit(signalOne, ip, result), ex.submit(signalTwo, ip, result)]
        for f in futs:
            f.result()

    open_p = set(result["probes"]["tcp_ports"]["open"])

    # ARP MAC lookup — runs after phase 1 so the OS ARP cache is populated
    signalZero(ip, result)

    # Early exit: nothing responded at all (and no ARP entry proving it's alive)
    if (
        not result["probes"]["icmp"]["responded"]
        and not open_p
        and not result["probes"]["arp"]["mac"]
    ):
        result["classification"]["platform"] = "unreachable"
        result["classification"]["reachable"] = False
        result["classification"]["duration_ms"] = round((time.time() - start) * 1000)
        return result

    # ── Phase 1 short-circuit: port signature alone is definitive ─────────────
    classify(result)
    if result["classification"]["confidence"] >= SHORT_CIRCUIT:
        _enrich_identity(ip, result)  # grab os_hint/hostname before bailing
        classify(result)
        result["classification"]["duration_ms"] = round((time.time() - start) * 1000)
        if _VERBOSE:
            _print_debug(result)
        return result

    # ── Phase 2: protocol probes on open ports (parallel) ──────────────────
    phase2: list = []
    if 445 in open_p:
        phase2.append(signalThree)
    if 22 in open_p:
        phase2.append(signalFour)
    if 443 in open_p:
        phase2.append(signalFive)
    if open_p & {80, 443, 8080, 8443}:
        phase2.append(signalSix)
    if open_p & {80, 443, 8080, 8443}:
        phase2.append(signalTwelve)  # UPnP desc
    if 1883 in open_p:
        phase2.append(signalThirteen)  # MQTT
    if 554 in open_p:
        phase2.append(signalFifteen)  # RTSP

    if phase2:
        with ThreadPoolExecutor(max_workers=max(len(phase2), 1)) as ex:
            for f in as_completed([ex.submit(fn, ip, result) for fn in phase2]):
                f.result()

    # Short-circuit: if already high confidence, skip phase 3
    classify(result)
    if result["classification"]["confidence"] >= SHORT_CIRCUIT:
        _enrich_identity(ip, result)  # grab os_hint/hostname before bailing
        classify(result)
        result["classification"]["duration_ms"] = round((time.time() - start) * 1000)
        if _VERBOSE:
            _print_debug(result)
        return result

    # ── Phase 3: supplementary signals (UDP + less-common TCP) ─────────────
    phase3: list = [
        signalSeven,  # SNMP (UDP)
        signalEight,  # NetBIOS (UDP)
        signalEleven,
    ]  # mDNS (UDP 5353)
    if 3389 in open_p:
        phase3.append(signalNine)
    if 902 in open_p:
        phase3.append(signalTen)
    if open_p & {631, 9100}:
        phase3.append(signalFourteen)  # IPP/JetDirect
    if 23 in open_p:
        phase3.append(signalSixteen)  # Telnet banner

    with ThreadPoolExecutor(max_workers=max(len(phase3), 1)) as ex:
        for f in as_completed([ex.submit(fn, ip, result) for fn in phase3]):
            f.result()

    classify(result)
    result["classification"]["duration_ms"] = round((time.time() - start) * 1000)

    if _VERBOSE:
        _print_debug(result)

    return result


# ---------------------------------------------------------------------------
# Multi-target helpers
# ---------------------------------------------------------------------------
def _expand_target(target: str) -> list[str]:
    """Expand a single IP, hostname, or CIDR range to a list of IPs."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses == 1:
            return [str(net.network_address)]
        # Skip network and broadcast for subnets larger than /31
        hosts = list(net.hosts()) if net.prefixlen < 31 else list(net)
        return [str(h) for h in hosts]
    except ValueError:
        # Treat as hostname
        return [target]


def _write_result(result: dict, out_fh):
    line = json.dumps(result)
    with _stdout_lock:
        print(line)
        if out_fh is not None:
            out_fh.write(line + "\n")
            out_fh.flush()


def _get_local_networks() -> list[str]:
    """Return CIDR strings for every non-loopback IPv4 interface."""
    networks: list[str] = []
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(["ipconfig"], timeout=5).decode(
                errors="ignore"
            )
            ips: list[str] = []
            masks: list[str] = []
            for line in out.splitlines():
                m = re.search(r"IPv4 Address[^:]*:\s*([\d.]+)", line)
                if m:
                    ips.append(m.group(1))
                m = re.search(r"Subnet Mask[^:]*:\s*([\d.]+)", line)
                if m:
                    masks.append(m.group(1))
            for ip_addr, mask in zip(ips, masks):
                try:
                    net = ipaddress.IPv4Network(f"{ip_addr}/{mask}", strict=False)
                    if not net.is_loopback and net.prefixlen < 32:
                        networks.append(str(net))
                except Exception:
                    pass
        else:
            out = subprocess.check_output(
                ["ip", "-o", "-f", "inet", "addr", "show"], timeout=5
            ).decode(errors="ignore")
            for line in out.splitlines():
                m = re.search(r"\d+:\s+\S+\s+inet\s+([\d.]+/\d+)", line)
                if m:
                    try:
                        net = ipaddress.IPv4Network(m.group(1), strict=False)
                        if not net.is_loopback and net.prefixlen < 32:
                            networks.append(str(net))
                    except Exception:
                        pass
    except Exception:
        pass
    return networks


def main():
    global TIMEOUT
    parser = argparse.ArgumentParser(
        description="Network OS fingerprinter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="IP/CIDR",
        help="One or more IP addresses or CIDR ranges",
    )
    parser.add_argument(
        "-f",
        "--file",
        metavar="FILE",
        help="Read targets from file (one per line)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=10,
        metavar="N",
        help="Parallel fingerprint workers (default: 10)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Append JSONL results to this file",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=TIMEOUT,
        metavar="SEC",
        help=f"Per-probe socket timeout in seconds (default: {TIMEOUT})",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Auto-discover and scan all hosts on local network interfaces",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Print detailed per-signal trace and scoring breakdown to stderr",
    )
    args = parser.parse_args()
    TIMEOUT = args.timeout

    # Collect all targets
    raw_targets: list[str] = list(args.targets)
    if args.file:
        try:
            with open(args.file) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        raw_targets.append(line)
        except OSError as exc:
            print(f"Cannot read target file: {exc}", file=sys.stderr)
            sys.exit(1)

    if args.local:
        local_nets = _get_local_networks()
        if not local_nets:
            print("Could not detect any local network interfaces", file=sys.stderr)
            sys.exit(1)
        print(f"# Scanning local networks: {', '.join(local_nets)}", file=sys.stderr)
        raw_targets.extend(local_nets)

    if not raw_targets:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Expand CIDR ranges
    ips: list[str] = []
    for t in raw_targets:
        ips.extend(_expand_target(t))

    # Auto-generate output filename when --local is used without -o
    output_path = args.output
    if not output_path and args.local:
        import datetime

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"scan_{ts}.jsonl"
        print(f"# Output → {output_path}", file=sys.stderr)

    out_fh = None
    if output_path:
        try:
            out_fh = open(output_path, "a", encoding="utf-8")
        except OSError as exc:
            print(f"Cannot open output file: {exc}", file=sys.stderr)
            sys.exit(1)

    global _VERBOSE
    _VERBOSE = args.debug

    try:
        if len(ips) == 1:
            result = fingerprint(ips[0])
            _write_result(result, out_fh)
        else:
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                futures = {ex.submit(fingerprint, ip): ip for ip in ips}
                for fut in as_completed(futures):
                    try:
                        _write_result(fut.result(), out_fh)
                    except Exception as exc:
                        ip = futures[fut]
                        err_result = _build_result()
                        err_result["classification"]["ip"] = ip
                        err_result["classification"]["error"] = str(exc)
                        _write_result(err_result, out_fh)
    finally:
        if out_fh is not None:
            out_fh.close()


if __name__ == "__main__":
    main()
