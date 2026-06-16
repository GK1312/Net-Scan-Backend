from __future__ import annotations

# RTSP response fingerprint tables.
#
# RTSP (Real Time Streaming Protocol, RFC 7826 / RFC 2326) is used primarily
# by IP cameras, DVRs, NVRs, and media servers on port 554 (and sometimes 8554).
#
# An OPTIONS request returns a status line and headers including "Server:".
# Two signals:
#   SERVER_HINTS   — "Server:" header substring → (platform, device_hint)
#   STATUS_HINTS   — status line / first response line → (platform, device_hint)
#
# All matches are case-insensitive. First match wins.


# ── RTSP alternate port ────────────────────────────────────────────────────
RTSP_ALT_PORT = 8554   # Some cameras and media servers use 8554

# ── Server header → (platform, device_hint) ───────────────────────────────
SERVER_HINTS: list[tuple[str, str, str]] = [
    # ── Hikvision (market leader in IP cameras) ───────────────────────────
    ("hikvision",               "iot",            "Hikvision IP camera"),
    ("hikvision-webs",          "iot",            "Hikvision IP camera"),
    # ── Dahua ─────────────────────────────────────────────────────────────
    ("dahua",                   "iot",            "Dahua IP camera"),
    ("dh_",                     "iot",            "Dahua IP camera"),
    # ── Axis ──────────────────────────────────────────────────────────────
    ("axis",                    "iot",            "Axis IP camera"),
    ("axis rtsp",               "iot",            "Axis IP camera"),
    # ── Bosch ─────────────────────────────────────────────────────────────
    ("bosch",                   "iot",            "Bosch IP camera"),
    # ── Sony ──────────────────────────────────────────────────────────────
    ("sony",                    "iot",            "Sony IP camera"),
    # ── Hanwha / Samsung ──────────────────────────────────────────────────
    ("hanwha",                  "iot",            "Hanwha Techwin IP camera"),
    ("samsung",                 "iot",            "Samsung IP camera"),
    # ── Vivotek ───────────────────────────────────────────────────────────
    ("vivotek",                 "iot",            "Vivotek IP camera"),
    # ── Reolink ───────────────────────────────────────────────────────────
    ("reolink",                 "iot",            "Reolink IP camera"),
    # ── Amcrest / Dahua OEM ───────────────────────────────────────────────
    ("amcrest",                 "iot",            "Amcrest IP camera (Dahua OEM)"),
    # ── Foscam ────────────────────────────────────────────────────────────
    ("foscam",                  "iot",            "Foscam IP camera"),
    # ── D-Link ────────────────────────────────────────────────────────────
    ("dcs",                     "iot",            "D-Link IP camera (DCS series)"),
    ("d-link",                  "iot",            "D-Link IP camera"),
    # ── Pelco ─────────────────────────────────────────────────────────────
    ("pelco",                   "iot",            "Pelco IP camera"),
    # ── Uniview ───────────────────────────────────────────────────────────
    ("uniview",                 "iot",            "Uniview (UNV) IP camera"),
    # ── Tiandy ────────────────────────────────────────────────────────────
    ("tiandy",                  "iot",            "Tiandy IP camera"),
    # ── Generic DVR/NVR ───────────────────────────────────────────────────
    ("dvr",                     "iot",            "DVR"),
    ("nvr",                     "iot",            "NVR"),
    ("ipcam",                   "iot",            "IP camera"),
    ("ip camera",               "iot",            "IP camera"),
    ("ip cam",                  "iot",            "IP camera"),
    ("rtspserver",              "iot",            "Generic RTSP server"),
    ("rtsp server",             "iot",            "Generic RTSP server"),
    # ── GStreamer (Linux-based RTSP servers) ──────────────────────────────
    ("gstreamer",               "linux",          "GStreamer RTSP server (Linux)"),
    ("gst-rtsp",                "linux",          "GStreamer RTSP (Linux)"),
    # ── FFmpeg-based RTSP ─────────────────────────────────────────────────
    ("ffmpeg",                  "linux",          "FFmpeg RTSP stream (Linux)"),
    # ── VLC ───────────────────────────────────────────────────────────────
    ("vlc",                     "linux",          "VLC media player RTSP stream"),
    ("videolan",                "linux",          "VLC / VideoLAN RTSP stream"),
    # ── Live555 (widely embedded) ─────────────────────────────────────────
    ("live555",                 "iot",            "Live555 RTSP library (embedded)"),
    ("livestreaming",           "iot",            "Live555 RTSP stream"),
    # ── RTSP Simple Server / MediaMTX ─────────────────────────────────────
    ("mediamtx",                "linux",          "MediaMTX (RTSP Simple Server)"),
    ("rtsp-simple-server",      "linux",          "RTSP Simple Server"),
    # ── Wowza Streaming Engine ────────────────────────────────────────────
    ("wowza",                   "linux",          "Wowza Streaming Engine"),
    # ── Nimble Streamer ───────────────────────────────────────────────────
    ("nimble",                  "linux",          "Nimble Streamer"),
    # ── Darwin Streaming Server (macOS) ───────────────────────────────────
    ("dss/",                    "macos",          "Darwin Streaming Server (macOS)"),
    ("darwin",                  "macos",          "Darwin Streaming Server (macOS)"),
    # ── Synology ──────────────────────────────────────────────────────────
    ("synology",                "linux",          "Synology NAS Surveillance Station"),
    # ── QNAP ─────────────────────────────────────────────────────────────
    ("qnap",                    "linux",          "QNAP NAS surveillance"),
    # ── Milestone / enterprise VMS ────────────────────────────────────────
    ("milestone",               "windows",        "Milestone XProtect VMS (Windows)"),
    ("exacqvision",             "windows",        "ExacqVision VMS (Windows)"),
    # ── Embedded RTOS ─────────────────────────────────────────────────────
    ("vxworks",                 "iot",            "VxWorks RTOS (embedded camera)"),
]

# ── RTSP status line / response → (platform, device_hint) ─────────────────
# Matched against the full first line of the response.
STATUS_HINTS: list[tuple[str, str, str]] = [
    ("rtsp/1.0 200",            "iot",            "RTSP/1.0 server (likely IP camera)"),
    ("rtsp/2.0 200",            "iot",            "RTSP/2.0 server"),
    ("rtsp/1.0 401",            "iot",            "RTSP server requires auth (IP camera)"),
    ("rtsp/1.0 403",            "iot",            "RTSP server forbidden"),
    ("rtsp/1.0 404",            "iot",            "RTSP server — stream not found"),
    ("rtsp/1.0 454",            "iot",            "RTSP server — session not found"),
    ("rtsp/1.0 500",            "iot",            "RTSP server internal error"),
    ("rtsp/1.0 551",            "iot",            "RTSP server — option not supported"),
]

# ── Common RTSP stream URL path patterns ──────────────────────────────────
# These paths are tried by the RTSP probe when querying for a live stream.
# Format: (path, vendor_hint)
STREAM_PATHS: list[tuple[str, str]] = [
    ("/",                           "generic"),
    ("/live",                       "generic"),
    ("/stream",                     "generic"),
    ("/stream1",                    "generic"),
    ("/stream2",                    "generic (sub-stream)"),
    ("/live/ch0",                   "generic"),
    ("/live/ch00_0",                "Hikvision"),
    ("/Streaming/Channels/101",     "Hikvision"),
    ("/Streaming/Channels/1",       "Hikvision"),
    ("/cam/realmonitor?channel=1&subtype=0", "Dahua"),
    ("/cam/realmonitor?channel=1&subtype=1", "Dahua (sub-stream)"),
    ("/axis-media/media.amp",       "Axis"),
    ("/mpeg4/media.amp",            "Axis"),
    ("/h264/media.amp",             "Axis"),
    ("/1",                          "Reolink / generic"),
    ("/live/main",                  "Reolink"),
    ("/live/sub",                   "Reolink (sub-stream)"),
    ("/video1",                     "Foscam"),
    ("/videoMain",                  "Foscam"),
    ("/media/video1",               "D-Link DCS"),
    ("/ucast/11",                   "Vivotek"),
    ("/live.sdp",                   "generic / Bosch"),
    ("/h264Preview_01_main",        "Amcrest / Dahua OEM"),
    ("/h264Preview_01_sub",         "Amcrest / Dahua OEM (sub-stream)"),
    ("/channel1",                   "generic"),
    ("/0",                          "generic"),
    ("/medias/1",                   "generic"),
    ("/onvif/profile2/media.smp",   "ONVIF profile stream"),
]
