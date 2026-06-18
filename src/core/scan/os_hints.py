from __future__ import annotations

# Map an SMB/NTLMSSP version triple (major, minor, build) to a human OS name.
#
# Caveat: NTLMSSP reports only major.minor.build, and Windows client and server
# SKUs share the same build (e.g. 26100 is BOTH Windows 11 24H2 AND Server 2025).
# Distinguishing client vs server for a shared build isn't possible from this
# probe alone, so for a shared build we name BOTH ("Windows 8 / Server 2012")
# rather than guessing the client; builds that are server-exclusive (e.g. 20348)
# are named as Server only.

# --- Windows 10/11 / Server 2016+ all report version 10.0; the build decides ---
_BUILD_10: dict[int, str] = {
    # Windows 10 (client) — shared builds name both client and server SKU
    10240: "Windows 10 1507",
    10586: "Windows 10 1511",
    14393: "Windows 10 1607 / Server 2016",
    15063: "Windows 10 1703",
    16299: "Windows 10 1709 / Server 1709",
    17134: "Windows 10 1803 / Server 1803",
    17763: "Windows 10 1809 / Server 2019",
    18362: "Windows 10 1903 / Server 1903",
    18363: "Windows 10 1909 / Server 1909",
    19041: "Windows 10 2004 / Server 2004",
    19042: "Windows 10 20H2 / Server 20H2",
    19043: "Windows 10 21H1",
    19044: "Windows 10 21H2",
    19045: "Windows 10 22H2",
    # Windows Server (server-exclusive builds — no client uses these)
    20348: "Windows Server 2022",
    25398: "Windows Server, version 23H2",
    # Windows 11 (client)
    22000: "Windows 11 21H2",
    22621: "Windows 11 22H2",
    22631: "Windows 11 23H2",
    26100: "Windows 11 24H2 / Server 2025",
    26200: "Windows 11 25H2",
}

# --- Pre-10.0, keyed by exact build for SP/RTM granularity (build is globally
# unique to its release, so the major.minor isn't needed). Checked first. ---
_LEGACY_BUILD: dict[int, str] = {
    9600: "Windows 8.1 / Server 2012 R2",
    9200: "Windows 8 / Server 2012",
    7601: "Windows 7 SP1 / Server 2008 R2 SP1",
    7600: "Windows 7 / Server 2008 R2 (RTM)",
    6002: "Windows Vista SP2 / Server 2008 SP2",
    6001: "Windows Vista SP1 / Server 2008",
    6000: "Windows Vista (RTM)",
    3790: "Windows Server 2003 / XP x64",
    2600: "Windows XP",
}

# --- Pre-10.0 fallback keyed by (major, minor); names both client and server SKU ---
_LEGACY: dict[tuple[int, int], str] = {
    (6, 3): "Windows 8.1 / Server 2012 R2",
    (6, 2): "Windows 8 / Server 2012",
    (6, 1): "Windows 7 / Server 2008 R2",
    (6, 0): "Windows Vista / Server 2008",
    (5, 2): "Windows XP x64 / Server 2003",
    (5, 1): "Windows XP",
    (5, 0): "Windows 2000",
    (4, 0): "Windows NT 4.0",
}


def win_version_name(major: int, minor: int, build: int) -> str:
    """Best-effort OS name from an SMB/NTLMSSP version triple, e.g.
    (10, 0, 26100) -> 'Windows 11 24H2 / Server 2025',
    (6, 1, 7601) -> 'Windows 7 SP1 / Server 2008 R2 SP1'."""
    if (major, minor) == (10, 0):
        known = _BUILD_10.get(build)
        if known:
            return known
        # Unknown 10.0 build: 22000+ is Windows 11, otherwise Windows 10.
        return "Windows 11" if build >= 22000 else "Windows 10"
    legacy_build = _LEGACY_BUILD.get(build)
    if legacy_build:
        return legacy_build
    legacy = _LEGACY.get((major, minor))
    if legacy:
        return legacy
    return f"Windows (NT {major}.{minor}, build {build})"
