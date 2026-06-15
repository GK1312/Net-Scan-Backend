from __future__ import annotations

# Map an SMB/NTLMSSP version triple (major, minor, build) to a human OS name.
#
# Caveat: NTLMSSP reports only major.minor.build, and Windows client and server
# SKUs share the same build (e.g. 26100 is BOTH Windows 11 24H2 AND Server 2025).
# So for a build used by both, we name the client (the common case) and note the
# server collision in a comment; builds that are server-exclusive (e.g. 20348)
# are named as Server. Distinguishing client vs server for a shared build needs
# another signal and isn't possible from this probe alone.

# --- Windows 10/11 / Server 2016+ all report version 10.0; the build decides ---
_BUILD_10: dict[int, str] = {
    # Windows 10 (client)            # collides with
    10240: "Windows 10 1507",
    10586: "Windows 10 1511",
    14393: "Windows 10 1607",        # Server 2016
    15063: "Windows 10 1703",
    16299: "Windows 10 1709",        # Server 1709
    17134: "Windows 10 1803",        # Server 1803
    17763: "Windows 10 1809",        # Server 2019
    18362: "Windows 10 1903",        # Server 1903
    18363: "Windows 10 1909",        # Server 1909
    19041: "Windows 10 2004",        # Server 2004
    19042: "Windows 10 20H2",        # Server 20H2
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
    26100: "Windows 11 24H2",        # Server 2025
    26200: "Windows 11 25H2",
}

# --- Pre-10.0 releases keyed by (major, minor); client name (shares build with server) ---
_LEGACY: dict[tuple[int, int], str] = {
    (6, 3): "Windows 8.1",       # / Server 2012 R2
    (6, 2): "Windows 8",         # / Server 2012
    (6, 1): "Windows 7",         # / Server 2008 R2
    (6, 0): "Windows Vista",     # / Server 2008
    (5, 2): "Windows XP x64",    # / Server 2003 / 2003 R2
    (5, 1): "Windows XP",
    (5, 0): "Windows 2000",
    (4, 0): "Windows NT 4.0",
}


def win_version_name(major: int, minor: int, build: int) -> str:
    """Best-effort OS name from an SMB/NTLMSSP version triple,
    e.g. (10, 0, 26100) -> 'Windows 11 24H2', (6, 1, 7601) -> 'Windows 7'."""
    if (major, minor) == (10, 0):
        known = _BUILD_10.get(build)
        if known:
            return known
        # Unknown 10.0 build: 22000+ is Windows 11, otherwise Windows 10.
        return "Windows 11" if build >= 22000 else "Windows 10"
    legacy = _LEGACY.get((major, minor))
    if legacy:
        return legacy
    return f"Windows (NT {major}.{minor}, build {build})"
