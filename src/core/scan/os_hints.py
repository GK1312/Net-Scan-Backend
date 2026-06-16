from __future__ import annotations

_BUILD_10: dict[int, str] = {
    # Client-only builds
    10240: "Windows 10 1507",
    10586: "Windows 10 1511",
    15063: "Windows 10 1703",
    19043: "Windows 10 21H1",
    19044: "Windows 10 21H2",
    19045: "Windows 10 22H2",
    22000: "Windows 11 21H2",
    22621: "Windows 11 22H2",
    22631: "Windows 11 23H2",
    26200: "Windows 11 25H2",
    # Shared client / server builds
    14393: "Windows 10 1607 / Server 2016",
    16299: "Windows 10 1709 / Server 1709",
    17134: "Windows 10 1803 / Server 1803",
    17763: "Windows 10 1809 / Server 2019",
    18362: "Windows 10 1903 / Server 1903",
    18363: "Windows 10 1909 / Server 1909",
    19041: "Windows 10 2004 / Server 2004",
    19042: "Windows 10 20H2 / Server 20H2",
    26100: "Windows 11 24H2 / Server 2025",
    # Server-exclusive builds
    20348: "Windows Server 2022",
    25398: "Windows Server 2022 23H2",
}

# --- Pre-10.0 releases keyed by (major, minor) ---
_LEGACY: dict[tuple[int, int], str] = {
    (6, 3): "Windows 8.1 / Server 2012 R2",
    (6, 2): "Windows 8 / Server 2012",
    (6, 1): "Windows 7 / Server 2008 R2",
    (6, 0): "Windows Vista / Server 2008",
    (5, 2): "Windows XP x64 / Server 2003",
    (5, 1): "Windows XP",
    (5, 0): "Windows 2000 / Server 2000",
    (4, 0): "Windows NT 4.0 / Server NT 4.0",
}


def win_version_name(major: int, minor: int, build: int) -> str:
    if (major, minor) == (10, 0):
        known = _BUILD_10.get(build)
        if known:
            return known
        return "Windows 11" if build >= 22000 else "Windows 10"
    legacy = _LEGACY.get((major, minor))
    if legacy:
        return legacy
    return f"Windows (NT {major}.{minor}, build {build})"
