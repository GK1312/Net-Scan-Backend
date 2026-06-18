---
name: classifier-identity-rules
description: The scan classifier rewrite dropped the old per-device identity heuristics; where they now live in scoring.py
metadata:
  type: project
---

The current `src/core/scan/scoring.py` is a rewrite of an older classifier (`old-version.py`). The rewrite switched to a clean additive vote model (`share × saturation`) but **silently dropped most of the old classifier's specific device-identity heuristics**, so many real devices regressed to generic `linux`/`Linux/Unix`/low-confidence. Reconciled host-by-host (vCenter, ESXi, Jio gateway, Win Server 2012, mobile) then in a full pass against `old-version.py` (~2680–3350) on 2026-06-18.

**Why:** the vote model dilutes single strong signals (e.g. an ESXi host's own SSH/TTL-64 vote `linux`), and the rewrite simply lacked the brand/identity tables the old one had.

**How to apply** — when a device is misclassified as generic `linux`, the rule almost certainly belongs in one of these (all in `scoring.py`):
- `_DEVICE_IDENTITY` — vendor-unique TLS cert subject/issuer or reverse-DNS hostname → (platform, os_hint). e.g. Jio `RILSELFCERT`/`reliance`.
- `_HTTP_SERVER_KEYWORDS` / `_HTTP_TITLE_KEYWORDS` — router-firmware / camera / printer brands in HTTP `Server`/`<title>`.
- `_UPNP_VENDOR_KEYWORDS` + router/camera keyword fallbacks in the UPnP block.
- telnet keyword sets in `_score_banners`; `_PLATFORM_OS_HINT` + `_platform_specific_hint` for os_hint detail.
- `_has_definitive_signal` (floors confidence to `_DEFINITIVE_CONFIDENCE=90` for proof-grade signals: `vmware_authd` banner, device-identity match). Extend here for SMB native_os / SNMP enterprise-OID if needed.
- OUI table is in `oui.py` (fully ported). Version freshness lives in two places: SMB/NTLMSSP Windows builds in `os_hints.py` (`_BUILD_10`, `_LEGACY_BUILD` for SP/RTM detail, `_LEGACY`), and SSH-OpenSSH→distro maps in `scoring.py` (`_UBUNTU_VERSIONS`/`_DEBIAN_VERSIONS`/`_FEDORA_VERSIONS`/`_BARE_OPENSSH_OS` + `_SSH_OS_TOKENS`). `PROBE_PORTS`==`tcp_ports.DEFAULT_PORTS` (21 ports), and SNMP enterprise-OID→platform is `_SNMP_ENTERPRISE` — all reconciled to old-version.py.

Intentionally NOT ported: "silent host → mobile" (misclassifies firewalled servers) and "default gateway → wifi_ap" (no meaning for distributed worker pods). Confidence numbers won't match the old classifier — only rules were translated, not the 0–1 `bump` weights. Related: [[amqp-port-gotcha]].
