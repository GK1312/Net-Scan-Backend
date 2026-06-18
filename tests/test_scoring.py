from __future__ import annotations

import pytest

from src.core.scan.models import Probes
from src.core.scan.scoring import _os_hint_from_ssh, build_classification, score


def test_windows_host_classified_with_high_confidence():
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_received": 128, "ttl_estimated": 128},
            "tcp_ports": {"open": [135, 445, 3389]},
            "smb": {
                "responded": True,
                "native_os": "Windows 11 24H2",
                "os_version": "10.0.26100",
                "is_samba": False,
                "computer_name": "DESKTOP1",
            },
        }
    )
    s = score("10.0.0.1", probes)
    assert s.platform == "windows"
    assert s.confidence > 50
    assert s.os_hint == "Windows 11 24H2"
    assert s.hostname == "DESKTOP1"


def test_printer_from_ports_and_ipp():
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_estimated": 64},
            "tcp_ports": {"open": [80, 631, 9100]},
            "ipp": {"responded": True, "make_model": "HP LaserJet"},
        }
    )
    assert score("10.0.0.2", probes).platform == "printer"


def test_linux_from_ssh_banner():
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_estimated": 64},
            "tcp_ports": {"open": [22]},
            "ssh": {"responded": True, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu"},
        }
    )
    assert score("10.0.0.3", probes).platform == "linux"


def test_network_device_from_snmp():
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_estimated": 255},
            "tcp_ports": {"open": [22, 161]},
            "snmp": {"responded": True, "sys_descr": "Cisco IOS Software"},
        }
    )
    assert score("10.0.0.4", probes).platform == "network_device"


def test_empty_probes_is_unknown():
    s = score("10.0.0.5", Probes())
    assert s.platform == "unknown"
    assert s.confidence == 0.0


def test_oui_vote_and_randomized_mac_ignored():
    real = Probes(
        **{
            "arp": {
                "mac": "18:FE:34:11:22:33",
                "manufacturer": "Espressif",
                "platform_hint": "iot",
                "randomized": False,
            }
        }
    )
    assert score("10.0.0.6", real).platform == "iot"

    randomized = Probes(
        **{
            "arp": {
                "mac": "1A:FE:34:11:22:33",
                "manufacturer": "Espressif",
                "platform_hint": "iot",
                "randomized": True,
            }
        }
    )
    assert score("10.0.0.7", randomized).platform == "unknown"


def test_reachable_via_arp_only():
    probes = Probes(**{"arp": {"mac": "AA:BB:CC:DD:EE:FF"}})
    s = score("10.0.0.8", probes)
    classification = build_classification("10.0.0.8", probes, s, 5)
    assert classification.reachable is True


def test_os_hint_from_ssh_banner_without_icmp():
    probes = Probes(
        **{
            "tcp_ports": {"open": [22]},
            "ssh": {"responded": True, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
        }
    )
    s = score("192.168.1.117", probes)
    assert s.platform == "linux"
    assert s.os_hint == "Ubuntu 22.04 LTS"


def test_os_hint_rhel_family_from_bare_openssh_version():

    probes = Probes(
        **{
            "tcp_ports": {"open": [22]},
            "ssh": {"responded": True, "banner": "SSH-2.0-OpenSSH_8.7"},
        }
    )
    s = score("192.168.1.117", probes)
    assert s.platform == "linux"
    assert s.os_hint == "RHEL / AlmaLinux / Rocky / Oracle 9"


def test_vcenter_appliance_stays_linux_with_vmware_hint():
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_received": 64, "ttl_estimated": 64},
            "tcp_ports": {"open": [22, 80, 443]},
            "ssh": {"responded": True, "banner": "SSH-2.0-OpenSSH_7.4"},
            "http": {"responded": True, "title": '" + ID_VC_Welcome + "'},
        }
    )
    s = score("192.168.1.100", probes)
    assert s.platform == "linux"
    assert s.os_hint == "VMware vCenter Server Appliance (Photon OS)"


def test_esxi_authd_banner_floors_confidence_despite_linux_signals():
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_received": 64, "ttl_estimated": 64},
            "tcp_ports": {"open": [22, 80, 443, 902]},
            "ssh": {"responded": True, "banner": "SSH-2.0-OpenSSH_7.9"},
            "vmware_authd": {
                "responded": True,
                "banner": "220 VMware Authentication Daemon Version 1.10",
            },
        }
    )
    s = score("192.168.1.108", probes)
    assert s.platform == "vmware_esxi"
    assert s.confidence >= 90
    assert s.os_hint == "VMware ESXi"


def test_vmware_port_without_authd_is_not_floored():
    # Port 902 alone (no authd handshake) is a vote, not proof -> no floor.
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_received": 64, "ttl_estimated": 64},
            "tcp_ports": {"open": [22, 902]},
            "ssh": {"responded": True, "banner": "SSH-2.0-OpenSSH_7.9"},
        }
    )
    s = score("192.168.1.108", probes)
    assert s.confidence < 90


def test_jio_gateway_identified_from_tls_cert_and_hostname():
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_received": 64, "ttl_estimated": 64},
            "tcp_ports": {"open": [80, 443, 8080, 8443]},
            "tls_443": {"responded": True, "subject": "RILSELFCERT"},
            "revdns": {"hostname": "reliance.reliance"},
        }
    )
    s = score("192.168.1.101", probes)
    assert s.platform == "wifi_ap"
    assert s.os_hint == "Jio ISP Gateway"
    assert s.confidence >= 90


def test_randomized_mac_with_ttl_64_is_mobile():
    # Phone on Wi-Fi: privacy/randomized MAC, TTL 64, no open ports/services.
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_received": 64, "ttl_estimated": 64},
            "arp": {"mac": "A2:56:10:6D:C7:01", "randomized": True},
        }
    )
    s = score("192.168.1.139", probes)
    assert s.platform == "mobile"
    assert s.os_hint == "Android / iOS device"
    assert s.confidence >= 80


def test_ttl_64_without_randomized_mac_stays_linux():
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_received": 64, "ttl_estimated": 64},
            "arp": {"mac": "00:11:22:33:44:55", "randomized": False},
        }
    )
    s = score("192.168.1.50", probes)
    assert s.platform == "linux"
    assert s.os_hint == "Linux/Unix"


@pytest.mark.parametrize(
    ("server", "expected_platform"),
    [
        ("OpenWrt/LuCI", "wifi_ap"),
        ("Boa/0.94 RouterOS", "wifi_ap"),
        ("App-webs/ Hikvision", "iot"),
        ("Dahua Web Server", "iot"),
        ("KS_HTTP/1.0 Lexmark", "printer"),
    ],
)
def test_http_server_brand_votes_platform(server, expected_platform):
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_received": 64, "ttl_estimated": 64},
            "tcp_ports": {"open": [80]},
            "http": {"responded": True, "server": server},
        }
    )
    assert score("10.0.0.9", probes).platform == expected_platform


def test_http_title_keyword_votes_platform():
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_received": 64, "ttl_estimated": 64},
            "tcp_ports": {"open": [80]},
            "http": {"responded": True, "title": "Network Camera Login"},
        }
    )
    assert score("10.0.0.10", probes).platform == "iot"


def test_telnet_banner_keyword_expansion():
    juniper = Probes(
        **{"telnet": {"responded": True, "banner": "Juniper Networks JUNOS"}}
    )
    assert score("10.0.0.11", juniper).platform == "network_device"
    openwrt = Probes(**{"telnet": {"responded": True, "banner": "OpenWrt login:"}})
    assert score("10.0.0.12", openwrt).platform == "iot"


def test_os_hint_windows_winrm_and_smb1():
    winrm = Probes(
        **{
            "icmp": {"responded": True, "ttl_received": 128, "ttl_estimated": 128},
            "tcp_ports": {"open": [135, 5985]},
        }
    )
    assert score("10.0.0.13", winrm).os_hint == "Windows (WinRM)"

    smb1 = Probes(
        **{
            "icmp": {"responded": True, "ttl_received": 128, "ttl_estimated": 128},
            "tcp_ports": {"open": [135, 445]},
            "smb": {"probed": True, "responded": False},
        }
    )
    assert "SMB v1" in (score("10.0.0.14", smb1).os_hint or "")


def test_os_hint_printer_from_ipp_make_model():
    probes = Probes(
        **{
            "tcp_ports": {"open": [631]},
            "ipp": {"responded": True, "make_model": "HP LaserJet M404"},
        }
    )
    s = score("10.0.0.15", probes)
    assert s.platform == "printer"
    assert s.os_hint == "HP LaserJet M404"


def test_os_hint_iot_camera_from_rtsp():
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_received": 64, "ttl_estimated": 64},
            "tcp_ports": {"open": [554]},
            "rtsp": {"responded": True, "banner": "RTSP/1.0 200 OK"},
        }
    )
    s = score("10.0.0.16", probes)
    assert s.platform == "iot"
    assert s.os_hint == "IoT Camera / NVR (RTSP)"


def test_ssh_distro_beats_generic_ttl_hint():

    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_received": 64, "ttl_estimated": 64},
            "tcp_ports": {"open": [22]},
            "ssh": {"responded": True, "banner": "SSH-2.0-OpenSSH_8.7"},
        }
    )
    s = score("192.168.1.117", probes)
    assert s.platform == "linux"
    assert s.os_hint == "RHEL / AlmaLinux / Rocky / Oracle 9"


@pytest.mark.parametrize(
    ("banner", "expected"),
    [
        ("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11", "Ubuntu 20.04 LTS"),
        ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3", "Ubuntu 24.04 LTS"),
        ("SSH-2.0-OpenSSH_9.2p1 Debian-2", "Debian 12 (bookworm)"),
        ("SSH-2.0-OpenSSH_7.9p1 Raspbian-10", "Raspberry Pi OS"),
        ("SSH-2.0-OpenSSH_8.4 FreeBSD-20240701", "FreeBSD"),
        ("SSH-2.0-OpenSSH_9.6 (SUSE Linux Enterprise)", "SUSE Linux"),
        ("SSH-2.0-OpenSSH_for_Windows_8.1", "Windows (OpenSSH)"),
        ("SSH-2.0-OpenSSH_8.7", "RHEL / AlmaLinux / Rocky / Oracle 9"),
        ("SSH-2.0-OpenSSH_9.9", "RHEL / AlmaLinux / Rocky / Oracle 10"),
        ("SSH-2.0-OpenSSH_6.6.1", "RHEL / CentOS 6"),
        ("SSH-2.0-OpenSSH_9.9p1 Ubuntu-2", "Ubuntu 25.04"),
        ("SSH-2.0-OpenSSH_9.9p1 Debian-1", "Debian 13 (trixie)"),
        ("SSH-2.0-OpenSSH_9.6 Fedora", "Fedora 40"),
        ("SSH-2.0-OpenSSH_8.7 Rocky", "Rocky Linux"),
        ("SSH-2.0-dropbear_2022.83", "Embedded Linux (Dropbear)"),
        ("SSH-2.0-Cisco-1.25", "Cisco network OS"),
        ("SSH-2.0-OpenSSH_9.0", "Linux/Unix"),
    ],
)
def test_os_hint_from_ssh_banner_matrix(banner, expected):
    assert _os_hint_from_ssh(banner) == expected


def test_os_hint_unknown_openssh_version_is_generic():
    probes = Probes(
        **{
            "tcp_ports": {"open": [22]},
            "ssh": {"responded": True, "banner": "SSH-2.0-OpenSSH_9.5"},
        }
    )
    assert score("x", probes).os_hint == "Linux/Unix"


def test_os_hint_platform_fallback_when_no_specific_source():
    s = score("10.0.2.1", Probes(**{"tcp_ports": {"open": [9100]}}))
    assert s.platform == "printer"
    assert s.os_hint == "Printer"


def test_os_hint_stays_null_for_unknown():
    assert score("10.0.2.2", Probes()).os_hint is None


def test_hostname_from_snmp_sysname():
    probes = Probes(
        **{
            "tcp_ports": {"open": [22]},
            "snmp": {"responded": True, "sys_name": "web01.example.com"},
        }
    )
    assert score("192.168.1.117", probes).hostname == "web01.example.com"


def test_hostname_from_reverse_dns_as_last_resort():
    probes = Probes(
        **{
            "tcp_ports": {"open": [22]},
            "revdns": {"hostname": "host.ptr.example.com"},
        }
    )
    assert score("192.168.1.117", probes).hostname == "host.ptr.example.com"


def test_hostname_prefers_snmp_over_reverse_dns():
    probes = Probes(
        **{
            "snmp": {"responded": True, "sys_name": "snmp-name"},
            "revdns": {"hostname": "ptr-name.example.com"},
        }
    )
    assert score("x", probes).hostname == "snmp-name"


def test_hostname_prefers_smb_over_snmp():
    probes = Probes(
        **{
            "smb": {"responded": True, "computer_name": "WINBOX"},
            "snmp": {"responded": True, "sys_name": "snmp-name"},
        }
    )
    assert score("x", probes).hostname == "WINBOX"


def test_netbios_response_votes_windows():
    probes = Probes(
        **{"netbios": {"responded": True, "computer_name": "PC1", "domain": "WG"}}
    )
    assert score("10.0.1.1", probes).platform == "windows"


def test_tls_cert_vendor_votes_platform():
    probes = Probes(
        **{
            "tcp_ports": {"open": [443]},
            "tls_443": {
                "responded": True,
                "subject": "VMware ESXi",
                "issuer": "VMware",
            },
        }
    )
    assert score("10.0.1.2", probes).platform == "vmware_esxi"


def test_snmp_enterprise_oid_votes_network_device():
    probes = Probes(
        **{"snmp": {"responded": True, "sys_object_id": "1.3.6.1.4.1.9.1.1208"}}
    )
    assert score("10.0.1.3", probes).platform == "network_device"


def test_upnp_vendor_votes_wifi_ap():
    probes = Probes(
        **{
            "tcp_ports": {"open": [80]},
            "upnp": {
                "responded": True,
                "manufacturer": "NETGEAR",
                "model_name": "R7000",
            },
        }
    )
    assert score("10.0.1.4", probes).platform == "wifi_ap"


def test_confidence_damped_on_thin_evidence():
    thin = score("10.0.1.5", Probes(**{"tcp_ports": {"open": [445]}}))
    assert thin.platform == "windows"
    assert 0 < thin.confidence < 60
    strong = score(
        "10.0.1.6",
        Probes(
            **{
                "icmp": {"responded": True, "ttl_estimated": 128},
                "tcp_ports": {"open": [445, 3389]},
                "smb": {
                    "responded": True,
                    "native_os": "Windows 10",
                    "os_version": "10.0.19045",
                },
            }
        ),
    )
    assert strong.confidence >= 90
    assert strong.confidence > thin.confidence


def test_score_log_and_evidence_populated():
    probes = Probes(
        **{
            "icmp": {"responded": True, "ttl_estimated": 128},
            "tcp_ports": {"open": [445]},
        }
    )
    s = score("10.0.0.9", probes)
    assert s.score_log
    assert s.evidence.ttl_rule["estimated"] == 128
    assert 445 in s.evidence.port_rule["open"]
    assert s.evidence.conflict_resolution["winner"] == s.platform
