"""
Unit tests for the Network Reconnaissance Tool.

Run with:
    venv/bin/python -m pytest tests/ -v

Note: tests that require raw sockets (scapy) are mocked,
so this suite runs WITHOUT sudo/root privileges.
"""

import socket
from unittest.mock import patch, MagicMock
import pytest

from scanner.utils import get_service
from scanner.udp import get_udp_service
from scanner.os_detect import get_os_from_ttl, fingerprint_os
from scanner.core import scan_port


# ---------------------------------------------------------------------------
# scanner.utils — TCP service name mapping
# ---------------------------------------------------------------------------

class TestGetService:

    def test_known_tcp_ports(self):
        assert get_service(22) == "SSH"
        assert get_service(80) == "HTTP"
        assert get_service(443) == "HTTPS"
        assert get_service(445) == "SMB"

    def test_unknown_tcp_port_returns_unknown(self):
        assert get_service(54321) == "Unknown"

    def test_port_zero_returns_unknown(self):
        assert get_service(0) == "Unknown"


# ---------------------------------------------------------------------------
# scanner.udp — UDP service name mapping
# ---------------------------------------------------------------------------

class TestGetUdpService:

    def test_known_udp_ports(self):
        assert get_udp_service(53) == "DNS"
        assert get_udp_service(123) == "NTP"
        assert get_udp_service(161) == "SNMP"

    def test_unknown_udp_port_returns_unknown(self):
        assert get_udp_service(9999) == "Unknown"


# ---------------------------------------------------------------------------
# scanner.os_detect — TTL -> OS mapping
# ---------------------------------------------------------------------------

class TestGetOsFromTtl:

    def test_linux_ttl(self):
        # Common Linux default TTL is 64
        assert get_os_from_ttl(64) == "Linux / Android"
        assert get_os_from_ttl(60) == "Linux / Android"  # decremented by hops

    def test_windows_ttl(self):
        # Common Windows default TTL is 128
        assert get_os_from_ttl(128) == "Windows"
        assert get_os_from_ttl(120) == "Windows"

    def test_network_device_ttl(self):
        # Cisco/network gear default TTL is 255
        assert get_os_from_ttl(150) == "Cisco / Network Device"

    def test_solaris_aix_ttl(self):
        assert get_os_from_ttl(250) == "Solaris / AIX"

    def test_ttl_boundary_values(self):
        assert get_os_from_ttl(0) == "Linux / Android"
        assert get_os_from_ttl(255) == "Solaris / AIX"


class TestFingerprintOs:

    @patch("scanner.os_detect.scapy.sr1")
    def test_fingerprint_with_response(self, mock_sr1):
        """Simulate an ICMP reply with TTL=64 (Linux)."""
        mock_response = MagicMock()
        mock_response.ttl = 64
        mock_sr1.return_value = mock_response

        result = fingerprint_os("192.168.1.1")

        assert result["ttl"] == 64
        assert result["os_guess"] == "Linux / Android"
        assert result["confidence"] == "high"

    @patch("scanner.os_detect.scapy.sr1")
    def test_fingerprint_no_response(self, mock_sr1):
        """Simulate a host that doesn't respond to ICMP (filtered/down)."""
        mock_sr1.return_value = None

        result = fingerprint_os("192.168.1.250")

        assert result["ttl"] is None
        assert result["os_guess"] == "Unknown"
        assert result["confidence"] == "low"

    @patch("scanner.os_detect.scapy.sr1")
    def test_fingerprint_windows_ttl(self, mock_sr1):
        mock_response = MagicMock()
        mock_response.ttl = 128
        mock_sr1.return_value = mock_response

        result = fingerprint_os("192.168.1.4")

        assert result["os_guess"] == "Windows"
        assert result["confidence"] == "high"


# ---------------------------------------------------------------------------
# scanner.core — TCP connect scan
# ---------------------------------------------------------------------------

class TestScanPort:

    @patch("scanner.core.socket.socket")
    def test_open_port_returns_true(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0  # 0 = success/open
        mock_socket_cls.return_value = mock_sock

        assert scan_port("192.168.1.1", 80) is True
        mock_sock.close.assert_called_once()

    @patch("scanner.core.socket.socket")
    def test_closed_port_returns_false(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # ECONNREFUSED
        mock_socket_cls.return_value = mock_sock

        assert scan_port("192.168.1.1", 9999) is False

    @patch("scanner.core.socket.socket")
    def test_exception_returns_false(self, mock_socket_cls):
        mock_socket_cls.side_effect = socket.error("network unreachable")

        assert scan_port("10.0.0.1", 80) is False


# ---------------------------------------------------------------------------
# Integration-style sanity check (no network, no sudo)
# ---------------------------------------------------------------------------

class TestServiceMappingConsistency:
    """Make sure TCP and UDP service maps don't silently collide
    in ways that would confuse JSON output."""

    def test_dns_present_in_both_maps(self):
        # Port 53 is DNS on both TCP and UDP — should be labeled consistently
        assert get_service(53) == "DNS"
        assert get_udp_service(53) == "DNS"
