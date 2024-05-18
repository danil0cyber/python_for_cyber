"""
Test for network_scanner
"""

from typing import List, Tuple, Optional, Any
import logging
import pytest  # pylint: disable=E0401
from scapy.all import IP, TCP, UDP, DNS  # pylint: disable=E0611
from pre_matrix.reconnaissance.network_scanner import (
    syn_scan,
    dns_scan,
    ip_range,
    scan_ip_block,
)


# Mocking scapy's sr function to control its behavior during tests
@pytest.fixture(autouse=True)
def mock_sr_func(monkeypatch) -> None:
    """Fixture to mock scapy's sr function for testing purposes.

    Args:
        monkeypatch (pytest.MonkeyPatch): The monkeypatch fixture.
    """

    def mock_sr(*args: Any) -> Tuple[List[Tuple[Any, Any]], List]:
        """Mock function to simulate different network responses.

        Args:
            *args: Positional arguments.

        Returns:
            Tuple[List[Tuple[Any, Any]], List]: Mocked response packets.
        """
        packet = args[0]
        if packet.haslayer(TCP):
            if 80 in packet[TCP].dport:
                return (
                    [
                        (
                            packet,
                            IP(src=packet[IP].dst)
                            / TCP(
                                sport=packet[TCP].dport,
                                dport=packet[TCP].sport,
                                flags="SA",
                            ),
                        )
                    ],
                    [],
                )
            return ([], [])
        if packet.haslayer(UDP):
            if packet[UDP].dport == 53:
                return (
                    [
                        (
                            packet,
                            IP(src=packet[IP].dst)
                            / UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
                            / DNS(
                                id=packet[DNS].id,
                                qr=1,
                                qdcount=1,
                                ancount=1,
                                qd=packet[DNS].qd,
                            ),
                        )
                    ],
                    [],
                )
            return ([], [])
        return ([], [])

    monkeypatch.setattr("scapy.all.sr", mock_sr)


# Test for syn_scan function
@pytest.mark.parametrize(
    "target_host, ports, expected_info_log",
    [
        ("192.168.1.1", [80], "Open ports at 192.168.1.1"),
        ("192.168.1.1", [9999], "Open ports at 192.168.1.1"),
        ("192.168.1.1", None, "Open ports at 192.168.1.1"),
    ],
)
def test_syn_scan(
    caplog: pytest.LogCaptureFixture,
    target_host: str,
    ports: Optional[List[int]],
    expected_info_log: str,
) -> None:
    """Test the syn_scan function.

    Args:
        caplog (pytest.LogCaptureFixture): Capture log fixture.
        target_host (str): Target IP address.
        ports (Optional[List[int]]): List of ports to scan.
        expected_info_log (str): Expected log message.
    """
    with caplog.at_level(logging.INFO):  # Ensure INFO level logging is captured
        syn_scan(target_host, ports)
    assert expected_info_log in caplog.text


# Test for dns_scan function
@pytest.mark.parametrize(
    "target_host, query, expected_info_log",
    [
        ("192.168.1.1", "example.com", "DNS Server at 192.168.1.1"),
        ("192.168.1.1", "nonexistent.domain", "DNS Server at 192.168.1.1"),
    ],
)
def test_dns_scan(
    caplog: pytest.LogCaptureFixture,
    target_host: str,
    query: str,
    expected_info_log: str,
) -> None:
    """Test the dns_scan function.

    Args:
        caplog (pytest.LogCaptureFixture): Capture log fixture.
        target_host (str): Target IP address.
        query (str): DNS query name.
        expected_info_log (str): Expected log message.
    """
    with caplog.at_level(logging.DEBUG):  # Ensure DEBUG level logging is captured
        dns_scan(target_host, query)
    print(caplog.text)  # Print the captured logs for debugging
    assert expected_info_log in caplog.text


# Test for ip_range function
@pytest.mark.parametrize(
    "start_ip, end_ip, expected_range",
    [
        (
            "192.168.1.1",
            "192.168.1.5",
            ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"],
        ),
        (
            "192.168.1.254",
            "192.168.2.1",
            ["192.168.1.254", "192.168.1.255", "192.168.2.0", "192.168.2.1"],
        ),
    ],
)
def test_ip_range(start_ip: str, end_ip: str, expected_range: List[str]) -> None:
    """
    Test the ip_range function.

    Args:
        start_ip (str): Starting IP address.
        end_ip (str): Ending IP address.
        expected_range (List[str]): Expected list of IP addresses.
    """
    result = ip_range(start_ip, end_ip)
    assert result == expected_range


# Test for scan_ip_block function
@pytest.mark.parametrize(
    "start_ip, end_ip, expected_logs",
    [
        (
            "192.168.1.1",
            "192.168.1.1",
            [
                "Scanning host 192.168.1.1",
                "Open ports at 192.168.1.1",
                "DNS Server at 192.168.1.1",
            ],
        ),
    ],
)
def test_scan_ip_block(
    caplog: pytest.LogCaptureFixture,
    start_ip: str,
    end_ip: str,
    expected_logs: List[str],
) -> None:
    """
    Test the scan_ip_block function.

    Args:
        caplog (pytest.LogCaptureFixture): Capture log fixture.
        start_ip (str): Starting IP address.
        end_ip (str): Ending IP address.
        expected_logs (List[str]): Expected log messages.
    """
    with caplog.at_level(logging.INFO):  # Ensure INFO level logging is captured
        scan_ip_block(start_ip, end_ip)
    for log in expected_logs:
        assert log in caplog.text
