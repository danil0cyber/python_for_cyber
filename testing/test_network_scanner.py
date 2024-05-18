"""
Test for network_scanner
"""

import contextlib
from typing import List, Tuple, Optional, Any
import logging
import pytest  # pylint: disable=E0401
from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR  # pylint: disable=E0611
from pre_matrix.reconnaissance.network_scanner import (
    syn_scan,
    dns_scan,
    ip_range,
    scan_ip_block,
)


class CustomTestException(Exception):
    """Custom exception class for testing purposes."""


@pytest.fixture(autouse=True)
def configure_logging() -> None:
    """Fixture to configure logging for the tests."""
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger("pre_matrix.reconnaissance.network_scanner")
    logger.setLevel(logging.DEBUG)


def mock_sr_syn_scan(*_args: Any, **_kwargs: Any) -> Tuple[List[Tuple[Any, Any]], List]:
    """Mock function to simulate SYN scan responses.

    Args:
        *_args: Positional arguments.
        *_kwargs: Keyword arguments.

    Returns:
        Tuple[List[Tuple[Any, Any]], List]: Mocked response packets.
    """
    pkt_sent = IP(dst="192.168.1.1") / TCP(sport=5555, dport=80, flags="S")
    pkt_received = IP(src="192.168.1.1") / TCP(sport=80, dport=5555, flags="SA")
    return [((pkt_sent, pkt_received))], []


def mock_sr_dns_scan(*_args: Any, **_kwargs: Any) -> Tuple[List[Tuple[Any, Any]], List]:
    """Mock function to simulate DNS scan responses.

    Args:
        *_args: Positional arguments.
        *_kwargs: Keyword arguments.

    Returns:
        Tuple[List[Tuple[Any, Any]], List]: Mocked response packets.
    """
    pkt_sent = (
        IP(dst="192.168.1.1")
        / UDP(sport=5555, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    pkt_received = (
        IP(src="192.168.1.1")
        / UDP(sport=53, dport=5555)
        / DNS(
            rd=1,
            qr=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(rrname="example.com", ttl=10),
        )
    )
    return [((pkt_sent, pkt_received))], []


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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test the syn_scan function.

    Args:
        caplog (pytest.LogCaptureFixture): Capture log fixture.
        target_host (str): Target IP address.
        ports (Optional[List[int]]): List of ports to scan.
        expected_info_log (str): Expected log message.
        monkeypatch (pytest.MonkeyPatch): The monkeypatch fixture.
    """
    monkeypatch.setattr(
        "pre_matrix.reconnaissance.network_scanner.sr", mock_sr_syn_scan
    )
    with caplog.at_level(logging.INFO):  # Ensure INFO level logging is captured
        syn_scan(target_host, ports)
    assert expected_info_log in caplog.text
    assert "80" in caplog.text  # Ensure that the specific port is logged


@pytest.mark.parametrize(
    "target_host, exception_message",
    [
        ("192.168.1.1", "An error occurred during SYN scan: Test Exception"),
    ],
)
def test_syn_scan_exception(
    caplog: pytest.LogCaptureFixture,
    target_host: str,
    exception_message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test the syn_scan function for exception handling.

    Args:
        caplog (pytest.LogCaptureFixture): Capture log fixture.
        target_host (str): Target IP address.
        exception_message (str): Expected exception log message.
        monkeypatch (pytest.MonkeyPatch): The monkeypatch fixture.
    """

    def mock_sr_local(
        *_args: Any, **_kwargs: Any
    ) -> Tuple[List[Tuple[Any, Any]], List]:
        raise CustomTestException("Test Exception")

    monkeypatch.setattr("pre_matrix.reconnaissance.network_scanner.sr", mock_sr_local)

    with caplog.at_level(logging.ERROR):  # Ensure ERROR level logging is captured
        with contextlib.suppress(CustomTestException):
            syn_scan(target_host)
    # Ensure that the exception is logged
    assert exception_message in caplog.text


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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test the dns_scan function.

    Args:
        caplog (pytest.LogCaptureFixture): Capture log fixture.
        target_host (str): Target IP address.
        query (str): DNS query name.
        expected_info_log (str): Expected log message.
        monkeypatch (pytest.MonkeyPatch): The monkeypatch fixture.
    """
    monkeypatch.setattr(
        "pre_matrix.reconnaissance.network_scanner.sr", mock_sr_dns_scan
    )
    with caplog.at_level(logging.DEBUG):  # Ensure DEBUG level logging is captured
        dns_scan(target_host, query)
    assert expected_info_log in caplog.text
    assert (
        "Received DNS response from" in caplog.text
    )  # Ensure the DNS response is logged


@pytest.mark.parametrize(
    "target_host, exception_message",
    [
        ("192.168.1.1", "An error occurred during DNS scan: Test Exception"),
    ],
)
def test_dns_scan_exception(
    caplog: pytest.LogCaptureFixture,
    target_host: str,
    exception_message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test the dns_scan function for exception handling.

    Args:
        caplog (pytest.LogCaptureFixture): Capture log fixture.
        target_host (str): Target IP address.
        exception_message (str): Expected exception log message.
        monkeypatch (pytest.MonkeyPatch): The monkeypatch fixture.
    """

    def mock_sr_local(
        *_args: Any, **_kwargs: Any
    ) -> Tuple[List[Tuple[Any, Any]], List]:
        raise CustomTestException("Test Exception")

    monkeypatch.setattr("pre_matrix.reconnaissance.network_scanner.sr", mock_sr_local)

    with caplog.at_level(logging.ERROR):  # Ensure ERROR level logging is captured
        with contextlib.suppress(CustomTestException):
            dns_scan(target_host)
    # Ensure that the exception is logged
    assert exception_message in caplog.text


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
    """Test the ip_range function.

    Args:
        start_ip (str): Starting IP address.
        end_ip (str): Ending IP address.
        expected_range (List[str]): Expected list of IP addresses.
    """
    result = ip_range(start_ip, end_ip)
    assert result == expected_range


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
    """Test the scan_ip_block function.

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
