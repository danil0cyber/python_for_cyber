"""
A network scanner using Scapy to find open ports and DNS servers on a target.

Library: https://scapy.readthedocs.io/en/latest/introduction.html
"""

import logging
from typing import List, Optional
from scapy.all import sr, IP, TCP, UDP, DNS, DNSQR  # pylint: disable=E0611

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

DEFAULT_DNS_QUERY: str = "nmap.org"


## SYN SCAN ##
def syn_scan(
    target_host: str,
    ports: Optional[List[int]] = None,
    verbose: int = 0,
    timeout: int = 5,
) -> None:
    """
    Perform a SYN scan on the specified host to identify open ports.

    Args:
        target_host (str): Target IP address.
        ports (Optional[List[int]], optional): List of ports to scan. Defaults to a predefined list.
        verbose (int, optional): Verbosity level. Defaults to 0.
        timeout (int, optional): Packet response timeout. Defaults to 5.
    """
    if ports is None:
        # List of common ports to scan
        ports = [21, 22, 23, 25, 53, 80, 443, 445, 8080, 8443, 30000]

    try:
        # Send SYN packets to the target host on specified ports
        answered, _ = sr(
            IP(dst=target_host) / TCP(sport=5555, dport=ports, flags="S"),
            timeout=timeout,
            verbose=verbose,
        )
        logger.info("Open ports at %s", target_host)
        for send_packet, received_packet in answered:
            # Check if the port is open by matching sent and received packet ports
            if send_packet[TCP].dport == received_packet[TCP].sport:
                logger.info(send_packet[TCP].dport)
    except Exception as e:  # pylint: disable=W0718
        logger.error("An error occurred during SYN scan: %s", e)
        raise  # Ensure the exception propagates


## DNS SCAN ##
def dns_scan(
    target_host: str, query: str = DEFAULT_DNS_QUERY, verbose: int = 0, timeout: int = 5
) -> None:
    """
    Perform a DNS scan on the specified host.

    Args:
        target_host (str): Target IP address.
        query (str, optional): DNS query name. Defaults to DEFAULT_DNS_QUERY.
        verbose (int, optional): Verbosity level. Defaults to 0.
        timeout (int, optional): Packet response timeout. Defaults to 5.
    """
    try:
        # Send a DNS query to the target host
        answered, _ = sr(
            IP(dst=target_host)
            / UDP(sport=5555, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=query)),
            timeout=timeout,
            verbose=verbose,
        )
        logger.info("DNS Server at %s", target_host)
        for _, received_packet in answered:
            # Check if the response contains a DNS layer
            if received_packet.haslayer(DNS):
                logger.info("Received DNS response from %s", target_host)
    except Exception as e:  # pylint: disable=W0718
        logger.error("An error occurred during DNS scan: %s", e)
        raise  # Ensure the exception propagates


## IP BLOCK SCAN ##
def ip_range(start_ip: str, end_ip: str) -> List[str]:
    """
    Generate a list of IP addresses between start_ip and end_ip, inclusive.

    Args:
        start_ip (str): Starting IP address.
        end_ip (str): Ending IP address.

    Returns:
        List[str]: List of IP addresses within the specified range.
    """
    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))

    # Initialize a temporary variable with the start IP and an empty list for the IP range
    temp = start[:]
    ip_list = []

    # Loop until the temporary IP address matches the end IP address
    while temp != end:
        ip_list.append(".".join(map(str, temp)))
        # Increment the last octet of the IP address
        temp[3] += 1
        # Handle the carry over for each octet
        for i in (3, 2, 1, 0):
            if temp[i] == 256:
                temp[i] = 0
                if i > 0:
                    temp[i - 1] += 1

    # Append the end IP address to the list
    ip_list.append(".".join(map(str, end)))

    return ip_list


def scan_ip_block(start_ip: str, end_ip: str) -> None:
    """
    Scan a range of IP addresses between start_ip and end_ip, inclusive.

    Args:
        start_ip (str): Starting IP address.
        end_ip (str): Ending IP address.
    """
    ip_list = ip_range(start_ip, end_ip)
    for ip in ip_list:
        logger.info("Scanning host %s", ip)
        syn_scan(ip)
        dns_scan(ip)


if __name__ == "__main__":
    # Perform SYN scan on Google's public DNS server
    target_host_1: str = "8.8.8.8"
    syn_scan(target_host_1)

    # Perform DNS scan on Nmap's test server
    target_host_2: str = "45.33.32.156"
    dns_scan(target_host_2)

    # Perform scans on the local network IP range
    target_start_ip: str = "192.168.1.1"
    target_end_ip: str = "192.168.1.10"  # Example local IP range
    scan_ip_block(target_start_ip, target_end_ip)
