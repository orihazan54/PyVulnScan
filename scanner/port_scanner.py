"""
Port Scanner Module
-------------------
This module is responsible for scanning network ports on a target host.
It uses multi-threading for fast, concurrent port scanning.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List


# Common ports to scan by default - the "top 20" most relevant for security assessment
COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # RPCbind
    135,   # MSRPC
    139,   # NetBIOS
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    993,   # IMAPS
    995,   # POP3S
    1723,  # PPTP
    3306,  # MySQL
    3389,  # RDP
    5900,  # VNC
    8080,  # HTTP-Proxy
]


def scan_port(target: str, port: int, timeout: float = 1.0) -> tuple[int, bool]:
    """
    Attempts to connect to a single port on the target host.
    
    Args:
        target: The IP address or hostname to scan
        port: The port number to check (0-65535)
        timeout: How long to wait for a response, in seconds
    
    Returns:
        A tuple (port, is_open) - the port number and whether it's open.
        We return the port too so we know which result belongs to which port
        when running concurrently.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        result = sock.connect_ex((target, port))
        return (port, result == 0)
    except (socket.gaierror, socket.error):
        return (port, False)
    finally:
        sock.close()


def scan_ports(
    target: str,
    ports: List[int] = None,
    timeout: float = 1.0,
    max_workers: int = 100
) -> List[int]:
    """
    Scans multiple ports concurrently using a thread pool.
    
    Args:
        target: The IP address or hostname to scan
        ports: List of ports to scan. Defaults to COMMON_PORTS.
        timeout: Timeout per port, in seconds
        max_workers: Maximum number of concurrent threads
    
    Returns:
        Sorted list of open ports.
    """
    # Use default port list if none provided
    if ports is None:
        ports = COMMON_PORTS
    
    print(f"[*] Starting scan on {target}")
    print(f"[*] Scanning {len(ports)} ports with {max_workers} threads...")
    
    open_ports = []
    
    # ThreadPoolExecutor manages a pool of worker threads for us
    # The 'with' statement ensures threads are properly cleaned up
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all scan tasks to the pool - they start running immediately
        # 'futures' is a dict mapping each Future object to its port
        futures = {
            executor.submit(scan_port, target, port, timeout): port
            for port in ports
        }
        
        # as_completed yields futures as they finish, in completion order
        # (NOT in submission order - that's the whole point!)
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                print(f"[+] Port {port} is OPEN")
                open_ports.append(port)
    
    # Sort because threads finish in unpredictable order
    open_ports.sort()
    print(f"[*] Scan complete. Found {len(open_ports)} open ports.")
    return open_ports


if __name__ == "__main__":
    target = "scanme.nmap.org"
    open_ports = scan_ports(target)
    print(f"\nOpen ports: {open_ports}")