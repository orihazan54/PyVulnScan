"""
Port Scanner Module
-------------------
This module is responsible for scanning network ports on a target host.
It identifies which ports are open by attempting TCP connections.
"""

import socket
from typing import List


def scan_port(target: str, port: int, timeout: float = 1.0) -> bool:
    """
    Attempts to connect to a single port on the target host.
    
    Args:
        target: The IP address or hostname to scan (e.g., "scanme.nmap.org")
        port: The port number to check (0-65535)
        timeout: How long to wait for a response, in seconds
    
    Returns:
        True if the port is open, False otherwise.
    """
    # Create a TCP socket
    # AF_INET = IPv4, SOCK_STREAM = TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Set timeout - so we don't wait forever on closed/filtered ports
    sock.settimeout(timeout)
    
    try:
        # connect_ex returns 0 if successful, error code otherwise
        result = sock.connect_ex((target, port))
        return result == 0
    except socket.gaierror:
        # gaierror = "get address info" error - hostname couldn't be resolved
        print(f"[!] Hostname '{target}' could not be resolved")
        return False
    except socket.error as e:
        # Generic socket error
        print(f"[!] Socket error: {e}")
        return False
    finally:
        # Always close the socket, even if an exception occurred
        sock.close()


def scan_ports(target: str, ports: List[int], timeout: float = 1.0) -> List[int]:
    """
    Scans a list of ports on the target host.
    
    Args:
        target: The IP address or hostname to scan
        ports: List of port numbers to check
        timeout: Timeout per port, in seconds
    
    Returns:
        List of open ports.
    """
    open_ports = []
    
    print(f"[*] Starting scan on {target}")
    print(f"[*] Scanning {len(ports)} ports...")
    
    for port in ports:
        if scan_port(target, port, timeout):
            print(f"[+] Port {port} is OPEN")
            open_ports.append(port)
    
    print(f"[*] Scan complete. Found {len(open_ports)} open ports.")
    return open_ports


# This block runs only if you execute this file directly
# (e.g., python scanner/port_scanner.py)
# It doesn't run when the file is imported as a module
if __name__ == "__main__":
    # Test with common ports on scanme.nmap.org
    # This is a server explicitly set up for testing scanners
    target = "scanme.nmap.org"
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
    
    open_ports = scan_ports(target, common_ports)
    print(f"\nOpen ports: {open_ports}")