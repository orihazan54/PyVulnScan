"""
Service Detector Module
-----------------------
This module performs banner grabbing on open ports to identify
the services running and their versions.
"""

import socket
import re
from dataclasses import dataclass
from typing import Optional


# Mapping of common ports to their typical service names
# This is just a fallback - we prefer actual banner-based detection
COMMON_PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Proxy",
}


@dataclass
class ServiceInfo:
    """
    Holds information about a detected service.
    
    Using @dataclass is a clean Python pattern for "data containers"
    that auto-generates __init__, __repr__, and __eq__ methods.
    """
    port: int
    service: str = "unknown"
    product: Optional[str] = None      # e.g., "OpenSSH", "Apache"
    version: Optional[str] = None      # e.g., "8.2p1", "2.4.41"
    banner: Optional[str] = None       # The raw banner string
    
    def __str__(self) -> str:
        """Pretty print for human-readable output."""
        parts = [f"Port {self.port}", self.service]
        if self.product:
            product_str = self.product
            if self.version:
                product_str += f" {self.version}"
            parts.append(f"({product_str})")
        return " - ".join(parts)


def grab_banner_passive(target: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """
    Grabs a banner by simply connecting and waiting for the server to send data.
    Works for services that send a greeting on connection (SSH, FTP, SMTP, etc.)
    
    Args:
        target: The hostname or IP
        port: The port to connect to
        timeout: How long to wait for the banner
    
    Returns:
        The banner as a string, or None if no banner received.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        sock.connect((target, port))
        # recv blocks until data arrives or timeout
        # 1024 bytes is more than enough for a banner
        banner_bytes = sock.recv(1024)
        # decode bytes to string, replace any invalid UTF-8 chars
        # strip() removes the trailing \r\n that most banners have
        return banner_bytes.decode(errors="replace").strip()
    except (socket.timeout, socket.error):
        return None
    finally:
        sock.close()


def grab_banner_http(target: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """
    Grabs a banner from an HTTP service by sending a GET request
    and parsing the Server header from the response.
    
    HTTP servers don't send a banner on connect - we need to ask first.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        sock.connect((target, port))
        
        # Build a minimal HTTP/1.1 request
        # Host header is required in HTTP/1.1
        # \r\n\r\n marks end of headers
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"User-Agent: PyVulnScan/1.0\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())
        
        # Read the response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            # We only need the headers, not the body
            if b"\r\n\r\n" in response:
                break
        
        # Decode and look for Server header
        response_str = response.decode(errors="replace")
        # Use regex to extract the Server header value
        match = re.search(r"^Server:\s*(.+)$", response_str, re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None
    except (socket.timeout, socket.error):
        return None
    finally:
        sock.close()


def parse_banner(banner: str) -> tuple[Optional[str], Optional[str]]:
    """
    Parses a raw banner string to extract product name and version.
    
    Examples:
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" -> ("OpenSSH", "8.2p1")
        "Apache/2.4.41 (Ubuntu)" -> ("Apache", "2.4.41")
        "ProFTPD 1.3.5 Server" -> ("ProFTPD", "1.3.5")
    
    Returns:
        Tuple of (product, version), either can be None if not found.
    """
    if not banner:
        return (None, None)
    
    # Pattern 1: SSH banners "SSH-2.0-OpenSSH_8.2p1"
    ssh_match = re.search(r"SSH-[\d.]+-([A-Za-z]+)[_\-]?([\d.\w]+)?", banner)
    if ssh_match:
        return (ssh_match.group(1), ssh_match.group(2))
    
    # Pattern 2: HTTP-style "Apache/2.4.41" or "nginx/1.18.0"
    http_match = re.search(r"([A-Za-z][A-Za-z0-9\-_]+)/([\d.]+)", banner)
    if http_match:
        return (http_match.group(1), http_match.group(2))
    
    # Pattern 3: FTP-style "220 ProFTPD 1.3.5"
    ftp_match = re.search(r"\b([A-Z][A-Za-z]+)\s+([\d.]+)", banner)
    if ftp_match:
        return (ftp_match.group(1), ftp_match.group(2))
    
    # Couldn't parse - return what we have
    return (None, None)


def detect_service(target: str, port: int, timeout: float = 3.0) -> ServiceInfo:
    """
    Performs full service detection on a single port.
    
    Strategy:
        1. For HTTP ports (80, 8080, etc) - send HTTP request
        2. For HTTPS - mark as HTTPS (full TLS handshake is complex)
        3. For everything else - try passive banner grab
        4. Fall back to common-port lookup if nothing detected
    
    Returns:
        A ServiceInfo object with whatever was detected.
    """
    info = ServiceInfo(port=port)
    
    # Default service name from common-ports list
    info.service = COMMON_PORT_SERVICES.get(port, "unknown")
    
    # HTTP ports - need to send GET request
    if port in (80, 8080, 8000, 8888):
        banner = grab_banner_http(target, port, timeout)
        if banner:
            info.banner = banner
            product, version = parse_banner(banner)
            info.product = product
            info.version = version
        return info
    
    # HTTPS - we don't do TLS in this basic version
    if port in (443, 8443):
        info.service = "HTTPS"
        return info
    
    # Everything else - passive banner grab
    banner = grab_banner_passive(target, port, timeout)
    if banner:
        info.banner = banner
        product, version = parse_banner(banner)
        info.product = product
        info.version = version
    
    return info


if __name__ == "__main__":
    # Test on scanme.nmap.org's open ports
    target = "scanme.nmap.org"
    test_ports = [21, 22, 80]
    
    print(f"[*] Detecting services on {target}\n")
    for port in test_ports:
        info = detect_service(target, port)
        print(info)
        if info.banner:
            print(f"   Banner: {info.banner[:100]}")  # First 100 chars
        print()