"""SentinelX SSRF Guard (Server-Side Request Forgery Defense)
Validates all outbound target URLs against private, loopback, link-local,
cloud metadata, and reserved networks.
"""

import ipaddress
import socket
from urllib.parse import urlparse
from backend.app.core.exceptions import SSRFViolationError
from backend.app.core.logging import logger

# Blocked IP networks
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),          # IPv4 loopback
    ipaddress.ip_network("10.0.0.0/8"),           # RFC 1918 Private
    ipaddress.ip_network("172.16.0.0/12"),        # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),       # RFC 1918 Private
    ipaddress.ip_network("169.254.0.0/16"),       # Link-local / Cloud metadata (169.254.169.254)
    ipaddress.ip_network("0.0.0.0/8"),            # Current network
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
    ipaddress.ip_network("::1/128"),              # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),             # IPv6 Unique Local Address
    ipaddress.ip_network("fe80::/10"),            # IPv6 Link-local
    ipaddress.ip_network("ff00::/8"),             # IPv6 Multicast
]


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Checks if an IP address belongs to any blocked or private network."""
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return True
    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True
    return False


def validate_url_for_outbound(url: str) -> str:
    """Validates that a URL does not target loopback, private, or metadata services.
    Raises SSRFViolationError if unsafe.
    """
    if not url or not isinstance(url, str):
        raise SSRFViolationError("URL cannot be empty")

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise SSRFViolationError(f"Unsupported URL scheme '{scheme}'. Only http and https permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFViolationError("URL missing valid hostname")

    # Clean hostname
    hostname = hostname.strip().lower()

    # Block well-known metadata / localhost domain aliases
    blocked_hostnames = {
        "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
        "metadata.google.internal", "instance-data", "metadata"
    }
    if hostname in blocked_hostnames or hostname.endswith(".localhost"):
        raise SSRFViolationError(f"Hostname '{hostname}' resolves to blocked internal namespace")

    # Check if hostname is direct IP literal
    try:
        ip = ipaddress.ip_address(hostname)
        if is_ip_blocked(ip):
            raise SSRFViolationError(f"Direct IP '{hostname}' belongs to a blocked internal or private network")
        return url
    except ValueError:
        pass  # Not an IP literal, proceed to DNS resolution

    # Resolve hostname to all associated IPs to check DNS rebinding
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = set()
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            resolved_ips.add(ip_str)

        if not resolved_ips:
            raise SSRFViolationError(f"Hostname '{hostname}' could not be resolved")

        for ip_str in resolved_ips:
            ip = ipaddress.ip_address(ip_str)
            if is_ip_blocked(ip):
                raise SSRFViolationError(f"Hostname '{hostname}' resolved to blocked internal IP '{ip_str}'")

    except socket.gaierror as e:
        logger.warning(f"DNS resolution failure for '{hostname}': {e}")
        # Allow scan to continue as unresolvable / offline target rather than crashing,
        # but mark as unresolvable
    except SSRFViolationError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in SSRF check for '{hostname}': {e}")
        raise SSRFViolationError(f"SSRF inspection error: {e}")

    return url
