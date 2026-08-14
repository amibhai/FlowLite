"""IP address scope classification.

The previous implementation checked five RFC 1918-ish ranges and labelled
everything else "public" -- so carrier-grade NAT space, link-local, multicast,
benchmarking and documentation ranges were all reported as public internet
destinations, which is exactly backwards for anomaly detection.

This classifier covers the full IANA special-purpose registries for IPv4 and
IPv6 and returns one of :data:`SCOPES`.
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Tuple

__all__ = ["classify_address", "is_private", "SCOPES"]

SCOPES = (
    "private",
    "public",
    "loopback",
    "link-local",
    "multicast",
    "broadcast",
    "cgnat",
    "reserved",
    "unspecified",
    "invalid",
)

# Ordered most-specific first; the first containing network wins.
_V4_RANGES: List[Tuple[ipaddress.IPv4Network, str]] = [
    (ipaddress.ip_network("0.0.0.0/32"), "unspecified"),
    (ipaddress.ip_network("127.0.0.0/8"), "loopback"),
    (ipaddress.ip_network("169.254.0.0/16"), "link-local"),
    (ipaddress.ip_network("100.64.0.0/10"), "cgnat"),
    (ipaddress.ip_network("10.0.0.0/8"), "private"),
    (ipaddress.ip_network("172.16.0.0/12"), "private"),
    (ipaddress.ip_network("192.168.0.0/16"), "private"),
    (ipaddress.ip_network("192.0.0.0/24"), "reserved"),
    (ipaddress.ip_network("192.0.2.0/24"), "reserved"),
    (ipaddress.ip_network("198.51.100.0/24"), "reserved"),
    (ipaddress.ip_network("203.0.113.0/24"), "reserved"),
    (ipaddress.ip_network("198.18.0.0/15"), "reserved"),
    (ipaddress.ip_network("192.88.99.0/24"), "reserved"),
    (ipaddress.ip_network("224.0.0.0/4"), "multicast"),
    (ipaddress.ip_network("255.255.255.255/32"), "broadcast"),
    (ipaddress.ip_network("240.0.0.0/4"), "reserved"),
]

_V6_RANGES: List[Tuple[ipaddress.IPv6Network, str]] = [
    (ipaddress.ip_network("::/128"), "unspecified"),
    (ipaddress.ip_network("::1/128"), "loopback"),
    (ipaddress.ip_network("fe80::/10"), "link-local"),
    (ipaddress.ip_network("fc00::/7"), "private"),
    (ipaddress.ip_network("ff00::/8"), "multicast"),
    (ipaddress.ip_network("2001:db8::/32"), "reserved"),
    (ipaddress.ip_network("2001::/23"), "reserved"),
    (ipaddress.ip_network("100::/64"), "reserved"),
    (ipaddress.ip_network("::ffff:0:0/96"), "reserved"),
]

_PRIVATE_SCOPES = frozenset({"private", "loopback", "link-local", "cgnat", "unspecified"})

# Address strings repeat constantly in real traffic, and ipaddress parsing is
# comparatively expensive, so results are memoised with a hard ceiling.
_CACHE: Dict[str, str] = {}
_CACHE_LIMIT = 100_000


def classify_address(ip: str) -> str:
    """Return the scope of ``ip`` -- one of :data:`SCOPES`."""
    cached = _CACHE.get(ip)
    if cached is not None:
        return cached
    scope = _classify_uncached(ip)
    if len(_CACHE) < _CACHE_LIMIT:
        _CACHE[ip] = scope
    return scope


def _classify_uncached(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.version == 4:
        for network, scope in _V4_RANGES:
            if addr in network:
                return scope
        return "public"
    for network6, scope in _V6_RANGES:
        if addr in network6:
            return scope
    return "public"


def is_private(ip: str) -> bool:
    """True when ``ip`` is not routable on the public internet."""
    return classify_address(ip) in _PRIVATE_SCOPES
