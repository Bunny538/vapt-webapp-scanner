"""Small helpers: scope guard and snippets."""
from __future__ import annotations

import ipaddress
import socket


def is_local_host(host: str | None) -> bool:
    """True for loopback / private / link-local targets (safe lab ranges)."""
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            ips = [ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(host, None)]
        except OSError:
            return False
    return bool(ips) and all(ip.is_loopback or ip.is_private or ip.is_link_local for ip in ips)


def snippet(text: str, needle: str, radius: int = 70) -> str:
    i = text.find(needle)
    if i < 0:
        return ""
    start = max(0, i - radius)
    return text[start : i + len(needle) + radius].replace("\n", " ").strip()
