"""Parsing and validating monitored targets: "host", "host:port", "[ipv6]:port"."""

from __future__ import annotations

import ipaddress
import re

DEFAULT_PORT = 443

# Permissive enough for internal names (single labels, underscores), strict
# enough to reject anything that isn't a plausible hostname.
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,62})"
_HOSTNAME = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*$")


def _parse_port(value: str) -> int:
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise ValueError(f"invalid port {value!r}")
    return int(value)


def parse_target(raw: str) -> tuple[str, int]:
    """Split and validate a target. Raises ValueError with a readable reason."""
    text = raw.strip()
    if not text:
        raise ValueError("empty target")

    if text.startswith("["):
        host, closed, rest = text[1:].partition("]")
        if not closed or (rest and not rest.startswith(":")):
            raise ValueError(f"invalid target {raw!r}; write IPv6 addresses as [addr]:port")
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise ValueError(f"invalid IPv6 address {host!r}") from None
        port = _parse_port(rest[1:]) if rest else DEFAULT_PORT
        return host.lower(), port

    host, sep, port_text = text.rpartition(":")
    if not sep:
        host, port = text, DEFAULT_PORT
    elif ":" in host:
        raise ValueError(f"invalid target {raw!r}; write IPv6 addresses as [addr]:port")
    else:
        port = _parse_port(port_text)

    host = host.lower().rstrip(".")
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if not _HOSTNAME.match(host):
            raise ValueError(f"invalid hostname {host!r}") from None
    return host, port


def format_target(hostname: str, port: int) -> str:
    return f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"
