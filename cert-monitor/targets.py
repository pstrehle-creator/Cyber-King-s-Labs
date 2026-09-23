"""Parsing and validating monitored targets.

A target is "host", "host:port" or "[ipv6]:port" for a direct TLS
connection, optionally prefixed with smtp://, imap:// or pop3:// for a
service that upgrades a plaintext connection with STARTTLS.
"""

from __future__ import annotations

import ipaddress
import re

DEFAULT_PORT = 443
# Direct TLS, plus the STARTTLS protocols and their standard plaintext ports.
PROTOCOL_PORTS = {"tls": 443, "smtp": 25, "imap": 143, "pop3": 110}
STARTTLS_PROTOCOLS = ("smtp", "imap", "pop3")

# Permissive enough for internal names (single labels, underscores), strict
# enough to reject anything that isn't a plausible hostname.
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,62})"
_HOSTNAME = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*$")


def _parse_port(value: str) -> int:
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise ValueError(f"invalid port {value!r}")
    return int(value)


def parse_target(raw: str) -> tuple[str, int, str]:
    """Split and validate a target into (hostname, port, protocol). Raises
    ValueError with a readable reason."""
    text = raw.strip()
    if not text:
        raise ValueError("empty target")

    protocol = "tls"
    scheme, sep, rest = text.partition("://")
    if sep:
        protocol = scheme.lower()
        if protocol not in STARTTLS_PROTOCOLS:
            raise ValueError(
                f"unsupported protocol {scheme!r}; use host:port for TLS, "
                "or smtp://, imap:// or pop3:// for STARTTLS"
            )
        text = rest
    default_port = PROTOCOL_PORTS[protocol]

    if text.startswith("["):
        host, closed, rest = text[1:].partition("]")
        if not closed or (rest and not rest.startswith(":")):
            raise ValueError(f"invalid target {raw!r}; write IPv6 addresses as [addr]:port")
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise ValueError(f"invalid IPv6 address {host!r}") from None
        port = _parse_port(rest[1:]) if rest else default_port
        return host.lower(), port, protocol

    host, sep, port_text = text.rpartition(":")
    if not sep:
        host, port = text, default_port
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
    return host, port, protocol


def format_target(hostname: str, port: int, protocol: str = "tls") -> str:
    address = f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"
    return address if protocol == "tls" else f"{protocol}://{address}"
