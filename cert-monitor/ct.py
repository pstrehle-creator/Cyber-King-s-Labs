"""Certificate Transparency lookups via crt.sh."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

CRTSH_URL = "https://crt.sh/"
# Popular domains can return enormous result sets; refuse rather than
# exhaust memory.
MAX_RESPONSE_BYTES = 50 * 1024 * 1024

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOSTNAME_PATTERN = re.compile(rf"^(?=.{{1,253}}$)(?:{_LABEL}\.)+[a-z][a-z0-9-]{{0,62}}$")


class CTLookupError(Exception):
    pass


@dataclass(frozen=True)
class CTCertificate:
    issuer_ca_id: int
    serial_number: str
    issuer: str
    names: tuple[str, ...]
    not_before: str
    not_after: str
    crtsh_id: int

    @property
    def key(self) -> str:
        # A precertificate and its final certificate share issuer and serial,
        # but have separate crt.sh ids; this treats them as one certificate.
        return f"{self.issuer_ca_id}:{self.serial_number}"

    @property
    def url(self) -> str:
        return f"{CRTSH_URL}?id={self.crtsh_id}"


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not HOSTNAME_PATTERN.match(domain):
        raise ValueError(f"not a valid domain name: {value!r}")
    return domain


def is_valid_name(name: str) -> bool:
    return bool(HOSTNAME_PATTERN.match(name.removeprefix("*.")))


def in_domain(name: str, domain: str) -> bool:
    bare = name.removeprefix("*.")
    return bare == domain or bare.endswith("." + domain)


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def parse_entries(entries: list[dict], domain: str, now: datetime | None = None) -> list[CTCertificate]:
    """Turn crt.sh JSON rows into unexpired certificates, keeping only names
    under `domain`. Malformed rows are skipped."""
    now = now or datetime.now(timezone.utc)
    merged: dict[tuple[int, str], dict] = {}
    for entry in entries:
        try:
            ca_id = int(entry["issuer_ca_id"])
            serial = str(entry["serial_number"]).lower()
            not_before = _parse_time(entry["not_before"])
            not_after = _parse_time(entry["not_after"])
            crtsh_id = int(entry["id"])
            raw_names = str(entry.get("name_value", "")).split("\n") + [str(entry.get("common_name") or "")]
        except (KeyError, TypeError, ValueError):
            continue
        if not_after <= now:
            continue
        names = {
            n.strip().lower() for n in raw_names
            if n.strip() and is_valid_name(n.strip().lower()) and in_domain(n.strip().lower(), domain)
        }
        if not names:
            continue
        item = merged.setdefault(
            (ca_id, serial),
            {
                "issuer": str(entry.get("issuer_name") or ""),
                "names": set(),
                "not_before": not_before,
                "not_after": not_after,
                "crtsh_id": crtsh_id,
            },
        )
        item["names"] |= names
        item["crtsh_id"] = min(item["crtsh_id"], crtsh_id)

    return [
        CTCertificate(
            issuer_ca_id=ca_id,
            serial_number=serial,
            issuer=item["issuer"],
            names=tuple(sorted(item["names"])),
            not_before=item["not_before"].isoformat(timespec="seconds"),
            not_after=item["not_after"].isoformat(timespec="seconds"),
            crtsh_id=item["crtsh_id"],
        )
        for (ca_id, serial), item in sorted(merged.items(), key=lambda kv: kv[1]["crtsh_id"])
    ]


def fetch_certificates(domain: str, timeout: float = 60) -> list[CTCertificate]:
    """All unexpired certificates crt.sh knows for `domain` and its subdomains.
    Raises CTLookupError if any lookup fails, so a partial answer is never
    mistaken for the full set."""
    entries: list[dict] = []
    for query in (domain, f"%.{domain}"):
        url = CRTSH_URL + "?" + urllib.parse.urlencode({"q": query, "output": "json", "exclude": "expired"})
        request = urllib.request.Request(url, headers={"User-Agent": "cert-monitor"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except (urllib.error.URLError, OSError) as exc:
            raise CTLookupError(f"crt.sh lookup for {query!r} failed: {exc}") from exc
        if len(body) > MAX_RESPONSE_BYTES:
            raise CTLookupError(f"crt.sh response for {query!r} is larger than {MAX_RESPONSE_BYTES} bytes")
        try:
            data = json.loads(body)
        except ValueError as exc:
            raise CTLookupError(f"crt.sh returned something other than JSON for {query!r}") from exc
        if not isinstance(data, list):
            raise CTLookupError(f"unexpected crt.sh response for {query!r}")
        entries.extend(e for e in data if isinstance(e, dict))
    return parse_entries(entries, domain)
