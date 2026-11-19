"""Privacy helpers for masking internal and configured IP networks."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_DOMAIN_LABEL = re.compile(r"^[a-z0-9_-]+$")
_HOST_FORBIDDEN = set(" /\\@?#|,")

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_BRACKET = re.compile(r"\[([0-9A-Fa-f:]{2,})\](?::(\d+))?")

_FULL_MASK = {
    4: "x.x.x.x",
    6: "x:x:x:x:x:x:x:x",
}


def normalize_domain(value: str) -> str:
    """Normalize one excluded domain for exact-or-subdomain matching.

    Accepts ``example.com``, ``.example.com`` and ``*.example.com``. The
    returned value is lower-case ASCII/Punycode with no leading wildcard or
    trailing dot. Invalid values raise ``ValueError``.
    """

    text = value.strip().lower()
    if text.startswith("*."):
        text = text[2:]
    elif text.startswith("."):
        text = text[1:]
    text = text.rstrip(".")
    if not text:
        raise ValueError("empty domain")
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid internationalized domain: {value!r}") from exc
    if len(text) > 253:
        raise ValueError(f"domain is too long: {value!r}")
    for label in text.split("."):
        if not label or len(label) > 63:
            raise ValueError(f"invalid domain label: {value!r}")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError(f"invalid domain label: {value!r}")
        if not _DOMAIN_LABEL.fullmatch(label):
            raise ValueError(f"invalid domain: {value!r}")
    return text


def normalize_host(value: str | None) -> str:
    """Normalize a Host header, SNI name or URL host for domain matching."""

    if value is None:
        return ""
    text = value.strip().strip('"').lower()
    if not text or text == "-":
        return ""
    if text.startswith("["):
        closing = text.find("]")
        if closing < 0:
            return ""
        address = text[1:closing]
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return ""
        return f"[{address}]"
    if text.count(":") == 1:
        host, _, port = text.rpartition(":")
        if port.isdigit():
            text = host
    text = text.rstrip(".")
    if not text or any(character in _HOST_FORBIDDEN for character in text):
        return ""
    if any(ord(character) > 127 for character in text):
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError:
            return ""
    return text


def host_from_url(value: str) -> str:
    """Return the normalized host from an absolute or scheme-relative URL."""

    text = value.strip()
    if text.startswith("//"):
        text = "http:" + text
    if not text.startswith(("http://", "https://")):
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return ""
    return normalize_host(parsed.hostname)


def domain_matches(host: str | None, domains: tuple[str, ...]) -> bool:
    """Return True when ``host`` is a configured domain or its subdomain."""

    if not domains:
        return False
    normalized = normalize_host(host)
    if not normalized:
        return False
    for domain in domains:
        if normalized == domain or normalized.endswith(f".{domain}"):
            return True
    return False


def domain_only_path(host: str, path: str) -> str:
    """Replace a request target with a domain-only label.

    The scheme is preserved when the original request target is an absolute
    URL. Origin-form requests do not contain a scheme, so the label is just the
    domain and a trailing slash.
    """

    if not host:
        return path
    scheme = ""
    if path.startswith(("http://", "https://")):
        try:
            scheme = urlsplit(path).scheme
        except ValueError:
            scheme = ""
    prefix = f"{scheme}://" if scheme else ""
    return f"{prefix}{host}/"


def _match_network(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: tuple[IPNetwork, ...],
) -> IPNetwork | None:
    for network in networks:
        if address.version == network.version and address in network:
            return network
    return None


def _mask_with_prefix(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address, prefixlen: int
) -> str:
    if isinstance(address, ipaddress.IPv4Address):
        keep = max(0, min(3, prefixlen // 8))
        octets = str(address).split(".")
        return ".".join(octets[:keep] + ["x"] * (4 - keep))
    keep = max(1, min(4, prefixlen // 16))
    hextets = address.exploded.split(":")
    prefix = ":".join(f"{int(hextet, 16):x}" for hextet in hextets[:keep])
    return f"{prefix}::x"


def should_mask(
    value: str,
    networks: tuple[IPNetwork, ...] = (),
    mask_non_global: bool = True,
) -> bool:
    """Return True when an address should be masked."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if _match_network(address, networks) is not None:
        return True
    return mask_non_global and not address.is_global


def is_internal_ip(value: str) -> bool:
    """Return True for non-global addresses (private, loopback, ULA, docs)."""

    return should_mask(value)


def mask_ip(
    value: str,
    networks: tuple[IPNetwork, ...] = (),
    mask_non_global: bool = True,
    full: bool = False,
) -> str:
    """Mask an address, using the configured network prefix when it matches.

    Example masks:
      192.0.0.0/8 configured  -> 192.x.x.x
      172.0.0.0/8 configured  -> 172.x.x.x
      default private IPv4    -> 192.0.x.x
      default private IPv6    -> fd00:1234::x
      full=True               -> x.x.x.x / x:x:x:x:x:x:x:x
      public address          -> unchanged
    """

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    network = _match_network(address, networks)
    if network is None and (address.is_global or not mask_non_global):
        return str(address)
    if full:
        return _FULL_MASK[address.version]
    if network is not None:
        return _mask_with_prefix(address, network.prefixlen)
    if address.version == 6 and (address.is_loopback or address.is_unspecified):
        return "::x"
    return _mask_with_prefix(address, 16 if address.version == 4 else 32)


def mask_text_ips(
    text: str,
    networks: tuple[IPNetwork, ...] = (),
    mask_non_global: bool = True,
    full: bool = False,
) -> str:
    """Mask internal/configured IP literals embedded in a URL or text field."""

    def replace_v4(match: re.Match[str]) -> str:
        candidate = match.group(0)
        return (
            mask_ip(candidate, networks, mask_non_global, full)
            if should_mask(candidate, networks, mask_non_global)
            else candidate
        )

    def replace_v6(match: re.Match[str]) -> str:
        candidate = match.group(1)
        port = match.group(2)
        if should_mask(candidate, networks, mask_non_global):
            suffix = f":{port}" if port else ""
            return f"[{mask_ip(candidate, networks, mask_non_global, full)}]{suffix}"
        return match.group(0)

    return _IPV6_BRACKET.sub(replace_v6, _IPV4.sub(replace_v4, text))
