"""Privacy helpers for masking internal and configured IP networks."""

from __future__ import annotations

import ipaddress
import re

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_BRACKET = re.compile(r"\[([0-9A-Fa-f:]{2,})\](?::(\d+))?")

_FULL_MASK = {
    4: "x.x.x.x",
    6: "x:x:x:x:x:x:x:x",
}


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


def mask_http_line(
    line: str,
    networks: tuple[IPNetwork, ...] = (),
    mask_non_global: bool = True,
    full: bool = False,
) -> str:
    """Mask internal/configured addresses in an HTTP log line before GoAccess."""

    space = line.find(" ")
    if space < 0:
        return mask_text_ips(line, networks, mask_non_global, full)
    client, rest = line[:space], line[space:]
    if client.startswith("["):
        end = client.find("]")
        if end > 1:
            candidate = client[1:end]
            if should_mask(candidate, networks, mask_non_global):
                client = (
                    f"[{mask_ip(candidate, networks, mask_non_global, full)}]"
                    + client[end + 1 :]
                )
    else:
        candidate, separator, port = client.rpartition(":")
        if separator and should_mask(candidate, networks, mask_non_global):
            client = f"{mask_ip(candidate, networks, mask_non_global, full)}:{port}"
    return client + mask_text_ips(rest, networks, mask_non_global, full)
