"""Privacy helpers for internal IP addresses."""

from __future__ import annotations

import ipaddress
import re


def is_internal_ip(value: str) -> bool:
    """Return True for non-global addresses (private, loopback, ULA, docs)."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not address.is_global


def mask_ip(value: str) -> str:
    """Mask the host part of a non-global IP while keeping a stable prefix.

    Public addresses are returned unchanged. IPv4 keeps the first two octets;
    IPv6 keeps the first two hextets. The result is stable for grouping and
    search, but does not reveal the full internal host address.
    """

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    if address.is_global:
        return str(address)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return mask_ip(str(address.ipv4_mapped))
    if isinstance(address, ipaddress.IPv4Address):
        octets = str(address).split(".")
        return f"{octets[0]}.{octets[1]}.x.x"
    if address.is_loopback or address.is_unspecified:
        return "::x"
    hextets = address.exploded.split(":")
    return f"{int(hextets[0], 16):x}:{int(hextets[1], 16):x}::x"


_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_BRACKET = re.compile(r"\[([0-9A-Fa-f:]{2,})\](?::(\d+))?")


def mask_text_ips(text: str) -> str:
    """Mask internal IP literals embedded in a URL or other text field."""

    def replace_v4(match: re.Match[str]) -> str:
        candidate = match.group(0)
        return mask_ip(candidate) if is_internal_ip(candidate) else candidate

    def replace_v6(match: re.Match[str]) -> str:
        candidate = match.group(1)
        port = match.group(2)
        if is_internal_ip(candidate):
            suffix = f":{port}" if port else ""
            return f"[{mask_ip(candidate)}]{suffix}"
        return match.group(0)

    return _IPV6_BRACKET.sub(replace_v6, _IPV4.sub(replace_v4, text))


def mask_http_line(line: str) -> str:
    """Mask internal addresses in an HTTP log line before it reaches GoAccess."""

    space = line.find(" ")
    if space < 0:
        return mask_text_ips(line)
    client, rest = line[:space], line[space:]
    if client.startswith("["):
        end = client.find("]")
        if end > 1:
            candidate = client[1:end]
            if is_internal_ip(candidate):
                client = f"[{mask_ip(candidate)}]" + client[end + 1 :]
    else:
        candidate, separator, port = client.rpartition(":")
        if separator and is_internal_ip(candidate):
            client = f"{mask_ip(candidate)}:{port}"
    return client + mask_text_ips(rest)
