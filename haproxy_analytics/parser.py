"""Parsers for the supported HAProxy log formats.

Supported inputs:
  * syslog-wrapped or plain HAProxy HTTP logs written by ``option httplog``
  * the SNI capture format used by a TCP frontend:
    ``src=... dst=... sni=...``
  * syslog "message repeated N times" compression for either format

The parser never treats a log field as markup. The frontend renders every value
through DOM text nodes.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime

SYSLOG_TIMESTAMP = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
)
HAPROXY_PROGRAM = re.compile(
    r"\bhaproxy(?:-[\w-]+)?(?:\[\d+\])?:\s+(?P<message>.*)$", re.IGNORECASE
)
REPEATED = re.compile(r"^message repeated\s+(\d+)\s+times:\s*\[\s*(.*?)\s*\]$")
TLS = re.compile(r"^src=(?P<src>\S+)\s+dst=(?P<dst>\S+)\s+sni=(?P<sni>\S+)")

HTTP_STANDARD = re.compile(
    r"^(?P<client>\S+):(?P<port>\d+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r"(?P<frontend>\S+)\s+"
    r"(?P<backend>\S+)\s+"
    r"(?P<timers>\S+)\s+"
    r"(?P<status>\d{3}|-{3})\s+"
    r"(?P<bytes>-|\d+)\s*"
    r"(?P<rest>.*)$"
)
HTTP_SIMPLE = re.compile(
    r"^(?P<client>\S+):(?P<port>\d+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r"(?P<frontend>\S+)\s+"
    r"(?P<backend>\S+)\s+"
    r"(?P<status>\d{3}|-{3})\s+"
    r"(?P<bytes>-|\d+)\s*"
    r"(?P<rest>.*)$"
)
QUOTED_REQUEST = re.compile(r'"([^"]*)"')
REQUEST = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/\S+)")


@dataclass(frozen=True)
class TlsEvent:
    ip: str
    dst: str
    sni: str
    timestamp: str
    timestamp_display: str
    count: int = 1


@dataclass(frozen=True)
class HttpEvent:
    ip: str
    timestamp: str
    timestamp_display: str
    frontend: str
    backend: str
    status: str
    bytes: int
    method: str
    path: str
    protocol: str
    count: int = 1


@dataclass(frozen=True)
class ParsedEvent:
    event: TlsEvent | HttpEvent
    http_message: str | None = None


def split_syslog_line(raw_line: str) -> tuple[str, str | None]:
    """Return ``(message, syslog timestamp)`` without a syslog program prefix."""

    line = raw_line.rstrip("\r\n")
    timestamp = None
    ts_match = SYSLOG_TIMESTAMP.match(line)
    if ts_match:
        timestamp = ts_match.group("ts")

    # RFC 5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG.
    # rsyslog's RSYSLOG_SyslogProtocol23Format uses this shape. The HAProxy
    # payload is the final field in normal forwarding configurations.
    if line.startswith("<") and ">1 " in line[:8]:
        parts = line.split(" ", 7)
        if len(parts) == 8:
            timestamp = parts[1]
            message = parts[7].strip()
            program = HAPROXY_PROGRAM.search(message)
            if program:
                message = program.group("message").strip()
            return message, timestamp

    program = HAPROXY_PROGRAM.search(line)
    if program:
        return program.group("message").strip(), timestamp
    return line.strip(), timestamp


def _display_time(value: str | None) -> str:
    if not value:
        return "-"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass
    try:
        parsed = datetime.strptime(f"{datetime.now().year} {value}", "%Y %b %d %H:%M:%S")
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


def _display_http_time(value: str) -> str:
    for pattern in ("%d/%b/%Y:%H:%M:%S.%f", "%d/%b/%Y:%H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
        try:
            return datetime.strptime(value, pattern).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return value


def _clean_ip(value: str) -> str:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def _clean_name(value: str) -> str:
    return value.rstrip("~")


def _request_parts(rest: str) -> tuple[str, str, str]:
    quoted = QUOTED_REQUEST.search(rest)
    request = quoted.group(1) if quoted else " ".join(rest.split()[:3])
    match = REQUEST.match(request)
    if not match:
        return "-", "-", "-"
    return match.group("method"), match.group("path"), match.group("protocol")


def _parse_event(message: str, count: int, syslog_time: str | None) -> ParsedEvent | None:
    tls = TLS.match(message)
    if tls:
        return ParsedEvent(
            TlsEvent(
                ip=_clean_ip(tls.group("src")),
                dst=tls.group("dst"),
                sni=tls.group("sni"),
                timestamp=syslog_time or "-",
                timestamp_display=_display_time(syslog_time),
                count=count,
            )
        )

    for pattern in (HTTP_STANDARD, HTTP_SIMPLE):
        match = pattern.match(message)
        if not match:
            continue
        method, path, protocol = _request_parts(match.group("rest"))
        bytes_text = match.group("bytes")
        return ParsedEvent(
            HttpEvent(
                ip=_clean_ip(match.group("client")),
                timestamp=match.group("timestamp"),
                timestamp_display=_display_http_time(match.group("timestamp")),
                frontend=_clean_name(match.group("frontend")),
                backend=_clean_name(match.group("backend").split("/")[0]),
                status=match.group("status"),
                bytes=int(bytes_text) if bytes_text.isdigit() else 0,
                method=method,
                path=path,
                protocol=protocol,
                count=count,
            ),
            http_message=message,
        )
    return None


def parse_line(raw_line: str) -> ParsedEvent | None:
    """Parse one line and return an event, or ``None`` for unrelated input."""

    message, syslog_time = split_syslog_line(raw_line)
    if not message:
        return None

    repeated = REPEATED.match(message)
    if repeated:
        count = int(repeated.group(1))
        inner = repeated.group(2).strip()
        inner_message, _ = split_syslog_line(inner)
        parsed = _parse_event(inner_message, count, syslog_time)
        if parsed and parsed.http_message:
            parsed = ParsedEvent(parsed.event, parsed.http_message)
        return parsed

    return _parse_event(message, 1, syslog_time)
