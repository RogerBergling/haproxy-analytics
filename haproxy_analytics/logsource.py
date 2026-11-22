"""Read-only log file access and an optional syslog receiver.

The file path is the default source. A syslog listener is opt-in: it must be
explicitly enabled, it has a source-network allowlist, and TCP can be wrapped in
TLS with optional client-certificate verification. Accepted messages are kept in
a bounded in-memory ring; nothing is written to disk.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import socketserver
import ssl
import threading
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import IPNetwork
from .syslog_store import SyslogStore

LOGGER = logging.getLogger(__name__)


def normalize_ip(value: str) -> str:
    """Normalize IPv4-mapped IPv6 addresses for allowlist checks."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def read_log_tail(path: Path, max_bytes: int) -> tuple[list[str], dict[str, Any]]:
    """Read at most ``max_bytes`` from the end of a log file.

    When the file is larger than the limit, the first partial line is discarded
    so the parser never sees a truncated record.
    """

    meta: dict[str, Any] = {
        "path": str(path),
        "exists": False,
        "size": 0,
        "bytes_read": 0,
        "truncated": False,
        "mtime": None,
    }
    try:
        stat = path.stat()
    except OSError:
        return [], meta
    meta.update({"exists": True, "size": stat.st_size, "mtime": stat.st_mtime})
    if not path.is_file() or stat.st_size == 0:
        return [], meta

    start = max(0, stat.st_size - max_bytes)
    try:
        with path.open("rb") as handle:
            if start:
                handle.seek(start)
                handle.readline()  # discard a partial first line
                meta["truncated"] = True
            data = handle.read(max_bytes)
    except OSError as exc:
        LOGGER.warning("Could not read log file %s: %s", path, exc)
        meta["error"] = "read-failed"
        return [], meta

    meta["bytes_read"] = len(data)
    text = data.decode("utf-8", errors="replace")
    return text.splitlines(), meta


class SyslogBuffer:
    """Bounded thread-safe ring of raw syslog lines.

    Both the line count and the total UTF-8 byte size are capped. The byte
    cap matters because a sender can otherwise fill the line ring with
    maximum-size messages and exhaust memory.
    """

    def __init__(self, max_lines: int, max_bytes: int = 64 * 1024 * 1024) -> None:
        self._lines: deque[str] = deque()
        self._lock = threading.Lock()
        self.max_lines = max_lines
        self.max_bytes = max_bytes
        self._bytes = 0
        self.received = 0
        self.dropped = 0
        self.rejected = 0

    @staticmethod
    def _size(line: str) -> int:
        return len(line.encode("utf-8", "replace")) + 1

    def append(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        size = self._size(line)
        with self._lock:
            if size > self.max_bytes:
                self.dropped += 1
                return
            while self._lines and (
                len(self._lines) >= self.max_lines or self._bytes + size > self.max_bytes
            ):
                removed = self._lines.popleft()
                self._bytes -= self._size(removed)
                self.dropped += 1
            self._lines.append(line)
            self._bytes += size
            self.received += 1

    def reject(self) -> None:
        with self._lock:
            self.rejected += 1

    def drop(self) -> None:
        with self._lock:
            self.dropped += 1

    def clear(self) -> None:
        with self._lock:
            self._lines.clear()
            self._bytes = 0

    def snapshot(self) -> list[str]:
        with self._lock:
            return list(self._lines)

    def info(self) -> dict[str, Any]:
        with self._lock:
            return {
                "buffered": len(self._lines),
                "max_lines": self.max_lines,
                "buffered_bytes": self._bytes,
                "max_bytes": self.max_bytes,
                "received": self.received,
                "dropped": self.dropped,
                "rejected": self.rejected,
            }


@dataclass
class _SyslogState:
    buffer: SyslogBuffer
    allowed: tuple[IPNetwork, ...]
    max_message_bytes: int
    store: SyslogStore | None = None
    received: int = 0

    def is_allowed(self, source: str) -> bool:
        normalized = normalize_ip(source)
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            return False
        return any(address in network for network in self.allowed)

    def receive_datagram(self, data: bytes, source: str) -> None:
        if not self.is_allowed(source):
            self.buffer.reject()
            return
        if len(data) > self.max_message_bytes:
            self.buffer.drop()
            return
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            self.buffer.append(line)
            if self.store is not None:
                self.store.append(line)

    def receive_line(self, data: bytes, source: str) -> None:
        if not self.is_allowed(source):
            self.buffer.reject()
            return
        if len(data) > self.max_message_bytes:
            self.buffer.drop()
            return
        line = data.decode("utf-8", errors="replace").strip()
        if not line:
            return
        self.buffer.append(line)
        if self.store is not None:
            self.store.append(line)


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:  # noqa: D401 - socketserver callback
        data, _socket = self.request
        self.server.state.receive_datagram(data, self.client_address[0])  # type: ignore[attr-defined]


class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        state: _SyslogState = self.server.state  # type: ignore[attr-defined]
        try:
            while True:
                line = self.rfile.readline(state.max_message_bytes + 1)
                if not line:
                    break
                state.receive_line(line, self.client_address[0])
        except (ConnectionError, OSError, ssl.SSLError):
            # A sender may close the connection or the TLS session at any time.
            # That is normal and must not produce a server traceback.
            return


class _BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    """ThreadingMixIn with a hard cap on concurrent request threads."""

    daemon_threads = True

    def __init__(self, *args: Any, max_threads: int = 64, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._request_slots = threading.BoundedSemaphore(max(1, max_threads))

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class _ThreadingUDPServer(_BoundedThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    state: _SyslogState


class _ThreadingTCPServer(_BoundedThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    state: _SyslogState
    ssl_context: ssl.SSLContext | None = None

    def get_request(self):
        sock, address = super().get_request()
        if self.ssl_context is not None:
            try:
                sock = self.ssl_context.wrap_socket(sock, server_side=True)
            except ssl.SSLError:
                sock.close()
                raise
        return sock, address


class _ThreadingUDP6Server(_ThreadingUDPServer):
    address_family = socket.AF_INET6


class _ThreadingTCP6Server(_ThreadingTCPServer):
    address_family = socket.AF_INET6


@dataclass
class SyslogServer:
    host: str
    port: int
    protocols: tuple[str, ...]
    allowed: tuple[IPNetwork, ...]
    buffer: SyslogBuffer
    max_message_bytes: int
    max_threads: int = 64
    store: SyslogStore | None = None
    tls_cert: Path | None = None
    tls_key: Path | None = None
    tls_ca: Path | None = None
    require_client_cert: bool = False
    _servers: list[Any] = field(default_factory=list)
    _threads: list[threading.Thread] = field(default_factory=list)
    bound: list[dict[str, Any]] = field(default_factory=list)

    def _ssl_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        assert self.tls_cert is not None
        assert self.tls_key is not None
        context.load_cert_chain(certfile=str(self.tls_cert), keyfile=str(self.tls_key))
        if self.tls_ca:
            context.load_verify_locations(cafile=str(self.tls_ca))
        if self.require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
        return context

    def start(self) -> None:
        state = _SyslogState(
            buffer=self.buffer,
            allowed=self.allowed,
            max_message_bytes=self.max_message_bytes,
            store=self.store,
        )
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET

        if "udp" in self.protocols:
            server_class = _ThreadingUDP6Server if family == socket.AF_INET6 else _ThreadingUDPServer
            udp = server_class(
                (self.host, self.port), _UDPHandler, max_threads=self.max_threads
            )
            udp.state = state
            self._add_server(udp, "udp")

        if "tcp" in self.protocols:
            server_class = _ThreadingTCP6Server if family == socket.AF_INET6 else _ThreadingTCPServer
            tcp = server_class(
                (self.host, self.port), _TCPHandler, max_threads=self.max_threads
            )
            tcp.state = state
            tcp.ssl_context = self._ssl_context() if self.tls_cert else None
            self._add_server(tcp, "tcp")

        if not self._servers:
            raise OSError("No syslog protocol was enabled")

        LOGGER.info(
            "Syslog receiver listening on %s (%s)",
            ", ".join(f"{item['protocol']}://{item['host']}:{item['port']}" for item in self.bound),
            "TLS" if self.tls_cert else "plain",
        )

    def _add_server(self, server: Any, protocol: str) -> None:
        self._servers.append(server)
        address = server.server_address
        host, port = address[0], address[1]
        self.bound.append({"protocol": protocol, "host": host, "port": port})
        thread = threading.Thread(
            target=server.serve_forever,
            name=f"syslog-{protocol}",
            daemon=True,
        )
        thread.start()
        self._threads.append(thread)

    def stop(self) -> None:
        for server in self._servers:
            try:
                server.shutdown()
            except Exception:  # noqa: BLE001 - best-effort shutdown
                pass
            try:
                server.server_close()
            except Exception:  # noqa: BLE001 - best-effort shutdown
                pass
        for thread in self._threads:
            thread.join(timeout=2)
        self._servers.clear()
        self._threads.clear()
        if self.store is not None:
            self.store.close()

    def info(self) -> dict[str, Any]:
        payload = {
            "enabled": True,
            "listen": f"{self.host}:{self.port}",
            "protocols": list(self.protocols),
            "tls": bool(self.tls_cert),
            "require_client_cert": self.require_client_cert,
            "bound": list(self.bound),
        }
        payload.update(self.buffer.info())
        payload["store"] = self.store.info() if self.store is not None else {"enabled": False}
        return payload

    def clear(self) -> dict[str, Any]:
        self.buffer.clear()
        if self.store is not None:
            self.store.clear()
        return self.info()
