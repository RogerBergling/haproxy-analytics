"""HTTP server for the dashboard, JSON API and optional GoAccess report."""

from __future__ import annotations

import ipaddress
import json
import logging
import mimetypes
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .config import Settings
from .logsource import normalize_ip
from .snapshot import SnapshotService
from .version import version_info

LOGGER = logging.getLogger(__name__)

MAIN_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'none'"
)
GOACCESS_CSP = (
    "sandbox allow-scripts; "
    "default-src 'none'; "
    "style-src 'unsafe-inline'; "
    "script-src 'unsafe-inline'; "
    "img-src data:; "
    "font-src data:; "
    "frame-ancestors 'self'"
)
SECURITY_HEADERS = {
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
}
MIME_OVERRIDES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8",
    ".map": "application/json; charset=utf-8",
}
STATIC_ROOT_FILES = {"favicon.svg", "robots.txt"}


class AnalyticsHandler(BaseHTTPRequestHandler):
    server_version = ""
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return ""

    def log_message(self, fmt: str, *args: object) -> None:
        # Never log request paths or client addresses by default. They can
        # contain or reveal sensitive traffic information.
        LOGGER.debug("request: " + fmt, *args)

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        # Keep parser-generated errors plain, short and covered by the same
        # security headers as every other response.
        try:
            status = HTTPStatus(code)
        except ValueError:
            status = HTTPStatus.BAD_REQUEST
        self._send_text(status, message or status.phrase)

    @property
    def settings(self) -> Settings:
        return self.server.settings  # type: ignore[attr-defined]

    @property
    def service(self) -> SnapshotService:
        return self.server.service  # type: ignore[attr-defined]

    def _common_headers(self, *, csp: str = MAIN_CSP, frame_options: str = "DENY") -> None:
        self.send_header("Content-Security-Policy", csp)
        for name, value in SECURITY_HEADERS.items():
            if name == "X-Frame-Options":
                self.send_header(name, frame_options)
            else:
                self.send_header(name, value)

    def _send_bytes(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        head_only: bool = False,
        extra_headers: dict[str, str] | None = None,
        csp: str = MAIN_CSP,
        frame_options: str = "DENY",
    ) -> None:
        self.send_response(status)
        self._common_headers(csp=csp, frame_options=frame_options)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _send_json(
        self,
        payload: Any,
        status: HTTPStatus = HTTPStatus.OK,
        *,
        head_only: bool = False,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8", head_only=head_only)

    def _send_text(
        self,
        status: HTTPStatus,
        text: str,
        *,
        head_only: bool = False,
    ) -> None:
        self._send_bytes(
            status,
            text.encode("utf-8"),
            "text/plain; charset=utf-8",
            head_only=head_only,
        )

    def _resolve_static(self, path: str) -> Path | None:
        public_dir = self.settings.public_dir.resolve()
        if path in ("/", "/index.html"):
            relative = "index.html"
        elif path.startswith("/assets/"):
            relative = path.lstrip("/")
        elif path in {f"/{name}" for name in STATIC_ROOT_FILES}:
            relative = path.lstrip("/")
        else:
            return None

        decoded = unquote(relative)
        if "\x00" in decoded:
            return None
        candidate = (public_dir / decoded).resolve()
        try:
            candidate.relative_to(public_dir)
        except ValueError:
            return None
        if any(part.startswith(".") for part in candidate.relative_to(public_dir).parts):
            return None
        if not candidate.is_file():
            return None
        return candidate

    def _serve_static(self, path: str, *, head_only: bool = False) -> None:
        candidate = self._resolve_static(path)
        if candidate is None:
            self._send_text(HTTPStatus.NOT_FOUND, "Not found", head_only=head_only)
            return
        try:
            data = candidate.read_bytes()
        except OSError:
            self._send_text(HTTPStatus.NOT_FOUND, "Not found", head_only=head_only)
            return
        suffix = candidate.suffix.lower()
        content_type = (
            MIME_OVERRIDES.get(suffix)
            or mimetypes.guess_type(candidate.name)[0]
            or "application/octet-stream"
        )
        self._send_bytes(HTTPStatus.OK, data, content_type, head_only=head_only)

    def _client_ip(self) -> str:
        peer = normalize_ip(self.client_address[0])
        trusted = self.settings.trusted_proxies
        if not trusted:
            return peer
        try:
            peer_address = ipaddress.ip_address(peer)
        except ValueError:
            return peer
        if not any(peer_address in network for network in trusted):
            return peer

        forwarded = self.headers.get("X-Forwarded-For", "")
        hops: list[str] = []
        for item in forwarded.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                hops.append(str(ipaddress.ip_address(item)))
            except ValueError:
                continue
        for hop in reversed(hops):
            try:
                address = ipaddress.ip_address(hop)
            except ValueError:
                continue
            if not any(address in network for network in trusted):
                return hop
        return peer

    def _serve_root(self, *, head_only: bool = False) -> None:
        self._serve_static("/index.html", head_only=head_only)

    def _serve_snapshot(self, *, head_only: bool = False) -> None:
        self._send_json(self.service.snapshot(), head_only=head_only)

    def _serve_whoami(self, *, head_only: bool = False) -> None:
        self._send_json({"ip": self._client_ip()}, head_only=head_only)

    def _serve_health(self, *, head_only: bool = False) -> None:
        health = self.service.health()
        status = HTTPStatus.OK if health.get("status") == "ok" else HTTPStatus.SERVICE_UNAVAILABLE
        self._send_json(health, status, head_only=head_only)

    def _serve_version(self, *, head_only: bool = False) -> None:
        self._send_json(version_info(), head_only=head_only)

    def _serve_goaccess(self, *, head_only: bool = False) -> None:
        html = self.service.goaccess_html()
        if not html:
            self._send_text(
                HTTPStatus.NOT_FOUND,
                "No GoAccess report is available. Enable GOACCESS_ENABLED and wait for a refresh.",
                head_only=head_only,
            )
            return
        self._send_bytes(
            HTTPStatus.OK,
            html.encode("utf-8"),
            "text/html; charset=utf-8",
            head_only=head_only,
            csp=GOACCESS_CSP,
            frame_options="SAMEORIGIN",
        )

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            self._serve_root()
        elif path == "/api/snapshot":
            self._serve_snapshot()
        elif path == "/api/whoami":
            self._serve_whoami()
        elif path in ("/healthz", "/api/health"):
            self._serve_health()
        elif path == "/version.json":
            self._serve_version()
        elif path == "/goaccess":
            self._serve_goaccess()
        elif path.startswith("/assets/") or path in {f"/{name}" for name in STATIC_ROOT_FILES}:
            self._serve_static(path)
        else:
            self._send_text(HTTPStatus.NOT_FOUND, "Not found")

    def do_HEAD(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            self._serve_root(head_only=True)
        elif path == "/api/snapshot":
            self._serve_snapshot(head_only=True)
        elif path == "/api/whoami":
            self._serve_whoami(head_only=True)
        elif path in ("/healthz", "/api/health"):
            self._serve_health(head_only=True)
        elif path == "/version.json":
            self._serve_version(head_only=True)
        elif path == "/goaccess":
            self._serve_goaccess(head_only=True)
        elif path.startswith("/assets/") or path in {f"/{name}" for name in STATIC_ROOT_FILES}:
            self._serve_static(path, head_only=True)
        else:
            self._send_text(HTTPStatus.NOT_FOUND, "Not found", head_only=True)

    def _reject_method(self) -> None:
        self.close_connection = True
        body = b"Method not allowed"
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self._common_headers()
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = _reject_method  # type: ignore[assignment]
    do_PUT = _reject_method  # type: ignore[assignment]
    do_DELETE = _reject_method  # type: ignore[assignment]
    do_PATCH = _reject_method  # type: ignore[assignment]
    do_OPTIONS = _reject_method  # type: ignore[assignment]


class AnalyticsHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], settings: Settings, service: SnapshotService):
        self.settings = settings
        self.service = service
        super().__init__(address, AnalyticsHandler)


def create_server(settings: Settings, service: SnapshotService) -> AnalyticsHTTPServer:
    return AnalyticsHTTPServer((settings.bind, settings.port), settings, service)
