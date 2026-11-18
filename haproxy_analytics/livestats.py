"""Read-only HAProxy runtime API client and cached live snapshot.

The service connects to an operator-configured HAProxy stats socket, sends only
two whitelisted commands (``show info`` and ``show stat``), parses the response
by field name, and keeps the latest result in memory. The browser cannot send
commands to HAProxy. Server addresses are intentionally omitted from the
payload because they reveal internal topology.
"""

from __future__ import annotations

import csv
import logging
import socket
import threading
import time
from datetime import datetime
from typing import Any

from .config import Settings

LOGGER = logging.getLogger(__name__)

# One non-interactive command line. Never build this from request input.
LIVE_COMMAND = b"show info;show stat\n"

_INFO_FIELDS = {
    "version": "Version",
    "release_date": "Release_date",
    "uptime": "Uptime",
    "uptime_seconds": "Uptime_sec",
    "processes": "Nbproc",
    "threads": "Nbthread",
    "current_connections": "CurrConns",
    "cumulative_connections": "CumConns",
    "connection_rate": "ConnRate",
    "max_connection_rate": "MaxConnRate",
    "max_connections": "MaxConn",
    "current_ssl_connections": "CurrSslConns",
    "cumulative_ssl_connections": "CumSslConns",
    "ssl_connection_rate": "SslRate",
    "max_ssl_connection_rate": "MaxSslRate",
    "tasks": "Tasks",
    "run_queue": "Run_queue",
    "idle_percent": "Idle_pct",
    "memory_max_mb": "Memmax_MB",
    "pool_allocated_mb": "PoolAlloc_MB",
    "pool_used_mb": "PoolUsed_MB",
    "pool_failed": "PoolFailed",
    "dropped_logs": "DroppedLogs",
    "failed_resolutions": "FailedResolutions",
}

_INFO_TEXT_FIELDS = {"version", "release_date", "uptime"}
_INFO_FLOAT_FIELDS = {"idle_percent"}


class StatsSocketError(RuntimeError):
    """Raised when the runtime API response cannot be used safely."""


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "-":
        return None
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    text = str(value).strip().rstrip("%")
    if not text or text == "-":
        return None
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def _as_text(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _endpoint(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _empty_info() -> dict[str, Any]:
    info: dict[str, Any] = {name: None for name in _INFO_FIELDS}
    info["version"] = "-"
    info["release_date"] = "-"
    info["uptime"] = "-"
    return info


def _empty_summary() -> dict[str, Any]:
    return {
        "frontends": 0,
        "backends": 0,
        "servers": 0,
        "servers_up": 0,
        "servers_down": 0,
        "servers_maintenance": 0,
        "servers_drain": 0,
        "servers_no_check": 0,
        "servers_unknown": 0,
        "backends_up": 0,
        "backends_down": 0,
        "current_sessions": 0,
        "session_rate": 0,
        "request_rate": 0,
        "requests_total": 0,
        "bytes_in": 0,
        "bytes_out": 0,
        "http_4xx": 0,
        "http_5xx": 0,
        "connection_errors": 0,
        "response_errors": 0,
        "max_connections": None,
    }


def _base_meta(
    *,
    enabled: bool,
    endpoint: str | None,
    refresh_seconds: int | None,
    warnings: list[str],
) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "connected": False,
        "read_only": True,
        "endpoint": endpoint,
        "generated_at": _now(),
        "refresh_seconds": refresh_seconds,
        "last_success": None,
        "last_error": None,
        "consecutive_errors": 0,
        "duration_ms": 0,
        "warnings": warnings,
    }


def disabled_payload(
    message: str = (
        "Live stats are disabled. Set HAPROXY_STATS_SOCKET to a read-only "
        "HAProxy stats socket host:port."
    ),
) -> dict[str, Any]:
    """Return the stable response shape when live stats are not configured."""

    return {
        "meta": _base_meta(
            enabled=False,
            endpoint=None,
            refresh_seconds=None,
            warnings=[message],
        ),
        "info": _empty_info(),
        "summary": _empty_summary(),
        "frontends": [],
        "backends": [],
        "servers": [],
    }


def _info_payload(raw: dict[str, str]) -> dict[str, Any]:
    info: dict[str, Any] = {}
    for name, field in _INFO_FIELDS.items():
        value = raw.get(field)
        if name in _INFO_TEXT_FIELDS:
            info[name] = _as_text(value)
        elif name in _INFO_FLOAT_FIELDS:
            info[name] = _as_float(value)
        else:
            info[name] = _as_int(value)
    return info


def _metrics(row: dict[str, str]) -> dict[str, Any]:
    return {
        "current_sessions": _as_int(row.get("scur")),
        "max_sessions": _as_int(row.get("smax")),
        "session_limit": _as_int(row.get("slim")),
        "total_sessions": _as_int(row.get("stot")),
        "bytes_in": _as_int(row.get("bin")),
        "bytes_out": _as_int(row.get("bout")),
        "session_rate": _as_int(row.get("rate")),
        "max_session_rate": _as_int(row.get("rate_max")),
        "request_rate": _as_int(row.get("req_rate")),
        "max_request_rate": _as_int(row.get("req_rate_max")),
        "requests_total": _as_int(row.get("req_tot")),
        "http_1xx": _as_int(row.get("hrsp_1xx")),
        "http_2xx": _as_int(row.get("hrsp_2xx")),
        "http_3xx": _as_int(row.get("hrsp_3xx")),
        "http_4xx": _as_int(row.get("hrsp_4xx")),
        "http_5xx": _as_int(row.get("hrsp_5xx")),
        "http_other": _as_int(row.get("hrsp_other")),
        "connection_errors": _as_int(row.get("econ")),
        "response_errors": _as_int(row.get("eresp")),
        "retries": _as_int(row.get("wretr")),
        "redispatches": _as_int(row.get("wredis")),
        "client_aborts": _as_int(row.get("cli_abrt")),
        "server_aborts": _as_int(row.get("srv_abrt")),
        "response_time_ms": _as_int(row.get("rtime")),
        "total_time_ms": _as_int(row.get("ttime")),
        "last_change_seconds": _as_int(row.get("lastchg")),
        "downtime_seconds": _as_int(row.get("downtime")),
        "check_status": _as_text(row.get("check_status")),
        "check_health": _as_int(row.get("check_health")),
        "weight": _as_int(row.get("weight")),
        "mode": _as_text(row.get("mode")),
    }


def _frontend(row: dict[str, str]) -> dict[str, Any]:
    return {
        "name": _as_text(row.get("pxname")),
        "status": _as_text(row.get("status")),
        **_metrics(row),
    }


def _backend(row: dict[str, str]) -> dict[str, Any]:
    return {
        "name": _as_text(row.get("pxname")),
        "status": _as_text(row.get("status")),
        **_metrics(row),
    }


def _server(row: dict[str, str]) -> dict[str, Any]:
    return {
        "backend": _as_text(row.get("pxname")),
        "name": _as_text(row.get("svname")),
        "status": _as_text(row.get("status")),
        **_metrics(row),
    }


def _classify(
    rows: list[dict[str, str]], max_rows: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], bool]:
    frontends: list[dict[str, Any]] = []
    backends: list[dict[str, Any]] = []
    servers: list[dict[str, Any]] = []

    for row in rows:
        svname = (row.get("svname") or "").strip()
        row_type = (row.get("type") or "").strip()
        if svname == "FRONTEND" or row_type == "0":
            frontends.append(_frontend(row))
        elif svname == "BACKEND" or row_type == "1":
            backends.append(_backend(row))
        elif row_type == "2":
            servers.append(_server(row))

    frontends.sort(key=lambda item: item["name"])
    backends.sort(key=lambda item: item["name"])
    servers.sort(key=lambda item: (item["backend"], item["name"]))

    truncated = (
        len(frontends) > max_rows or len(backends) > max_rows or len(servers) > max_rows
    )
    return (
        frontends[:max_rows],
        backends[:max_rows],
        servers[:max_rows],
        truncated,
    )


def _server_state(status: str) -> str:
    text = status.strip().upper()
    if text == "UP" or text.startswith("UP "):
        return "up"
    if text == "DOWN" or text.startswith("DOWN "):
        return "down"
    if text.startswith("MAINT"):
        return "maintenance"
    if text.startswith("DRAIN"):
        return "drain"
    if text in {"NO CHECK", "NO-CHECK"}:
        return "no_check"
    return "unknown"


def _summary(
    info: dict[str, Any],
    frontends: list[dict[str, Any]],
    backends: list[dict[str, Any]],
    servers: list[dict[str, Any]],
) -> dict[str, Any]:
    summary = _empty_summary()
    summary.update(
        {
            "frontends": len(frontends),
            "backends": len(backends),
            "servers": len(servers),
            "current_sessions": sum(item["current_sessions"] or 0 for item in frontends),
            "session_rate": sum(item["session_rate"] or 0 for item in frontends),
            "request_rate": sum(item["request_rate"] or 0 for item in frontends),
            "requests_total": sum(item["requests_total"] or 0 for item in frontends),
            "bytes_in": sum(item["bytes_in"] or 0 for item in frontends),
            "bytes_out": sum(item["bytes_out"] or 0 for item in frontends),
            "http_4xx": sum(item["http_4xx"] or 0 for item in frontends),
            "http_5xx": sum(item["http_5xx"] or 0 for item in frontends),
            "connection_errors": sum(
                item["connection_errors"] or 0 for item in frontends
            ),
            "response_errors": sum(item["response_errors"] or 0 for item in frontends),
            "backends_up": sum(
                1 for item in backends if _server_state(item["status"]) == "up"
            ),
            "backends_down": sum(
                1 for item in backends if _server_state(item["status"]) == "down"
            ),
        }
    )

    for server in servers:
        state = _server_state(server["status"])
        if state == "up":
            summary["servers_up"] += 1
        elif state == "down":
            summary["servers_down"] += 1
        elif state == "maintenance":
            summary["servers_maintenance"] += 1
        elif state == "drain":
            summary["servers_drain"] += 1
        elif state == "no_check":
            summary["servers_no_check"] += 1
        else:
            summary["servers_unknown"] += 1

    # The info block is kept in the payload for the UI; expose the same maxconn
    # value through summary so a consumer does not need to know HAProxy names.
    summary["max_connections"] = info.get("max_connections")
    return summary


def _parse_info(lines: list[str]) -> dict[str, str]:
    info: dict[str, str] = {}
    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue
        key, separator, value = line.partition(":")
        if separator and key.strip():
            info[key.strip()] = value.strip()
    return info


def _parse_stat(lines: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        if not line.startswith("#"):
            index += 1
            continue

        header_text = line[1:].strip()
        try:
            header = next(csv.reader([header_text]))
        except csv.Error as exc:
            raise StatsSocketError(f"Invalid show stat header: {exc}") from exc
        if not header or header[0] != "pxname":
            index += 1
            continue

        index += 1
        while index < len(lines):
            row_line = lines[index]
            if not row_line.strip() or row_line.startswith("#"):
                break
            try:
                values = next(csv.reader([row_line]))
            except csv.Error as exc:
                raise StatsSocketError(f"Invalid show stat row: {exc}") from exc
            if len(values) < len(header):
                values.extend([""] * (len(header) - len(values)))
            rows.append(dict(zip(header, values[: len(header)])))
            index += 1
    return rows


def parse_response(text: str) -> tuple[dict[str, str], list[dict[str, str]]]:
    """Parse a non-interactive ``show info;show stat`` response."""

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    for line in lines:
        error = line.strip().lower()
        if error.startswith(("unknown command", "permission denied", "access denied")):
            raise StatsSocketError(line.strip())
    stat_index = next(
        (index for index, line in enumerate(lines) if line.startswith("#")),
        None,
    )
    if stat_index is None:
        info = _parse_info(lines)
        if not info:
            raise StatsSocketError("HAProxy response contained no show info fields.")
        return info, []
    info = _parse_info(lines[:stat_index])
    rows = _parse_stat(lines[stat_index:])
    if not info:
        raise StatsSocketError("HAProxy response contained no show info fields.")
    return info, rows


class LiveStatsService:
    """Poll a read-only HAProxy stats socket and cache the latest payload."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lock = threading.Lock()
        self._refresh_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_logged_error: str | None = None
        self._consecutive_errors = 0
        self._payload: dict[str, Any] = self._empty_enabled_payload(
            "Waiting for the first live stats poll."
        )

    def _empty_enabled_payload(self, message: str) -> dict[str, Any]:
        return {
            "meta": _base_meta(
                enabled=True,
                endpoint=self._endpoint(),
                refresh_seconds=self.settings.stats_refresh_seconds,
                warnings=[message],
            ),
            "info": _empty_info(),
            "summary": _empty_summary(),
            "frontends": [],
            "backends": [],
            "servers": [],
        }

    def _endpoint(self) -> str | None:
        if self.settings.stats_host is None or self.settings.stats_port is None:
            return None
        return _endpoint(self.settings.stats_host, self.settings.stats_port)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run,
            name="live-stats-refresh",
            daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.refresh_once()
            if self._stop.wait(self.settings.stats_refresh_seconds):
                break

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def refresh_once(self) -> None:
        with self._refresh_lock:
            self._refresh_once_locked()

    def _refresh_once_locked(self) -> None:
        if not self.settings.stats_host or not self.settings.stats_port:
            with self._lock:
                self._payload = disabled_payload()
            return

        started = time.monotonic()
        try:
            info_raw, rows_raw = self._fetch()
            info = _info_payload(info_raw)
            frontends, backends, servers, truncated = _classify(
                rows_raw, self.settings.stats_max_rows
            )
            warnings: list[str] = []
            if not rows_raw:
                warnings.append("HAProxy returned no show stat rows.")
            if truncated:
                warnings.append(
                    f"Live stats were capped at {self.settings.stats_max_rows:,} rows "
                    "per proxy type."
                )

            duration_ms = round((time.monotonic() - started) * 1000, 1)
            now = time.time()
            payload = {
                "meta": _base_meta(
                    enabled=True,
                    endpoint=self._endpoint(),
                    refresh_seconds=self.settings.stats_refresh_seconds,
                    warnings=warnings,
                ),
                "info": info,
                "summary": _summary(info, frontends, backends, servers),
                "frontends": frontends,
                "backends": backends,
                "servers": servers,
            }
            payload["meta"].update(
                {
                    "connected": True,
                    "generated_at": _now(),
                    "last_success": now,
                    "duration_ms": duration_ms,
                }
            )
            with self._lock:
                self._payload = payload
                self._consecutive_errors = 0
            if self._last_logged_error is not None:
                LOGGER.info("HAProxy live stats connection recovered")
                self._last_logged_error = None
        except Exception as exc:  # noqa: BLE001 - keep the last good snapshot visible
            error = str(exc) or exc.__class__.__name__
            duration_ms = round((time.monotonic() - started) * 1000, 1)
            with self._lock:
                self._consecutive_errors += 1
                meta = dict(self._payload["meta"])
                meta.update(
                    {
                        "connected": False,
                        "generated_at": _now(),
                        "last_error": error,
                        "consecutive_errors": self._consecutive_errors,
                        "duration_ms": duration_ms,
                        "warnings": [f"Live stats refresh failed: {error}"],
                    }
                )
                self._payload = {**self._payload, "meta": meta}
            if error != self._last_logged_error:
                LOGGER.warning("HAProxy live stats refresh failed: %s", error)
                self._last_logged_error = error

    def _fetch(self) -> tuple[dict[str, str], list[dict[str, str]]]:
        assert self.settings.stats_host is not None
        assert self.settings.stats_port is not None
        timeout = self.settings.stats_timeout_seconds
        chunks: list[bytes] = []
        total = 0
        with socket.create_connection(
            (self.settings.stats_host, self.settings.stats_port),
            timeout=timeout,
        ) as connection:
            deadline = time.monotonic() + timeout
            connection.settimeout(timeout)
            connection.sendall(LIVE_COMMAND)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise StatsSocketError("HAProxy response timed out.")
                connection.settimeout(remaining)
                chunk = connection.recv(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.settings.stats_max_bytes:
                    raise StatsSocketError(
                        f"HAProxy response exceeded {self.settings.stats_max_bytes:,} bytes."
                    )
                chunks.append(chunk)

        if not chunks:
            raise StatsSocketError("HAProxy returned an empty response.")
        text = b"".join(chunks).decode("utf-8", errors="replace")
        return parse_response(text)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return self._payload

    def status(self) -> dict[str, Any]:
        with self._lock:
            meta = self._payload["meta"]
            return {
                "enabled": meta.get("enabled", True),
                "connected": meta.get("connected", False),
                "endpoint": meta.get("endpoint"),
                "refresh_seconds": meta.get("refresh_seconds"),
                "last_success": meta.get("last_success"),
                "last_error": meta.get("last_error"),
                "consecutive_errors": meta.get("consecutive_errors", 0),
            }
