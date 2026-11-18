"""Snapshot service: parse sources, aggregate, and hold the latest result."""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .aggregate import Aggregator
from .config import Settings
from .geoip import GeoResolver
from .goaccess import GoAccessRunner, build_goaccess_line
from .logsource import SyslogServer, read_log_tail
from .parser import parse_line
from .privacy import mask_http_line
from .version import version_info

LOGGER = logging.getLogger(__name__)


def _empty_payload(message: str) -> dict[str, Any]:
    return {
        "meta": {
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "refresh_seconds": 60,
            "version": version_info(),
            "demo": False,
            "source": {"file": {"exists": False}, "syslog": {"enabled": False}},
            "geoip": {"city": False, "asn": False},
            "goaccess": {"enabled": False, "available": False, "generated": False, "error": None},
            "privacy": {"mask_internal_ips": True, "mask_networks": [], "mask_full": False},
            "parser": {"unparsed_lines": 0, "repeated_groups": 0, "events": 0},
            "warnings": [message],
            "duration_ms": 0,
        },
        "kpis": {
            "http_total": 0,
            "tls_total": 0,
            "unique_ips": 0,
            "countries": 0,
            "errors": 0,
            "bytes": 0,
            "geo_points": 0,
            "sni_hostnames": 0,
            "http_backends": 0,
            "no_sni": 0,
            "latest_seen": "-",
        },
        "http": {
            "total": 0,
            "bandwidth": 0,
            "errors": 0,
            "methods": [],
            "statuses": [],
            "backends": [],
            "paths": [],
            "countries": [],
            "asns": [],
        },
        "tls": {"total": 0, "snis": [], "no_sni": 0, "countries": [], "asns": [], "recent": []},
        "geo": {"countries": [], "cities": [], "points": [], "country_count": 0},
        "visitors": {
            "total": 0,
            "raw_total": 0,
            "masked": False,
            "rows": [],
            "truncated": False,
        },
        "parser": {"unparsed_lines": 0, "repeated_groups": 0, "events": 0},
    }


class SnapshotService:
    def __init__(self, settings: Settings, syslog: SyslogServer | None = None) -> None:
        self.settings = settings
        self.syslog = syslog
        self._lock = threading.Lock()
        self._refresh_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._snapshot: dict[str, Any] | None = None
        self._goaccess_html: str | None = None
        self._last_success: float | None = None
        self._last_error: str | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="snapshot-refresh", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.refresh_once()
            if self._stop.wait(self.settings.refresh_seconds):
                break

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None

    def refresh_once(self) -> None:
        with self._refresh_lock:
            self._refresh_once_locked()

    def _refresh_once_locked(self) -> None:
        started = time.monotonic()
        warnings: list[str] = []
        sources: list[str] = []
        file_meta: dict[str, Any] = {
            "path": str(self.settings.log_file) if self.settings.log_file else None,
            "exists": False,
            "size": 0,
            "bytes_read": 0,
            "truncated": False,
            "mtime": None,
        }
        syslog_info: dict[str, Any] = {"enabled": self.syslog is not None}
        if self.syslog is not None:
            syslog_info.update(self.syslog.info())

        try:
            lines: list[str] = []
            if self.settings.demo:
                demo_path = self.settings.demo_log
                if demo_path.is_file():
                    demo_lines, demo_meta = read_log_tail(demo_path, self.settings.max_log_bytes)
                    lines.extend(demo_lines)
                    file_meta = demo_meta
                    sources.append("demo")
                else:
                    warnings.append(f"Demo log not found at {demo_path}.")
            else:
                if self.settings.log_file:
                    file_lines, file_meta = read_log_tail(
                        self.settings.log_file, self.settings.max_log_bytes
                    )
                    if file_meta.get("exists"):
                        lines.extend(file_lines)
                        if file_meta.get("size", 0) > 0:
                            sources.append("file")
                    else:
                        if self.syslog is not None:
                            warnings.append(
                                f"Log file not found at {self.settings.log_file}; "
                                "using the syslog receiver."
                            )
                        else:
                            warnings.append(
                                f"Log file not found at {self.settings.log_file}. "
                                "Mount a log file or enable the syslog receiver."
                            )
                    if file_meta.get("truncated"):
                        warnings.append(
                            f"Only the last {self.settings.max_log_bytes:,} bytes of the log file "
                            "were read. Increase MAX_LOG_BYTES for a wider window."
                        )
                if self.syslog is not None:
                    syslog_lines: list[str] = []
                    store = self.syslog.store
                    if store is not None:
                        syslog_lines = store.read_lines(self.settings.max_log_bytes)
                    if not syslog_lines:
                        syslog_lines = self.syslog.buffer.snapshot()
                    if syslog_lines:
                        lines.extend(syslog_lines)
                        sources.append("syslog")
                    if store is not None and store.write_errors:
                        warnings.append(
                            f"{store.write_errors} syslog lines could not be written to "
                            f"{store.path}. Check the data directory permissions and disk space."
                        )
                    store_info = syslog_info.get("store") or {}
                    store_has_history = bool(
                        store_info.get("enabled") and store_info.get("total_bytes", 0)
                    )
                    if syslog_info.get("buffered", 0) == 0 and not store_has_history:
                        warnings.append(
                            "The syslog receiver is enabled but its in-memory buffer and "
                            "persistent store are empty."
                        )
                    if syslog_info.get("rejected", 0):
                        warnings.append(
                            f"{syslog_info['rejected']} syslog messages were rejected by the "
                            "source allowlist."
                        )
                    if syslog_info.get("dropped", 0):
                        warnings.append(
                            f"{syslog_info['dropped']} syslog messages were dropped because the "
                            "buffer or message limit was reached."
                        )
                    if self._syslog_is_loopback_only():
                        warnings.append(
                            "The syslog receiver currently allows loopback sources only. "
                            "Set SYSLOG_ALLOWED_NETWORKS to the sending host or relay network."
                        )

            if len(sources) > 1:
                warnings.append(
                    "Both file and syslog sources are active. If the same events are present in "
                    "both, they are counted twice."
                )
            if not sources and self.syslog is None:
                warnings.append(
                    "No events are available. Configure HAPROXY_LOG_FILE or SYSLOG_LISTEN, "
                    "or start with DEMO_MODE=true to explore the interface."
                )

            geo = GeoResolver(self.settings.geoip_city_db, self.settings.geoip_asn_db)
            geo_has_city = geo.has_city
            geo_has_asn = geo.has_asn
            geo_warnings = list(geo.warnings)
            aggregator = Aggregator(
                geo,
                self.settings.max_visitor_rows,
                max_request_rows=self.settings.max_request_rows,
                mask_internal_ips=self.settings.mask_internal_ips,
                mask_networks=self.settings.mask_networks,
                mask_full=self.settings.mask_full,
            )
            goaccess_lines: list[str] = []
            goaccess_cap = self.settings.goaccess_max_lines
            runner = GoAccessRunner(
                enabled=self.settings.goaccess_enabled,
                binary=self.settings.goaccess_binary,
                config=self.settings.goaccess_config,
                timeout=self.settings.goaccess_timeout,
                max_lines=self.settings.goaccess_max_lines,
                max_html_bytes=self.settings.goaccess_max_html_bytes,
                geoip_city_db=self.settings.geoip_city_db,
                geoip_asn_db=self.settings.geoip_asn_db,
            )
            use_standard_lines = runner.uses_standard_format()

            try:
                for line in lines:
                    parsed = parse_line(line)
                    if parsed is None:
                        if line.strip():
                            aggregator.record_unparsed()
                        continue
                    if parsed.event.count > 1:
                        aggregator.record_repeated()
                    aggregator.add(parsed)
                    if parsed.http_message and self.settings.goaccess_enabled:
                        frontends = self.settings.goaccess_frontends
                        if not frontends or parsed.event.frontend in frontends:
                            remaining = goaccess_cap - len(goaccess_lines)
                            if remaining > 0:
                                repeat = min(parsed.event.count, remaining)
                                if use_standard_lines:
                                    http_message = build_goaccess_line(
                                        parsed.event,
                                        self.settings.mask_networks,
                                        self.settings.mask_internal_ips,
                                        self.settings.mask_full,
                                    )
                                else:
                                    http_message = parsed.http_message
                                    if (
                                        self.settings.mask_internal_ips
                                        or self.settings.mask_networks
                                    ):
                                        http_message = mask_http_line(
                                            http_message,
                                            self.settings.mask_networks,
                                            self.settings.mask_internal_ips,
                                            self.settings.mask_full,
                                        )
                                goaccess_lines.extend([http_message] * repeat)
            finally:
                geo.close()

            data = aggregator.build()
            warnings.extend(geo_warnings)

            if aggregator.unparsed_lines:
                warnings.append(
                    f"{aggregator.unparsed_lines:,} non-empty lines did not match a supported "
                    "HAProxy format and were ignored."
                )

            goaccess_html: str | None = None
            goaccess_status = runner.status()
            if self.settings.goaccess_enabled:
                if self.settings.goaccess_frontends and not goaccess_lines:
                    warnings.append(
                        "GOACCESS_FRONTENDS is set but no HTTP lines from those frontends "
                        "were found. Check the configured names."
                    )
                goaccess_html, goaccess_status = runner.generate(goaccess_lines)
                if goaccess_status.get("error") and goaccess_status["error"] not in warnings:
                    warnings.append(goaccess_status["error"])
                if goaccess_status.get("skipped_lines"):
                    warnings.append(
                        f"{goaccess_status['skipped_lines']:,} HTTP events were omitted from "
                        "the GoAccess report because they could not be represented in the "
                        "standard GoAccess format."
                    )
                for warning in goaccess_status.get("config_warnings", []):
                    if warning not in warnings:
                        warnings.append(warning)

            data["meta"] = {
                "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                "refresh_seconds": self.settings.refresh_seconds,
                "version": version_info(),
                "demo": self.settings.demo,
                "source": {
                    "file": file_meta,
                    "syslog": syslog_info,
                    "active": sources,
                },
                "geoip": {
                    "city": geo_has_city,
                    "asn": geo_has_asn,
                    "city_path": str(self.settings.geoip_city_db),
                    "asn_path": str(self.settings.geoip_asn_db),
                },
                "goaccess": goaccess_status,
                "privacy": {
                    "mask_internal_ips": self.settings.mask_internal_ips,
                    "mask_networks": [str(network) for network in self.settings.mask_networks],
                    "mask_full": self.settings.mask_full,
                },
                "parser": data["parser"],
                "warnings": warnings,
                "duration_ms": round((time.monotonic() - started) * 1000, 1),
            }

            with self._lock:
                self._snapshot = data
                self._goaccess_html = goaccess_html
                self._last_success = time.time()
                self._last_error = None
        except Exception as exc:  # noqa: BLE001 - keep the last good snapshot visible
            LOGGER.exception("Snapshot refresh failed")
            with self._lock:
                self._last_error = str(exc)
                if self._snapshot is None:
                    self._snapshot = _empty_payload(f"Snapshot refresh failed: {exc}")
                    self._goaccess_html = None

    def clear_syslog_history(self) -> dict[str, Any]:
        if self.syslog is None or self.syslog.store is None:
            return {"cleared": False, "error": "No persistent syslog store is configured."}
        self.syslog.clear()
        self.refresh_once()
        return {"cleared": True, "store": self.syslog.store.info()}

    def _syslog_is_loopback_only(self) -> bool:
        if self.syslog is None:
            return False
        for network in self.syslog.allowed:
            if str(network) not in {"127.0.0.0/8", "::1/128"}:
                return False
        return True

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            if self._snapshot is None:
                return _empty_payload(
                    "The first snapshot is still being built. Refresh the page in a moment."
                )
            return self._snapshot

    def goaccess_html(self) -> str | None:
        with self._lock:
            return self._goaccess_html

    def health(self) -> dict[str, Any]:
        with self._lock:
            age = None if self._last_success is None else round(time.time() - self._last_success, 1)
            return {
                "status": "ok" if self._last_success is not None and not self._last_error else "degraded",
                "last_success": self._last_success,
                "last_error": self._last_error,
                "snapshot_age_seconds": age,
                "refresh_seconds": self.settings.refresh_seconds,
                "version": version_info(),
            }
