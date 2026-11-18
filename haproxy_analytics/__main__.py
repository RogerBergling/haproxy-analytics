"""Command-line entry point for HAProxy Analytics."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys

from .config import ConfigError, Settings
from .logsource import SyslogBuffer, SyslogServer
from .server import create_server
from .snapshot import SnapshotService
from .version import version_info

LOGGER = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="haproxy-analytics",
        description="Read-only HAProxy HTTP, TLS/SNI and GeoIP analytics dashboard.",
    )
    parser.add_argument("--bind", help="HTTP bind address (environment: APP_BIND)")
    parser.add_argument("--port", type=int, help="HTTP port (environment: APP_PORT)")
    parser.add_argument("--log", help="HAProxy log file (environment: HAPROXY_LOG_FILE)")
    parser.add_argument("--refresh", type=int, help="Refresh interval in seconds")
    parser.add_argument("--geoip-city", help="GeoLite2 City MMDB path")
    parser.add_argument("--geoip-asn", help="GeoLite2 ASN MMDB path")
    parser.add_argument("--syslog-listen", help="Syslog listen address, for example 0.0.0.0:5514")
    parser.add_argument("--demo", action="store_true", help="Use the bundled synthetic demo log")
    parser.add_argument("--log-level", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    return parser


def _apply_cli_overrides(args: argparse.Namespace) -> None:
    mapping = {
        "bind": "APP_BIND",
        "port": "APP_PORT",
        "log": "HAPROXY_LOG_FILE",
        "refresh": "REFRESH_SECONDS",
        "geoip_city": "GEOIP_CITY_DB",
        "geoip_asn": "GEOIP_ASN_DB",
        "syslog_listen": "SYSLOG_LISTEN",
        "log_level": "LOG_LEVEL",
    }
    for attribute, environment in mapping.items():
        value = getattr(args, attribute, None)
        if value is not None:
            os.environ[environment] = str(value)
    if args.demo:
        os.environ["DEMO_MODE"] = "true"


def _handle_signal(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.version:
        info = version_info()
        print(f"HAProxy Analytics {info['version']} ({info['commit']})")
        return 0

    _apply_cli_overrides(args)
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    syslog_server: SyslogServer | None = None
    if settings.syslog_listen:
        assert settings.syslog_host is not None and settings.syslog_port is not None
        buffer = SyslogBuffer(settings.syslog_buffer_lines)
        syslog_server = SyslogServer(
            host=settings.syslog_host,
            port=settings.syslog_port,
            protocols=settings.syslog_protocols,
            allowed=settings.syslog_allowed_networks,
            buffer=buffer,
            max_message_bytes=settings.syslog_max_message_bytes,
            tls_cert=settings.syslog_tls_cert,
            tls_key=settings.syslog_tls_key,
            tls_ca=settings.syslog_tls_ca,
            require_client_cert=settings.syslog_tls_require_client_cert,
        )
        try:
            syslog_server.start()
        except OSError as exc:
            LOGGER.error("Could not start the syslog receiver: %s", exc)
            syslog_server.stop()
            return 1

    service = SnapshotService(settings, syslog_server)
    service.start()

    try:
        server = create_server(settings, service)
    except OSError as exc:
        LOGGER.error("Could not start the dashboard server on %s:%s: %s", settings.bind, settings.port, exc)
        service.stop()
        if syslog_server:
            syslog_server.stop()
        return 1

    print(
        f"HAProxy Analytics is serving on http://{settings.bind}:{settings.port}/ "
        f"(refresh every {settings.refresh_seconds}s)",
        flush=True,
    )
    if settings.demo:
        print("Demo mode is active. All values come from the bundled synthetic log.", flush=True)

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        service.stop()
        if syslog_server:
            syslog_server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
