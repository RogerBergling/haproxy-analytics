"""Environment and command-line configuration.

All values have safe local-development defaults. The container image sets
container-friendly paths through environment variables; Compose supplies the
deployment-specific paths and secrets through .env.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, replace
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PUBLIC_DIR = PROJECT_ROOT / "public"
DEFAULT_DEMO_LOG = PROJECT_ROOT / "examples" / "demo-haproxy.log"


class ConfigError(ValueError):
    """Raised when an environment value cannot be used safely."""


IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name)
    if not raw:
        return default
    value = raw.lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean (true/false), got {raw!r}")


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}, got {value}")
    return value


def _env_csv(name: str) -> tuple[str, ...]:
    raw = _env(name)
    if not raw:
        return ()
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _parse_networks(name: str, values: tuple[str, ...]) -> tuple[IPNetwork, ...]:
    networks: list[IPNetwork] = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ConfigError(f"{name} contains an invalid network {value!r}: {exc}") from exc
    return tuple(networks)


def _parse_listen(value: str) -> tuple[str, int] | None:
    if not value:
        return None
    if value.startswith("["):
        host, separator, port_text = value[1:].partition("]:")
        if not separator:
            raise ConfigError(f"SYSLOG_LISTEN must look like [::]:5514, got {value!r}")
    else:
        host, separator, port_text = value.rpartition(":")
        if not separator:
            raise ConfigError(f"SYSLOG_LISTEN must look like 0.0.0.0:5514, got {value!r}")
    host = host or "127.0.0.1"
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ConfigError(f"SYSLOG_LISTEN has an invalid port: {value!r}") from exc
    if not 1 <= port <= 65535:
        raise ConfigError(f"SYSLOG_LISTEN port must be between 1 and 65535, got {port}")
    return host, port


def _resolve_path(value: str, default: Path) -> Path:
    if not value:
        return default
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


@dataclass(frozen=True)
class Settings:
    bind: str
    port: int
    public_dir: Path
    demo: bool
    demo_log: Path
    log_file: Path | None
    refresh_seconds: int
    max_log_bytes: int
    max_visitor_rows: int
    max_request_rows: int
    mask_internal_ips: bool
    mask_networks: tuple[IPNetwork, ...]
    mask_full: bool
    geoip_city_db: Path
    geoip_asn_db: Path
    trusted_proxies: tuple[IPNetwork, ...]
    syslog_listen: str | None
    syslog_host: str | None
    syslog_port: int | None
    syslog_protocols: tuple[str, ...]
    syslog_allowed_networks: tuple[IPNetwork, ...]
    syslog_buffer_lines: int
    syslog_max_message_bytes: int
    syslog_store_file: Path | None
    syslog_store_max_bytes: int
    syslog_store_backups: int
    syslog_tls_cert: Path | None
    syslog_tls_key: Path | None
    syslog_tls_ca: Path | None
    syslog_tls_require_client_cert: bool
    log_level: str

    @classmethod
    def from_env(cls) -> "Settings":
        public_dir = _resolve_path(_env("PUBLIC_DIR"), DEFAULT_PUBLIC_DIR)
        demo = _env_bool("DEMO_MODE", False)
        demo_log = _resolve_path(_env("DEMO_LOG"), DEFAULT_DEMO_LOG)

        log_file_value = _env("HAPROXY_LOG_FILE", "/logs/haproxy.log")
        log_file = _resolve_path(log_file_value, Path("/logs/haproxy.log")) if log_file_value else None

        listen_value = _env("SYSLOG_LISTEN")
        listen = _parse_listen(listen_value)

        protocols = tuple(item.lower() for item in _env_csv("SYSLOG_PROTOCOLS")) or ("udp",)
        for protocol in protocols:
            if protocol not in {"udp", "tcp"}:
                raise ConfigError(f"SYSLOG_PROTOCOLS supports udp and tcp, got {protocol!r}")

        tls_cert_value = _env("SYSLOG_TLS_CERT")
        tls_key_value = _env("SYSLOG_TLS_KEY")
        tls_ca_value = _env("SYSLOG_TLS_CA")
        tls_cert = Path(tls_cert_value) if tls_cert_value else None
        tls_key = Path(tls_key_value) if tls_key_value else None
        tls_ca = Path(tls_ca_value) if tls_ca_value else None
        if bool(tls_cert) != bool(tls_key):
            raise ConfigError("SYSLOG_TLS_CERT and SYSLOG_TLS_KEY must be set together")
        if tls_cert and "tcp" not in protocols:
            raise ConfigError("Syslog TLS requires tcp in SYSLOG_PROTOCOLS")
        if tls_ca and not tls_cert:
            raise ConfigError("SYSLOG_TLS_CA requires SYSLOG_TLS_CERT and SYSLOG_TLS_KEY")
        require_client_cert = _env_bool("SYSLOG_TLS_REQUIRE_CLIENT_CERT", False)
        if require_client_cert and not tls_ca:
            raise ConfigError("SYSLOG_TLS_REQUIRE_CLIENT_CERT requires SYSLOG_TLS_CA")
        if require_client_cert and not tls_cert:
            raise ConfigError("SYSLOG_TLS_REQUIRE_CLIENT_CERT requires syslog TCP TLS")

        allowed = _parse_networks(
            "SYSLOG_ALLOWED_NETWORKS",
            _env_csv("SYSLOG_ALLOWED_NETWORKS") or ("127.0.0.0/8", "::1/128"),
        )

        trusted = _parse_networks("TRUSTED_PROXIES", _env_csv("TRUSTED_PROXIES"))

        app_port = _env_int("APP_PORT", 8080, 1)
        if app_port > 65535:
            raise ConfigError(f"APP_PORT must be between 1 and 65535, got {app_port}")

        return cls(
            bind=_env("APP_BIND", "127.0.0.1"),
            port=app_port,
            public_dir=public_dir,
            demo=demo,
            demo_log=demo_log,
            log_file=log_file,
            refresh_seconds=_env_int("REFRESH_SECONDS", 60, 1),
            max_log_bytes=_env_int("MAX_LOG_BYTES", 32 * 1024 * 1024, 1024),
            max_visitor_rows=_env_int("MAX_VISITOR_ROWS", 5000, 1),
            max_request_rows=_env_int("MAX_REQUEST_ROWS", 2000, 1),
            mask_internal_ips=_env_bool("MASK_INTERNAL_IPS", True),
            mask_networks=_parse_networks("MASK_NETWORKS", _env_csv("MASK_NETWORKS")),
            mask_full=_env_bool("MASK_FULL", False),
            geoip_city_db=_resolve_path(_env("GEOIP_CITY_DB"), Path("/geoip/GeoLite2-City.mmdb")),
            geoip_asn_db=_resolve_path(_env("GEOIP_ASN_DB"), Path("/geoip/GeoLite2-ASN.mmdb")),
            trusted_proxies=trusted,
            syslog_listen=listen_value or None,
            syslog_host=listen[0] if listen else None,
            syslog_port=listen[1] if listen else None,
            syslog_protocols=protocols,
            syslog_allowed_networks=allowed,
            syslog_buffer_lines=_env_int("SYSLOG_BUFFER_LINES", 200000, 1),
            syslog_max_message_bytes=_env_int("SYSLOG_MAX_MESSAGE_BYTES", 65536, 256),
            syslog_store_file=(
                _resolve_path(_env("SYSLOG_STORE_FILE"), Path("/data/syslog.log"))
                if _env("SYSLOG_STORE_FILE")
                else None
            ),
            syslog_store_max_bytes=_env_int(
                "SYSLOG_STORE_MAX_BYTES", 512 * 1024 * 1024, 1024 * 1024
            ),
            syslog_store_backups=_env_int("SYSLOG_STORE_BACKUPS", 1, 0),
            syslog_tls_cert=tls_cert,
            syslog_tls_key=tls_key,
            syslog_tls_ca=tls_ca,
            syslog_tls_require_client_cert=require_client_cert,
            log_level=_env("LOG_LEVEL", "INFO").upper() or "INFO",
        )

    def with_overrides(self, **values: object) -> "Settings":
        """Return a copy with selected fields replaced (used by CLI flags)."""

        return replace(self, **values)
