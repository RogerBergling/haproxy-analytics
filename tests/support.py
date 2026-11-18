"""Shared test helpers."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from haproxy_analytics.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEMO_LOG = PROJECT_ROOT / "examples" / "demo-haproxy.log"


def base_settings(tmp_path: Path, **overrides: object) -> Settings:
    with patch.dict(os.environ, {}, clear=True):
        settings = Settings.from_env()
    values = {
        "public_dir": PROJECT_ROOT / "public",
        "demo": False,
        "demo_log": DEMO_LOG,
        "log_file": None,
        "geoip_city_db": tmp_path / "missing-city.mmdb",
        "geoip_asn_db": tmp_path / "missing-asn.mmdb",
        "goaccess_enabled": False,
        "syslog_listen": None,
        "syslog_host": None,
        "syslog_port": None,
        "trusted_proxies": (),
        "refresh_seconds": 60,
    }
    values.update(overrides)
    return settings.with_overrides(**values)


def demo_settings(tmp_path: Path, **overrides: object) -> Settings:
    values = {"demo": True, "demo_log": DEMO_LOG, "log_file": None}
    values.update(overrides)
    return base_settings(tmp_path, **values)
