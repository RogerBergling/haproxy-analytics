from __future__ import annotations

import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from haproxy_analytics.logsource import SyslogBuffer, SyslogServer
from haproxy_analytics.snapshot import SnapshotService

from tests.support import DEMO_LOG, demo_settings


class SnapshotTests(unittest.TestCase):
    def test_demo_snapshot_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            service = SnapshotService(demo_settings(Path(temp)))
            service.refresh_once()
            snapshot = service.snapshot()

        self.assertEqual(snapshot["kpis"]["http_total"], 20)
        self.assertEqual(snapshot["kpis"]["tls_total"], 12)
        self.assertEqual(snapshot["kpis"]["unique_ips"], 12)
        self.assertEqual(snapshot["kpis"]["errors"], 7)
        self.assertEqual(snapshot["kpis"]["bytes"], 53902)
        self.assertEqual(snapshot["tls"]["snis"][0], {"name": "api.example.com", "count": 5})
        self.assertEqual(snapshot["http"]["backends"][0], {"name": "bk_app", "count": 9})
        self.assertTrue(snapshot["meta"]["demo"])
        warnings = " ".join(snapshot["meta"]["warnings"]).lower()
        self.assertTrue("maxminddb" in warnings or "geoip" in warnings)
        self.assertGreater(len(snapshot["visitors"]["rows"]), 0)
        self.assertEqual(service.health()["status"], "ok")

    def test_missing_log_file_is_not_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            settings = demo_settings(Path(temp), demo=False, log_file=Path(temp) / "missing.log")
            service = SnapshotService(settings)
            service.refresh_once()
            snapshot = service.snapshot()

        self.assertEqual(snapshot["kpis"]["http_total"], 0)
        self.assertEqual(snapshot["kpis"]["tls_total"], 0)
        self.assertTrue(any("Log file not found" in warning for warning in snapshot["meta"]["warnings"]))

    def test_syslog_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            settings = demo_settings(Path(temp), demo=False, log_file=None)
            buffer = SyslogBuffer(1000)
            for line in DEMO_LOG.read_text(encoding="utf-8").splitlines():
                buffer.append(line)
            syslog = SyslogServer(
                host="127.0.0.1",
                port=0,
                protocols=("udp",),
                allowed=(ipaddress.ip_network("127.0.0.0/8"),),
                buffer=buffer,
                max_message_bytes=65536,
            )
            service = SnapshotService(settings, syslog)
            service.refresh_once()
            snapshot = service.snapshot()

        self.assertEqual(snapshot["kpis"]["http_total"], 20)
        self.assertEqual(snapshot["kpis"]["tls_total"], 12)
        self.assertTrue(snapshot["meta"]["source"]["syslog"]["enabled"])
        self.assertIn("syslog", snapshot["meta"]["source"]["active"])

    def test_goaccess_disabled_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            service = SnapshotService(demo_settings(Path(temp)))
            service.refresh_once()
            snapshot = service.snapshot()
        self.assertFalse(snapshot["meta"]["goaccess"]["enabled"])
        self.assertFalse(snapshot["meta"]["goaccess"]["generated"])

    def test_failed_refresh_keeps_last_good_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            service = SnapshotService(demo_settings(Path(temp)))
            service.refresh_once()
            self.assertEqual(service.snapshot()["kpis"]["http_total"], 20)

            with patch(
                "haproxy_analytics.snapshot.parse_line",
                side_effect=RuntimeError("simulated failure"),
            ), patch("haproxy_analytics.snapshot.LOGGER.exception"):
                service.refresh_once()

            self.assertEqual(service.snapshot()["kpis"]["http_total"], 20)
            self.assertIn("simulated failure", service.health()["last_error"] or "")


if __name__ == "__main__":
    unittest.main()
