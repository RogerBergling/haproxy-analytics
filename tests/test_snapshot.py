from __future__ import annotations

import ipaddress
import json
import stat
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


    def test_internal_ips_are_masked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            service = SnapshotService(demo_settings(Path(temp), mask_internal_ips=True))
            service.refresh_once()
            snapshot = service.snapshot()

        self.assertTrue(snapshot["visitors"]["masked"])
        self.assertGreater(snapshot["visitors"]["raw_total"], snapshot["visitors"]["total"])
        payload = json.dumps(snapshot)
        for raw in (
            "203.0.113.10",
            "203.0.113.20",
            "192.0.2.10",
            "198.51.100.44",
            "2001:db8::10",
        ):
            self.assertNotIn(raw, payload)
        for row in snapshot["visitors"]["rows"]:
            self.assertTrue(
                row["ip"] in {"8.8.8.8", "1.1.1.1", "9.9.9.9"}
                or ".x.x" in row["ip"]
                or row["ip"].endswith("::x"),
                row["ip"],
            )


    def test_internal_ip_in_http_path_is_masked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            log = temp_path / "haproxy.log"
            log.write_text(
                'Nov 18 00:00:00 demo haproxy[1]: 203.0.113.10:1234 '
                '[18/Nov/2026:00:00:00.000] ft_https bk_app/app1 0/0/1/2/3 200 1 '
                '"GET http://192.0.2.20/admin HTTP/1.1"\n',
                encoding="utf-8",
            )
            settings = demo_settings(
                temp_path,
                demo=False,
                log_file=log,
                mask_internal_ips=True,
            )
            service = SnapshotService(settings)
            service.refresh_once()
            snapshot = service.snapshot()

        self.assertEqual(snapshot["http"]["paths"][0]["name"], "http://192.0.x.x/admin")
        self.assertNotIn("192.0.2.20", json.dumps(snapshot))


    def test_goaccess_input_is_masked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            log = temp_path / "haproxy.log"
            log.write_text(
                'Nov 18 00:00:00 demo haproxy[1]: 192.0.2.20:1234 '
                '[18/Nov/2026:00:00:00.000] ft_https bk_app/app1 0/0/1/2/3 200 1 '
                '"GET http://192.0.2.20/admin HTTP/1.1"\n',
                encoding="utf-8",
            )
            binary = temp_path / "goaccess"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "from pathlib import Path\n"
                "args = sys.argv[1:]\n"
                "source = Path(args[0])\n"
                "output = Path(args[args.index('-o') + 1])\n"
                "output.write_text(source.read_text(encoding='utf-8'), encoding='utf-8')\n",
                encoding="utf-8",
            )
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            config = temp_path / "goaccess.conf"
            config.write_text("time-format %H:%M:%S\n", encoding="utf-8")
            settings = demo_settings(
                temp_path,
                demo=False,
                log_file=log,
                mask_internal_ips=True,
                goaccess_enabled=True,
                goaccess_binary=str(binary),
                goaccess_config=config,
            )
            service = SnapshotService(settings)
            service.refresh_once()
            html = service.goaccess_html() or ""

        self.assertIn("192.0.x.x", html)
        self.assertNotIn("192.0.2.20", html)


    def test_internal_ips_in_sni_and_backends_are_masked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            log = temp_path / "haproxy.log"
            log.write_text(
                'Nov 18 00:00:00 demo haproxy[1]: 192.0.2.10:1234 '
                '[18/Nov/2026:00:00:00.000] ft_https 192.0.2.30/app1 0/0/1/2/3 200 1 '
                '"GET / HTTP/1.1"\n'
                'Nov 18 00:00:01 demo haproxy[1]: src=192.0.2.10 '
                'dst=198.51.100.10:443 sni=192.0.2.20\n',
                encoding="utf-8",
            )
            settings = demo_settings(
                temp_path,
                demo=False,
                log_file=log,
                mask_internal_ips=True,
            )
            service = SnapshotService(settings)
            service.refresh_once()
            snapshot = service.snapshot()

        self.assertEqual(snapshot["http"]["backends"][0]["name"], "192.0.x.x")
        self.assertEqual(snapshot["tls"]["snis"][0]["name"], "192.0.x.x")
        payload = json.dumps(snapshot)
        self.assertNotIn("192.0.2.20", payload)
        self.assertNotIn("192.0.2.30", payload)

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
