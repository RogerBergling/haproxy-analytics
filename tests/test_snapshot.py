from __future__ import annotations

import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from haproxy_analytics.logsource import SyslogBuffer, SyslogServer
from haproxy_analytics.snapshot import SnapshotService

from tests.support import DEMO_LOG, PROJECT_ROOT, demo_settings


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
        self.assertEqual(len(snapshot["http"]["recent"]), 19)
        self.assertEqual(snapshot["http"]["recent_limit"], 2000)
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


    def test_excluded_domains_drop_matching_http_and_tls_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            log = temp_path / "haproxy.log"
            log.write_text(
                'Nov 18 00:00:00 demo haproxy[1]: src=203.0.113.10 '
                'dst=198.51.100.10:443 sni=private.example.com\n'
                'Nov 18 00:00:01 demo haproxy[1]: src=203.0.113.11 '
                'dst=198.51.100.10:443 sni=public.example.com\n'
                'Nov 18 00:00:02 demo haproxy[1]: 203.0.113.12:1234 '
                '[18/Nov/2026:00:00:02.000] ft_https bk_app/app1 0/0/1/2/3 200 1 '
                '{private.example.com} {} "GET /login?token=secret HTTP/1.1"\n'
                'Nov 18 00:00:03 demo haproxy[1]: 203.0.113.13:1234 '
                '[18/Nov/2026:00:00:03.000] ft_https bk_app/app1 0/0/1/2/3 200 1 '
                '{public.example.com} {} "GET /ok HTTP/1.1"\n'
                'Nov 18 00:00:04 demo haproxy[1]: 203.0.113.14:1234 '
                '[18/Nov/2026:00:00:04.000] ft_https bk_app/app1 0/0/1/2/3 200 1 '
                '"GET https://private.example.com/callback?secret HTTP/1.1"\n'
                'Nov 18 00:00:05 demo haproxy[1]: 203.0.113.15:1234 '
                '[18/Nov/2026:00:00:05.000] ft_https bk_app/app1 0/0/1/2/3 200 1 '
                '"GET /hidden HTTP/1.1"\n',
                encoding="utf-8",
            )
            settings = demo_settings(
                temp_path,
                demo=False,
                log_file=log,
                excluded_domains=("private.example.com",),
            )
            service = SnapshotService(settings)
            service.refresh_once()
            snapshot = service.snapshot()

        payload = json.dumps(snapshot)
        self.assertNotIn("token=secret", payload)
        self.assertNotIn("private.example.com", payload)
        self.assertNotIn("203.0.113.12", payload)
        self.assertNotIn("203.0.113.14", payload)
        self.assertEqual(snapshot["kpis"]["http_total"], 2)
        self.assertEqual(snapshot["kpis"]["tls_total"], 1)
        self.assertEqual(snapshot["parser"]["excluded_events"], 3)
        self.assertEqual(snapshot["meta"]["privacy"]["excluded_domains"], 1)
        self.assertEqual(snapshot["meta"]["privacy"]["excluded_events"], 3)
        self.assertIn("/hidden", payload)
        self.assertIn("/ok", payload)

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


    def test_request_rows_are_newest_first_and_capped(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            log = temp_path / "haproxy.log"
            log.write_text(
                'Nov 18 00:00:00 demo haproxy[1]: 203.0.113.10:1234 '
                '[18/Nov/2026:00:00:00.123] ft_web bk_app/app1 0/0/1/2/3 200 10 '
                '"GET /one HTTP/1.1"\n'
                'Nov 18 00:00:01 demo haproxy[1]: 203.0.113.11:1234 '
                '[18/Nov/2026:00:00:01.123] ft_web bk_app/app1 0/0/1/2/3 200 20 '
                '"GET /two HTTP/1.1"\n'
                'Nov 18 00:00:02 demo haproxy[1]: 203.0.113.12:1234 '
                '[18/Nov/2026:00:00:02.123] ft_web bk_app/app1 0/0/1/2/3 200 30 '
                '"GET /three HTTP/1.1"\n',
                encoding="utf-8",
            )
            settings = demo_settings(
                temp_path,
                demo=False,
                log_file=log,
                max_request_rows=2,
            )
            service = SnapshotService(settings)
            service.refresh_once()
            snapshot = service.snapshot()

        recent = snapshot["http"]["recent"]
        self.assertEqual(len(recent), 2)
        self.assertEqual(recent[0]["path"], "/three")
        self.assertEqual(recent[0]["method"], "GET")
        self.assertEqual(recent[0]["bytes"], 30)
        self.assertEqual(recent[0]["port"], "1234")
        self.assertEqual(recent[0]["server"], "app1")
        self.assertEqual(recent[1]["path"], "/two")
        self.assertEqual(snapshot["http"]["recent_limit"], 2)
        self.assertEqual(snapshot["http"]["total"], 3)

    def test_request_rows_mask_internal_ips_and_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            log = temp_path / "haproxy.log"
            log.write_text(
                'Nov 18 00:00:00 demo haproxy[1]: 192.0.2.20:1234 '
                '[18/Nov/2026:00:00:00.123] ft_web bk_app/app1 0/0/1/2/3 200 10 '
                '"GET http://192.0.2.20/admin HTTP/1.1"\n',
                encoding="utf-8",
            )
            settings = demo_settings(
                temp_path,
                demo=False,
                log_file=log,
                mask_internal_ips=True,
                mask_full=True,
            )
            service = SnapshotService(settings)
            service.refresh_once()
            snapshot = service.snapshot()

        row = snapshot["http"]["recent"][0]
        self.assertEqual(row["ip"], "x.x.x.x")
        self.assertEqual(row["path"], "http://x.x.x.x/admin")
        self.assertNotIn("192.0.2.20", json.dumps(snapshot))

    def test_http_detail_counters_and_per_ip_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            log = temp_path / "haproxy.log"
            log.write_text(
                'Nov 18 00:00:00 demo haproxy[1]: 203.0.113.10:1234 '
                '[18/Nov/2026:00:00:00.123] ft_web bk_app/app1 0/0/1/2/3 200 10 '
                '"GET /a HTTP/1.1"\n'
                'Nov 18 00:00:01 demo haproxy[1]: 203.0.113.10:1235 '
                '[18/Nov/2026:00:00:01.123] ft_web bk_app/app1 0/0/1/2/3 500 20 '
                '"GET /b HTTP/1.1"\n'
                'Nov 18 00:00:02 demo haproxy[1]: 203.0.113.11:1236 '
                '[18/Nov/2026:00:00:02.123] ft_web bk_api/api1 0/0/1/2/3 304 0 '
                '"GET /a HTTP/1.1"\n',
                encoding="utf-8",
            )
            settings = demo_settings(temp_path, demo=False, log_file=log)
            service = SnapshotService(settings)
            service.refresh_once()
            http = service.snapshot()["http"]

        self.assertEqual(http["total"], 3)
        self.assertEqual(http["unique_ips"], 2)
        self.assertEqual(http["bandwidth"], 30)
        self.assertEqual(http["avg_bytes"], 10)
        self.assertEqual(http["error_rate"], 33.3)
        classes = {item["name"]: item["count"] for item in http["status_classes"]}
        self.assertEqual(classes, {"2xx": 1, "3xx": 1, "4xx": 0, "5xx": 1, "other": 0})
        self.assertEqual(http["protocols"], [{"name": "HTTP/1.1", "count": 3}])
        paths = {item["name"]: item for item in http["paths"]}
        self.assertEqual(paths["/a"]["count"], 2)
        self.assertEqual(paths["/a"]["visitors"], 2)
        self.assertEqual(paths["/a"]["bytes"], 10)
        self.assertEqual(paths["/b"]["count"], 1)
        self.assertEqual(paths["/b"]["bytes"], 20)
        hourly = {item["name"]: item["count"] for item in http["hourly"]}
        self.assertEqual(hourly["00:00"], 3)
        self.assertEqual(sum(hourly.values()), 3)

        rows = {row["ip"]: row for row in http["ip_details"]}
        first = rows["203.0.113.10"]
        self.assertEqual(first["requests"], 2)
        self.assertEqual(first["bytes"], 30)
        self.assertEqual(first["errors"], 1)
        self.assertEqual(first["status_2xx"], 1)
        self.assertEqual(first["status_5xx"], 1)
        self.assertEqual(first["methods"], [{"name": "GET", "count": 2}])
        self.assertEqual({item["name"] for item in first["top_paths"]}, {"/a", "/b"})
        self.assertEqual(first["backends"], [{"name": "bk_app", "count": 2}])
        self.assertEqual(first["first_seen"], "2026-11-18 00:00:00")
        self.assertEqual(first["last_seen"], "2026-11-18 00:00:01")
        second = rows["203.0.113.11"]
        self.assertEqual(second["requests"], 1)
        self.assertEqual(second["status_3xx"], 1)

    def test_http_ip_details_group_masked_clients(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            log = temp_path / "haproxy.log"
            log.write_text(
                'Nov 18 00:00:00 demo haproxy[1]: 192.0.2.20:1234 '
                '[18/Nov/2026:00:00:00.123] ft_web bk_app/app1 0/0/1/2/3 200 10 '
                '"GET /a HTTP/1.1"\n'
                'Nov 18 00:00:01 demo haproxy[1]: 192.0.2.21:1235 '
                '[18/Nov/2026:00:00:01.123] ft_web bk_app/app1 0/0/1/2/3 200 20 '
                '"GET /b HTTP/1.1"\n',
                encoding="utf-8",
            )
            settings = demo_settings(
                temp_path,
                demo=False,
                log_file=log,
                mask_internal_ips=True,
                mask_full=True,
            )
            service = SnapshotService(settings)
            service.refresh_once()
            http = service.snapshot()["http"]

        self.assertEqual(http["unique_ips"], 2)
        self.assertEqual(len(http["ip_details"]), 1)
        self.assertEqual(http["ip_details"][0]["ip"], "x.x.x.x")
        self.assertEqual(http["ip_details"][0]["requests"], 2)

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


    def test_configured_networks_are_masked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            log = temp_path / "haproxy.log"
            log.write_text(
                'Nov 18 00:00:00 demo haproxy[1]: 192.0.2.10:1234 '
                '[18/Nov/2026:00:00:00.000] ft_https bk_app/app1 0/0/1/2/3 200 1 '
                '"GET /one HTTP/1.1"\n'
                'Nov 18 00:00:01 demo haproxy[1]: 172.0.0.5:1235 '
                '[18/Nov/2026:00:00:01.000] ft_https bk_app/app1 0/0/1/2/3 200 1 '
                '"GET /two HTTP/1.1"\n'
                'Nov 18 00:00:02 demo haproxy[1]: 8.8.8.8:1236 '
                '[18/Nov/2026:00:00:02.000] ft_https bk_app/app1 0/0/1/2/3 200 1 '
                '"GET /three HTTP/1.1"\n',
                encoding="utf-8",
            )
            settings = demo_settings(
                temp_path,
                demo=False,
                log_file=log,
                mask_internal_ips=False,
                mask_networks=(
                    ipaddress.ip_network("192.0.0.0/8"),
                    ipaddress.ip_network("172.0.0.0/8"),
                ),
            )
            service = SnapshotService(settings)
            service.refresh_once()
            snapshot = service.snapshot()

        ips = {row["ip"] for row in snapshot["visitors"]["rows"]}
        self.assertEqual(ips, {"192.x.x.x", "172.x.x.x", "8.8.8.8"})
        self.assertTrue(snapshot["visitors"]["masked"])
        payload = json.dumps(snapshot)
        self.assertNotIn("192.0.2.10", payload)
        self.assertNotIn("172.0.0.5", payload)


    def test_full_mask_groups_all_masked_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            log = temp_path / "haproxy.log"
            log.write_text(
                'Nov 18 00:00:00 demo haproxy[1]: 192.0.2.10:1234 '
                '[18/Nov/2026:00:00:00.000] ft_https bk_app/app1 0/0/1/2/3 200 1 '
                '"GET /one HTTP/1.1"\n'
                'Nov 18 00:00:01 demo haproxy[1]: 172.0.0.5:1235 '
                '[18/Nov/2026:00:00:01.000] ft_https bk_app/app1 0/0/1/2/3 200 1 '
                '"GET /two HTTP/1.1"\n'
                'Nov 18 00:00:02 demo haproxy[1]: 8.8.8.8:1236 '
                '[18/Nov/2026:00:00:02.000] ft_https bk_app/app1 0/0/1/2/3 200 1 '
                '"GET /three HTTP/1.1"\n',
                encoding="utf-8",
            )
            settings = demo_settings(
                temp_path,
                demo=False,
                log_file=log,
                mask_internal_ips=False,
                mask_networks=(
                    ipaddress.ip_network("192.0.0.0/8"),
                    ipaddress.ip_network("172.0.0.0/8"),
                ),
                mask_full=True,
            )
            service = SnapshotService(settings)
            service.refresh_once()
            snapshot = service.snapshot()

        ips = {row["ip"] for row in snapshot["visitors"]["rows"]}
        self.assertEqual(ips, {"x.x.x.x", "8.8.8.8"})
        self.assertEqual(snapshot["visitors"]["raw_total"], 3)
        self.assertEqual(snapshot["visitors"]["total"], 2)

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
