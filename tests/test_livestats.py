from __future__ import annotations

import csv
import io
import socket
import socketserver
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path

from haproxy_analytics.livestats import (
    LiveStatsService,
    StatsSocketError,
    disabled_payload,
    parse_response,
)

from tests.support import base_settings

STAT_HEADER = [
    "pxname",
    "svname",
    "scur",
    "smax",
    "slim",
    "stot",
    "bin",
    "bout",
    "status",
    "weight",
    "lastchg",
    "downtime",
    "type",
    "rate",
    "rate_max",
    "check_status",
    "check_health",
    "hrsp_1xx",
    "hrsp_2xx",
    "hrsp_3xx",
    "hrsp_4xx",
    "hrsp_5xx",
    "hrsp_other",
    "req_rate",
    "req_rate_max",
    "req_tot",
    "econ",
    "eresp",
    "wretr",
    "wredis",
    "rtime",
    "ttime",
    "mode",
    "addr",
]


def _csv_row(values: list[object]) -> str:
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\n").writerow(values)
    return buffer.getvalue()


def sample_response() -> bytes:
    info = "\n".join(
        [
            "Name: HAProxy",
            "Version: 3.0.30",
            "Release_date: 2026/10/01",
            "Nbproc: 1",
            "Nbthread: 4",
            "Uptime: 0d 0h01m02s",
            "Uptime_sec: 62",
            "Memmax_MB: 0",
            "PoolAlloc_MB: 12",
            "PoolUsed_MB: 4",
            "PoolFailed: 0",
            "CurrConns: 3",
            "CumConns: 100",
            "ConnRate: 2",
            "MaxConnRate: 10",
            "MaxConn: 2000",
            "CurrSslConns: 1",
            "CumSslConns: 50",
            "SslRate: 1",
            "MaxSslRate: 5",
            "Tasks: 20",
            "Run_queue: 0",
            "Idle_pct: 99",
            "DroppedLogs: 0",
            "FailedResolutions: 0",
        ]
    )
    rows = [
        [
            "fe_http",
            "FRONTEND",
            3,
            10,
            2000,
            100,
            5000,
            9000,
            "OPEN",
            0,
            0,
            0,
            0,
            2,
            10,
            "",
            None,
            0,
            90,
            5,
            3,
            2,
            0,
            2,
            10,
            100,
            0,
            0,
            0,
            0,
            1,
            2,
            "http",
            "",
        ],
        [
            "bk_app",
            "BACKEND",
            3,
            10,
            2000,
            100,
            5000,
            9000,
            "UP",
            1,
            62,
            0,
            1,
            2,
            10,
            "",
            None,
            0,
            90,
            5,
            3,
            2,
            0,
            2,
            10,
            100,
            0,
            0,
            0,
            0,
            1,
            2,
            "http",
            "",
        ],
        [
            "bk_app",
            "app1",
            3,
            10,
            2000,
            100,
            5000,
            9000,
            "UP",
            1,
            62,
            0,
            2,
            2,
            10,
            "L4OK",
            3,
            0,
            90,
            5,
            3,
            2,
            0,
            2,
            10,
            100,
            0,
            0,
            0,
            0,
            1,
            2,
            "http",
            "192.0.2.10:8080",
        ],
        [
            "bk_down",
            "BACKEND",
            0,
            0,
            10,
            0,
            0,
            0,
            "DOWN",
            1,
            0,
            120,
            1,
            0,
            0,
            "",
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            "http",
            "",
        ],
        [
            "bk_down",
            "down1",
            0,
            0,
            10,
            0,
            0,
            0,
            "DOWN",
            1,
            0,
            120,
            2,
            0,
            0,
            "L4CON",
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            "http",
            "192.0.2.11:8080",
        ],
    ]
    stat = "# " + ",".join(STAT_HEADER) + "\n"
    stat += "".join(_csv_row(row) for row in rows)
    return (info + "\n\n" + stat + "\n").encode("utf-8")


class _StatsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = b""
        while not data.endswith(b"\n"):
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data += chunk
        self.server.commands.append(data.decode("utf-8", errors="replace"))
        self.request.sendall(self.server.response)


class _StatsServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, response: bytes):
        self.response = response
        self.commands: list[str] = []
        super().__init__(("127.0.0.1", 0), _StatsHandler)


@contextmanager
def running_stats_server(response: bytes = sample_response()):
    server = _StatsServer(response)
    thread = threading.Thread(target=server.serve_forever, name="fake-stats", daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def service_settings(tmp_path: Path, server: _StatsServer, **overrides: object):
    values = {
        "stats_socket": f"127.0.0.1:{server.server_address[1]}",
        "stats_host": "127.0.0.1",
        "stats_port": server.server_address[1],
        "stats_refresh_seconds": 1,
        "stats_timeout_seconds": 2,
        "stats_max_bytes": 1024 * 1024,
        "stats_max_rows": 100,
    }
    values.update(overrides)
    return base_settings(tmp_path, **values)


class LiveStatsParserTests(unittest.TestCase):
    def test_parse_response(self) -> None:
        info, rows = parse_response(sample_response().decode("utf-8"))
        self.assertEqual(info["Version"], "3.0.30")
        self.assertEqual(info["Nbthread"], "4")
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0]["pxname"], "fe_http")

    def test_empty_response_is_rejected(self) -> None:
        with self.assertRaises(StatsSocketError):
            parse_response("")

    def test_runtime_api_error_is_rejected(self) -> None:
        with self.assertRaises(StatsSocketError):
            parse_response("Name: HAProxy\nPermission denied\n")


class LiveStatsServiceTests(unittest.TestCase):
    def test_service_fetches_and_omits_server_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as temp, running_stats_server() as server:
            service = LiveStatsService(service_settings(Path(temp), server))
            service.refresh_once()
            payload = service.snapshot()

            self.assertTrue(payload["meta"]["enabled"])
            self.assertTrue(payload["meta"]["connected"])
            self.assertIsNone(payload["meta"]["last_error"])
            self.assertEqual(payload["info"]["version"], "3.0.30")
            self.assertEqual(payload["info"]["threads"], 4)
            self.assertEqual(len(payload["frontends"]), 1)
            self.assertEqual(len(payload["backends"]), 2)
            self.assertEqual(len(payload["servers"]), 2)
            self.assertEqual(payload["summary"]["servers_up"], 1)
            self.assertEqual(payload["summary"]["servers_down"], 1)
            self.assertEqual(payload["summary"]["backends_down"], 1)
            self.assertEqual(payload["summary"]["http_5xx"], 2)
            self.assertNotIn("addr", payload["servers"][0])
            self.assertEqual(server.commands, ["show info;show stat\n"])

    def test_failure_keeps_a_stable_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                closed_port = probe.getsockname()[1]
            settings = base_settings(
                Path(temp),
                stats_socket=f"127.0.0.1:{closed_port}",
                stats_host="127.0.0.1",
                stats_port=closed_port,
                stats_timeout_seconds=1,
            )
            service = LiveStatsService(settings)
            with self.assertLogs("haproxy_analytics.livestats", level="WARNING"):
                service.refresh_once()
            payload = service.snapshot()

            self.assertTrue(payload["meta"]["enabled"])
            self.assertFalse(payload["meta"]["connected"])
            self.assertTrue(payload["meta"]["last_error"])
            self.assertEqual(payload["frontends"], [])
            self.assertEqual(payload["summary"]["current_sessions"], 0)

    def test_oversized_response_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp, running_stats_server(b"x" * 70000) as server:
            service = LiveStatsService(
                service_settings(Path(temp), server, stats_max_bytes=65536)
            )
            with self.assertLogs("haproxy_analytics.livestats", level="WARNING"):
                service.refresh_once()
            payload = service.snapshot()
            self.assertFalse(payload["meta"]["connected"])
            self.assertIn("exceeded", payload["meta"]["last_error"])

    def test_row_cap_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp, running_stats_server() as server:
            service = LiveStatsService(
                service_settings(Path(temp), server, stats_max_rows=1)
            )
            service.refresh_once()
            payload = service.snapshot()
            self.assertEqual(len(payload["backends"]), 1)
            self.assertTrue(payload["meta"]["warnings"])

    def test_disabled_payload(self) -> None:
        payload = disabled_payload()
        self.assertFalse(payload["meta"]["enabled"])
        self.assertTrue(payload["meta"]["read_only"])
        self.assertEqual(payload["frontends"], [])


if __name__ == "__main__":
    unittest.main()
