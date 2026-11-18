from __future__ import annotations

import http.client
import ipaddress
import json
import stat
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path

from haproxy_analytics.server import create_server
from haproxy_analytics.snapshot import SnapshotService

from tests.support import demo_settings

FAKE_GOACCESS = """#!/usr/bin/env python3
import sys
from pathlib import Path

args = sys.argv[1:]
output = Path(args[args.index("-o") + 1])
output.write_text("<!doctype html><title>fake goaccess</title>", encoding="utf-8")
"""


@contextmanager
def running_server(settings):
    settings = settings.with_overrides(port=0)
    service = SnapshotService(settings)
    service.refresh_once()
    server = create_server(settings, service)
    thread = threading.Thread(target=server.serve_forever, name="test-http", daemon=True)
    thread.start()
    try:
        yield server.server_address[1], service
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        service.stop()


def request(port: int, method: str, path: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        body = response.read()
        return response.status, {key.lower(): value for key, value in response.getheaders()}, body
    finally:
        connection.close()


class ServerTests(unittest.TestCase):
    def test_dashboard_and_security_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temp, running_server(demo_settings(Path(temp))) as (port, _service):
            status, headers, body = request(port, "GET", "/")
            self.assertEqual(status, 200)
            self.assertIn("HAProxy Analytics", body.decode("utf-8"))
            self.assertIn("default-src 'none'", headers["content-security-policy"])
            self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
            self.assertEqual(headers["x-content-type-options"], "nosniff")
            self.assertEqual(headers["x-frame-options"], "DENY")
            self.assertEqual(headers["referrer-policy"], "no-referrer")
            self.assertIn("no-store", headers["cache-control"])

    def test_snapshot_api(self) -> None:
        with tempfile.TemporaryDirectory() as temp, running_server(demo_settings(Path(temp))) as (port, _service):
            status, headers, body = request(port, "GET", "/api/snapshot")
            self.assertEqual(status, 200)
            self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
            payload = json.loads(body)
            self.assertEqual(payload["kpis"]["http_total"], 20)
            self.assertEqual(payload["kpis"]["tls_total"], 12)
            self.assertTrue(payload["meta"]["demo"])

    def test_whoami_without_trusted_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as temp, running_server(demo_settings(Path(temp))) as (port, _service):
            status, _headers, body = request(
                port, "GET", "/api/whoami", headers={"X-Forwarded-For": "203.0.113.5"}
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["ip"], "127.0.0.1")

    def test_whoami_with_trusted_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            settings = demo_settings(
                Path(temp),
                trusted_proxies=(ipaddress.ip_network("127.0.0.1/32"),),
            )
            with running_server(settings) as (port, _service):
                status, _headers, body = request(
                    port,
                    "GET",
                    "/api/whoami",
                    headers={"X-Forwarded-For": "203.0.113.5, 127.0.0.1"},
                )
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["ip"], "203.0.113.5")


    def test_whoami_masks_internal_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            settings = demo_settings(Path(temp), mask_internal_ips=True)
            with running_server(settings) as (port, _service):
                status, _headers, body = request(port, "GET", "/api/whoami")
                payload = json.loads(body)
                self.assertEqual(status, 200)
                self.assertEqual(payload["ip"], "127.0.x.x")
                self.assertTrue(payload["masked"])

    def test_whoami_leaves_public_ip_unmasked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            settings = demo_settings(
                Path(temp),
                mask_internal_ips=True,
                trusted_proxies=(ipaddress.ip_network("127.0.0.1/32"),),
            )
            with running_server(settings) as (port, _service):
                status, _headers, body = request(
                    port,
                    "GET",
                    "/api/whoami",
                    headers={"X-Forwarded-For": "8.8.8.8"},
                )
                payload = json.loads(body)
                self.assertEqual(status, 200)
                self.assertEqual(payload["ip"], "8.8.8.8")
                self.assertFalse(payload["masked"])


    def test_whoami_masks_configured_network(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            settings = demo_settings(
                Path(temp),
                mask_internal_ips=False,
                mask_networks=(ipaddress.ip_network("192.0.0.0/8"),),
                trusted_proxies=(ipaddress.ip_network("127.0.0.1/32"),),
            )
            with running_server(settings) as (port, _service):
                status, _headers, body = request(
                    port,
                    "GET",
                    "/api/whoami",
                    headers={"X-Forwarded-For": "192.1.2.3"},
                )
                payload = json.loads(body)
                self.assertEqual(status, 200)
                self.assertEqual(payload["ip"], "192.x.x.x")
                self.assertTrue(payload["masked"])

    def test_whoami_leaves_private_ip_unmasked_when_only_networks_are_masked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            settings = demo_settings(
                Path(temp),
                mask_internal_ips=False,
                mask_networks=(ipaddress.ip_network("192.0.0.0/8"),),
                trusted_proxies=(ipaddress.ip_network("127.0.0.1/32"),),
            )
            with running_server(settings) as (port, _service):
                status, _headers, body = request(
                    port,
                    "GET",
                    "/api/whoami",
                    headers={"X-Forwarded-For": "198.51.100.20"},
                )
                payload = json.loads(body)
                self.assertEqual(status, 200)
                self.assertEqual(payload["ip"], "198.51.100.20")
                self.assertFalse(payload["masked"])


    def test_whoami_full_mask(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            settings = demo_settings(
                Path(temp),
                mask_internal_ips=False,
                mask_networks=(ipaddress.ip_network("192.0.0.0/8"),),
                mask_full=True,
                trusted_proxies=(ipaddress.ip_network("127.0.0.1/32"),),
            )
            with running_server(settings) as (port, _service):
                status, _headers, body = request(
                    port,
                    "GET",
                    "/api/whoami",
                    headers={"X-Forwarded-For": "192.0.2.10"},
                )
                payload = json.loads(body)
                self.assertEqual(status, 200)
                self.assertEqual(payload["ip"], "x.x.x.x")
                self.assertTrue(payload["masked"])

    def test_snapshot_reports_masking(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            settings = demo_settings(Path(temp), mask_internal_ips=True)
            with running_server(settings) as (port, _service):
                status, _headers, body = request(port, "GET", "/api/snapshot")
                payload = json.loads(body)
                self.assertEqual(status, 200)
                self.assertTrue(payload["visitors"]["masked"])
                self.assertTrue(payload["meta"]["privacy"]["mask_internal_ips"])

    def test_health_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp, running_server(demo_settings(Path(temp))) as (port, _service):
            status, _headers, body = request(port, "GET", "/healthz")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["status"], "ok")

            status, _headers, body = request(port, "GET", "/version.json")
            self.assertEqual(status, 200)
            self.assertIn("version", json.loads(body))

    def test_static_assets(self) -> None:
        with tempfile.TemporaryDirectory() as temp, running_server(demo_settings(Path(temp))) as (port, _service):
            status, headers, body = request(port, "GET", "/assets/app.css")
            self.assertEqual(status, 200)
            self.assertIn("text/css", headers["content-type"])
            self.assertIn(b"--accent", body)

    def test_goaccess_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp, running_server(demo_settings(Path(temp))) as (port, _service):
            status, _headers, _body = request(port, "GET", "/goaccess")
            self.assertEqual(status, 404)

    def test_goaccess_report_is_sandboxed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            binary = temp_path / "goaccess"
            binary.write_text(FAKE_GOACCESS, encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            config = temp_path / "goaccess.conf"
            config.write_text("time-format %H:%M:%S\n", encoding="utf-8")
            settings = demo_settings(
                temp_path,
                goaccess_enabled=True,
                goaccess_binary=str(binary),
                goaccess_config=config,
            )
            with running_server(settings) as (port, _service):
                status, headers, body = request(port, "GET", "/goaccess")
                self.assertEqual(status, 200)
                self.assertIn("text/html", headers["content-type"])
                self.assertIn("sandbox allow-scripts", headers["content-security-policy"])
                self.assertIn("frame-ancestors 'self'", headers["content-security-policy"])
                self.assertIn(b"fake goaccess", body)

    def test_post_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp, running_server(demo_settings(Path(temp))) as (port, _service):
            status, headers, _body = request(port, "POST", "/")
            self.assertEqual(status, 405)
            self.assertEqual(headers["allow"], "GET, HEAD")

    def test_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp, running_server(demo_settings(Path(temp))) as (port, _service):
            for path in (
                "/assets/../haproxy_analytics/__init__.py",
                "/assets/%2e%2e/haproxy_analytics/__init__.py",
                "/assets/..%2fhaproxy_analytics%2f__init__.py",
            ):
                status, _headers, _body = request(port, "GET", path)
                self.assertEqual(status, 404, path)

    def test_head_has_no_body(self) -> None:
        with tempfile.TemporaryDirectory() as temp, running_server(demo_settings(Path(temp))) as (port, _service):
            status, headers, body = request(port, "HEAD", "/")
            self.assertEqual(status, 200)
            self.assertEqual(body, b"")
            self.assertGreater(int(headers["content-length"]), 0)


if __name__ == "__main__":
    unittest.main()
