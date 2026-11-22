#!/usr/bin/env python3
"""Start the real server with demo data and check the critical HTTP contracts."""

from __future__ import annotations

import http.client
import json
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from haproxy_analytics.server import create_server  # noqa: E402
from haproxy_analytics.snapshot import SnapshotService  # noqa: E402
from tests.support import demo_settings  # noqa: E402


def request(port: int, method: str, path: str) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, {key.lower(): value for key, value in response.getheaders()}, response.read()
    finally:
        connection.close()


def main() -> int:
    with tempfile.TemporaryDirectory() as temp:
        service = SnapshotService(demo_settings(Path(temp)))
        service.refresh_once()
        server_settings = service.settings.with_overrides(port=0)
        server = create_server(server_settings, service)
        thread = threading.Thread(target=server.serve_forever, name="smoke-http", daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            checks = []

            status, headers, body = request(port, "GET", "/")
            checks.append(("dashboard", status == 200 and b"HAProxy Analytics" in body))
            checks.append(("main CSP", "default-src 'none'" in headers.get("content-security-policy", "")))
            checks.append(("frame denial", headers.get("x-frame-options") == "DENY"))

            status, _headers, body = request(port, "GET", "/api/snapshot")
            snapshot = json.loads(body) if status == 200 else {}
            checks.append(("snapshot API", status == 200 and snapshot.get("kpis", {}).get("http_total") == 20))

            status, _headers, body = request(port, "GET", "/api/live")
            live = json.loads(body) if status == 200 else {}
            checks.append(
                (
                    "live API",
                    status == 200
                    and live.get("meta", {}).get("enabled") is False
                    and live.get("frontends") == [],
                )
            )

            status, _headers, body = request(port, "GET", "/api/whoami")
            checks.append(("whoami API", status == 200 and json.loads(body).get("ip") == "127.0.0.1"))

            status, _headers, _body = request(port, "GET", "/healthz")
            checks.append(("health API", status == 200))

            status, _headers, _body = request(port, "GET", "/version.json")
            checks.append(("version API", status == 200))

            status, _headers, body = request(port, "GET", "/theme.js")
            checks.append(("theme API", status == 200 and b"window.__APP_THEME__" in body))

            for asset in ("/assets/app.css", "/assets/app.js", "/assets/world-dark.svg", "/favicon.svg"):
                status, _headers, _body = request(port, "GET", asset)
                checks.append((asset, status == 200))

            status, _headers, _body = request(port, "POST", "/")
            checks.append(("POST rejected", status == 405))

            status, _headers, _body = request(port, "GET", "/assets/../haproxy_analytics/__init__.py")
            checks.append(("traversal rejected", status == 404))

            failed = [name for name, passed in checks if not passed]
            for name, passed in checks:
                print(f"{'PASS' if passed else 'FAIL':4} {name}")
            if failed:
                print(f"Smoke test failed: {', '.join(failed)}", file=sys.stderr)
                return 1
            print("Smoke test passed.")
            return 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            service.stop()


if __name__ == "__main__":
    raise SystemExit(main())
