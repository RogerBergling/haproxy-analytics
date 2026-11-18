from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from haproxy_analytics.config import ConfigError, Settings


class ConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings.from_env()
        self.assertEqual(settings.bind, "127.0.0.1")
        self.assertEqual(settings.port, 8080)
        self.assertEqual(str(settings.log_file), "/logs/haproxy.log")
        self.assertIsNone(settings.syslog_listen)
        self.assertEqual(settings.trusted_proxies, ())
        self.assertTrue(settings.mask_internal_ips)
        self.assertEqual(settings.mask_networks, ())
        self.assertFalse(settings.mask_full)
        self.assertIsNone(settings.syslog_store_file)

    def test_empty_log_file_disables_file_source(self) -> None:
        with patch.dict(os.environ, {"HAPROXY_LOG_FILE": ""}, clear=True):
            settings = Settings.from_env()
        self.assertIsNone(settings.log_file)

    def test_invalid_syslog_listen(self) -> None:
        with patch.dict(os.environ, {"SYSLOG_LISTEN": "not-a-listen"}, clear=True):
            with self.assertRaises(ConfigError):
                Settings.from_env()

    def test_mask_networks(self) -> None:
        with patch.dict(
            os.environ,
            {"MASK_NETWORKS": "192.0.0.0/8,172.0.0.0/8"},
            clear=True,
        ):
            settings = Settings.from_env()
        self.assertEqual(
            {str(network) for network in settings.mask_networks},
            {"192.0.0.0/8", "172.0.0.0/8"},
        )

    def test_max_request_rows(self) -> None:
        with patch.dict(os.environ, {"MAX_REQUEST_ROWS": "25"}, clear=True):
            settings = Settings.from_env()
        self.assertEqual(settings.max_request_rows, 25)

    def test_syslog_store(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SYSLOG_STORE_FILE": "/data/syslog.log",
                "SYSLOG_STORE_MAX_BYTES": "1048576",
                "SYSLOG_STORE_BACKUPS": "2",
            },
            clear=True,
        ):
            settings = Settings.from_env()
        self.assertEqual(str(settings.syslog_store_file), "/data/syslog.log")
        self.assertEqual(settings.syslog_store_max_bytes, 1048576)
        self.assertEqual(settings.syslog_store_backups, 2)

    def test_mask_full(self) -> None:
        with patch.dict(os.environ, {"MASK_FULL": "true"}, clear=True):
            settings = Settings.from_env()
        self.assertTrue(settings.mask_full)

    def test_invalid_mask_network(self) -> None:
        with patch.dict(os.environ, {"MASK_NETWORKS": "not-a-network"}, clear=True):
            with self.assertRaises(ConfigError):
                Settings.from_env()

    def test_invalid_network(self) -> None:
        with patch.dict(os.environ, {"SYSLOG_ALLOWED_NETWORKS": "not-a-network"}, clear=True):
            with self.assertRaises(ConfigError):
                Settings.from_env()

    def test_tls_requires_tcp(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SYSLOG_LISTEN": "127.0.0.1:5514",
                "SYSLOG_PROTOCOLS": "udp",
                "SYSLOG_TLS_CERT": "/tmp/cert.pem",
                "SYSLOG_TLS_KEY": "/tmp/key.pem",
            },
            clear=True,
        ):
            with self.assertRaises(ConfigError):
                Settings.from_env()

    def test_tls_cert_and_key_must_pair(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SYSLOG_LISTEN": "127.0.0.1:5514",
                "SYSLOG_PROTOCOLS": "tcp",
                "SYSLOG_TLS_CERT": "/tmp/cert.pem",
            },
            clear=True,
        ):
            with self.assertRaises(ConfigError):
                Settings.from_env()

    def test_tls_ca_requires_certificate(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SYSLOG_LISTEN": "127.0.0.1:5514",
                "SYSLOG_PROTOCOLS": "tcp",
                "SYSLOG_TLS_CA": "/tmp/ca.pem",
            },
            clear=True,
        ):
            with self.assertRaises(ConfigError):
                Settings.from_env()

    def test_client_cert_requires_ca_and_tls(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SYSLOG_LISTEN": "127.0.0.1:5514",
                "SYSLOG_PROTOCOLS": "tcp",
                "SYSLOG_TLS_CERT": "/tmp/cert.pem",
                "SYSLOG_TLS_KEY": "/tmp/key.pem",
                "SYSLOG_TLS_REQUIRE_CLIENT_CERT": "true",
            },
            clear=True,
        ):
            with self.assertRaises(ConfigError):
                Settings.from_env()

    def test_syslog_default_allowlist_is_loopback(self) -> None:
        with patch.dict(os.environ, {"SYSLOG_LISTEN": "0.0.0.0:5514"}, clear=True):
            settings = Settings.from_env()
        self.assertEqual(
            {str(network) for network in settings.syslog_allowed_networks},
            {"127.0.0.0/8", "::1/128"},
        )

    def test_trusted_proxies(self) -> None:
        with patch.dict(os.environ, {"TRUSTED_PROXIES": "192.0.2.10/32,2001:db8::/32"}, clear=True):
            settings = Settings.from_env()
        self.assertEqual(len(settings.trusted_proxies), 2)

    def test_demo_mode(self) -> None:
        with patch.dict(os.environ, {"DEMO_MODE": "true"}, clear=True):
            settings = Settings.from_env()
        self.assertTrue(settings.demo)

    def test_stats_socket_defaults_disabled(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings.from_env()
        self.assertIsNone(settings.stats_socket)
        self.assertIsNone(settings.stats_host)
        self.assertIsNone(settings.stats_port)
        self.assertEqual(settings.stats_refresh_seconds, 5)
        self.assertEqual(settings.stats_timeout_seconds, 2)
        self.assertEqual(settings.stats_max_rows, 500)
        self.assertGreaterEqual(settings.stats_max_bytes, 65536)

    def test_stats_socket_ipv4(self) -> None:
        with patch.dict(
            os.environ,
            {
                "HAPROXY_STATS_SOCKET": "192.0.2.20:8404",
                "STATS_REFRESH_SECONDS": "10",
                "STATS_TIMEOUT_SECONDS": "3",
                "STATS_MAX_BYTES": "131072",
                "STATS_MAX_ROWS": "25",
            },
            clear=True,
        ):
            settings = Settings.from_env()
        self.assertEqual(settings.stats_host, "192.0.2.20")
        self.assertEqual(settings.stats_port, 8404)
        self.assertEqual(settings.stats_refresh_seconds, 10)
        self.assertEqual(settings.stats_timeout_seconds, 3)
        self.assertEqual(settings.stats_max_bytes, 131072)
        self.assertEqual(settings.stats_max_rows, 25)

    def test_stats_socket_ipv6(self) -> None:
        with patch.dict(
            os.environ,
            {"HAPROXY_STATS_SOCKET": "[2001:db8::20]:8404"},
            clear=True,
        ):
            settings = Settings.from_env()
        self.assertEqual(settings.stats_host, "2001:db8::20")
        self.assertEqual(settings.stats_port, 8404)

    def test_invalid_stats_socket(self) -> None:
        for value in (
            "not-a-socket",
            ":8404",
            "192.0.2.20:0",
            "192.0.2.20:70000",
            "192.0.2.20:8404:extra",
            "0.0.0.0:8404",
            "[::]:8404",
        ):
            with self.subTest(value=value):
                with patch.dict(
                    os.environ,
                    {"HAPROXY_STATS_SOCKET": value},
                    clear=True,
                ):
                    with self.assertRaises(ConfigError):
                        Settings.from_env()

    def test_invalid_port(self) -> None:
        with patch.dict(os.environ, {"APP_PORT": "0"}, clear=True):
            with self.assertRaises(ConfigError):
                Settings.from_env()


if __name__ == "__main__":
    unittest.main()
