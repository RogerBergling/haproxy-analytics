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
        self.assertFalse(settings.goaccess_enabled)
        self.assertTrue(settings.mask_internal_ips)
        self.assertEqual(settings.mask_networks, ())

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

    def test_invalid_port(self) -> None:
        with patch.dict(os.environ, {"APP_PORT": "0"}, clear=True):
            with self.assertRaises(ConfigError):
                Settings.from_env()


if __name__ == "__main__":
    unittest.main()
