from __future__ import annotations

import ipaddress
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from haproxy_analytics.logsource import (
    SyslogBuffer,
    SyslogServer,
    read_log_tail,
)
from haproxy_analytics.syslog_store import SyslogStore


def wait_for(predicate, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


class LogSourceTests(unittest.TestCase):
    def test_read_tail_discards_partial_line(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "haproxy.log"
            source_lines = [f"{index:03d} " + "x" * 60 for index in range(100)]
            path.write_text("\n".join(source_lines) + "\n", encoding="utf-8")
            lines, meta = read_log_tail(path, 500)

        self.assertTrue(meta["exists"])
        self.assertTrue(meta["truncated"])
        self.assertGreater(len(lines), 0)
        for line in lines:
            self.assertIn(line, source_lines)

    def test_missing_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            lines, meta = read_log_tail(Path(temp) / "missing.log", 1024)
        self.assertEqual(lines, [])
        self.assertFalse(meta["exists"])

    def test_syslog_buffer_is_bounded(self) -> None:
        buffer = SyslogBuffer(2)
        buffer.append("one")
        buffer.append("two")
        buffer.append("three")
        self.assertEqual(buffer.snapshot(), ["two", "three"])
        self.assertEqual(buffer.info()["dropped"], 1)

    def test_udp_receiver_accepts_allowed_source(self) -> None:
        buffer = SyslogBuffer(100)
        server = SyslogServer(
            host="127.0.0.1",
            port=0,
            protocols=("udp",),
            allowed=(ipaddress.ip_network("127.0.0.0/8"),),
            buffer=buffer,
            max_message_bytes=65536,
        )
        server.start()
        try:
            port = server.bound[0]["port"]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(b"Nov 18 00:00:00 demo haproxy[1]: src=203.0.113.1 dst=198.51.100.1:443 sni=example.com", ("127.0.0.1", port))
            self.assertTrue(wait_for(lambda: buffer.info()["buffered"] == 1))
            self.assertIn("sni=example.com", buffer.snapshot()[0])
        finally:
            server.stop()

    def test_udp_receiver_rejects_untrusted_source(self) -> None:
        buffer = SyslogBuffer(100)
        server = SyslogServer(
            host="127.0.0.1",
            port=0,
            protocols=("udp",),
            allowed=(ipaddress.ip_network("192.0.2.0/24"),),
            buffer=buffer,
            max_message_bytes=65536,
        )
        server.start()
        try:
            port = server.bound[0]["port"]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(b"untrusted", ("127.0.0.1", port))
            self.assertTrue(wait_for(lambda: buffer.info()["rejected"] == 1))
            self.assertEqual(buffer.snapshot(), [])
        finally:
            server.stop()

    def test_tcp_receiver_accepts_allowed_source(self) -> None:
        buffer = SyslogBuffer(100)
        server = SyslogServer(
            host="127.0.0.1",
            port=0,
            protocols=("tcp",),
            allowed=(ipaddress.ip_network("127.0.0.0/8"),),
            buffer=buffer,
            max_message_bytes=65536,
        )
        server.start()
        try:
            port = server.bound[0]["port"]
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.sendall(b"Nov 18 00:00:00 demo haproxy[1]: src=203.0.113.2 dst=198.51.100.1:443 sni=tcp.example.com\n")
            self.assertTrue(wait_for(lambda: buffer.info()["buffered"] == 1))
            self.assertIn("tcp.example.com", buffer.snapshot()[0])
        finally:
            server.stop()

    @unittest.skipUnless(shutil.which("openssl"), "openssl is not installed")
    def test_tcp_tls_receiver(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            cert = temp_path / "cert.pem"
            key = temp_path / "key.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                ],
                check=True,
                capture_output=True,
            )
            buffer = SyslogBuffer(100)
            server = SyslogServer(
                host="127.0.0.1",
                port=0,
                protocols=("tcp",),
                allowed=(ipaddress.ip_network("127.0.0.0/8"),),
                buffer=buffer,
                max_message_bytes=65536,
                tls_cert=cert,
                tls_key=key,
            )
            server.start()
            try:
                port = server.bound[0]["port"]
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                    with context.wrap_socket(raw, server_hostname="localhost") as tls:
                        tls.sendall(
                            b"Nov 18 00:00:00 demo haproxy[1]: src=203.0.113.3 "
                            b"dst=198.51.100.1:443 sni=tls.example.com\n"
                        )
                self.assertTrue(wait_for(lambda: buffer.info()["buffered"] == 1))
                self.assertIn("tls.example.com", buffer.snapshot()[0])
            finally:
                server.stop()


    def test_udp_receiver_persists_to_store(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = SyslogStore(Path(temp) / "syslog.log", max_bytes=1024 * 1024, backups=1)
            buffer = SyslogBuffer(100)
            server = SyslogServer(
                host="127.0.0.1",
                port=0,
                protocols=("udp",),
                allowed=(ipaddress.ip_network("127.0.0.0/8"),),
                buffer=buffer,
                max_message_bytes=65536,
                store=store,
            )
            server.start()
            try:
                port = server.bound[0]["port"]
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.sendto(
                        b"Nov 18 00:00:00 demo haproxy[1]: src=203.0.113.1 "
                        b"dst=198.51.100.1:443 sni=stored.example.com",
                        ("127.0.0.1", port),
                    )
                self.assertTrue(wait_for(lambda: store.info()["total_bytes"] > 0))
                self.assertIn("stored.example.com", " ".join(store.read_lines(1024)))
            finally:
                server.stop()
                store.close()

    def test_oversized_udp_message_is_dropped(self) -> None:
        buffer = SyslogBuffer(100)
        server = SyslogServer(
            host="127.0.0.1",
            port=0,
            protocols=("udp",),
            allowed=(ipaddress.ip_network("127.0.0.0/8"),),
            buffer=buffer,
            max_message_bytes=8,
        )
        server.start()
        try:
            port = server.bound[0]["port"]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(b"this message is too large", ("127.0.0.1", port))
            self.assertTrue(wait_for(lambda: buffer.info()["dropped"] == 1))
            self.assertEqual(buffer.snapshot(), [])
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
