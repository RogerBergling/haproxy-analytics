from __future__ import annotations

import unittest

from haproxy_analytics.parser import HttpEvent, TlsEvent, parse_line


class ParserTests(unittest.TestCase):
    def test_standard_http_line(self) -> None:
        line = (
            'Nov 18 00:01:02 demo haproxy[1234]: 203.0.113.10:53124 '
            '[18/Nov/2026:00:01:02.123] ft_https bk_app/app1 0/0/1/2/3 200 5120 '
            '"GET /assets/app.css HTTP/1.1"'
        )
        parsed = parse_line(line)
        self.assertIsNotNone(parsed)
        event = parsed.event
        self.assertIsInstance(event, HttpEvent)
        self.assertEqual(event.ip, "203.0.113.10")
        self.assertEqual(event.frontend, "ft_https")
        self.assertEqual(event.backend, "bk_app")
        self.assertEqual(event.status, "200")
        self.assertEqual(event.bytes, 5120)
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/assets/app.css")
        self.assertEqual(event.protocol, "HTTP/1.1")
        self.assertEqual(event.timestamp_display, "2026-11-18 00:01:02")
        self.assertEqual(parsed.event.method, "GET")
        self.assertEqual(parsed.event.path, "/assets/app.css")

    def test_standard_http_line_with_captured_host(self) -> None:
        line = (
            'Nov 18 00:01:02 demo haproxy[1234]: 203.0.113.10:53124 '
            '[18/Nov/2026:00:01:02.123] ft_https bk_app/app1 0/0/1/2/3 200 5120 '
            '{App.Example.COM:443} {} "GET /private?token=secret HTTP/1.1"'
        )
        parsed = parse_line(line)
        self.assertIsNotNone(parsed)
        self.assertIsInstance(parsed.event, HttpEvent)
        self.assertEqual(parsed.event.hosts, ("app.example.com",))
        self.assertEqual(parsed.event.path, "/private?token=secret")

    def test_captured_host_does_not_have_to_be_first(self) -> None:
        line = (
            'Nov 18 00:01:02 demo haproxy[1234]: 203.0.113.10:53124 '
            '[18/Nov/2026:00:01:02.123] ft_https bk_app/app1 0/0/1/2/3 200 5120 '
            '{203.0.113.99|app.example.com} {} "GET /private HTTP/1.1"'
        )
        parsed = parse_line(line)
        self.assertIsNotNone(parsed)
        self.assertIsInstance(parsed.event, HttpEvent)
        self.assertIn("app.example.com", parsed.event.hosts)

    def test_ipv6_http_line(self) -> None:
        line = (
            'Nov 18 00:01:21 demo haproxy[2345]: [2001:0db8::0010]:53135 '
            '[18/Nov/2026:00:01:21.010] ft_https bk_app/app1 0/0/1/1/2 200 3072 '
            '"GET /ipv6 HTTP/1.1"'
        )
        parsed = parse_line(line)
        self.assertIsNotNone(parsed)
        self.assertIsInstance(parsed.event, HttpEvent)
        self.assertEqual(parsed.event.ip, "2001:db8::10")

    def test_tls_line(self) -> None:
        line = "Nov 18 00:01:03 demo haproxy[1234]: src=203.0.113.10 dst=198.51.100.10:443 sni=app.example.com"
        parsed = parse_line(line)
        self.assertIsNotNone(parsed)
        event = parsed.event
        self.assertIsInstance(event, TlsEvent)
        self.assertEqual(event.ip, "203.0.113.10")
        self.assertEqual(event.dst, "198.51.100.10:443")
        self.assertEqual(event.sni, "app.example.com")
        self.assertEqual(event.timestamp_display, "2026-11-18 00:01:03")

    def test_rfc5424_syslog_wrapper(self) -> None:
        line = (
            '<134>1 2026-11-18T00:01:02.123Z haproxy.example.com haproxy 1234 - - '
            '203.0.113.10:53124 [18/Nov/2026:00:01:02.123] ft_https bk_app/app1 '
            '0/0/1/2/3 200 5120 "GET /rfc5424 HTTP/1.1"'
        )
        parsed = parse_line(line)
        self.assertIsNotNone(parsed)
        self.assertIsInstance(parsed.event, HttpEvent)
        self.assertEqual(parsed.event.ip, "203.0.113.10")
        self.assertEqual(parsed.event.path, "/rfc5424")
        self.assertEqual(parsed.event.timestamp_display, "2026-11-18 00:01:02")

    def test_repeated_tls(self) -> None:
        line = (
            "Nov 18 00:01:25 demo haproxy[2345]: message repeated 3 times: "
            "[ src=203.0.113.30 dst=198.51.100.10:443 sni=api.example.com]"
        )
        parsed = parse_line(line)
        self.assertIsNotNone(parsed)
        self.assertIsInstance(parsed.event, TlsEvent)
        self.assertEqual(parsed.event.count, 3)

    def test_repeated_http(self) -> None:
        line = (
            "Nov 18 00:01:26 demo haproxy[2345]: message repeated 2 times: "
            '[ 203.0.113.40:53137 [18/Nov/2026:00:01:26.000] ft_https '
            'bk_static/static1 0/0/1/1/2 304 0 "GET /assets/app.js HTTP/1.1"]'
        )
        parsed = parse_line(line)
        self.assertIsNotNone(parsed)
        self.assertIsInstance(parsed.event, HttpEvent)
        self.assertEqual(parsed.event.count, 2)
        self.assertEqual(parsed.event.method, "GET")
        self.assertEqual(parsed.event.path, "/assets/app.js")

    def test_simple_http_format(self) -> None:
        line = (
            'Nov 18 00:01:28 demo haproxy[2345]: 203.0.113.40:53139 '
            '[18/Nov/2026:00:01:28.000] ft_https bk_app/app1 200 1024 '
            '"GET /simple-format HTTP/1.1"'
        )
        parsed = parse_line(line)
        self.assertIsNotNone(parsed)
        self.assertIsInstance(parsed.event, HttpEvent)
        self.assertEqual(parsed.event.status, "200")
        self.assertEqual(parsed.event.path, "/simple-format")

    def test_unquoted_request(self) -> None:
        line = (
            'Nov 18 00:01:30 demo haproxy[2345]: 203.0.113.50:53140 '
            '[18/Nov/2026:00:01:30.000] ft_https bk_app/app1 0/0/1/2/3 200 2048 '
            "GET /plain HTTP/1.1"
        )
        parsed = parse_line(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.event.path, "/plain")

    def test_unrelated_line_is_ignored(self) -> None:
        self.assertIsNone(parse_line("Nov 18 00:00:00 demo sshd[1]: Accepted publickey"))
        self.assertIsNone(parse_line(""))

    def test_missing_bytes_and_status(self) -> None:
        line = (
            'Nov 18 00:01:30 demo haproxy[2345]: 203.0.113.50:53140 '
            '[18/Nov/2026:00:01:30.000] ft_https bk_app/app1 0/0/1/2/3 --- - '
            '"GET /nope HTTP/1.1"'
        )
        parsed = parse_line(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.event.status, "---")
        self.assertEqual(parsed.event.bytes, 0)


if __name__ == "__main__":
    unittest.main()
