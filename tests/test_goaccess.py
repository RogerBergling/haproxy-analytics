from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from haproxy_analytics.goaccess import GoAccessRunner


FAKE_GOACCESS = """#!/usr/bin/env python3
import sys
from pathlib import Path

args = sys.argv[1:]
output = Path(args[args.index("-o") + 1])
output.write_text("<!doctype html><title>fake goaccess</title>", encoding="utf-8")
"""

ECHO_GOACCESS = """#!/usr/bin/env python3
import sys
from pathlib import Path

args = sys.argv[1:]
source = Path(args[0])
output = Path(args[args.index("-o") + 1])
output.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
"""

CONFIG_ECHO_GOACCESS = """#!/usr/bin/env python3
import sys
from pathlib import Path

args = sys.argv[1:]
config = Path(args[args.index("-p") + 1])
output = Path(args[args.index("-o") + 1])
output.write_text(config.read_text(encoding="utf-8"), encoding="utf-8")
"""

ERROR_GOACCESS = """#!/usr/bin/env python3
import sys

print(sys.argv, file=sys.stderr)
print("Token '---' doesn't match specifier '%s'", file=sys.stderr)
print("Format Errors - Verify your log/date/time format", file=sys.stderr)
raise SystemExit(1)
"""

GEOIP_ERROR_GOACCESS = """#!/usr/bin/env python3
import sys

print("Unable to open GeoIP2 database /var/lib/GeoIP/GeoLite2-City.mmdb: Error", file=sys.stderr)
raise SystemExit(1)
"""

STANDARD_CONFIG = (
    "time-format %H:%M:%S\n"
    "date-format %d/%b/%Y\n"
    'log-format %h:%^ [%d:%t.%^] %^ %^ %^ %s %b %^ %^ %^ %^ %^ "%r"\n'
)

STANDARD_LINE = (
    '203.0.113.10:1234 [18/Nov/2026:00:00:00.123] ft_https bk_app/app1 '
    '0/0/1/2/3 200 1 - - ---- 1/1/1/1/0 0/0 "GET / HTTP/1.1"'
)


class GoAccessTests(unittest.TestCase):
    def test_disabled_runner_does_not_execute(self) -> None:
        runner = GoAccessRunner(
            enabled=False,
            binary="/definitely/missing/goaccess",
            config=Path("/definitely/missing.conf"),
            timeout=5,
            max_lines=100,
            max_html_bytes=10000,
        )
        html, status = runner.generate(["203.0.113.10 - - [18/Nov/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1"])
        self.assertIsNone(html)
        self.assertFalse(status["enabled"])
        self.assertFalse(status["generated"])

    def test_missing_binary_is_reported(self) -> None:
        runner = GoAccessRunner(
            enabled=True,
            binary="/definitely/missing/goaccess",
            config=Path("/definitely/missing.conf"),
            timeout=5,
            max_lines=100,
            max_html_bytes=10000,
        )
        html, status = runner.generate(["line"])
        self.assertIsNone(html)
        self.assertTrue(status["enabled"])
        self.assertFalse(status["available"])
        self.assertIn("not found", status["error"])

    def test_fake_goaccess_produces_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            binary = temp_path / "goaccess"
            binary.write_text(FAKE_GOACCESS, encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            config = temp_path / "goaccess.conf"
            config.write_text("time-format %H:%M:%S\n", encoding="utf-8")
            runner = GoAccessRunner(
                enabled=True,
                binary=str(binary),
                config=config,
                timeout=5,
                max_lines=100,
                max_html_bytes=10000,
            )
            html, status = runner.generate(['203.0.113.10 - - [18/Nov/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1'])
        self.assertIsNotNone(html)
        self.assertIn("fake goaccess", html)
        self.assertTrue(status["generated"])
        self.assertEqual(status["lines"], 1)

    def test_report_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            binary = temp_path / "goaccess"
            binary.write_text(FAKE_GOACCESS, encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            config = temp_path / "goaccess.conf"
            config.write_text("time-format %H:%M:%S\n", encoding="utf-8")
            runner = GoAccessRunner(
                enabled=True,
                binary=str(binary),
                config=config,
                timeout=5,
                max_lines=100,
                max_html_bytes=10,
            )
            html, status = runner.generate(["line"])
        self.assertIsNone(html)
        self.assertIn("larger than", status["error"])

    def test_standard_input_is_normalized_and_filtered(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            binary = temp_path / "goaccess"
            binary.write_text(ECHO_GOACCESS, encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            config = temp_path / "goaccess.conf"
            config.write_text(STANDARD_CONFIG, encoding="utf-8")
            runner = GoAccessRunner(
                enabled=True,
                binary=str(binary),
                config=config,
                timeout=5,
                max_lines=100,
                max_html_bytes=10000,
            )
            html, status = runner.generate(
                [
                    STANDARD_LINE,
                    '2001:db8::10:1234 [18/Nov/2026:00:00:01.123] ft_https bk_app/app1 '
                    '0/0/1/2/3 200 1 "GET / HTTP/1.1"',
                    '203.0.113.11:1234 [18/Nov/2026:00:00:02] ft_https bk_app/app1 '
                    '0/0/1/2/3 200 1 "GET / HTTP/1.1"',
                    '203.0.113.12:1234 [18/Nov/2026:00:00:03.123] ft_https bk_app/app1 '
                    '0/0/1/2/3 --- 0 "GET / HTTP/1.1"',
                    '203.0.113.13:1234 [18/Nov/2026:00:00:04.123] ft_https bk_app/app1 '
                    '200 1 "GET / HTTP/1.1"',
                ]
            )
        self.assertIsNotNone(html)
        assert html is not None
        self.assertIn("[2001:db8::10]:1234", html)
        self.assertIn("00:00:02.000", html)
        self.assertNotIn(" --- ", html)
        self.assertEqual(status["lines"], 3)
        self.assertEqual(status["skipped_lines"], 2)
        self.assertEqual(status["skipped_reasons"]["status"], 1)
        self.assertEqual(status["skipped_reasons"]["fields"], 1)

    def test_custom_format_does_not_filter_input(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            binary = temp_path / "goaccess"
            binary.write_text(ECHO_GOACCESS, encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            config = temp_path / "goaccess.conf"
            config.write_text(
                "time-format %H:%M:%S\n"
                "date-format %d/%b/%Y\n"
                "log-format %h:%^ [%d:%t.%^] %^ %^ %^ %s %b %^ %^ %^ %^ %^ %^ \"%r\"\n",
                encoding="utf-8",
            )
            runner = GoAccessRunner(
                enabled=True,
                binary=str(binary),
                config=config,
                timeout=5,
                max_lines=100,
                max_html_bytes=10000,
            )
            html, status = runner.generate(
                [
                    '203.0.113.12:1234 [18/Nov/2026:00:00:03.123] ft_https bk_app/app1 '
                    '0/0/1/2/3 --- 0 "GET / HTTP/1.1"',
                ]
            )
        self.assertIsNotNone(html)
        self.assertIn("---", html)
        self.assertEqual(status["skipped_lines"], 0)

    def test_missing_geoip_database_is_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            binary = temp_path / "goaccess"
            binary.write_text(CONFIG_ECHO_GOACCESS, encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            city_db = temp_path / "geoip" / "GeoLite2-City.mmdb"
            city_db.parent.mkdir()
            city_db.write_bytes(b"")
            config = temp_path / "goaccess.conf"
            config.write_text(
                STANDARD_CONFIG + "geoip-database /var/lib/GeoIP/GeoLite2-City.mmdb\n",
                encoding="utf-8",
            )
            runner = GoAccessRunner(
                enabled=True,
                binary=str(binary),
                config=config,
                timeout=5,
                max_lines=100,
                max_html_bytes=10000,
                geoip_city_db=city_db,
            )
            html, status = runner.generate([STANDARD_LINE])
        self.assertIsNotNone(html)
        self.assertIn(f"geoip-database {city_db}", html)
        self.assertNotIn("/var/lib/GeoIP/GeoLite2-City.mmdb", html)
        self.assertFalse(status.get("config_warnings"))

    def test_missing_geoip_database_is_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            binary = temp_path / "goaccess"
            binary.write_text(CONFIG_ECHO_GOACCESS, encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            config = temp_path / "goaccess.conf"
            config.write_text(
                STANDARD_CONFIG + "geoip-database /var/lib/GeoIP/GeoLite2-City.mmdb\n",
                encoding="utf-8",
            )
            runner = GoAccessRunner(
                enabled=True,
                binary=str(binary),
                config=config,
                timeout=5,
                max_lines=100,
                max_html_bytes=10000,
            )
            html, status = runner.generate([STANDARD_LINE])
        self.assertIsNotNone(html)
        self.assertNotIn("geoip-database", html)
        self.assertEqual(len(status["config_warnings"]), 1)

    def test_error_detail_identifies_the_rejected_field(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            binary = temp_path / "goaccess"
            binary.write_text(ERROR_GOACCESS, encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            config = temp_path / "goaccess.conf"
            config.write_text(STANDARD_CONFIG, encoding="utf-8")
            runner = GoAccessRunner(
                enabled=True,
                binary=str(binary),
                config=config,
                timeout=5,
                max_lines=100,
                max_html_bytes=10000,
            )
            html, status = runner.generate([STANDARD_LINE])
        self.assertIsNone(html)
        self.assertFalse(status["generated"])
        self.assertIn("status (%s)", status["detail"])

    def test_error_detail_identifies_a_geoip_problem(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            binary = temp_path / "goaccess"
            binary.write_text(GEOIP_ERROR_GOACCESS, encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            config = temp_path / "goaccess.conf"
            config.write_text(STANDARD_CONFIG, encoding="utf-8")
            runner = GoAccessRunner(
                enabled=True,
                binary=str(binary),
                config=config,
                timeout=5,
                max_lines=100,
                max_html_bytes=10000,
            )
            html, status = runner.generate([STANDARD_LINE])
        self.assertIsNone(html)
        self.assertIn("GeoIP database", status["detail"])


if __name__ == "__main__":
    unittest.main()
