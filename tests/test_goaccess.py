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


if __name__ == "__main__":
    unittest.main()
