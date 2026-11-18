from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from haproxy_analytics.syslog_store import SyslogStore


class SyslogStoreTests(unittest.TestCase):
    def test_append_and_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "syslog.log"
            store = SyslogStore(path, max_bytes=1024 * 1024, backups=1)
            try:
                store.append("first line")
                store.append("second line")
                self.assertEqual(store.read_lines(1024 * 1024), ["first line", "second line"])
                info = store.info()
                self.assertTrue(info["enabled"])
                self.assertGreater(info["current_bytes"], 0)
                self.assertEqual(info["write_errors"], 0)
            finally:
                store.close()

    def test_rotation_keeps_backups(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "syslog.log"
            store = SyslogStore(path, max_bytes=40, backups=1)
            try:
                for index in range(10):
                    store.append(f"line-{index:02d}")
                files = sorted(Path(temp).glob("syslog.log*"))
                self.assertTrue(any(name.name == "syslog.log.1" for name in files))
                lines = store.read_lines(1024 * 1024)
                self.assertIn("line-09", lines)
                self.assertGreater(len(lines), 0)
            finally:
                store.close()

    def test_read_tail_across_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "syslog.log"
            store = SyslogStore(path, max_bytes=64, backups=2)
            try:
                for index in range(20):
                    store.append(f"line-{index:02d}")
                lines = store.read_lines(80)
                self.assertIn("line-19", lines)
                self.assertLessEqual(len(lines), 20)
            finally:
                store.close()


    def test_history_survives_new_store_instance(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "syslog.log"
            store = SyslogStore(path, max_bytes=1024 * 1024, backups=1)
            store.append("persisted line")
            store.close()
            reopened = SyslogStore(path, max_bytes=1024 * 1024, backups=1)
            try:
                self.assertEqual(reopened.read_lines(1024 * 1024), ["persisted line"])
            finally:
                reopened.close()

    def test_clear_removes_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "syslog.log"
            store = SyslogStore(path, max_bytes=32, backups=1)
            try:
                for index in range(10):
                    store.append(f"line-{index:02d}")
                store.clear()
                self.assertEqual(store.read_lines(1024 * 1024), [])
                self.assertEqual(list(Path(temp).glob("syslog.log*")), [])
                self.assertIsNotNone(store.info()["cleared_at"])
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
