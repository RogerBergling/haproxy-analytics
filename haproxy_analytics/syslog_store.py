"""Append-only persistent syslog history with bounded rotation."""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

LOGGER = logging.getLogger(__name__)


class SyslogStore:
    """Persist accepted syslog lines outside the container.

    The file is append-only and rotated by size. Reads always take the newest
    tail window, so a large on-disk history does not force the parser to load
    everything. The store is optional; the caller only creates it when a path is
    configured.
    """

    def __init__(self, path: Path, max_bytes: int, backups: int) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.Lock()
        self._handle: TextIO | None = None
        self.write_errors = 0
        self.last_error: str | None = None
        self.cleared_at: str | None = None

    @property
    def enabled(self) -> bool:
        return True

    def _backup_paths(self) -> list[Path]:
        return [Path(f"{self.path}.{index}") for index in range(1, self.backups + 1)]

    def _open_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # The log contains client IPs, SNI/hostnames and paths. Create it
        # owner-only so other local users cannot read the traffic history.
        fd = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        self._handle = os.fdopen(fd, "a", encoding="utf-8", errors="replace")

    def _close_locked(self) -> None:
        if self._handle is not None:
            try:
                self._handle.close()
            except OSError:
                pass
            self._handle = None

    def _rotate_locked(self) -> None:
        self._close_locked()
        if self.backups <= 0:
            try:
                self.path.unlink(missing_ok=True)
            except OSError as exc:
                LOGGER.warning("Could not remove full syslog store %s: %s", self.path, exc)
        else:
            oldest = self._backup_paths()[-1]
            try:
                oldest.unlink(missing_ok=True)
            except OSError as exc:
                LOGGER.warning("Could not remove old syslog backup %s: %s", oldest, exc)
            for index in range(self.backups - 1, 0, -1):
                source = Path(f"{self.path}.{index}")
                target = Path(f"{self.path}.{index + 1}")
                if source.is_file():
                    try:
                        os.replace(source, target)
                    except OSError as exc:
                        LOGGER.warning("Could not rotate syslog backup %s: %s", source, exc)
            if self.path.is_file():
                try:
                    os.replace(self.path, Path(f"{self.path}.1"))
                except OSError as exc:
                    LOGGER.warning("Could not rotate syslog store %s: %s", self.path, exc)
        self._open_locked()

    def append(self, line: str) -> None:
        data = line.rstrip("\r\n") + "\n"
        with self._lock:
            try:
                if self._handle is None:
                    self._open_locked()
                assert self._handle is not None
                current = os.fstat(self._handle.fileno()).st_size
                if self.max_bytes > 0 and current + len(data.encode("utf-8")) > self.max_bytes:
                    self._rotate_locked()
                    assert self._handle is not None
                self._handle.write(data)
                self._handle.flush()
                self.last_error = None
            except OSError as exc:
                self.write_errors += 1
                self.last_error = str(exc)
                self._close_locked()
                LOGGER.warning("Could not write syslog store %s: %s", self.path, exc)

    @staticmethod
    def _read_tail(path: Path, max_bytes: int) -> tuple[bytes, bool]:
        try:
            size = path.stat().st_size
        except OSError:
            return b"", False
        if size == 0:
            return b"", False
        read_size = min(size, max_bytes)
        with path.open("rb") as handle:
            if read_size < size:
                handle.seek(size - read_size - 1)
                previous = handle.read(1)
                handle.seek(size - read_size)
                return handle.read(read_size), previous != b"\n"
            return handle.read(), False

    def read_lines(self, max_bytes: int) -> list[str]:
        with self._lock:
            paths = [self.path] + self._backup_paths()
            chunks: list[bytes] = []
            remaining = max_bytes
            partial = False
            for path in paths:
                if remaining <= 0:
                    break
                data, was_partial = self._read_tail(path, remaining)
                if data:
                    chunks.append(data)
                    remaining -= len(data)
                    partial = was_partial
            if not chunks:
                return []
            payload = b"".join(reversed(chunks))
        text = payload.decode("utf-8", errors="replace")
        lines = text.splitlines()
        if partial and lines:
            lines = lines[1:]
        return lines

    def clear(self) -> None:
        with self._lock:
            self._close_locked()
            for path in self._backup_paths() + [self.path]:
                try:
                    path.unlink(missing_ok=True)
                except OSError as exc:
                    LOGGER.warning("Could not delete syslog store file %s: %s", path, exc)
            self.write_errors = 0
            self.last_error = None
            self.cleared_at = datetime.now().astimezone().isoformat(timespec="seconds")

    def info(self) -> dict[str, Any]:
        with self._lock:
            files = []
            total = 0
            current = 0
            for path in self._backup_paths() + [self.path]:
                try:
                    size = path.stat().st_size
                except OSError:
                    size = 0
                if size:
                    files.append({"path": str(path), "bytes": size})
                    total += size
                if path == self.path:
                    current = size
            return {
                "enabled": True,
                "path": str(self.path),
                "max_bytes": self.max_bytes,
                "backups": self.backups,
                "current_bytes": current,
                "total_bytes": total,
                "files": files,
                "write_errors": self.write_errors,
                "last_error": self.last_error,
                "cleared_at": self.cleared_at,
            }

    def close(self) -> None:
        with self._lock:
            self._close_locked()
