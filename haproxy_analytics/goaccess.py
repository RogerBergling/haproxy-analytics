"""Optional GoAccess report generation.

GoAccess is not required for the dashboard. When enabled, the app writes only
HTTP log lines to a temporary directory, runs the configured GoAccess binary
with a bounded timeout and serves the resulting HTML in a sandboxed iframe.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

_FALLBACK_CONFIG = """\
time-format %H:%M:%S
date-format %d/%b/%Y
log-format %h:%^ [%d:%t.%^] %^ %^ %^ %s %b %^ %^ %^ %^ %^ "%r"
"""


class GoAccessRunner:
    def __init__(
        self,
        enabled: bool,
        binary: str,
        config: Path,
        timeout: int,
        max_lines: int,
        max_html_bytes: int,
    ) -> None:
        self.enabled = enabled
        self.binary = binary
        self.config = Path(config)
        self.timeout = timeout
        self.max_lines = max_lines
        self.max_html_bytes = max_html_bytes

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def status(self) -> dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "available": self.available(), "generated": False, "error": None}
        available = self.available()
        return {
            "enabled": True,
            "available": available,
            "generated": False,
            "error": None if available else f"GoAccess binary not found: {self.binary}",
        }

    def generate(self, http_lines: list[str]) -> tuple[str | None, dict[str, Any]]:
        status = self.status()
        if not status["enabled"]:
            return None, status
        if not status["available"]:
            return None, status

        lines = http_lines[: self.max_lines]
        if not lines:
            status["error"] = "No HTTP log lines were available for GoAccess."
            return None, status
        if len(http_lines) > self.max_lines:
            status["truncated"] = True

        try:
            temp_context = tempfile.TemporaryDirectory(prefix="haproxy-analytics-")
        except OSError as exc:
            LOGGER.warning("Could not create a temporary GoAccess directory: %s", exc)
            status["error"] = "Could not create a temporary directory for GoAccess."
            return None, status

        with temp_context as temp_dir:
            temp = Path(temp_dir)
            log_path = temp / "http.log"
            output_path = temp / "goaccess.html"
            config_path = self.config
            try:
                log_path.write_text("\n".join(lines) + "\n", encoding="utf-8", errors="replace")
            except OSError as exc:
                LOGGER.warning("Could not write the temporary GoAccess input: %s", exc)
                status["error"] = "Could not write the temporary GoAccess input. Check /tmp space."
                return None, status

            if not config_path.is_file():
                config_path = temp / "goaccess.conf"
                try:
                    config_path.write_text(_FALLBACK_CONFIG, encoding="utf-8")
                except OSError as exc:
                    LOGGER.warning("Could not write the temporary GoAccess config: %s", exc)
                    status["error"] = "Could not write the temporary GoAccess configuration."
                    return None, status

            command = [
                self.binary,
                str(log_path),
                "--no-progress",
                "--no-global-config",
                "-p",
                str(config_path),
                "-o",
                str(output_path),
            ]
            environment = os.environ.copy()
            environment["HOME"] = str(temp)
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                    env=environment,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                LOGGER.warning("GoAccess execution failed: %s", exc)
                status["error"] = "GoAccess could not be executed. See the container logs."
                return None, status

            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip().splitlines()
                if detail:
                    LOGGER.warning("GoAccess failed: %s", detail[-1][:500])
                status["error"] = (
                    "GoAccess rejected the HTTP log format. Check the GoAccess configuration "
                    "and the HAProxy log format."
                )
                return None, status

            try:
                size = output_path.stat().st_size
            except OSError:
                status["error"] = "GoAccess did not produce a report."
                return None, status
            if size == 0:
                status["error"] = "GoAccess produced an empty report."
                return None, status
            if size > self.max_html_bytes:
                status["error"] = (
                    f"GoAccess report is larger than the configured limit "
                    f"({self.max_html_bytes} bytes)."
                )
                return None, status

            try:
                html = output_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                status["error"] = "The GoAccess report could not be read."
                return None, status

            status["generated"] = True
            status["lines"] = len(lines)
            status["bytes"] = size
            return html, status
