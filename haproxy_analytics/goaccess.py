"""Optional GoAccess report generation.

GoAccess is not required for the dashboard. When enabled, the app writes only
HTTP log lines to a temporary directory, runs the configured GoAccess binary
with a bounded timeout and serves the resulting HTML in a sandboxed iframe.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

_STANDARD_LOG_FORMAT = '%h:%^ [%d:%t.%^] %^ %^ %^ %s %b %^ %^ %^ %^ %^ "%r"'

_FALLBACK_CONFIG = f"""\
time-format %H:%M:%S
date-format %d/%b/%Y
log-format {_STANDARD_LOG_FORMAT}
"""

# A line the bundled GoAccess configuration can parse. The client address is
# validated because GoAccess validates %h, and the timestamp must include the
# seconds field the GoAccess config expects.
_STANDARD_LINE = re.compile(
    r"^(?P<client>\[[0-9A-Fa-f:.]+\]|[^\s\[]+):(?P<port>\d+)\s+"
    r"\[(?P<timestamp>\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]\s+"
    r"(?P<rest>.+)$"
)
_STANDARD_FIELDS = re.compile(
    r"^(?P<frontend>\S+)\s+(?P<backend>\S+)\s+(?P<timers>\S+)\s+"
    r"(?P<status>\d{3}|-{3})\s+(?P<bytes>-|\d+)\s+(?P<tail>.*)$"
)
_QUOTED_REQUEST = re.compile(r'"[^"]*"\s*$')
_SPECIFIER_ERROR = re.compile(r"Token '.*?' doesn't match specifier '(%[^']*)'")
_GEOIP_ERROR = re.compile(r"Unable to open GeoIP2 database ([^:]+):")
_SPECIFIER_FIELDS = {
    "%h": "client address",
    "%d": "date",
    "%t": "time",
    "%s": "status",
    "%b": "response size",
    "%r": "request",
    "%^": "skipped field",
}


def _normalize_client(value: str) -> str | None:
    """Return a canonical client address, or None when it is not an IP."""

    bracketed = value.startswith("[") and value.endswith("]")
    candidate = value[1:-1] if bracketed else value
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        return f"[{address.compressed}]"
    return str(address)


def _normalize_standard_line(line: str) -> tuple[str | None, str | None]:
    """Return a GoAccess-safe line and an optional rejection reason."""

    match = _STANDARD_LINE.match(line)
    if not match:
        return None, "not_standard"
    client = _normalize_client(match.group("client"))
    if client is None:
        return None, "client"
    timestamp = match.group("timestamp")
    if "." not in timestamp.rsplit(":", 1)[-1]:
        timestamp += ".000"
    fields = _STANDARD_FIELDS.match(match.group("rest"))
    if fields is None:
        return None, "fields"
    status = fields.group("status")
    if not re.fullmatch(r"[1-5]\d{2}", status):
        return None, "status"
    if not _QUOTED_REQUEST.search(fields.group("tail")):
        return None, "request"
    return (
        f"{client}:{match.group('port')} [{timestamp}] "
        f"{fields.group('frontend')} {fields.group('backend')} {fields.group('timers')} "
        f"{fields.group('status')} {fields.group('bytes')} {fields.group('tail')}",
        None,
    )


def _config_directives(path: Path) -> dict[str, str]:
    """Return the simple ``key value`` directives used by GoAccess."""

    directives: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return directives
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            directives[parts[0]] = parts[1].strip()
    return directives


class GoAccessRunner:
    def __init__(
        self,
        enabled: bool,
        binary: str,
        config: Path,
        timeout: int,
        max_lines: int,
        max_html_bytes: int,
        geoip_city_db: Path | None = None,
        geoip_asn_db: Path | None = None,
    ) -> None:
        self.enabled = enabled
        self.binary = binary
        self.config = Path(config)
        self.timeout = timeout
        self.max_lines = max_lines
        self.max_html_bytes = max_html_bytes
        self.geoip_city_db = Path(geoip_city_db) if geoip_city_db else None
        self.geoip_asn_db = Path(geoip_asn_db) if geoip_asn_db else None

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

    def _uses_standard_format(self) -> bool:
        if not self.config.is_file():
            return True
        directives = _config_directives(self.config)
        if directives.get("log-format") != _STANDARD_LOG_FORMAT:
            return False
        # Only normalize the standard timestamp shape. A custom date/time
        # format needs a custom input validator, not this one.
        return (
            directives.get("date-format") in (None, "%d/%b/%Y")
            and directives.get("time-format") in (None, "%H:%M:%S", "%T")
        )

    def _prepare_lines(self, lines: list[str]) -> tuple[list[str], int, dict[str, int]]:
        if not self._uses_standard_format():
            return list(lines), 0, {}
        prepared: list[str] = []
        reasons: dict[str, int] = {}
        for line in lines:
            normalized, reason = _normalize_standard_line(line)
            if normalized is None:
                reasons[reason or "unknown"] = reasons.get(reason or "unknown", 0) + 1
            else:
                prepared.append(normalized)
        return prepared, sum(reasons.values()), reasons

    def _resolve_geoip(self, value: str) -> str | None:
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = self.config.parent / candidate
        if candidate.is_file():
            return str(candidate)
        name = candidate.name.lower()
        for configured in (self.geoip_city_db, self.geoip_asn_db):
            if configured and configured.is_file() and configured.name.lower() == name:
                return str(configured)
        return None

    def _prepare_config(self, temp: Path) -> tuple[Path, list[str]]:
        if not self.config.is_file():
            path = temp / "goaccess.conf"
            path.write_text(_FALLBACK_CONFIG, encoding="utf-8")
            return path, []
        try:
            text = self.config.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            LOGGER.warning("Could not read the GoAccess config %s: %s", self.config, exc)
            path = temp / "goaccess.conf"
            path.write_text(_FALLBACK_CONFIG, encoding="utf-8")
            return path, []
        changed = False
        warnings: list[str] = []
        output: list[str] = []
        for raw in text.splitlines():
            stripped = raw.strip()
            if stripped.startswith("geoip-database"):
                value = stripped[len("geoip-database") :].strip().strip("\"'")
                resolved = self._resolve_geoip(value)
                if resolved is None:
                    changed = True
                    warnings.append(
                        f"GoAccess config references a missing GeoIP database ({value}); "
                        "the line was ignored."
                    )
                    continue
                if resolved != value:
                    changed = True
                    output.append(f"geoip-database {resolved}")
                    continue
            output.append(raw)
        if not changed:
            return self.config, warnings
        path = temp / "goaccess.conf"
        path.write_text("\n".join(output) + "\n", encoding="utf-8")
        return path, warnings

    @staticmethod
    def _error_detail(stderr: str, returncode: int) -> str:
        text = stderr or ""
        match = _SPECIFIER_ERROR.search(text)
        if match:
            specifier = match.group(1)
            field = _SPECIFIER_FIELDS.get(specifier, "log field")
            return (
                f"GoAccess could not parse the {field} ({specifier}) in at least one HTTP line. "
                "Check that GOACCESS_CONFIG matches the HAProxy log-format."
            )
        if _GEOIP_ERROR.search(text):
            return (
                "GoAccess could not open the GeoIP database configured in GOACCESS_CONFIG. "
                "Use a container path such as /geoip/GeoLite2-City.mmdb or remove the "
                "geoip-database line."
            )
        if "No time-format" in text or "No date-format" in text:
            return "GoAccess requires date-format and time-format directives in GOACCESS_CONFIG."
        return f"GoAccess exited with status {returncode}. See the container logs for the local error."

    def generate(self, http_lines: list[str]) -> tuple[str | None, dict[str, Any]]:
        status = self.status()
        if not status["enabled"]:
            return None, status
        if not status["available"]:
            return None, status

        status["input_lines"] = len(http_lines)
        prepared, skipped, reasons = self._prepare_lines(http_lines)
        status["skipped_lines"] = skipped
        if reasons:
            status["skipped_reasons"] = reasons
        lines = prepared[: self.max_lines]
        if not lines:
            status["error"] = (
                "No HTTP log lines matched the configured GoAccess log-format. "
                "Check GOACCESS_CONFIG and the HAProxy log-format."
            )
            return None, status
        if len(prepared) > self.max_lines:
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
            try:
                log_path.write_text("\n".join(lines) + "\n", encoding="utf-8", errors="replace")
            except OSError as exc:
                LOGGER.warning("Could not write the temporary GoAccess input: %s", exc)
                status["error"] = "Could not write the temporary GoAccess input. Check /tmp space."
                return None, status

            try:
                config_path, config_warnings = self._prepare_config(temp)
            except OSError as exc:
                LOGGER.warning("Could not write the temporary GoAccess config: %s", exc)
                status["error"] = "Could not write the temporary GoAccess configuration."
                return None, status
            if config_warnings:
                status["config_warnings"] = config_warnings
                for warning in config_warnings:
                    LOGGER.warning("%s", warning)

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
                status["detail"] = self._error_detail(
                    result.stderr or result.stdout or "", result.returncode
                )
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
