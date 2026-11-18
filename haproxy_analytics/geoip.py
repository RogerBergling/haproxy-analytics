"""Optional MaxMind GeoLite2 enrichment.

The application runs without GeoIP data. Missing databases, a missing Python
module or invalid addresses only produce warnings and "Unknown" locations.
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Any

try:  # optional runtime dependency
    import maxminddb
except ImportError:  # pragma: no cover - exercised in dependency-free runs
    maxminddb = None  # type: ignore[assignment]

LOGGER = logging.getLogger(__name__)

_UNKNOWN = {
    "country": "Unknown",
    "country_code": "",
    "city": "-",
    "asn": "-",
    "asn_number": None,
    "lat": None,
    "lon": None,
    "private": False,
}

_PRIVATE = {
    "country": "Private network",
    "country_code": "",
    "city": "-",
    "asn": "-",
    "asn_number": None,
    "lat": None,
    "lon": None,
    "private": True,
}


class GeoResolver:
    """Read-only GeoLite2 City/ASN lookup with a small in-process cache."""

    def __init__(self, city_db: Path, asn_db: Path) -> None:
        self.city_db = Path(city_db)
        self.asn_db = Path(asn_db)
        self.warnings: list[str] = []
        self.city_reader = self._open(self.city_db, "City")
        self.asn_reader = self._open(self.asn_db, "ASN")
        self._cache: dict[str, dict[str, Any]] = {}

    @property
    def has_city(self) -> bool:
        return self.city_reader is not None

    @property
    def has_asn(self) -> bool:
        return self.asn_reader is not None

    def _open(self, path: Path, label: str):
        if maxminddb is None:
            if not self.warnings:
                self.warnings.append(
                    "Python module 'maxminddb' is not installed; geography is unavailable."
                )
            return None
        if not path.is_file():
            self.warnings.append(f"GeoIP {label} database not found at {path}; continuing without it.")
            return None
        try:
            reader = maxminddb.open_database(str(path))
        except Exception as exc:  # noqa: BLE001 - operational warning, never fatal
            LOGGER.warning("Could not open GeoIP %s database %s: %s", label, path, exc)
            self.warnings.append(f"GeoIP {label} database could not be opened at {path}.")
            return None
        return reader

    def lookup(self, ip: str) -> dict[str, Any]:
        if ip in self._cache:
            return self._cache[ip]

        result = dict(_UNKNOWN)
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            self._cache[ip] = result
            return result

        if (
            address.is_loopback
            or address.is_link_local
            or address.is_unspecified
            or address.is_multicast
            or address.is_reserved
            or (address.is_private and not address.is_global)
        ):
            result = dict(_PRIVATE)
            self._cache[ip] = result
            return result

        if self.city_reader is not None:
            try:
                record = self.city_reader.get(ip) or {}
            except (ValueError, TypeError, OSError):
                record = {}
            country = record.get("country") or {}
            city = record.get("city") or {}
            location = record.get("location") or {}
            result["country"] = (country.get("names") or {}).get("en") or "Unknown"
            result["country_code"] = country.get("iso_code") or ""
            result["city"] = (city.get("names") or {}).get("en") or "-"
            latitude = location.get("latitude")
            longitude = location.get("longitude")
            if isinstance(latitude, (int, float)) and isinstance(longitude, (int, float)):
                if -90 <= latitude <= 90 and -180 <= longitude <= 180:
                    result["lat"] = float(latitude)
                    result["lon"] = float(longitude)

        if self.asn_reader is not None:
            try:
                asn_record = self.asn_reader.get(ip) or {}
            except (ValueError, TypeError, OSError):
                asn_record = {}
            result["asn"] = asn_record.get("autonomous_system_organization") or "-"
            result["asn_number"] = asn_record.get("autonomous_system_number")

        self._cache[ip] = result
        return result

    def close(self) -> None:
        for reader in (self.city_reader, self.asn_reader):
            if reader is not None:
                try:
                    reader.close()
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    pass
        self.city_reader = None
        self.asn_reader = None
