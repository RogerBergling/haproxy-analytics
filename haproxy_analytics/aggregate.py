"""In-memory aggregation of parsed HAProxy events."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from typing import Any

from .geoip import GeoResolver
from .parser import HttpEvent, ParsedEvent, TlsEvent

_UNKNOWN_COUNTRIES = {"Unknown", "Private network", "-"}


class Aggregator:
    """Collect counters and per-client details without storing raw log lines."""

    def __init__(self, geo: GeoResolver, max_visitor_rows: int = 5000) -> None:
        self.geo = geo
        self.max_visitor_rows = max_visitor_rows

        self.http_total = 0
        self.tls_total = 0
        self.bytes_out = 0
        self.unparsed_lines = 0
        self.parsed_events = 0
        self.repeated_groups = 0

        self.http_by_ip: Counter[str] = Counter()
        self.tls_by_ip: Counter[str] = Counter()
        self.http_backends: Counter[str] = Counter()
        self.http_status: Counter[str] = Counter()
        self.http_methods: Counter[str] = Counter()
        self.http_paths: Counter[str] = Counter()
        self.http_countries: Counter[str] = Counter()
        self.tls_countries: Counter[str] = Counter()
        self.http_asns: Counter[str] = Counter()
        self.tls_asns: Counter[str] = Counter()
        self.sni_counts: Counter[str] = Counter()

        self.ip_meta: dict[str, dict[str, Any]] = {}
        self.ip_snis: defaultdict[str, Counter[str]] = defaultdict(Counter)
        self.ip_backends: defaultdict[str, Counter[str]] = defaultdict(Counter)
        self.ip_last_seen: dict[str, str] = {}

        self.country_stats: defaultdict[str, dict[str, Any]] = defaultdict(
            lambda: {"http": 0, "tls": 0, "ips": set(), "cities": Counter(), "last_seen": "-"}
        )
        self.city_stats: defaultdict[tuple[str, str, str], dict[str, Any]] = defaultdict(
            lambda: {"http": 0, "tls": 0, "ips": set(), "last_seen": "-"}
        )
        self.map_points: defaultdict[tuple[float, float, str, str], dict[str, Any]] = defaultdict(
            lambda: {"http": 0, "tls": 0, "ips": set()}
        )
        self.recent_tls: deque[tuple[str, str, str, str, str]] = deque(maxlen=25)

    def record_unparsed(self) -> None:
        self.unparsed_lines += 1

    def record_repeated(self) -> None:
        self.repeated_groups += 1

    def _geo(self, ip: str) -> dict[str, Any]:
        if ip not in self.ip_meta:
            self.ip_meta[ip] = self.geo.lookup(ip)
        return self.ip_meta[ip]

    def _touch_ip(self, ip: str, when: str) -> None:
        current = self.ip_last_seen.get(ip, "")
        if when > current:
            self.ip_last_seen[ip] = when

    def _record_country(
        self, country: str, city: str, kind: str, count: int, ip: str, when: str
    ) -> None:
        stats = self.country_stats[country]
        stats[kind] += count
        stats["ips"].add(ip)
        if when > stats["last_seen"]:
            stats["last_seen"] = when
        if city not in ("-", ""):
            stats["cities"][city] += count

    def _record_city(
        self, country: str, country_code: str, city: str, kind: str, count: int, ip: str, when: str
    ) -> None:
        if city in ("-", "") or country in _UNKNOWN_COUNTRIES:
            return
        stats = self.city_stats[(country, country_code, city)]
        stats[kind] += count
        stats["ips"].add(ip)
        if when > stats["last_seen"]:
            stats["last_seen"] = when

    def _record_point(self, geo: dict[str, Any], kind: str, count: int, ip: str) -> None:
        lat, lon = geo.get("lat"), geo.get("lon")
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            return
        key = (round(float(lat), 1), round(float(lon), 1), geo["country"], geo["city"])
        point = self.map_points[key]
        point[kind] += count
        point["ips"].add(ip)

    def add(self, parsed: ParsedEvent) -> None:
        event = parsed.event
        if isinstance(event, TlsEvent):
            self._add_tls(event)
        elif isinstance(event, HttpEvent):
            self._add_http(event)

    def _add_tls(self, event: TlsEvent) -> None:
        count = event.count
        self.tls_total += count
        self.parsed_events += count
        self.tls_by_ip[event.ip] += count
        sni = "No SNI" if event.sni in ("-", "") else event.sni
        self.sni_counts[sni] += count
        self.ip_snis[event.ip][sni] += count
        self._touch_ip(event.ip, event.timestamp_display)

        geo = self._geo(event.ip)
        country = geo["country"]
        self.tls_countries[country] += count
        if geo["asn"] != "-":
            self.tls_asns[geo["asn"]] += count
        self._record_country(country, geo["city"], "tls", count, event.ip, event.timestamp_display)
        self._record_city(
            country, geo["country_code"], geo["city"], "tls", count, event.ip, event.timestamp_display
        )
        self._record_point(geo, "tls", count, event.ip)
        display = event.timestamp_display
        if count > 1:
            display = f"{display} (x{count})"
        self.recent_tls.appendleft((display, event.ip, sni, country, geo["city"]))

    def _add_http(self, event: HttpEvent) -> None:
        count = event.count
        self.http_total += count
        self.parsed_events += count
        self.http_by_ip[event.ip] += count
        self.http_backends[event.backend] += count
        self.http_status[event.status] += count
        self.http_methods[event.method] += count
        self.http_paths[event.path] += count
        self.bytes_out += event.bytes * count
        self.ip_backends[event.ip][event.backend] += count
        self._touch_ip(event.ip, event.timestamp_display)

        geo = self._geo(event.ip)
        country = geo["country"]
        self.http_countries[country] += count
        if geo["asn"] != "-":
            self.http_asns[geo["asn"]] += count
        self._record_country(country, geo["city"], "http", count, event.ip, event.timestamp_display)
        self._record_city(
            country, geo["country_code"], geo["city"], "http", count, event.ip, event.timestamp_display
        )
        self._record_point(geo, "http", count, event.ip)

    @staticmethod
    def _items(counter: Counter[str], limit: int) -> list[dict[str, Any]]:
        return [{"name": name, "count": count} for name, count in counter.most_common(limit)]

    @staticmethod
    def _location(geo: dict[str, Any]) -> str:
        parts = [part for part in (geo["city"], geo["country"]) if part not in ("-", "")]
        return ", ".join(parts) or "Unknown"

    def build(self) -> dict[str, Any]:
        all_ips = set(self.http_by_ip) | set(self.tls_by_ip)
        country_count = sum(1 for name in self.country_stats if name not in _UNKNOWN_COUNTRIES)
        errors = sum(
            count for status, count in self.http_status.items() if status[:1] in {"4", "5"}
        )
        known_sni = Counter({name: count for name, count in self.sni_counts.items() if name != "No SNI"})
        total_events = self.http_total + self.tls_total

        visitor_rows: list[dict[str, Any]] = []
        for ip in sorted(
            all_ips,
            key=lambda address: (
                self.ip_last_seen.get(address, ""),
                self.tls_by_ip[address] + self.http_by_ip[address],
            ),
            reverse=True,
        ):
            geo = self._geo(ip)
            snis = [[name, count] for name, count in self.ip_snis[ip].most_common()]
            backends = [[name, count] for name, count in self.ip_backends[ip].most_common()]
            location = self._location(geo)
            last_seen = self.ip_last_seen.get(ip, "-")
            search = " ".join(
                [
                    ip,
                    location,
                    geo["asn"],
                    " ".join(name for name, _ in snis),
                    " ".join(name for name, _ in backends),
                    last_seen,
                ]
            ).lower()
            visitor_rows.append(
                {
                    "ip": ip,
                    "country": geo["country"],
                    "country_code": geo["country_code"],
                    "city": geo["city"],
                    "location": location,
                    "asn": geo["asn"],
                    "snis": snis,
                    "backends": backends,
                    "tls": self.tls_by_ip[ip],
                    "http": self.http_by_ip[ip],
                    "last_seen": last_seen,
                    "search": search,
                }
            )

        visitor_total = len(visitor_rows)
        if len(visitor_rows) > self.max_visitor_rows:
            visitor_rows = visitor_rows[: self.max_visitor_rows]

        countries = []
        for name, stats in self.country_stats.items():
            total = stats["http"] + stats["tls"]
            countries.append(
                {
                    "country": name,
                    "country_code": self._country_code(name),
                    "http": stats["http"],
                    "tls": stats["tls"],
                    "total": total,
                    "ips": len(stats["ips"]),
                    "share": round(100 * total / total_events, 2) if total_events else 0,
                    "top_cities": [[city, count] for city, count in stats["cities"].most_common(4)],
                    "last_seen": stats["last_seen"],
                }
            )
        countries.sort(key=lambda item: (item["total"], item["ips"]), reverse=True)

        cities = []
        for (country, country_code, city), stats in self.city_stats.items():
            total = stats["http"] + stats["tls"]
            cities.append(
                {
                    "country": country,
                    "country_code": country_code,
                    "city": city,
                    "http": stats["http"],
                    "tls": stats["tls"],
                    "total": total,
                    "ips": len(stats["ips"]),
                    "share": round(100 * total / total_events, 2) if total_events else 0,
                    "last_seen": stats["last_seen"],
                }
            )
        cities.sort(key=lambda item: (item["total"], item["ips"]), reverse=True)

        points = []
        for (lat, lon, country, city), stats in self.map_points.items():
            total = stats["http"] + stats["tls"]
            points.append(
                {
                    "lat": lat,
                    "lon": lon,
                    "country": country,
                    "city": city,
                    "http": stats["http"],
                    "tls": stats["tls"],
                    "total": total,
                    "ips": sorted(stats["ips"])[:2000],
                }
            )
        points.sort(key=lambda item: item["total"], reverse=True)

        latest_seen = max(self.ip_last_seen.values(), default="-")

        return {
            "kpis": {
                "http_total": self.http_total,
                "tls_total": self.tls_total,
                "unique_ips": len(all_ips),
                "countries": country_count,
                "errors": errors,
                "bytes": self.bytes_out,
                "geo_points": len(self.map_points),
                "sni_hostnames": len(known_sni),
                "http_backends": len(self.http_backends),
                "no_sni": self.sni_counts.get("No SNI", 0),
                "latest_seen": latest_seen,
            },
            "http": {
                "total": self.http_total,
                "bandwidth": self.bytes_out,
                "errors": errors,
                "methods": self._items(self.http_methods, 10),
                "statuses": self._items(self.http_status, 12),
                "backends": self._items(self.http_backends, 15),
                "paths": self._items(self.http_paths, 30),
                "countries": self._items(self.http_countries, 15),
                "asns": self._items(self.http_asns, 15),
            },
            "tls": {
                "total": self.tls_total,
                "snis": self._items(known_sni, 20),
                "no_sni": self.sni_counts.get("No SNI", 0),
                "countries": self._items(self.tls_countries, 15),
                "asns": self._items(self.tls_asns, 15),
                "recent": [
                    {
                        "time": when,
                        "ip": ip,
                        "sni": sni,
                        "country": country,
                        "city": city,
                    }
                    for when, ip, sni, country, city in self.recent_tls
                ],
            },
            "geo": {
                "countries": countries[:100],
                "cities": cities[:100],
                "points": points[:700],
                "country_count": country_count,
            },
            "visitors": {
                "total": visitor_total,
                "rows": visitor_rows,
                "truncated": visitor_total > len(visitor_rows),
            },
            "parser": {
                "unparsed_lines": self.unparsed_lines,
                "repeated_groups": self.repeated_groups,
                "events": self.parsed_events,
            },
        }

    def _country_code(self, country: str) -> str:
        for geo in self.ip_meta.values():
            if geo["country"] == country and geo["country_code"]:
                return geo["country_code"]
        return ""
