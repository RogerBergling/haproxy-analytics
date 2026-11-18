"""In-memory aggregation of parsed HAProxy events."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Any

from .geoip import GeoResolver
from .parser import HttpEvent, ParsedEvent, TlsEvent
from .privacy import IPNetwork, mask_ip, mask_text_ips

_UNKNOWN_COUNTRIES = {"Unknown", "Private network", "-"}


@dataclass(frozen=True)
class RequestRow:
    when: str
    ip: str
    method: str
    path: str
    status: str
    size: int
    frontend: str
    backend: str
    country: str
    city: str
    protocol: str
    count: int
    port: str
    server: str


class Aggregator:
    """Collect counters and per-client details without storing raw log lines."""

    def __init__(
        self,
        geo: GeoResolver,
        max_visitor_rows: int = 5000,
        max_request_rows: int = 2000,
        mask_internal_ips: bool = False,
        mask_networks: tuple[IPNetwork, ...] = (),
        mask_full: bool = False,
    ) -> None:
        self.geo = geo
        self.max_visitor_rows = max_visitor_rows
        self.max_request_rows = max_request_rows
        self.mask_internal_ips = mask_internal_ips
        self.mask_networks = mask_networks
        self.mask_full = mask_full
        self.masking_enabled = mask_internal_ips or bool(mask_networks)

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
        self.http_path_bytes: Counter[str] = Counter()
        self.http_path_ips: defaultdict[str, set[str]] = defaultdict(set)
        self.http_countries: Counter[str] = Counter()
        self.tls_countries: Counter[str] = Counter()
        self.http_asns: Counter[str] = Counter()
        self.tls_asns: Counter[str] = Counter()
        self.sni_counts: Counter[str] = Counter()
        self.http_bytes_by_ip: Counter[str] = Counter()
        self.http_errors_by_ip: Counter[str] = Counter()
        self.http_status_by_ip: defaultdict[str, Counter[str]] = defaultdict(Counter)
        self.http_methods_by_ip: defaultdict[str, Counter[str]] = defaultdict(Counter)
        self.http_protocols_by_ip: defaultdict[str, Counter[str]] = defaultdict(Counter)
        self.http_paths_by_ip: defaultdict[str, Counter[str]] = defaultdict(Counter)
        self.http_backends_by_ip: defaultdict[str, Counter[str]] = defaultdict(Counter)
        self.http_first_seen: dict[str, str] = {}
        self.http_last_seen: dict[str, str] = {}
        self.http_protocols: Counter[str] = Counter()
        self.http_status_classes: Counter[str] = Counter()
        self.http_hourly: Counter[int] = Counter()

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
        self.recent_http: deque[RequestRow] = deque(maxlen=max_request_rows)

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
        self.http_path_bytes[event.path] += event.bytes * count
        self.http_path_ips[event.path].add(event.ip)
        self.bytes_out += event.bytes * count
        self.ip_backends[event.ip][event.backend] += count
        self._touch_ip(event.ip, event.timestamp_display)

        size = event.bytes * count
        self.http_bytes_by_ip[event.ip] += size
        if event.status[:1] in {"4", "5"}:
            self.http_errors_by_ip[event.ip] += count
        self.http_status_by_ip[event.ip][event.status] += count
        self.http_methods_by_ip[event.ip][event.method] += count
        self.http_protocols[event.protocol] += count
        self.http_protocols_by_ip[event.ip][event.protocol] += count
        self.http_paths_by_ip[event.ip][event.path] += count
        self.http_backends_by_ip[event.ip][event.backend] += count
        status_class = (
            f"{event.status[0]}xx" if event.status[:1] in "12345" else "other"
        )
        self.http_status_classes[status_class] += count
        when = event.timestamp_display
        if when and when != "-":
            first = self.http_first_seen.get(event.ip)
            if first is None or when < first:
                self.http_first_seen[event.ip] = when
            last = self.http_last_seen.get(event.ip)
            if last is None or when > last:
                self.http_last_seen[event.ip] = when
            hour = when[11:13]
            if hour.isdigit():
                self.http_hourly[int(hour)] += count

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
        self.recent_http.appendleft(
            RequestRow(
                when=event.timestamp_display,
                ip=event.ip,
                method=event.method,
                path=event.path,
                status=event.status,
                size=event.bytes,
                frontend=event.frontend,
                backend=event.backend,
                country=country,
                city=geo["city"],
                protocol=event.protocol,
                count=count,
                port=event.client_port,
                server=event.server,
            )
        )

    @staticmethod
    def _items(counter: Counter[str], limit: int) -> list[dict[str, Any]]:
        return [{"name": name, "count": count} for name, count in counter.most_common(limit)]

    def _mask_text(self, value: str) -> str:
        if not self.masking_enabled:
            return value
        return mask_text_ips(value, self.mask_networks, self.mask_internal_ips, self.mask_full)

    def _mask_counter(self, counter: Counter[str]) -> Counter[str]:
        if not self.masking_enabled:
            return counter
        masked: Counter[str] = Counter()
        for name, count in counter.items():
            masked[mask_text_ips(name, self.mask_networks, self.mask_internal_ips, self.mask_full)] += count
        return masked

    @staticmethod
    def _location(geo: dict[str, Any]) -> str:
        parts = [part for part in (geo["city"], geo["country"]) if part not in ("-", "")]
        return ", ".join(parts) or "Unknown"

    def _http_ip_details(self) -> list[dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        for ip, requests in self.http_by_ip.items():
            geo = self._geo(ip)
            display_ip = (
                mask_ip(ip, self.mask_networks, self.mask_internal_ips, self.mask_full)
                if self.masking_enabled
                else ip
            )
            row = rows.get(display_ip)
            if row is None:
                row = {
                    "ip": display_ip,
                    "country": geo["country"],
                    "city": geo["city"],
                    "asn": geo["asn"],
                    "requests": 0,
                    "bytes": 0,
                    "errors": 0,
                    "_statuses": Counter(),
                    "_methods": Counter(),
                    "_protocols": Counter(),
                    "_paths": Counter(),
                    "_backends": Counter(),
                    "first_seen": self.http_first_seen.get(ip, "-"),
                    "last_seen": self.http_last_seen.get(ip, "-"),
                }
                rows[display_ip] = row
            else:
                for key in ("country", "city", "asn"):
                    if row[key] != geo[key]:
                        row[key] = "Multiple"
                first = self.http_first_seen.get(ip, "-")
                if first != "-" and (row["first_seen"] == "-" or first < row["first_seen"]):
                    row["first_seen"] = first
                last = self.http_last_seen.get(ip, "-")
                if last > row["last_seen"]:
                    row["last_seen"] = last
            row["requests"] += requests
            row["bytes"] += self.http_bytes_by_ip[ip]
            row["errors"] += self.http_errors_by_ip[ip]
            row["_statuses"].update(self.http_status_by_ip[ip])
            row["_methods"].update(self.http_methods_by_ip[ip])
            row["_protocols"].update(self.http_protocols_by_ip[ip])
            row["_paths"].update(self.http_paths_by_ip[ip])
            row["_backends"].update(self.http_backends_by_ip[ip])

        result: list[dict[str, Any]] = []
        for row in sorted(
            rows.values(), key=lambda item: (item["requests"], item["bytes"]), reverse=True
        ):
            classes: Counter[str] = Counter()
            for status, count in row.pop("_statuses").items():
                if status[:1] in "12345":
                    classes[f"{status[0]}xx"] += count
                else:
                    classes["other"] += count
            result.append(
                {
                    "ip": row["ip"],
                    "country": row["country"],
                    "city": row["city"],
                    "asn": row["asn"],
                    "requests": row["requests"],
                    "bytes": row["bytes"],
                    "errors": row["errors"],
                    "status_2xx": classes.get("2xx", 0),
                    "status_3xx": classes.get("3xx", 0),
                    "status_4xx": classes.get("4xx", 0),
                    "status_5xx": classes.get("5xx", 0),
                    "status_other": classes.get("other", 0),
                    "methods": self._items(row.pop("_methods"), 6),
                    "protocols": self._items(row.pop("_protocols"), 5),
                    "top_paths": self._items(self._mask_counter(row.pop("_paths")), 4),
                    "backends": self._items(self._mask_counter(row.pop("_backends")), 5),
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                }
            )
        return result[: self.max_visitor_rows]

    def build(self) -> dict[str, Any]:
        all_ips = set(self.http_by_ip) | set(self.tls_by_ip)
        country_count = sum(1 for name in self.country_stats if name not in _UNKNOWN_COUNTRIES)
        errors = sum(
            count for status, count in self.http_status.items() if status[:1] in {"4", "5"}
        )
        known_sni = Counter({name: count for name, count in self.sni_counts.items() if name != "No SNI"})
        if self.masking_enabled:
            known_sni = self._mask_counter(known_sni)
        http_backends = self._mask_counter(self.http_backends)
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
            snis = [
                [name, count]
                for name, count in self._mask_counter(self.ip_snis[ip]).most_common()
            ]
            backends = [
                [name, count]
                for name, count in self._mask_counter(self.ip_backends[ip]).most_common()
            ]
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

        raw_total = len(all_ips)
        if self.masking_enabled:
            merged: dict[str, dict[str, Any]] = {}
            for row in visitor_rows:
                display_ip = mask_ip(row["ip"], self.mask_networks, self.mask_internal_ips, self.mask_full)
                if display_ip not in merged:
                    merged[display_ip] = {
                        "ip": display_ip,
                        "country": row["country"],
                        "country_code": row["country_code"],
                        "city": row["city"],
                        "location": row["location"],
                        "asn": row["asn"],
                        "snis": Counter({name: count for name, count in row["snis"]}),
                        "backends": Counter({name: count for name, count in row["backends"]}),
                        "tls": 0,
                        "http": 0,
                        "last_seen": row["last_seen"],
                    }
                target = merged[display_ip]
                target["tls"] += row["tls"]
                target["http"] += row["http"]
                target["snis"].update({name: count for name, count in row["snis"]})
                target["backends"].update({name: count for name, count in row["backends"]})
                if row["last_seen"] > target["last_seen"]:
                    target["last_seen"] = row["last_seen"]

            visitor_rows = []
            for display_ip, row in merged.items():
                snis = [[name, count] for name, count in row["snis"].most_common()]
                backends = [[name, count] for name, count in row["backends"].most_common()]
                search = " ".join(
                    [
                        display_ip,
                        row["location"],
                        row["asn"],
                        " ".join(name for name, _ in snis),
                        " ".join(name for name, _ in backends),
                        row["last_seen"],
                    ]
                ).lower()
                visitor_rows.append(
                    {
                        "ip": display_ip,
                        "country": row["country"],
                        "country_code": row["country_code"],
                        "city": row["city"],
                        "location": row["location"],
                        "asn": row["asn"],
                        "snis": snis,
                        "backends": backends,
                        "tls": row["tls"],
                        "http": row["http"],
                        "last_seen": row["last_seen"],
                        "search": search,
                    }
                )
            visitor_rows.sort(
                key=lambda item: (item["last_seen"], item["tls"] + item["http"]), reverse=True
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
                    "ips": sorted(
                        {
                            mask_ip(ip, self.mask_networks, self.mask_internal_ips, self.mask_full)
                            if self.masking_enabled
                            else ip
                            for ip in stats["ips"]
                        }
                    )[:2000],
                }
            )
        points.sort(key=lambda item: item["total"], reverse=True)

        latest_seen = max(self.ip_last_seen.values(), default="-")

        path_rows: dict[str, dict[str, Any]] = {}
        for name, count in self.http_paths.items():
            display = (
                mask_text_ips(name, self.mask_networks, self.mask_internal_ips, self.mask_full)
                if self.masking_enabled
                else name
            )
            row = path_rows.setdefault(
                display, {"name": display, "count": 0, "bytes": 0, "ips": set()}
            )
            row["count"] += count
            row["bytes"] += self.http_path_bytes[name]
            row["ips"] |= self.http_path_ips[name]
        http_paths_payload = [
            {
                "name": row["name"],
                "count": row["count"],
                "bytes": row["bytes"],
                "visitors": len(row["ips"]),
            }
            for row in sorted(
                path_rows.values(), key=lambda item: item["count"], reverse=True
            )[:30]
        ]

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
                "http_backends": len(http_backends),
                "no_sni": self.sni_counts.get("No SNI", 0),
                "latest_seen": latest_seen,
            },
            "http": {
                "total": self.http_total,
                "bandwidth": self.bytes_out,
                "errors": errors,
                "unique_ips": len(self.http_by_ip),
                "avg_bytes": round(self.bytes_out / self.http_total) if self.http_total else 0,
                "error_rate": round(errors / self.http_total * 100, 1) if self.http_total else 0.0,
                "methods": self._items(self.http_methods, 10),
                "statuses": self._items(self.http_status, 12),
                "status_classes": [
                    {"name": name, "count": self.http_status_classes.get(name, 0)}
                    for name in ("2xx", "3xx", "4xx", "5xx", "other")
                ],
                "protocols": self._items(self.http_protocols, 10),
                "hourly": [
                    {"name": f"{hour:02d}:00", "count": self.http_hourly.get(hour, 0)}
                    for hour in range(24)
                ],
                "backends": self._items(http_backends, 15),
                "paths": http_paths_payload,
                "countries": self._items(self.http_countries, 15),
                "asns": self._items(self.http_asns, 15),
                "ip_details": self._http_ip_details(),
                "recent_limit": self.max_request_rows,
                "recent": [
                    {
                        "time": row.when,
                        "ip": mask_ip(
                            row.ip, self.mask_networks, self.mask_internal_ips, self.mask_full
                        )
                        if self.masking_enabled
                        else row.ip,
                        "method": row.method,
                        "path": self._mask_text(row.path),
                        "status": row.status,
                        "bytes": row.size,
                        "frontend": self._mask_text(row.frontend),
                        "backend": self._mask_text(row.backend),
                        "country": row.country,
                        "city": row.city,
                        "protocol": row.protocol,
                        "count": row.count,
                        "port": row.port,
                        "server": self._mask_text(row.server),
                    }
                    for row in self.recent_http
                ],
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
                        "ip": mask_ip(ip, self.mask_networks, self.mask_internal_ips, self.mask_full)
                        if self.masking_enabled
                        else ip,
                        "sni": mask_text_ips(sni, self.mask_networks, self.mask_internal_ips, self.mask_full)
                        if self.masking_enabled
                        else sni,
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
                "raw_total": raw_total,
                "masked": self.masking_enabled,
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
