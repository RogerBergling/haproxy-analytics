# Architecture

HAProxy Analytics is deliberately small. It is a read-only analysis process with
a static browser dashboard, not a log platform.

## Components

| Component | File | Responsibility |
| --- | --- | --- |
| HTTP server | `haproxy_analytics/server.py` | Serves the dashboard, JSON API, health/version endpoints and the optional GoAccess report. Applies security headers and method restrictions. |
| Snapshot service | `haproxy_analytics/snapshot.py` | Reads sources, runs the parser and aggregator, holds the latest snapshot and the optional GoAccess HTML in memory. |
| Parser | `haproxy_analytics/parser.py` | Recognises syslog prefixes, HTTP `option httplog` records, SNI records and `message repeated` groups. |
| Aggregator | `haproxy_analytics/aggregate.py` | Produces counters, per-IP details, country/city statistics and map points. |
| GeoIP resolver | `haproxy_analytics/geoip.py` | Optional MaxMind City/ASN lookups from local MMDB files. Never performs network lookups. |
| GoAccess runner | `haproxy_analytics/goaccess.py` | Optional subprocess with a timeout and output-size cap. |
| Log sources | `haproxy_analytics/logsource.py` | Read-only file tail reader, bounded syslog ring buffer and optional UDP/TCP receiver. |
| Configuration | `haproxy_analytics/config.py` | Parses environment and CLI values with safe defaults. |
| Frontend | `public/` | Static HTML, CSS and ES modules. No build step, framework or CDN. |

## Data flow

```text
                 ┌──────────────────────────────┐
 /logs/haproxy.log│ read the last MAX_LOG_BYTES  │
                 └──────────────┬───────────────┘
                                │
 optional syslog UDP/TCP ───────┤
 (allowlist, optional TLS)      │
                                ▼
                        parser (one line at a time)
                                │
                                ▼
                    aggregator (bounded counters)
                                │
              ┌─────────────────┼──────────────────┐
              ▼                 ▼                  ▼
        snapshot JSON     map points/country    optional GoAccess
              │                 │                  │
              └─────────────────┴──────────────────┘
                                │
                                ▼
                    in-memory snapshot + HTML
                                │
                                ▼
                  same-origin HTTP server (no writes)
```

The snapshot is rebuilt by a background thread every `REFRESH_SECONDS`. The
HTTP request path only serialises the current snapshot; it never re-reads the
log. A failed refresh leaves the last successful snapshot visible and records
the error in `/healthz`.

## Source modes

- **File**: reads at most `MAX_LOG_BYTES` from the end of the file. If the file
  is larger, the first partial line is discarded. The source is opened
  read-only. Rotated or compressed files are not followed automatically.
- **Syslog**: opt-in. UDP and/or TCP, a source-network allowlist, a bounded
  in-memory ring, a maximum message size and optional TCP TLS with optional
  client certificates. No persistence; a restart clears the ring.
- **Both**: both sources are parsed. If the same events exist in both, they are
  counted twice, so the snapshot includes a warning.
- **Demo**: reads the bundled synthetic log. It does not touch HAProxy.

## Snapshot API

`GET /api/snapshot` returns a JSON object with:

- `meta`: generation time, refresh interval, version, active sources, GeoIP
  availability, GoAccess status, parser statistics and warnings.
- `kpis`: HTTP requests, TLS connections, unique IPs, countries, 4xx/5xx,
  bandwidth, geolocated points, SNI hostnames and backends.
- `http`: methods, statuses, backends, paths, countries and ASNs.
- `tls`: SNI hostnames, countries, ASNs and recent connections.
- `geo`: countries, cities and map points with per-point IP lists for the
  self-highlight feature.
- `visitors`: per-IP rows capped by `MAX_VISITOR_ROWS`. When
  `MASK_INTERNAL_IPS` is enabled, non-global addresses are masked and rows are
  grouped by their masked prefix; `visitors.masked` and `visitors.raw_total`
  describe the result.
- `parser`: unparsed line and repeated-group counts.

The API is same-origin and protected by the same network boundary as the HTML.
It is not a public API.

## Threading and memory

- One refresh thread per process.
- One thread per HTTP request (`ThreadingHTTPServer`).
- Optional syslog threads (`ThreadingMixIn`), daemon threads.
- The snapshot is replaced atomically under a lock.
- Raw log lines are never stored in the snapshot. The visitor table is capped,
  top lists are capped, map points are capped and the syslog ring is bounded.
- GoAccess uses a temporary directory under `/tmp`; the container runs with a
  small tmpfs so a missing cleanup cannot fill the image.

## Security boundaries

1. **Network**: the app is intended to be reachable only through HAProxy. The
   default Compose binding is `127.0.0.1`.
2. **Authentication**: provided by HAProxy, not by this process. There is no
   account database to attack.
3. **Log input**: treated as untrusted text. Values are inserted into the DOM
   with `textContent` and DOM APIs, never `innerHTML`.
4. **Forwarded IPs**: `X-Forwarded-For` is ignored unless the direct peer is in
   `TRUSTED_PROXIES`.
5. **Syslog**: source allowlist, size limits and optional TLS/mTLS. Plain syslog
   has no authentication and must be kept on a trusted network.
6. **GoAccess**: generated HTML is served in a sandboxed iframe with a separate
   CSP. It cannot access the parent page or make network requests.
7. **Container**: non-root user, read-only root filesystem, no capabilities and
   `no-new-privileges`.

## Deliberate omissions

- No database or persistent event store.
- No user accounts, sessions, password hashes or MFA.
- No external IP geolocation or map tile service.
- No log upload endpoint.
- No background job queue.
- No automatic log rotation or compression handling.
- No long-term history across restarts when using syslog only.

These are scope decisions, not hidden limitations. The documentation explains
the deployment patterns that provide persistence and history outside the app.
