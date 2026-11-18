# Architecture

HAProxy Analytics is deliberately small. It is a read-only analysis process with
a static browser dashboard, not a log platform.

## Components

| Component | File | Responsibility |
| --- | --- | --- |
| HTTP server | `haproxy_analytics/server.py` | Serves the dashboard, JSON API, health/version endpoints and the token-protected syslog clear endpoint. Applies security headers and method restrictions. |
| Snapshot service | `haproxy_analytics/snapshot.py` | Reads sources, runs the parser and aggregator, and holds the latest snapshot in memory. |
| Parser | `haproxy_analytics/parser.py` | Recognises syslog prefixes, HTTP `option httplog` records, SNI records and `message repeated` groups. |
| Aggregator | `haproxy_analytics/aggregate.py` | Produces counters, per-IP details, country/city statistics and map points. |
| GeoIP resolver | `haproxy_analytics/geoip.py` | Optional MaxMind City/ASN lookups from local MMDB files. Never performs network lookups. |
| Log sources | `haproxy_analytics/logsource.py` | Read-only file tail reader, bounded syslog ring buffer and optional UDP/TCP receiver. |
| Syslog store | `haproxy_analytics/syslog_store.py` | Optional append-only persistent syslog history with size rotation and a clear operation. |
| Live stats | `haproxy_analytics/livestats.py` | Read-only HAProxy runtime API client, bounded cache and parser for `show info` / `show stat`. |
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
        snapshot JSON     map points/country   HTTP/IP detail rows
              │                 │                  │
              └─────────────────┴──────────────────┘
                                │
                                ▼
                    in-memory snapshot + HTML
                                │
 optional HAProxy stats socket  │
 (remote, read-only, level user)│
              │                 │
              ▼                 │
      live stats cache ─────────┤
      (show info / show stat)   │
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
  client certificates. By default a restart clears the ring. Set
  `SYSLOG_STORE_FILE=/data/syslog.log` to persist accepted lines in the
  dedicated `/data` volume, with size rotation and a clear-history action.
- **Both**: both sources are parsed. If the same events exist in both, they are
  counted twice, so the snapshot includes a warning.
- **Demo**: reads the bundled synthetic log. It does not touch HAProxy.
- **Live stats**: an independent, optional read-only connection to a dedicated
  HAProxy stats socket. It does not consume log data and does not affect the
  snapshot counters.

## Snapshot API

`GET /api/snapshot` returns a JSON object with:

- `meta`: generation time, refresh interval, version, active sources, GeoIP
  availability, syslog store status, parser statistics and warnings.
- `kpis`: HTTP requests, TLS connections, unique IPs, countries, 4xx/5xx,
  bandwidth, geolocated points, SNI hostnames and backends.
- `http`: methods, statuses, status classes, protocols, hourly distribution,
  backends, paths, countries, ASNs, per-IP details, and the newest individual
  requests, capped by `MAX_REQUEST_ROWS`.
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

### Live stats API

`GET /api/live` returns:

- `meta`: whether live stats are enabled, connection state, endpoint,
  refresh interval, last success/error, consecutive errors and warnings;
- `info`: curated `show info` fields such as version, uptime, connections,
  SSL counters, tasks, idle percentage and memory;
- `summary`: aggregate frontend/backend/server counts, sessions, rates, bytes,
  HTTP 4xx/5xx and errors;
- `frontends`, `backends`, `servers`: bounded rows from `show stat`.
  Internal server addresses and ports are intentionally omitted.

The service sends only `show info;show stat`; the HTTP client cannot supply
commands. A failed poll keeps the last good payload visible and updates the
connection metadata. When no socket is configured, the endpoint returns a
stable disabled payload with HTTP 200.

## Threading and memory

- One refresh thread per process for the log snapshot.
- One optional live-stats refresh thread when `HAPROXY_STATS_SOCKET` is set.
- One thread per HTTP request (`ThreadingHTTPServer`).
- Optional syslog threads (`ThreadingMixIn`), daemon threads.
- The snapshot is replaced atomically under a lock.
- Raw log lines are never stored in the snapshot. The visitor table is capped,
  top lists are capped, map points are capped and the syslog ring is bounded.
- The live payload is capped by response size and row count. Server addresses
  are dropped before the payload is stored.

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
6. **Live stats**: an optional outbound connection to a dedicated read-only
   stats socket. The socket has no TLS or authentication of its own, so it must
   be bound to a private interface, firewalled to the analytics host and kept
   at `level user`. The app sends only two whitelisted `show` commands.
7. **Rendering**: dashboard values are inserted as text nodes and DOM APIs, never
   `innerHTML`. There is no third-party report iframe or chart script.
8. **Container**: non-root user, read-only root filesystem, no capabilities and
   `no-new-privileges`.

## Deliberate omissions

- No database or queryable event store. The optional syslog file store is append-only.
- No user accounts, sessions, password hashes or MFA.
- No external IP geolocation or map tile service.
- No log upload endpoint.
- No HAProxy runtime-control commands. Live stats are observation only.
- No `show sess`, `show errors` or stick-table dumps in the web view; those expose client-level data beyond the aggregate live view.
- No background job queue.
- No automatic rotation or compression for the mounted file source. The optional syslog store rotates by size.
- No long-term history unless the optional syslog store is enabled or the log is kept externally.

These are scope decisions, not hidden limitations. The documentation explains
the deployment patterns that provide persistence and history outside the app.
