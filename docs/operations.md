# Operations

This is the operational runbook for the dashboard and parser. For deployment
setup see [deployment.md](deployment.md); for HAProxy snippets see
[haproxy.md](haproxy.md).

## Start and verify

```bash
docker compose up -d
docker compose ps
docker compose logs --tail=100 haproxy-analytics

curl -fsS http://127.0.0.1:8009/healthz
curl -fsS http://127.0.0.1:8009/version.json
curl -fsS http://127.0.0.1:8009/api/whoami
curl -fsS http://127.0.0.1:8009/api/live
```

`/healthz` returns 200 after the first successful snapshot. Warnings about a
missing GeoIP database or an empty source do not make the process unhealthy.
A failed snapshot build returns 503 and keeps the last good snapshot visible.

## Snapshot refresh

- The refresh thread runs every `REFRESH_SECONDS` (default 60).
- The browser polls `/api/snapshot` on the same interval. The page does not
  use WebSockets or server push.
- A failed refresh keeps the previous snapshot and records `last_error` in
  `/healthz`.
- Refreshing a very large log is bounded by `MAX_LOG_BYTES`, but still costs CPU.
  Increase the interval or reduce the tail window on small hosts.

## Live stats

Live stats are independent of the log snapshot:

- enable them with `HAPROXY_STATS_SOCKET=host:port`;
- the app connects to a dedicated HAProxy stats socket at `level user` and sends
  only `show info;show stat`;
- the poll interval is `STATS_REFRESH_SECONDS` (default 5);
- the browser polls `/api/live` only while the Live view is active and visible;
- the last good payload is kept when a poll fails; `meta.connected` and
  `meta.last_error` show the current state;
- `STATS_MAX_BYTES` and `STATS_MAX_ROWS` bound the response and tables;
- internal server addresses and ports are omitted from the payload.

The stats protocol has no TLS or authentication. Keep the socket on a private
interface, firewall it to the analytics host and never expose it through
HAProxy. See [haproxy.md](haproxy.md#5-read-only-live-stats-socket).

Check connectivity from the analytics host:

```bash
printf 'show info\n' | socat - TCP:192.0.2.20:8404 | head
printf 'show stat\n' | socat - TCP:192.0.2.20:8404 | head -n 3
curl -fsS http://127.0.0.1:8009/api/live
```

If `meta.connected` is false, check the endpoint, firewall, HAProxy stats socket
bind and the HAProxy reload. The app reconnects on the next interval and does
not require a restart after a transient failure.

## Domain filtering

Use `EXCLUDED_DOMAINS` to drop sensitive applications before aggregation, or
`DOMAIN_ONLY_DOMAINS` to keep their counts while replacing the URI with the
domain:

```dotenv
EXCLUDED_DOMAINS=private.example.com,secret.example.org
DOMAIN_ONLY_DOMAINS=sendpass.example.com
```

Check the result:

```bash
curl -fsS http://127.0.0.1:8009/api/snapshot \
  | python3 -c 'import json,sys; p=json.load(sys.stdin)["meta"]["privacy"]; print(p["excluded_domains"], p["domain_only_domains"], p["excluded_events"], p["redacted_paths"])'
```

- SNI matching works for TLS/SNI events.
- HTTP matching needs `capture request header Host len 64` in the HAProxy
  frontend, unless the request target is an absolute URL with a host.
- The filter is exact-or-subdomain and case-insensitive.
- Excluded events do not appear in KPIs, maps, visitors, paths or request rows.
- Domain-only events keep request/status/byte/backend counts, but show
  `sendpass.example.com/` or `https://sendpass.example.com/` instead of the
  original path and query string.
- The two lists must not overlap or contain each other.
- Raw log lines, rotated files and `SYSLOG_STORE_FILE` are not redacted. Use
  source-side log controls and retention for secrets that must not be written.

## Parser formats

### Standard HTTP (`option httplog`)

```text
203.0.113.10:53124 [18/Nov/2026:00:01:02.123] ft_https bk_app/app1 0/0/1/2/3 200 5120 "GET /assets/app.css HTTP/1.1"
```

Fields used by the app:

| Field | Meaning |
| --- | --- |
| `203.0.113.10` | Client IP. |
| `53124` | Client port (ignored for grouping). |
| `[18/Nov/2026:00:01:02.123]` | HAProxy timestamp. |
| `ft_https` | Frontend (trailing `~` is stripped). |
| `bk_app/app1` | Backend/server; the backend part is used. |
| `0/0/1/2/3` | Timers (not used for analytics). |
| `200` | Status. `---` is accepted. |
| `5120` | Response bytes; `-` becomes 0. |
| `"GET ... HTTP/1.1"` | Request method, path and protocol. |

A simple format without the timer field is also accepted:

```text
203.0.113.10:53124 [18/Nov/2026:00:01:02.123] ft_https bk_app/app1 200 5120 "GET / HTTP/1.1"
```

### TLS/SNI

```text
src=203.0.113.10 dst=198.51.100.10:443 sni=app.example.com
```

The SNI value `-` is grouped as `No SNI`. The timestamp comes from the syslog
prefix when present.

### Repeated messages

```text
message repeated 3 times: [ src=203.0.113.10 dst=198.51.100.10:443 sni=app.example.com]
message repeated 2 times: [ 203.0.113.20:53137 [18/Nov/2026:00:01:26.000] ft_https bk_static/static1 0/0/1/1/2 304 0 "GET /assets/app.js HTTP/1.1"]
```

The count is applied to the relevant counters and request rows.

## Diagnose an empty or partial dashboard

1. Check the source metadata in the snapshot (the UI warning banner or
   `curl /api/snapshot`).
2. Is `HAPROXY_LOG_FILE` present and readable by UID/GID `10001`?
3. Does the file contain new records after the last deployment?
4. If using syslog, is `SYSLOG_LISTEN` set, the port mapped, the sender
   allowlisted and the firewall open?
5. Look for parser warnings: `unparsed_lines` is reported in `meta.parser` and
   becomes a UI warning when non-zero.
6. Verify the log format against the examples above. A custom HAProxy
   `log-format` with a different field order will not parse as the standard
   format.

## Common parser problems

### `sni=-`

- The capture line runs after accept. Move
  `tcp-request content capture req.ssl_sni len 100` above
  `tcp-request content accept if { req_ssl_hello_type 1 }`.
- The client did not send SNI. Some tools and old clients do not.
- The connection is not a TLS ClientHello (health check, port scan, plain
  protocol).
- You are looking at old records from before the capture fix.

### No HTTP analytics

- The terminating frontend is `mode tcp`. It cannot log HTTP requests.
- `option httplog` is missing or the log target is not the file being read.
- HAProxy logs to a different facility or file.
- The log is rotated and the container is reading an old mount.
- The HTTP record has a custom format the parser does not recognise.

### `unparsed_lines` grows

A nonzero count is not always an error: a shared syslog stream contains other
services. If it grows with HAProxy traffic, compare the actual line with the
supported formats. Add a custom parser only after deciding how to map the
fields; do not silently drop data.

### Timestamps look wrong

HAProxy timestamps do not include a timezone. The app displays the recorded
date and time. `TZ` affects generated-at metadata, not the log timestamps.
Check the HAProxy host clock and the sender/relay clock.

## HTTP analytics, requests and per-IP details

HTTP analytics are generated natively from parsed events; there is no external
report process.

The **HTTP analytics** page includes:

- total requests, unique HTTP client IPs, bandwidth, 4xx/5xx counts and average
  response size;
- method types, status classes (2xx/3xx/4xx/5xx), protocols and an hourly
  distribution;
- top paths with requests, unique visitors and bytes, plus backends, countries and ASNs;
- a **Per-IP HTTP details** table with request/byte totals, error counts,
  status classes, method types, protocols, top paths, backends and first/last
  seen timestamps;
- a **Latest requests** table with method, status, path, bytes, backend/server
  and protocol, plus a link to the full Requests tab.

The **Requests** tab lists the newest individual HTTP events, capped by
`MAX_REQUEST_ROWS` (default 2000). It includes time, client address and port,
country/city, method, request, status, bytes, frontend, backend/server and
protocol. The text filter searches all columns. **View requests** on a per-IP
row opens the Requests tab with that client preselected.

Increase `MAX_REQUEST_ROWS` and `MAX_LOG_BYTES` together if you need a longer
individual-request list. The counters and per-IP details are always computed
over the parsed log window, even when only the newest request rows are kept.

### Private IPs and per-IP detail

Masking applies to the native tables exactly as it does to the rest of the
dashboard. The default `MASK_INTERNAL_IPS=true` masks private and other
non-global addresses. With `MASK_FULL=true`, all masked clients collapse into
one `x.x.x.x` row, which hides per-IP differences.

To see individual private IPs and keep per-IP HTTP detail meaningful:

```dotenv
MASK_INTERNAL_IPS=false
MASK_NETWORKS=
MASK_FULL=false
```

If `MASK_NETWORKS` still contains `192.0.0.0/8` or `172.0.0.0/8`, those ranges
remain masked. Remove or narrow the list. Keep the dashboard behind the
authenticated HAProxy frontend when masking is disabled.

## Log rotation

The app reads the current file, not a directory or a glob. Options:

- `logrotate` with `copytruncate` keeps the same inode; the app reads the
  truncated current file on the next refresh.
- Rotate and create a new current file. The app opens the path again on the next
  refresh, so the new file is read.
- Keep the rotated files if you need history outside the current window. The app
  does not read them automatically.
- Compressed files are not read. Decompress or use a central log store.

A rotation can make the visible counts smaller because older records leave the
current file. This is expected for a current-file reader.

## Performance and memory

| Control | Effect |
| --- | --- |
| `MAX_LOG_BYTES` | Tail window; the main CPU and memory bound. |
| `REFRESH_SECONDS` | How often the full tail is re-parsed. |
| `MAX_VISITOR_ROWS` | Maximum visitor rows in the snapshot/API. |
| `MAX_REQUEST_ROWS` | Newest individual HTTP requests retained for the Requests view/API. |
| `SYSLOG_BUFFER_LINES` | In-memory syslog history. |
| `SYSLOG_MAX_MESSAGE_BYTES` | Per-message cap. |
| `STATS_REFRESH_SECONDS` | How often the live stats socket is polled. |
| `STATS_MAX_BYTES` | Maximum runtime API response. |
| `STATS_MAX_ROWS` | Maximum live table rows per category. |

The app keeps counters and per-IP details in memory, not raw lines. A very large
unique-IP or unique-path set still costs memory. Monitor the container and raise
`REFRESH_SECONDS` before increasing every limit. Live stats add one small
outbound connection per poll; `STATS_MAX_BYTES` and `STATS_MAX_ROWS` keep the
payload bounded even if HAProxy has many proxies or servers.

## Storage and disk usage

### Syslog receiver without a persistent store

By default the syslog receiver is **memory-only**:

- Accepted messages are stored in a bounded in-memory ring,
  `SYSLOG_BUFFER_LINES` (default 200,000).
- Nothing is written to disk in this mode.
- A restart clears the ring.
- When the ring is full, the oldest lines are dropped. The app keeps running,
  increments the `dropped` counter and shows a snapshot warning.
- Messages larger than `SYSLOG_MAX_MESSAGE_BYTES` are dropped and counted.
- Large rings consume RAM, not disk.

### Persistent syslog history

Set `SYSLOG_STORE_FILE=/data/syslog.log` to persist accepted syslog lines in the
host directory mounted at `/data` (`DATA_DIR`, default `./data`):

```dotenv
DATA_DIR=./data
SYSLOG_STORE_FILE=/data/syslog.log
SYSLOG_STORE_MAX_BYTES=536870912
SYSLOG_STORE_BACKUPS=1
```

The history survives restarts and reboots. Disk use is bounded by roughly
`(SYSLOG_STORE_BACKUPS + 1) × SYSLOG_STORE_MAX_BYTES`; with the defaults that is
about 1 GB.

The dashboard still reads only the newest `MAX_LOG_BYTES` tail. Increase
`MAX_LOG_BYTES` and `REFRESH_SECONDS` together if you want a larger analysis
window and can accept the extra parsing cost.

When the current file reaches `SYSLOG_STORE_MAX_BYTES`, it is rotated to
`syslog.log.1`; older backups are shifted or removed according to
`SYSLOG_STORE_BACKUPS`.

The **Security & privacy** tab has a **Clear syslog history** action. It removes
the current file and all backups, clears the in-memory buffer, and rebuilds the
snapshot. The action is CSRF-protected with a per-process token and should only
be reachable behind the authenticated HAProxy frontend.

If the data directory is not writable, the app keeps running and shows write
errors in the snapshot. The receiver continues to accept lines into its
in-memory ring, but new lines may not appear in the dashboard until the store is
writable again.

### Other storage paths

- **File mode** only reads the mounted log. It never writes to it.
- **Snapshot data** is in memory.
- **Docker container logs** are written by the Docker logging driver on the
  host. The supplied Compose file caps `json-file` logs at 10 MB × 3 files.
- **GeoIP databases** live in the host `./geoip` directory and are typically
  tens of MB. The optional updater writes them there.

### If the host disk is full

- The memory-only path does not require disk space.
- The persistent syslog store reports write errors and stops persisting new
  lines until space is available.
- Docker may fail to write container logs, create temporary files or restart
  the container.
- The **Clear syslog history** action can free the persistent store's disk space.
- A container restart can fail until Docker has writable disk space again.

If host memory is exhausted, the kernel can OOM-kill the container. That loses
the in-memory syslog ring.

Monitor:

```bash
df -h
docker system df
du -sh geoip/ data/
docker stats haproxy-analytics
curl -s http://127.0.0.1:8009/api/snapshot \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["meta"]["source"]["syslog"]); print(d["meta"]["warnings"])'
```

## Health, version and logs

```bash
curl -fsS http://127.0.0.1:8009/healthz | python3 -m json.tool
curl -fsS http://127.0.0.1:8009/version.json | python3 -m json.tool
docker compose logs -f --tail=200 haproxy-analytics
docker stats haproxy-analytics
```

The app does not log request paths or client addresses by default. Container
logs contain startup/configuration messages and operational errors.

Live stats connection state is in `/api/live` and in the `live` block of
`/healthz`:

```bash
curl -fsS http://127.0.0.1:8009/api/live \
  | python3 -c 'import json,sys; m=json.load(sys.stdin)["meta"]; print(m["enabled"], m["connected"], m["last_error"])'
```

## Upgrade and rollback

```bash
docker compose pull
docker compose up -d --force-recreate
```

Pin a reviewed digest in production. Rollback by setting `IMAGE_TAG` to the
previous reviewed tag or digest. There is no application data to migrate.

## Backup

There is no application database. Back up:

- `.env` (contains deployment settings and possibly GeoIP credentials);
- `compose.yaml` if you changed it;
- GeoIP databases if you cannot re-download them;
- HAProxy configuration and certificates;
- any external central log store.

Do not commit those backups to the repository.

## Reboot behavior

- The container starts with the host/Compose policy.
- The refresh thread rebuilds the snapshot from the configured sources.
- The optional live-stats thread reconnects to the configured stats socket.
- File mode reads the current file; syslog mode starts with an empty ring.
- HAProxy and rsyslog start according to their own service configuration.
- `pull_policy: if_not_present` means a restart does not silently pull a new
  image.

## Security operations

See [security.md](security.md) for the full checklist. The short version:

- keep the app behind HAProxy with TLS and authentication;
- keep `APP_BIND=127.0.0.1` unless you have a controlled private network;
- keep `TRUSTED_PROXIES` and `SYSLOG_ALLOWED_NETWORKS` narrow;
- keep `HAPROXY_STATS_SOCKET` on a private interface with `level user` and firewall it to the analytics host;
- keep `MASK_INTERNAL_IPS=true` unless raw internal client addresses are required;
- use syslog TLS/mTLS across untrusted networks;
- rotate credentials and certificates;
- review the public repository before making it visible;
- run `python3 scripts/verify.py` and Gitleaks in CI.
