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

The count is applied to the relevant counters. Repeated HTTP lines are expanded
for GoAccess up to `GOACCESS_MAX_LINES`.

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

## GoAccess

GoAccess is optional.

```dotenv
GOACCESS_ENABLED=true
GOACCESS_TIMEOUT=60
GOACCESS_MAX_LINES=100000
```

The image includes the `goaccess` binary and a bundled config at
`/app/config/goaccess-haproxy.conf`. If your HAProxy format differs:

1. Create a GoAccess config that matches it.
2. Mount it into the container, for example add this to the app service:
   `- ./goaccess.conf:/config/goaccess.conf:ro`
3. Set `GOACCESS_CONFIG=/config/goaccess.conf` in `.env`.
4. Restart and check the GoAccess tab and container logs.

The app passes only HTTP lines (with the syslog prefix removed) to GoAccess. TLS
SNI lines are not GoAccess input. A non-zero exit produces a generic dashboard
message and a detailed local log entry.

Do not embed the GoAccess HTML directly into the main page. The sandbox is part
of the security model.

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
| `SYSLOG_BUFFER_LINES` | In-memory syslog history. |
| `SYSLOG_MAX_MESSAGE_BYTES` | Per-message cap. |
| `GOACCESS_MAX_LINES` | HTTP lines passed to GoAccess. |
| `GOACCESS_MAX_HTML_BYTES` | Maximum report size served. |

The app keeps counters and per-IP details in memory, not raw lines. A very large
unique-IP or unique-path set still costs memory. Monitor the container and raise
`REFRESH_SECONDS` before increasing every limit.

## Health, version and logs

```bash
curl -fsS http://127.0.0.1:8009/healthz | python3 -m json.tool
curl -fsS http://127.0.0.1:8009/version.json | python3 -m json.tool
docker compose logs -f --tail=200 haproxy-analytics
docker stats haproxy-analytics
```

The app does not log request paths or client addresses by default. Container
logs contain startup/configuration messages and operational errors.

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
- File mode reads the current file; syslog mode starts with an empty ring.
- HAProxy and rsyslog start according to their own service configuration.
- `pull_policy: if_not_present` means a restart does not silently pull a new
  image.

## Security operations

See [security.md](security.md) for the full checklist. The short version:

- keep the app behind HAProxy with TLS and authentication;
- keep `APP_BIND=127.0.0.1` unless you have a controlled private network;
- keep `TRUSTED_PROXIES` and `SYSLOG_ALLOWED_NETWORKS` narrow;
- use syslog TLS/mTLS across untrusted networks;
- rotate credentials and certificates;
- review the public repository before making it visible;
- run `python3 scripts/verify.py` and Gitleaks in CI.
