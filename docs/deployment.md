# Deployment

This guide covers the Docker Compose deployment, the environment file, volumes,
permissions, GeoIP data and upgrades. For HAProxy snippets see
[haproxy.md](haproxy.md). For log shipping see [external-logs.md](external-logs.md).

## Prerequisites

- Docker Engine 24+ with Compose v2.
- A read-only HAProxy log file, or a syslog sender you control.
- Optional: a dedicated read-only HAProxy stats socket for Live stats.
- Optional: MaxMind GeoLite2 City and ASN databases.
- Recommended: HAProxy in front for TLS and authentication.

The published image supports `linux/amd64` and `linux/arm64`:

```text
ghcr.io/rogerbergling/haproxy-analytics:latest
```

## Directory layout

```text
haproxy-analytics/
├── compose.yaml
├── .env                  # local, ignored by git
├── logs/
│   └── haproxy.log       # current log, mounted read-only
├── geoip/
│   ├── GeoLite2-City.mmdb
│   └── GeoLite2-ASN.mmdb
├── data/                 # optional persistent syslog history, writable
└── certs/                # optional syslog TLS material, ignored by git
```

`logs/`, `geoip/`, `data/`, `certs/` and `.env` are in `.gitignore`.

## Start

```bash
git clone https://github.com/RogerBergling/haproxy-analytics.git
cd haproxy-analytics
cp .env.example .env
mkdir -p logs geoip data
sudo chown 10001:10001 data

# For a first test, copy the current HAProxy log. The app reads the file; it
# never writes it. For a live same-host deployment, set
# HAPROXY_LOG_DIR=/var/log in .env instead of copying.
cp /var/log/haproxy.log logs/haproxy.log

# Optional: copy GeoLite2 databases.
cp /var/lib/GeoIP/GeoLite2-City.mmdb geoip/
cp /var/lib/GeoIP/GeoLite2-ASN.mmdb geoip/

docker compose up -d
docker compose ps
```

Open <http://127.0.0.1:8009>. If the dashboard is empty, check
`docker compose logs -f haproxy-analytics` and the snapshot warnings in the UI.

## Environment reference

Copy `.env.example` to `.env`. Do not commit `.env`. The application reads
environment variables; Compose reads `.env` and injects them. A local Python run
uses the shell environment or CLI flags, not `.env` automatically.

| Variable | Default | Notes |
| --- | --- | --- |
| `IMAGE_TAG` | `latest` | Use a tag or digest you have reviewed. |
| `APP_BIND` | `127.0.0.1` | Host interface for the published port. Keep loopback unless HAProxy is on the same host and the network is controlled. |
| `APP_PORT` | `8009` | Published host port. The container always listens on 8080 internally. |
| `TZ` | `UTC` | Container timezone for generated-at timestamps. HAProxy log timestamps keep their recorded timezone-free value. |
| `HAPROXY_LOG_DIR` | `./logs` | Host directory mounted at `/logs` read-only. |
| `HAPROXY_LOG_FILE` | `/logs/haproxy.log` | Path inside the container. Set to empty to disable file mode (syslog only). |
| `MAX_LOG_BYTES` | `33554432` | Read at most this many bytes from the end of the log. |
| `REFRESH_SECONDS` | `60` | Snapshot rebuild interval. The browser also polls on this interval. |
| `MAX_VISITOR_ROWS` | `5000` | Upper bound on returned visitor rows. |
| `MAX_REQUEST_ROWS` | `2000` | Newest individual HTTP requests retained for the Requests view and API. |
| `MASK_INTERNAL_IPS` | `true` | Mask non-global client IPs (private, loopback, documentation) in the dashboard and API. Public IPs remain visible. |
| `MASK_NETWORKS` | empty | Additional CIDRs to mask even if public, for example `192.0.0.0/8,172.0.0.0/8`. |
| `MASK_FULL` | `false` | Use one full mask (`x.x.x.x` / `x:x:x:x:x:x:x:x`) instead of prefix masks. |
| `EXCLUDED_DOMAINS` | empty | Comma-separated domains to drop before aggregation. Matches the domain and all subdomains. HTTP matching needs a captured Host header. |
| `GEOIP_DIR` | `./geoip` | Host directory mounted at `/geoip` read-only. |
| `GEOIP_CITY_DB` | `/geoip/GeoLite2-City.mmdb` | City database path inside the container. |
| `GEOIP_ASN_DB` | `/geoip/GeoLite2-ASN.mmdb` | ASN database path inside the container. |
| `TRUSTED_PROXIES` | empty | Comma-separated CIDRs allowed to supply `X-Forwarded-For`. Use only the HAProxy address. |
| `HAPROXY_STATS_SOCKET` | empty | Optional read-only HAProxy stats socket as `host:port`. Empty disables Live stats. |
| `STATS_REFRESH_SECONDS` | `5` | Live stats poll interval. |
| `STATS_TIMEOUT_SECONDS` | `2` | Live stats connect/read timeout. |
| `STATS_MAX_BYTES` | `4194304` | Maximum runtime API response size. |
| `STATS_MAX_ROWS` | `500` | Maximum rows per live table category. |
| `SYSLOG_LISTEN` | empty | Optional `host:port`, for example `0.0.0.0:5514`. Empty disables the receiver. |
| `SYSLOG_PROTOCOLS` | `udp` | `udp`, `tcp`, or both comma-separated. |
| `SYSLOG_ALLOWED_NETWORKS` | `127.0.0.0/8,::1/128` | Source allowlist. Set the sending host or relay network. |
| `SYSLOG_BUFFER_LINES` | `200000` | In-memory ring size. |
| `SYSLOG_MAX_MESSAGE_BYTES` | `65536` | Oversized messages are dropped. |
| `DATA_DIR` | `./data` | Host directory for optional persistent syslog history, mounted read-write at `/data`. |
| `SYSLOG_STORE_FILE` | empty | Set to `/data/syslog.log` to persist received syslog lines. Empty keeps the receiver memory-only. |
| `SYSLOG_STORE_MAX_BYTES` | `536870912` | Maximum size of the current syslog file before rotation. |
| `SYSLOG_STORE_BACKUPS` | `1` | Number of rotated files kept. |
| `SYSLOG_TLS_CERT` | empty | Container path to a PEM certificate chain for TCP syslog. |
| `SYSLOG_TLS_KEY` | empty | Container path to the private key. |
| `SYSLOG_TLS_CA` | empty | Optional CA bundle for verifying client certificates. |
| `SYSLOG_TLS_REQUIRE_CLIENT_CERT` | `false` | Set true for mTLS. |
| `SYSLOG_BIND` / `SYSLOG_PORT` | `127.0.0.1` / `5514` | Host side of the optional Compose port mappings. |
| `SYSLOG_CERT_DIR` | `./certs` | Host directory for optional syslog TLS material. |
| `LOG_LEVEL` | `INFO` | Container log level. |
| `DEMO_MODE` | `false` | Use the bundled synthetic log. |
| `GEOIP_ACCOUNT_ID` | placeholder | Only used by the optional `geoip-update` profile. |
| `GEOIP_LICENSE_KEY` | placeholder | Only used by the optional `geoip-update` profile. |
| `GEOIP_EDITION_IDS` | `GeoLite2-City GeoLite2-ASN` | Space-separated MaxMind edition IDs. |

### File source

The container user is UID/GID `10001`. The mounted log must be readable by that
user. Typical options:

```bash
# Make the file readable by the container user (numeric group 10001).
sudo chown root:10001 logs/haproxy.log
sudo chmod 0640 logs/haproxy.log

# Or grant a group read access and add UID 10001 to that group on the host.
```

Do not make the log world-readable if the host has stricter requirements.
The app only needs read access.

The app reads the **current file** with `MAX_LOG_BYTES` from the end. It does not
follow rotated or compressed files automatically. See
[operations.md](operations.md#log-rotation).

### GeoIP data

See [geoip.md](geoip.md). Quick options:

```bash
# Manual copy
cp /var/lib/GeoIP/GeoLite2-City.mmdb geoip/
cp /var/lib/GeoIP/GeoLite2-ASN.mmdb geoip/
chmod 0644 geoip/*.mmdb

# Optional one-shot Compose profile (requires MaxMind credentials in .env)
docker compose --profile geoip run --rm geoip-update
```

The Compose profile is **one-shot**; it does not schedule itself. For cron and
systemd timer examples on the Docker host, see
[geoip.md](geoip.md#automatic-updates-on-the-docker-host).

The app never downloads databases and never sends client IPs to MaxMind.

### HTTP analytics and per-IP details

The HTTP analytics page is generated natively from parsed HAProxy events. It
includes request totals, status classes, methods, protocols, an hourly
distribution, bandwidth, top paths, backends, countries and ASNs.

The **Per-IP HTTP details** table adds, for each displayed client IP:

- request and byte totals, plus 4xx/5xx counts;
- 2xx/3xx/4xx/5xx breakdowns;
- method types, protocols, top paths and backends;
- first and last seen timestamps.

The **Requests** tab lists the newest individual HTTP requests, including
client IP and port, country/city, request, status, bytes, frontend,
backend/server and protocol. It is capped by `MAX_REQUEST_ROWS` (default 2000)
and has a text filter. Selecting **View requests** on a per-IP row opens the
same table filtered to that client.

#### Private IPs and per-IP detail

By default `MASK_INTERNAL_IPS=true` masks non-global addresses in the dashboard
and API. `MASK_FULL=true` collapses all masked addresses to `x.x.x.x`, so every
private client appears in one grouped row. This is intentional for shared or
less-trusted access.

To keep individual private IPs visible for per-IP analysis, disable internal
masking and clear the explicit mask networks:

```dotenv
MASK_INTERNAL_IPS=false
MASK_NETWORKS=
MASK_FULL=false
```

Restart the container after the change. The dashboard must remain behind the
authenticated HAProxy frontend; with masking disabled it contains raw client
addresses.

If `MASK_NETWORKS` contains `192.0.0.0/8` or `172.0.0.0/8`, those ranges stay
masked even when `MASK_INTERNAL_IPS=false`. Remove or narrow the list to see
those addresses.

### Domain exclusion

Use `EXCLUDED_DOMAINS` when an application places secrets in URLs or when a
domain should not appear in the dashboard at all:

```dotenv
EXCLUDED_DOMAINS=private.example.com,secret.example.org
```

Matching rules:

- multiple domains are comma-separated;
- matching is case-insensitive;
- `example.com` matches `example.com` and every subdomain such as
  `app.example.com`;
- a leading `.` or `*.` is accepted and normalized;
- do not include a scheme, path, port or credentials.

The filter is applied before aggregation, so matching events do not contribute
to KPIs, maps, visitors, paths, requests or the API. TLS/SNI events are matched
by SNI. HTTP events are matched by:

1. the captured `Host` header, if present in the log; or
2. the host of an absolute request URL such as
   `https://private.example.com/callback`.

For HTTP domain exclusion, capture the Host header in the HAProxy frontend:

```haproxy
frontend fe_https
    mode http
    option httplog
    capture request header Host len 64
```

The parser accepts logs with or without the capture. Without it, ordinary
origin-form requests (`GET /path HTTP/1.1`) cannot be attributed to a domain.

> **Important:** this is an application-level filter. It does not redact the
> raw HAProxy log, the optional persistent syslog store or existing backups. If
> the URL itself contains a secret, also prevent or redact that logging at the
> HAProxy/rsyslog source and apply your retention policy. See
> [haproxy.md](haproxy.md#excluding-domains) for a source-side ACL example.

The current count of excluded domains and skipped events is shown in the
**Security & privacy** tab and in `meta.privacy` on `/api/snapshot`.

### Syslog receiver

The receiver is disabled by default. To let a remote HAProxy/rsyslog push events
directly into the container:

1. Set `HAPROXY_LOG_FILE=` (empty) in `.env` if you do not also want file mode.
2. Set `SYSLOG_LISTEN=0.0.0.0:5514`.
3. Set `SYSLOG_ALLOWED_NETWORKS` to the sender or relay network, for example
   `192.0.2.10/32` (documentation address; replace it).
4. The Compose file already publishes the receiver ports on loopback; set
   `SYSLOG_BIND` to the host interface a remote sender can reach. Keep
   `127.0.0.1` if a local rsyslog relay forwards to the container.
5. Restart: `docker compose up -d --force-recreate`.

For TCP TLS, set `SYSLOG_PROTOCOLS=tcp`, mount `./certs` and set container paths:

```dotenv
SYSLOG_TLS_CERT=/certs/server.crt
SYSLOG_TLS_KEY=/certs/server.key
SYSLOG_TLS_CA=/certs/ca.crt
SYSLOG_TLS_REQUIRE_CLIENT_CERT=true
```

Uncomment the certs volume in `compose.yaml`. Plain UDP/TCP syslog has no
authentication; use a private network, firewall rules or TLS.

### Persistent syslog history

The syslog receiver is memory-only unless `SYSLOG_STORE_FILE` is set. To keep
received lines across restarts and reboots:

1. Create the data directory and give it to the container user:

   ```bash
   mkdir -p data
   sudo chown 10001:10001 data
   ```

2. Set these values in `.env`:

   ```dotenv
   DATA_DIR=./data
   SYSLOG_STORE_FILE=/data/syslog.log
   SYSLOG_STORE_MAX_BYTES=536870912
   SYSLOG_STORE_BACKUPS=1
   ```

3. Recreate the container:

   ```bash
   docker compose up -d --force-recreate
   ```

The Compose file mounts `DATA_DIR` at `/data` read-write. The app appends
accepted syslog lines there and reads the newest tail on every refresh. The
on-disk history survives reboot; the dashboard window is still bounded by
`MAX_LOG_BYTES`.

When the current file reaches `SYSLOG_STORE_MAX_BYTES`, it is rotated to
`syslog.log.1`; `SYSLOG_STORE_BACKUPS` controls how many rotated files remain.
Disk use is bounded by roughly `(backups + 1) × max bytes`.

The **Security & privacy** tab contains a **Clear syslog history** action. It
removes the current file and all backups and clears the in-memory buffer. The
action is CSRF-protected with a per-process token and should only be available
behind the authenticated HAProxy frontend.

If the data directory is not writable, the app keeps running and reports write
errors in the snapshot. The receiver still accepts lines into memory, but new
lines may not appear until the store is writable again.

### Live HAProxy stats socket

The **Live stats** view is optional and read-only. It polls a dedicated HAProxy
runtime socket and shows global info plus frontend, backend and server health,
sessions, rates, errors and bytes. It never sends runtime-control commands.

On the remote HAProxy, add a separate `level user` socket; do not reuse the
admin socket:

```haproxy
global
    stats socket /run/haproxy/admin.sock mode 660 level admin

    # Replace with a private interface address on the HAProxy host.
    stats socket ipv4@192.0.2.20:8404 level user
    stats timeout 30s
```

On the analytics host:

```dotenv
HAPROXY_STATS_SOCKET=192.0.2.20:8404
STATS_REFRESH_SECONDS=5
STATS_TIMEOUT_SECONDS=2
STATS_MAX_BYTES=4194304
STATS_MAX_ROWS=500
```

Then recreate the container:

```bash
docker compose up -d --force-recreate
```

Security requirements:

- Bind the socket to one private interface address, never `0.0.0.0`.
- Firewall the port to the analytics host only.
- Keep `level user`; `operator` and `admin` allow state-changing commands.
- Do not publish the port through HAProxy or a router.
- HAProxy's stats protocol has no TLS or authentication. Use an SSH tunnel or
  mTLS agent if the network path is not fully trusted.
- The app omits internal server addresses and ports from the live payload.
- The live endpoint is protected by the same dashboard TLS/authentication
  boundary. Do not expose the app port directly.

Verify from the analytics host:

```bash
printf 'show info\n' | socat - TCP:192.0.2.20:8404 | head
curl -fsS http://127.0.0.1:8009/api/live
```

The `/api/live` response includes `meta.enabled`, `meta.connected`,
`meta.last_error`, `info`, `summary`, `frontends`, `backends` and `servers`.
A failed poll keeps the last good payload and reports the connection error.
When `HAPROXY_STATS_SOCKET` is empty, the endpoint returns a disabled payload
and the dashboard shows a configuration hint.

## Put HAProxy in front

The app has no login. HAProxy should:

- terminate TLS for a dedicated dashboard hostname;
- require authentication;
- forward to the published host port, `127.0.0.1:8009` by default;
- optionally add `X-Forwarded-For` (and set `TRUSTED_PROXIES` to the HAProxy
  address) so `/api/whoami` can identify the viewer.

A complete example is in [haproxy.md](haproxy.md#protect-the-dashboard-with-haproxy).
Do not publish the dashboard port (8009 by default) to the internet.

## Health and operations

```bash
curl -fsS http://127.0.0.1:8009/healthz
curl -fsS http://127.0.0.1:8009/version.json
docker compose ps
docker compose logs --tail=100 haproxy-analytics
```

`/healthz` returns 200 when a snapshot has been built successfully. A warning
about a missing GeoIP database or log file does not make the process unhealthy;
the snapshot still exists. A failure to build any snapshot returns 503.

## Upgrade

```bash
docker compose pull
docker compose up -d --force-recreate
```

Pin a reviewed image digest in production. The Compose file uses
`pull_policy: if_not_present` so an ordinary restart does not silently change
the running image.

Rollback:

```bash
IMAGE_TAG=sha-<reviewed-commit> docker compose up -d --force-recreate
```

No application data lives in the container. A rollback only changes the image.

## Local Python run

```bash
python3 -m pip install -r requirements.txt
python3 -m haproxy_analytics \
  --bind 127.0.0.1 \
  --port 8080 \
  --log ./logs/haproxy.log \
  --geoip-city ./geoip/GeoLite2-City.mmdb \
  --geoip-asn ./geoip/GeoLite2-ASN.mmdb \
  --stats-socket 192.0.2.20:8404
```

For the bundled demo:

```bash
python3 -m haproxy_analytics --demo --bind 127.0.0.1 --port 8080
```

CLI flags override the corresponding environment values.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Dashboard is empty | Is the log mounted at `HAPROXY_LOG_FILE`? Is it readable by UID 10001? Does it contain new records? |
| Geo columns show Unknown | Is `maxminddb` installed and are both MMDB paths valid? Private addresses are intentionally not geolocated. |
| GeoIP DB missing warning | Mount `./geoip` and set the two paths. The rest of the dashboard still works. |
| Private IPs all show `x.x.x.x` | Set `MASK_INTERNAL_IPS=false`, `MASK_NETWORKS=` and `MASK_FULL=false`, then restart. Keep the dashboard behind authentication. |
| Per-IP table has one grouped row | Masking is enabled. Disable internal masking as above to distinguish clients. |
| HTTP details are empty | Is the log using `option httplog` on an HTTP frontend? Check the snapshot warnings for parser counts. |
| Syslog buffer empty | Is `SYSLOG_LISTEN` set to `0.0.0.0:5514`, the Compose syslog port reachable and the sender allowlisted? Check the container logs and the health JSON. |
| Live stats show `offline` | Is `HAPROXY_STATS_SOCKET` reachable from the container? Test with `socat` from the analytics host and check the HAProxy firewall and stats socket bind. |
| Live stats disabled | Set `HAPROXY_STATS_SOCKET` to the private `host:port` and recreate the container. Empty disables the view intentionally. |
| Excluded domain still appears | Check `meta.privacy.excluded_events`; for HTTP, capture `Host` in HAProxy. The filter does not redact raw logs or the syslog store. |
| Viewer IP is the proxy | Set `TRUSTED_PROXIES` to the HAProxy address and ensure HAProxy sends `X-Forwarded-For`. |
| 403/404 from HAProxy | Check the dashboard hostname, auth userlist and backend address. |
| Container restarts | Check `docker compose logs`; a bad `SYSLOG_LISTEN`, TLS pair or port conflict fails fast. |

More parser and format guidance is in [operations.md](operations.md).
