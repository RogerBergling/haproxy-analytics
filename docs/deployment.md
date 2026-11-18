# Deployment

This guide covers the Docker Compose deployment, the environment file, volumes,
permissions, GeoIP data and upgrades. For HAProxy snippets see
[haproxy.md](haproxy.md). For log shipping see [external-logs.md](external-logs.md).

## Prerequisites

- Docker Engine 24+ with Compose v2.
- A read-only HAProxy log file, or a syslog sender you control.
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
└── certs/                # optional syslog TLS material, ignored by git
```

`logs/`, `geoip/`, `certs/` and `.env` are in `.gitignore`.

## Start

```bash
git clone https://github.com/RogerBergling/haproxy-analytics.git
cd haproxy-analytics
cp .env.example .env
mkdir -p logs geoip

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
| `MASK_INTERNAL_IPS` | `true` | Mask non-global client IPs (private, loopback, documentation) in the dashboard and API. Public IPs remain visible. |
| `MASK_NETWORKS` | empty | Additional CIDRs to mask even if public, for example `192.0.0.0/8,172.0.0.0/8`. |
| `GEOIP_DIR` | `./geoip` | Host directory mounted at `/geoip` read-only. |
| `GEOIP_CITY_DB` | `/geoip/GeoLite2-City.mmdb` | City database path inside the container. |
| `GEOIP_ASN_DB` | `/geoip/GeoLite2-ASN.mmdb` | ASN database path inside the container. |
| `TRUSTED_PROXIES` | empty | Comma-separated CIDRs allowed to supply `X-Forwarded-For`. Use only the HAProxy address. |
| `SYSLOG_LISTEN` | empty | Optional `host:port`, for example `0.0.0.0:5514`. Empty disables the receiver. |
| `SYSLOG_PROTOCOLS` | `udp` | `udp`, `tcp`, or both comma-separated. |
| `SYSLOG_ALLOWED_NETWORKS` | `127.0.0.0/8,::1/128` | Source allowlist. Set the sending host or relay network. |
| `SYSLOG_BUFFER_LINES` | `200000` | In-memory ring size. |
| `SYSLOG_MAX_MESSAGE_BYTES` | `65536` | Oversized messages are dropped. |
| `SYSLOG_TLS_CERT` | empty | Container path to a PEM certificate chain for TCP syslog. |
| `SYSLOG_TLS_KEY` | empty | Container path to the private key. |
| `SYSLOG_TLS_CA` | empty | Optional CA bundle for verifying client certificates. |
| `SYSLOG_TLS_REQUIRE_CLIENT_CERT` | `false` | Set true for mTLS. |
| `SYSLOG_BIND` / `SYSLOG_PORT` | `127.0.0.1` / `5514` | Host side of the optional Compose port mappings. |
| `SYSLOG_CERT_DIR` | `./certs` | Host directory for optional syslog TLS material. |
| `GOACCESS_ENABLED` | `false` | Generate the optional GoAccess report in the image. |
| `GOACCESS_BINARY` | `goaccess` | GoAccess binary name or path. |
| `GOACCESS_CONFIG` | `/app/config/goaccess-haproxy.conf` | GoAccess parser configuration inside the container. |
| `GOACCESS_TIMEOUT` | `60` | GoAccess execution timeout in seconds. |
| `GOACCESS_MAX_LINES` | `100000` | Maximum HTTP lines passed to GoAccess. |
| `GOACCESS_MAX_HTML_BYTES` | `5000000` | Maximum report size the app will serve. |
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

### GoAccess

The image contains GoAccess. Enable it when you want the detailed report:

```dotenv
GOACCESS_ENABLED=true
GOACCESS_TIMEOUT=60
GOACCESS_MAX_LINES=100000
```

The report is generated from HTTP lines only, in a temporary directory, and
served in a sandboxed iframe. If your HAProxy `log-format` is not the standard
`option httplog` format, mount a matching GoAccess configuration and set
`GOACCESS_CONFIG` to its container path. See [operations.md](operations.md#goaccess).

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
  --geoip-asn ./geoip/GeoLite2-ASN.mmdb
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
| GoAccess tab says not enabled | Set `GOACCESS_ENABLED=true` and restart. Check `docker compose logs` for format errors. |
| Syslog buffer empty | Is `SYSLOG_LISTEN` set to `0.0.0.0:5514`, the Compose syslog port reachable and the sender allowlisted? Check the container logs and the health JSON. |
| Viewer IP is the proxy | Set `TRUSTED_PROXIES` to the HAProxy address and ensure HAProxy sends `X-Forwarded-For`. |
| 403/404 from HAProxy | Check the dashboard hostname, auth userlist and backend address. |
| Container restarts | Check `docker compose logs`; a bad `SYSLOG_LISTEN`, TLS pair or port conflict fails fast. |

More parser and format guidance is in [operations.md](operations.md).
