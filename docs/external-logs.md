# External HAProxy logs

The application can run on the HAProxy host or on a separate analytics host.
This page compares the supported patterns and shows a safe syslog forwarding
setup. All addresses are documentation placeholders.

## Choose a pattern

| Pattern | Best for | History after restart | Security notes |
| --- | --- | --- | --- |
| Read a local file on the HAProxy host | Same-host deployment | The log file | Read-only mount; protect the file permissions. |
| Central rsyslog over TLS → file → app | Separate host, normal operations | The central log file | Recommended. TLS + certificate validation + local file retention. |
| Built-in syslog receiver | Separate host, quick setup, low volume | Optional persistent file via `SYSLOG_STORE_FILE`; otherwise memory-only | Disabled by default. Source allowlist and optional TCP TLS/mTLS. |
| Pull or copy logs with a script | Batch or offline analysis | Depends on the script | More credentials and scheduling; not built in. |

By default the built-in receiver is not a durable log store. Set
`SYSLOG_STORE_FILE=/data/syslog.log` to persist received lines in the dedicated
`/data` volume, or keep a central syslog file.

## Pattern 1: same host, mounted file

```text
HAProxy -> local rsyslog -> /var/log/haproxy.log
                                  │
                                  └─ read-only mount -> container
```

1. Ensure HAProxy logs to `local0` and rsyslog writes `/var/log/haproxy.log`.
2. Put the file where Compose can mount it, for example `./logs/haproxy.log`.
3. Set `HAPROXY_LOG_DIR=./logs` and `HAPROXY_LOG_FILE=/logs/haproxy.log`.
4. Make the file readable by container UID/GID `10001`.

The app reads only the current file, from the last `MAX_LOG_BYTES`. It does not
follow rotated or compressed files automatically.

## Pattern 2: central rsyslog over TLS (recommended for a separate host)

```text
HAProxy host                              Central host
-----------                               ------------
HAProxy -> local rsyslog --TLS--> rsyslog -> /var/log/haproxy/haproxy.log
                                                   │
                                                   └─ read-only mount -> app
```

### HAProxy host: local rsyslog

Keep HAProxy logging locally first. A minimal rsyslog rule:

```rsyslog
# /etc/rsyslog.d/10-haproxy.conf
local0.*    /var/log/haproxy.log
& stop
```

Then forward the same messages to the central host. Use the `omfwd` action with
TLS. The exact CA paths and certificate names are deployment-specific:

```rsyslog
# /etc/rsyslog.d/20-haproxy-forward.conf
action(
    type="omfwd"
    target="central.example.com"
    port="6514"
    protocol="tcp"
    template="RSYSLOG_SyslogProtocol23Format"
    tls="on"
    tls.caCert="/etc/rsyslog.d/ca.pem"
    tls.myCert="/etc/rsyslog.d/client.pem"
    tls.myPrivKey="/etc/rsyslog.d/client.key"
    tls.authMode="x509/name"
    tls.permittedPeer=["central.example.com"]
    action.resumeRetryCount="-1"
    queue.type="linkedList"
    queue.size="10000"
)
```

### Central host: receive over TLS

Enable the TLS stream driver and write to a file. A minimal example:

```rsyslog
# /etc/rsyslog.d/10-haproxy-receive.conf
module(load="imtcp"
       StreamDriver.Name="gtls"
       StreamDriver.Mode="1"
       StreamDriver.AuthMode="x509/name"
       PermittedPeer=["haproxy.example.com"])

input(type="imtcp" port="6514" ruleset="haproxy")

template(name="HAProxyFile" type="string"
         string="%timereported:::date-rfc3339% %hostname% %syslogtag%%msg%\n")

ruleset(name="haproxy") {
    action(type="omfile" file="/var/log/haproxy/haproxy.log"
           template="HAProxyFile"
           dirCreateMode="0750" fileCreateMode="0640")
}
```

The examples in [`examples/rsyslog/`](../examples/rsyslog/) are starting points,
not a complete PKI guide. Use certificates from your own CA, protect the private
keys, and restrict the receiver port with a firewall.

### Central host: mount the file

```dotenv
HAPROXY_LOG_DIR=/var/log/haproxy
HAPROXY_LOG_FILE=/logs/haproxy.log
```

Make sure UID/GID `10001` in the container can read the file. A common setup is a
dedicated group and `0640` permissions.

## Pattern 3: built-in syslog receiver

The app can listen for syslog directly. This is useful when you want a single
container on a dedicated analytics host and do not need durable history.

### Enable it

```dotenv
# .env
HAPROXY_LOG_FILE=
SYSLOG_LISTEN=0.0.0.0:5514
SYSLOG_PROTOCOLS=udp
SYSLOG_ALLOWED_NETWORKS=192.0.2.20/32
SYSLOG_BIND=127.0.0.1
SYSLOG_PORT=5514
```

The Compose file already publishes the receiver ports on loopback. Set
`SYSLOG_BIND` to the host interface a remote sender can reach:

```yaml
ports:
  - "${APP_BIND:-127.0.0.1}:${APP_PORT:-8009}:8080"
  - "${SYSLOG_BIND:-127.0.0.1}:${SYSLOG_PORT:-5514}:5514/udp"
  # - "${SYSLOG_BIND:-127.0.0.1}:${SYSLOG_PORT:-5514}:5514/tcp"
```

If the sender is on another host, `SYSLOG_BIND` must be an interface that host
can reach. Restrict it with the host firewall and keep
`SYSLOG_ALLOWED_NETWORKS` to the exact sender or relay address.

### Send from the HAProxy host

The simplest local test:

```bash
logger -n 192.0.2.30 -P 5514 -d "src=203.0.113.10 dst=198.51.100.10:443 sni=app.example.com"
```

For rsyslog forwarding, point the `omfwd` action at the analytics host. For
example, without TLS on a trusted network:

```rsyslog
action(
    type="omfwd"
    target="192.0.2.30"
    port="5514"
    protocol="udp"
    template="RSYSLOG_SyslogProtocol23Format"
)
```

Use TCP instead of UDP when you need delivery feedback:

```dotenv
SYSLOG_PROTOCOLS=tcp
```

and map the TCP port in Compose.

### TLS and client certificates

TCP syslog can be wrapped in TLS. The app supports:

```dotenv
SYSLOG_PROTOCOLS=tcp
SYSLOG_TLS_CERT=/certs/server.crt
SYSLOG_TLS_KEY=/certs/server.key
SYSLOG_TLS_CA=/certs/ca.crt
SYSLOG_TLS_REQUIRE_CLIENT_CERT=true
```

Uncomment the `./certs:/certs:ro` volume in `compose.yaml`. The certificate and
key are read by the container user; make them readable only as needed. With
`SYSLOG_TLS_REQUIRE_CLIENT_CERT=true`, a sender without a certificate signed by
the configured CA is rejected during the TLS handshake.

UDP has no TLS. Use UDP only on a trusted network or through a local relay.

## Message format

The receiver expects newline-delimited syslog messages. Do not send
octet-counted TCP framing directly to the app; use a local rsyslog relay or
configure the sender to use newline framing. The receiver accepts RFC 3164-style
and RFC 5424-style wrappers, as well as plain lines:

```text
<134>1 2026-11-18T00:01:02.123Z haproxy.example.com haproxy 1234 - - 203.0.113.10:53124 ...
```

```text
203.0.113.10:53124 [18/Nov/2026:00:01:02.123] ft_https bk_app/app1 0/0/1/2/3 200 5120 "GET / HTTP/1.1"
src=203.0.113.10 dst=198.51.100.10:443 sni=app.example.com
message repeated 3 times: [ src=203.0.113.10 dst=198.51.100.10:443 sni=app.example.com]
```

The app expands `message repeated` groups. It caps the syslog message size and
the ring buffer. Messages outside the allowlist are rejected and counted in the
snapshot metadata.

## Duplicate sources

If both `HAPROXY_LOG_FILE` and `SYSLOG_LISTEN` are active, events present in both
are counted twice. The snapshot displays a warning. Choose one primary source:

- file for history and normal operations;
- direct syslog for a simple live-only deployment.

A common compromise is to use file mode for the main log and leave the receiver
disabled. If you use the receiver for a second HAProxy, make sure the local file
does not already contain the same forwarded records.

## Time, rotation and retention

- HAProxy timestamps do not carry a timezone. The app displays the recorded
  date and time without converting it. `TZ` only affects the container's
  generated-at timestamp.
- The file source reads the tail window on every refresh. Rotated files are not
  followed; the new current file is read on the next refresh.
- By default the syslog receiver is in-memory only. A restart loses its ring
  buffer. Set `SYSLOG_STORE_FILE=/data/syslog.log` to persist it.
- The persistent syslog store rotates by size
  (`SYSLOG_STORE_MAX_BYTES`, `SYSLOG_STORE_BACKUPS`) and can be cleared from the
  dashboard's Security & privacy tab.
- For a larger dashboard window, increase `MAX_LOG_BYTES` and
  `REFRESH_SECONDS` together. The on-disk store can be larger than the parsed
  window.
- Compressed files are not read. Decompress them before mounting if they are
  part of the analysis window.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Receiver warning says loopback-only | `SYSLOG_ALLOWED_NETWORKS` still has only `127.0.0.0/8,::1/128`. Add the sender/relay network. |
| Buffer stays empty | Is `SYSLOG_LISTEN` set to `0.0.0.0:5514`? Is the Compose syslog port reachable? Is the host firewall open to the sender? |
| Rejected messages | The source address is outside `SYSLOG_ALLOWED_NETWORKS`. Check NAT and the actual peer address. |
| Dropped messages | The message exceeded `SYSLOG_MAX_MESSAGE_BYTES` or the ring exceeded `SYSLOG_BUFFER_LINES`. |
| TLS handshake fails | Certificate/key pairing, CA bundle, hostname, client certificate or clock skew. Check both ends' logs. |
| Counts double | Both file and syslog sources are active with the same events. Disable one. |
| No HTTP records from syslog | The sender may only forward TLS/SNI lines, or the HAProxy `log-format` is not the expected HTTP format. |

See [operations.md](operations.md) for parser diagnostics.
