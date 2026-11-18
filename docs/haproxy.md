# HAProxy configuration

This guide shows the HAProxy pieces needed for HAProxy Analytics:

1. HTTP logging with TLS termination, so the app can see requests, paths,
   status codes and backends.
2. TLS passthrough with SNI capture, so the app can see hostnames without
   decrypting traffic.
3. An authenticated HTTPS frontend for the dashboard itself.
4. Log destinations and validation.

Every example uses `example.com`, documentation addresses and placeholder
paths. Replace them with your own values. Validate every change with
`haproxy -c -f` before reloading.

> **Do not replace a working production `haproxy.cfg` wholesale.** Add or edit
> only the frontend/backend/logging pieces you need, and keep a timestamped
> backup.

## 1. HTTP mode and TLS termination

Use HTTP mode when HAProxy terminates TLS. The app can then read the HTTP
request records: method, path, status, bytes, backend and timestamps.

```haproxy
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend fe_https
    bind *:443 ssl crt /etc/haproxy/certs/example.com.pem alpn h2,http/1.1
    mode http
    option httplog
    # Optional: capture the Host header if you want it in a custom format.
    capture request header Host len 64
    default_backend bk_web

backend bk_web
    mode http
    option httpchk GET /
    server web1 192.0.2.10:8080 check
```

Notes:

- `option httplog` produces the standard field order the built-in parser and the
  bundled GoAccess configuration expect.
- `mode http` is required to see HTTP requests. A `mode tcp` frontend cannot
  produce HTTP analytics.
- TLS termination requires the certificate and key in a PEM file readable by
  the HAProxy user.
- Keep your existing timeouts, ACLs, backends and certificate paths.
- If you add a custom `log-format`, update the GoAccess configuration too. The
  built-in parser is deliberately tolerant of the standard format and the
  simple format, not arbitrary field orders.

### What the app receives

A standard record looks like:

```text
203.0.113.10:53124 [18/Nov/2026:00:01:02.123] ft_https bk_web/web1 0/0/1/2/3 200 5120 "GET /assets/app.css HTTP/1.1"
```

The app reads the client address, timestamp, frontend, backend, status, bytes,
method, path and protocol. It does not require a specific frontend or backend
name.

## 2. TLS passthrough with SNI capture

Use a TCP frontend when HAProxy must pass encrypted connections through to the
backend. The app can still see the ClientHello SNI hostname and the source
address. It cannot see the decrypted URL, headers or response status.

```haproxy
frontend fe_tls
    bind *:443
    mode tcp
    tcp-request inspect-delay 1s

    # Capture MUST come before accept. If accept runs first, the SNI capture
    # can be empty even for clients that sent a valid hostname.
    tcp-request content capture req.ssl_sni len 100
    tcp-request content accept if { req_ssl_hello_type 1 }

    log-format "src=%ci dst=%fi:%fp sni=%[capture.req.hdr(0)]"

    use_backend bk_app_tls if { req_ssl_sni -i app.example.com }
    use_backend bk_app_tls if { req_ssl_sni -i www.example.com }
    default_backend bk_reject

backend bk_app_tls
    mode tcp
    server app1 192.0.2.10:443 check

backend bk_reject
    mode tcp
    tcp-request content reject
```

Notes:

- The capture line must precede the accept line.
- `sni=-` means the client did not provide SNI, the capture ran too late, or
  the connection is not a TLS ClientHello.
- SNI is not the same as the HTTP `Host` header. One TLS connection can carry
  requests for one hostname only, but it can carry several HTTP requests.
- Do not add `accept-proxy` unless HAProxy really is behind a trusted proxy that
  sends the PROXY protocol. An incorrect `accept-proxy` breaks client addresses
  and can be a security problem.
- If you use both HTTP termination and passthrough, keep them on separate
  frontends or separate ports as your architecture requires.

## 3. Protect the dashboard with HAProxy

The app has no built-in login. Put it behind an HTTPS frontend with
authentication. A dedicated hostname is recommended.

```haproxy
userlist analytics_users
    # Generate a hash, for example:
    #   mkpasswd -m sha-512
    # or:
    #   openssl passwd -6
    user admin password $6$REPLACE_WITH_A_REAL_HASH

frontend fe_analytics
    bind *:8443 ssl crt /etc/haproxy/certs/analytics.example.com.pem alpn h2,http/1.1
    mode http
    option httplog

    # Basic authentication over TLS only.
    http-request auth realm "HAProxy Analytics" unless { http_auth(analytics_users) }

    # Optional hardening at the edge.
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Content-Type-Options "nosniff"

    default_backend bk_analytics

backend bk_analytics
    mode http
    option forwardfor
    server analytics 127.0.0.1:8080 check
```

Set `TRUSTED_PROXIES` in `.env` to the address HAProxy uses when connecting to
the app. With the example above, the app sees `127.0.0.1` as the peer:

```dotenv
TRUSTED_PROXIES=127.0.0.1/32
```

`option forwardfor` adds `X-Forwarded-For`. The app honours it only from a
trusted peer. Without this, `/api/whoami` correctly reports the proxy address,
not the browser address. The app does not parse the HAProxy PROXY protocol;
HAProxy must send a normal HTTP request with `X-Forwarded-For` when forwarding
to the dashboard.

If HAProxy is on another host, use its real address or a narrow network, for
example `192.0.2.20/32`. Do not add whole untrusted networks.

### Alternative: client certificates

If you prefer mutual TLS instead of a password, use a client certificate CA:

```haproxy
frontend fe_analytics_mtls
    bind *:8443 ssl crt /etc/haproxy/certs/analytics.example.com.pem ca-file /etc/haproxy/certs/client-ca.pem verify required alpn h2,http/1.1
    mode http
    option httplog
    default_backend bk_analytics
```

Choose one authentication method and document it for operators. The app itself
does not validate users.

## 4. Logging

### Local file

The simplest deployment keeps HAProxy and the app on the same host:

```haproxy
global
    log /dev/log local0

defaults
    log global
    option httplog
```

`rsyslog` writes the records to `/var/log/haproxy.log`. Mount that file into the
container read-only.

### Remote syslog

If the app runs on another host, forward logs with `rsyslog` over TLS rather
than exposing an unauthenticated syslog port. The pattern is:

```text
HAProxy host: HAProxy -> local rsyslog -> TLS -> central rsyslog -> file
central host: file -> read-only mount -> HAProxy Analytics container
```

See [external-logs.md](external-logs.md) and the examples in
[`examples/rsyslog/`](../examples/rsyslog/).

### Direct syslog receiver

The app can also receive syslog directly. That mode is opt-in and should be
restricted to a trusted sender network. See
[external-logs.md](external-logs.md#direct-syslog-receiver).

## 5. Validate and reload

Always validate before reloading:

```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
sudo systemctl reload haproxy
```

Check that records appear:

```bash
sudo grep ' ft_https ' /var/log/haproxy.log | tail -n 3
sudo grep 'src=' /var/log/haproxy.log | tail -n 3
```

If you use a remote log target, check the central receiver and the app's
snapshot warnings instead.

## 6. Common mistakes

| Problem | Cause | Fix |
| --- | --- | --- |
| `sni=-` for every TLS record | `tcp-request content accept` runs before the capture line | Move the capture line above accept. |
| `sni=-` for some clients | Client omitted SNI, or traffic is not TLS | Expected for some clients; verify with a known browser/curl. |
| No HTTP requests in the app | Frontend is `mode tcp`, or `option httplog` is missing | Use HTTP mode and `option httplog` on the terminating frontend. |
| GoAccess rejects the log | Custom `log-format` does not match the bundled GoAccess config | Mount a matching GoAccess config and set `GOACCESS_CONFIG`. |
| Viewer IP is always the proxy | `X-Forwarded-For` is not sent or the peer is not trusted | Add `option forwardfor` and set `TRUSTED_PROXIES`. |
| TLS passthrough shows no URLs | Traffic is encrypted end to end | Expected. Only SNI metadata is visible. |
| 503 from the dashboard backend | App not running or wrong port | Check `docker compose ps` and `curl http://127.0.0.1:8080/healthz`. |
| Auth loop or 401 | Wrong userlist/hash, or auth applied to health checks | Check the HAProxy logs; exclude health checks if needed. |

## 7. Minimal examples

Ready-to-adapt files:

- [`examples/haproxy/tls-termination-http.cfg`](../examples/haproxy/tls-termination-http.cfg)
- [`examples/haproxy/tls-passthrough-sni.cfg`](../examples/haproxy/tls-passthrough-sni.cfg)
- [`examples/haproxy/analytics-dashboard-auth.cfg`](../examples/haproxy/analytics-dashboard-auth.cfg)

They are fragments, not complete production configs. Keep your existing
routing, certificates, ACLs and timeouts.
