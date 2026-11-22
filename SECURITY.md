# Security policy

## Supported versions

The project is currently a 0.x release. Security fixes are applied to the
latest release on the `main` branch. There are no long-term support branches
yet.

## Reporting a vulnerability

Please use GitHub's private **Security advisories** feature for this repository
instead of opening a public issue. Include:

- the affected version or commit;
- the deployment mode (file log, syslog or both);
- a minimal reproduction that does not contain real client IPs, hostnames or
  credentials;
- the impact you believe is possible.

Do not paste production logs, `.env` files, MaxMind credentials, certificates
or private HAProxy configurations into an issue.

## Deployment assumptions

HAProxy Analytics is designed to sit **behind** a trusted HAProxy instance:

- the app has no built-in login;
- Compose binds the published port to `127.0.0.1` by default;
- HAProxy must terminate TLS and require authentication before proxying to the
  app;
- the app port must not be exposed directly to an untrusted network;
- the optional HAProxy stats socket must be a dedicated read-only socket at
  `level user`, bound to a private interface and firewalled to the analytics
  host;
- the host, container runtime, HAProxy and MaxMind databases must be patched
  and maintained by the operator.

The dashboard contains client IP addresses, SNI hostnames, requested paths,
status codes, timestamps, live HAProxy backend names and health state. Treat
it, its screenshots, exports and browser history as sensitive data.

## Security properties

- No upload endpoint, database or account system. The optional persistent syslog store writes only to a dedicated data volume.
- No CDNs, external fonts, analytics, telemetry, map tiles or third-party
  requests from the browser.
- Strict Content Security Policy, `frame-ancestors 'none'`, `nosniff`,
  `no-referrer` and `no-store` headers.
- Viewer IP forwarding is trusted only from explicitly configured proxy
  networks.
- The optional syslog receiver is disabled by default, has a source allowlist,
  bounded buffers and optional TCP TLS with optional client certificates.
- HTTP analytics are rendered natively; the app embeds no third-party report,
  chart library or external script.
- The optional Live stats view connects only to an operator-configured stats
  socket, sends only `show info;show stat`, and omits internal server addresses.
- The optional domain and path filters can drop configured HTTP/TLS events,
  keep domain-level counts while removing request paths, hide all HTTP paths,
  or strip all query strings. They are application-level filters, not log
  redaction.
- The container runs as a non-root user with a read-only root filesystem, all
  Linux capabilities dropped and `no-new-privileges`.
- CI runs unit tests, repository verification, an HTTP smoke test, a secret
  scan and a container build.

## Out of scope

- The accuracy or licensing of MaxMind GeoLite2 data.
- The content of HAProxy logs. Logs can contain personal data and secrets in
  URLs; the operator is responsible for retention and access.
- Compromise of the browser, the device, the container runtime or the host.
- Misconfigured HAProxy TLS, authentication, ACLs, stats socket exposure or
  firewall rules.
- Forwarding untrusted `X-Forwarded-For` headers. Only configure
  `TRUSTED_PROXIES` for proxies you control.

## Operator checklist

1. Keep `APP_BIND=127.0.0.1` in `.env` unless you have a separate network
   control.
2. Put HAProxy in front with TLS and authentication.
3. Set `TRUSTED_PROXIES` to the exact proxy address or network.
4. Keep `SYSLOG_ALLOWED_NETWORKS` as narrow as possible.
5. Use syslog TLS with client certificates when the receiver crosses an
   untrusted network.
6. Keep the live stats socket at `level user`, bound to a private interface,
   and firewalled to the analytics host only.
7. Set `EXCLUDED_DOMAINS` to drop sensitive applications,
   `DOMAIN_ONLY_DOMAINS` for selected domain-level counts without URIs,
   `HTTP_PATH_MODE=domain` to hide all HTTP paths, or
   `STRIP_QUERY_STRINGS=true` to remove query strings. Capture the Host header
   for HTTP matching. These modes filter the app, not the raw log or persistent
   syslog store.
8. Do not commit logs, `.env`, GeoIP databases, certificates or real HAProxy
   configurations.
9. Review the dashboard access logs and retention policy with the same care as
   the HAProxy logs themselves.
