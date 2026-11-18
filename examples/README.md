# Examples

Everything in this directory is synthetic or generic:

- `demo-haproxy.log` uses `example.com`, `example.net`, `example.org`,
  documentation IP ranges and well-known public resolver addresses. It contains
  no customer, tenant or private infrastructure data.
- `haproxy/` contains fragments for TLS termination, SNI passthrough, an
  authenticated dashboard frontend and a read-only live stats socket. They use
  `example.com`, documentation addresses and placeholder certificate paths.
- `rsyslog/` contains forwarding and receiving patterns. They use
  `example.com` and placeholder certificate paths.

These are starting points, not complete production configurations. Keep your
existing HAProxy routing, certificates, ACLs and timeouts, and validate with
`haproxy -c -f` before reloading.

The demo log is used by `DEMO_MODE=true` and by the automated tests. It is
intentionally not a real traffic sample. The documentation addresses cannot be
geolocated by MaxMind, which is why a demo run may show an empty map even with
real GeoLite2 databases installed.
