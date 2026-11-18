# Security and privacy

HAProxy Analytics is an observability tool for a trusted operator. It is not a
multi-tenant service and it does not try to be an authentication system.

## Threat model

The intended deployment is:

```text
operator browser
      │ HTTPS + authentication
      ▼
trusted HAProxy (TLS termination, auth, access control)
      │ loopback or a private network
      ▼
HAProxy Analytics container
      │ read-only
      ▼
HAProxy log file or trusted syslog sender
```

The main assets are:

- the client IP addresses, SNI hostnames, requested paths and timestamps in the
  dashboard;
- the HAProxy log itself;
- any MaxMind credentials used by the optional updater;
- TLS keys and certificates used by HAProxy or the optional syslog receiver.

## What the app does not do

- It does not terminate TLS.
- It has no login, user database, session store, password hashes or MFA.
- It does not upload logs to a third party.
- It does not call an external GeoIP service, map tile server, CDN, font server,
  analytics service or telemetry endpoint.
- It does not write to the log source.
- It does not store a database or persistent event history.
- It does not decrypt TLS passthrough traffic.

## Required controls

### 1. Keep the app behind HAProxy

The default Compose binding is `127.0.0.1:8009` (host) to `8080` (container). Keep it that way unless you have
a separate, controlled network boundary. HAProxy must:

- terminate TLS for a dedicated dashboard hostname;
- require authentication (password, mTLS or your existing SSO/forward-auth);
- restrict who can reach the dashboard frontend;
- forward only to the app's private address.

The example in [haproxy.md](haproxy.md#protect-the-dashboard-with-haproxy) uses
HAProxy basic authentication over TLS. The app intentionally does not duplicate
that function.

### 2. Protect the data at rest and in transit

Logs and the dashboard contain personal and network data. Apply the same
retention and access rules you apply to the HAProxy logs themselves:

- restrict filesystem permissions on the log and GeoIP directories;
- encrypt backups if they contain logs or screenshots;
- avoid pasting screenshots with real IPs into public issues;
- delete old logs according to your policy;
- restrict shell access to the analytics host.

### 3. Configure trusted proxies narrowly

`/api/whoami` uses the direct peer address by default. If HAProxy is in front and
you want the browser IP, HAProxy must add `X-Forwarded-For` and the app must
trust the immediate peer:

```dotenv
TRUSTED_PROXIES=127.0.0.1/32
```

Only add the actual proxy address or a narrow network. If an untrusted client
can reach the app directly and spoof `X-Forwarded-For`, the self-highlight can
show the wrong IP, but the app does not use the forwarded address for
authorization. It is still a data-integrity issue; keep the port private.

### 4. Treat syslog as untrusted input

Plain UDP/TCP syslog has no authentication. An attacker who can send packets to
the receiver can inject fake events. Mitigations:

- keep `SYSLOG_ALLOWED_NETWORKS` to the exact sender or relay;
- use a private network and a host firewall;
- prefer TCP TLS with client certificates for any network you do not fully
  trust;
- monitor the rejected/dropped counters in the snapshot metadata;
- do not expose the syslog port to the internet.

The receiver enforces a maximum message size and a bounded ring buffer, but it
cannot make an untrusted sender trustworthy.

### 5. Keep GoAccess sandboxed

The optional GoAccess report is generated HTML from log data. The app serves it
with a `sandbox` CSP in an iframe:

```text
sandbox allow-scripts;
default-src 'none';
style-src 'unsafe-inline';
script-src 'unsafe-inline';
img-src data:;
font-src data:;
frame-ancestors 'self'
```

It cannot read the parent page, navigate the top window or make network
requests. Do not change the app to embed GoAccess HTML directly in the main
document.

### 6. Harden the container

The supplied Compose file uses:

- a non-root user (UID/GID `10001`);
- a read-only root filesystem;
- a small `/tmp` tmpfs for temporary GoAccess output;
- `cap_drop: ALL`;
- `no-new-privileges:true`;
- no Docker socket;
- `pull_policy: if_not_present`.

Do not add the Docker socket, host networking or extra capabilities unless you
understand the exposure.

### 7. Manage secrets outside the repository

Never commit:

- `.env`;
- HAProxy logs or screenshots with real data;
- MaxMind account IDs or license keys;
- TLS private keys or certificates;
- HAProxy configurations containing real hostnames or addresses.

The repository's `scripts/verify.py` rejects common private-infrastructure
tokens, and Gitleaks scans the full history. These are guardrails, not a
substitute for reviewing a diff before publishing.

## Browser protections

The dashboard has a strict Content Security Policy:

```text
default-src 'none';
script-src 'self';
style-src 'self';
img-src 'self' data:;
font-src 'self';
connect-src 'self';
frame-src 'self';
object-src 'none';
base-uri 'none';
frame-ancestors 'none';
form-action 'none'
```

Additional headers:

- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- `Permissions-Policy` with camera, microphone, geolocation, payment and USB
  disabled
- `Cache-Control: no-store`

Frontend values from logs are inserted with `textContent` and DOM APIs, not
`innerHTML`. The repository verification script rejects `innerHTML`,
`document.write`, `eval` and `new Function` in the dashboard module.

The only browser storage is a local theme preference in `localStorage`. Traffic
data, filters and the viewer IP are held in page memory for the current tab and
are not written to browser storage.

The `X-Forwarded-For` header is read only after the direct peer passes the
trusted-proxy check. Invalid entries are ignored. The app does not use the
forwarded value for authentication or authorization.

## Internal IP masking

`MASK_INTERNAL_IPS` is enabled by default. The app masks non-global client
addresses before they enter the dashboard or the snapshot API:

```text
192.0.2.10      -> 192.0.x.x
198.51.100.20   -> 198.51.x.x
fd00:1234::1    -> fd00:1234::x
2001:db8::1     -> 2001:db8::x
```

Public addresses such as `8.8.8.8` remain visible. Masked rows are grouped by
their masked prefix, so the visitor table loses host-level detail for internal
networks by design. The same masking is applied to IP literals in requested
paths, SNI/backend names and the optional GoAccess input.

When the viewer's own address is internal, the `THIS IS YOU` self-highlight is
disabled. Highlighting a masked group would match several different clients.
Set `MASK_INTERNAL_IPS=false` only when raw internal IPs are required for
analysis and the dashboard access is tightly controlled.

## GeoIP privacy

MaxMind GeoLite2 lookups are local file reads. Client IP addresses are not sent
to MaxMind or any other service. The optional `geoip-update` profile downloads
databases from MaxMind using your account credentials; it does not send visitor
data.

GeoLite2 locations are approximate and can be wrong. A private address, VPN,
proxy or NAT address may not map to a meaningful location. Do not use the map
for access control or as proof of a person's location.

## Logging and error messages

The HTTP server suppresses access logging by default so request paths and client
addresses are not duplicated into container logs. Operational errors are
logged, but the app does not intentionally log raw request lines or credentials.
GoAccess stderr may contain a rejected log line and is logged locally for
diagnostics; the dashboard receives a generic error message instead of raw log
content.

## Known limitations

- The app cannot protect a compromised browser, device or host.
- The app cannot make plain syslog trustworthy.
- The app cannot prevent an operator from sharing sensitive screenshots.
- The app cannot validate the accuracy of MaxMind data.
- The app cannot enforce HAProxy authentication if the published dashboard port is exposed
  directly.
- The self-highlight is an IP comparison, not proof of identity. NAT and proxies
  make one IP represent multiple people.

## Incident checklist

If you believe the dashboard or a credential was exposed:

1. Remove public access to the app and HAProxy frontend.
2. Rotate the HAProxy authentication secret, TLS keys and MaxMind license key.
3. Review HAProxy and container logs for unexpected access.
4. Check whether screenshots, exports or `.env` files were published.
5. Revoke any leaked GitHub token or package credential.
6. Rebuild the container from a reviewed image and re-deploy behind the
   authenticated frontend.
7. Re-run `python3 scripts/verify.py` and the Gitleaks workflow before making
   the repository public again.
