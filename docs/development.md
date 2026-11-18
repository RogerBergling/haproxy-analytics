# Development

## Layout

```text
haproxy_analytics/
├── __init__.py          version
├── __main__.py          CLI, logging, signal handling
├── aggregate.py         counters, per-IP details, map points
├── config.py            environment and CLI configuration
├── geoip.py             optional MaxMind lookup
├── goaccess.py          optional GoAccess subprocess
├── logsource.py         file tail, syslog buffer/receiver
├── parser.py            HTTP, SNI and repeated-message parser
├── server.py            HTTP routes, security headers, whoami
├── snapshot.py          refresh loop and snapshot assembly
└── version.py           build metadata

public/
├── index.html           dashboard shell
├── favicon.svg
├── robots.txt
├── version.json         local default build metadata
└── assets/
    ├── app.css          design tokens and layout
    ├── app.js           view rendering, filters, theme, API polling
    ├── world-dark.svg
    └── world-light.svg

config/
└── goaccess-haproxy.conf

examples/
├── demo-haproxy.log     synthetic demo data
├── haproxy/             generic HAProxy snippets
└── rsyslog/             generic rsyslog snippets

tests/
├── support.py
├── test_config.py
├── test_logsource.py
├── test_parser.py
├── test_server.py
└── test_snapshot.py

scripts/
├── smoke.py             real server + demo + HTTP contract checks
└── verify.py            public repository and security checks
```

## Requirements

- Python 3.11 or newer.
- `maxminddb` for GeoIP. The app runs without it and reports a warning.
- Docker only for building/running the container.
- GoAccess is optional; the container image installs it.

## Run locally

```bash
python3 -m pip install -r requirements.txt
python3 -m haproxy_analytics --demo --bind 127.0.0.1 --port 8080
```

Open <http://127.0.0.1:8080>.

To read a real log:

```bash
python3 -m haproxy_analytics \
  --bind 127.0.0.1 \
  --port 8080 \
  --log ./logs/haproxy.log \
  --geoip-city ./geoip/GeoLite2-City.mmdb \
  --geoip-asn ./geoip/GeoLite2-ASN.mmdb
```

CLI flags override the matching environment variables. Use `--help` for the
current list.

## Tests and validation

```bash
python3 -m compileall -q haproxy_analytics tests scripts
python3 -m unittest discover -s tests -t . -v
python3 scripts/verify.py
python3 scripts/smoke.py
```

Or:

```bash
make validate
```

The test suite covers:

- standard, simple, IPv6, quoted and unquoted HTTP records;
- TLS/SNI records;
- repeated TLS and HTTP groups;
- missing status/bytes;
- file-tail truncation without partial lines;
- bounded syslog buffers;
- UDP/TCP receiver allowlists, size limits and TCP TLS;
- GoAccess disabled mode, missing binary, fake report generation and size limit;
- internal IP masking and masked visitor grouping;
- snapshot counts, warnings, source modes and failure fallback;
- HTTP routes, security headers, method rejection, traversal rejection,
  `/api/whoami` trust behavior, HEAD and version/health endpoints.

The smoke test starts the real server with the demo log and checks the dashboard,
API, assets, CSP, method rejection, traversal rejection and GoAccess absence.

## Frontend rules

- No framework, bundler, CDN, external font or third-party script.
- No `innerHTML`, `document.write`, `eval` or `new Function`. Values from logs
  are inserted with `textContent` and DOM APIs.
- Keep `connect-src` limited to `'self'`. Do not add a map tile service, a
  third-party IP lookup or remote fonts.
- Keep the GoAccess iframe sandboxed. Do not embed its HTML in the main page.
- Use the shared design tokens in `app.css`; keep dark and light themes usable.
- Status must have a text label in addition to color.
- Preserve keyboard focus, skip link, table semantics and reduced-motion
  behavior.

`scripts/verify.py` enforces the most important rules.

## Parser changes

When adding a format:

1. Add a focused parser test with a synthetic line.
2. Keep the standard HTTP and TLS formats working.
3. Decide how the new fields affect counts, visitor rows and GoAccess.
4. Update `docs/operations.md` and the demo log if it is a supported public
   example.
5. Do not log credentials, private addresses or real hostnames in tests.

## Adding configuration

- Read it in `config.py` with a safe default and validation.
- Add it to `.env.example` with a comment.
- Add it to `compose.yaml` if the container needs it.
- Document it in `docs/deployment.md`.
- Add a focused test when validation is non-trivial.

## Versioning and release

- The version lives in `VERSION` and `haproxy_analytics/__init__.py`.
- The Docker build receives `APP_VERSION`, `IMAGE_TAG`, `GIT_SHA`,
  `BUILD_DATE` and `BUILD_NUMBER`.
- `docker-publish.yml` publishes `linux/amd64` and `linux/arm64` images to
  `ghcr.io/rogerbergling/haproxy-analytics`.
- Tags include `latest` on the default branch, the branch/tag name, and
  `sha-<commit>`.
- Update the version and changelog together when the repository gets one.

## Public repository hygiene

- Never commit `.env`, logs, MMDB files, certificates, private keys or real
  HAProxy configs.
- Use `example.com`, `example.net`, `example.org` and documentation IP ranges in
  tests and docs.
- Do not add real customer names, internal hostnames, private IPs or account
  credentials.
- Run `python3 scripts/verify.py` and the Gitleaks workflow before publishing.
- Review the diff for accidental copy/paste from a production system.
