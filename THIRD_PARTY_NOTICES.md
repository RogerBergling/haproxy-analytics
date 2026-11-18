# Third-party notices

HAProxy Analytics is MIT licensed. The repository and the published container
image include or depend on the following separate components.

## maxminddb (MaxMind DB Reader for Python)

- License: Apache License 2.0.
- Upstream: <https://github.com/maxmind/MaxMind-DB-Reader-python>
- Used to read local GeoLite2 City/ASN databases. The package does not send
  client addresses anywhere.

The MaxMind GeoLite2 databases themselves are **not** included in this
repository or the image. They are licensed separately by MaxMind and must be
obtained by the operator. See [docs/geoip.md](docs/geoip.md).

## World map outlines

The simplified coastline paths in `public/assets/world-dark.svg` and
`public/assets/world-light.svg` are derived from low-resolution GSHHS
(Global Self-consistent, Hierarchical, High-resolution Geography Database)
coastline data. GSHHS is distributed by NOAA/NCEI:

<https://www.ngdc.noaa.gov/mgg/shorelines/gshhs.html>

Consult the GSHHS documentation for its current terms. No map tiles or external
map service are used at runtime.

## Base image

The container is built on the official `python:3.12-slim-bookworm` image. The
Debian packages in the image carry their own licenses; their copyright files are
available under `/usr/share/doc/` in the image.

## Python standard library

The application otherwise uses the Python standard library. It has no web
framework, JavaScript framework, CDN or external runtime service.
