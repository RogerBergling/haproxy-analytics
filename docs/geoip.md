# GeoIP

Geography is optional. The dashboard works without any MaxMind data; countries,
cities, ASN names and map points simply remain empty or `Unknown`.

The app only reads local MMDB files. It never sends client IPs to MaxMind or any
other service.

## Databases

Use the free GeoLite2 databases:

- `GeoLite2-City.mmdb` — country, region, city, latitude/longitude.
- `GeoLite2-ASN.mmdb` — autonomous system number and organization.

Place them in the host directory configured by `GEOIP_DIR` (default `./geoip`):

```text
geoip/
├── GeoLite2-City.mmdb
└── GeoLite2-ASN.mmdb
```

Container paths:

```dotenv
GEOIP_CITY_DB=/geoip/GeoLite2-City.mmdb
GEOIP_ASN_DB=/geoip/GeoLite2-ASN.mmdb
```

The container reads them as UID/GID `10001`. Make them readable:

```bash
chmod 0644 geoip/*.mmdb
```

Do not commit MMDB files to Git. They are licensed data and can be large.
`.gitignore` excludes `*.mmdb`, `geoip/` and `data/`.

## Get an account and license key

1. Create a MaxMind account at <https://www.maxmind.com/>.
2. Generate a license key with access to GeoLite2 City and ASN.
3. Put the account ID and license key in `.env` only:

```dotenv
GEOIP_ACCOUNT_ID=YOUR_MAXMIND_ACCOUNT_ID
GEOIP_LICENSE_KEY=YOUR_MAXMIND_LICENSE_KEY
GEOIP_EDITION_IDS=GeoLite2-City GeoLite2-ASN
```

These credentials are used only by the optional `geoip-update` Compose profile.
The dashboard container does not need them. Never commit the real values or put
them in a screenshot.

## Update options

### Option A: the Compose updater profile

```bash
docker compose --profile geoip run --rm geoip-update
```

The updater writes into `GEOIP_DIR`. Run it on a schedule with cron, a systemd
timer or your existing automation. The app reads the files on its next refresh.

### Option B: the host's `geoipupdate`

On Debian/Ubuntu, install `geoipupdate`, configure `/etc/GeoIP.conf` with your
credentials, and point `DatabaseDirectory` at the directory mounted into the
container. Then use the package's timer or your own schedule:

```bash
sudo geoipupdate -v
systemctl list-timers --all geoipupdate.timer
```

Do not copy `/etc/GeoIP.conf` into the repository.

### Option C: manual download

Download the `.tar.gz` editions from your MaxMind account, extract the MMDB
files and place them in `GEOIP_DIR`. This is suitable for an air-gapped host if
you transfer the files through an approved channel.

## Behavior without databases

The app starts normally and shows a warning:

- countries are `Unknown` or `Private network`;
- city and coordinates are empty;
- ASN is `-`;
- the map shows an empty-state message;
- HTTP and TLS counts still work.

This is intentional. GeoIP must never be a startup dependency for the traffic
analytics.

## Private and documentation addresses

The resolver does not attempt to geolocate:

- loopback, link-local, multicast, unspecified and reserved addresses;
- RFC 1918 private networks;
- documentation ranges such as `192.0.2.0/24`, `198.51.100.0/24` and
  `203.0.113.0/24`;
- IPv6 documentation and unique-local ranges.

They are shown as `Private network` or `Unknown`. Most addresses in the bundled
demo log are documentation ranges and cannot be geolocated; a few well-known
public resolver addresses may produce map points if a real database is
installed. The demo remains synthetic and clearly labelled.

## Accuracy and privacy

- GeoLite2 is approximate. City-level data can be wrong or missing.
- VPNs, proxies, mobile networks and CGNAT can place a client far from its
  physical location.
- One IP can represent many people.
- Do not use GeoIP for access control, fraud decisions or proof of identity.
- Keep the databases updated; old data drifts.
- The dashboard never calls MaxMind at request time.

## Licensing

MaxMind GeoLite2 data is subject to MaxMind's own license and terms. This
repository does not redistribute the databases. Review the current MaxMind terms
before deploying, especially if you expose derived data to third parties.
