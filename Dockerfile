# syntax=docker/dockerfile:1

# HAProxy Analytics is a read-only analytics service. The image contains the
# Python application, the static dashboard and the optional GoAccess binary.
# It has no database, no upload endpoint and no persistent write path.
# The base image is pinned by digest; update it deliberately.
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

ARG APP_VERSION=dev
ARG IMAGE_TAG=local
ARG GIT_SHA=local
ARG BUILD_DATE=
ARG BUILD_NUMBER=local

LABEL org.opencontainers.image.title="HAProxy Analytics" \
      org.opencontainers.image.description="Read-only HAProxy HTTP, TLS/SNI and GeoIP analytics dashboard" \
      org.opencontainers.image.source="https://github.com/RogerBergling/haproxy-analytics" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="$APP_VERSION" \
      org.opencontainers.image.revision="$GIT_SHA" \
      io.haproxy-analytics.build.image-tag="$IMAGE_TAG" \
      io.haproxy-analytics.build.number="$BUILD_NUMBER" \
      io.haproxy-analytics.build.date="$BUILD_DATE"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_VERSION="$APP_VERSION" \
    IMAGE_TAG="$IMAGE_TAG" \
    GIT_SHA="$GIT_SHA" \
    BUILD_DATE="$BUILD_DATE" \
    BUILD_NUMBER="$BUILD_NUMBER"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends goaccess tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app --no-create-home --shell /usr/sbin/nologin app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --requirement requirements.txt

COPY --chown=app:app haproxy_analytics ./haproxy_analytics
COPY --chown=app:app public ./public
COPY --chown=app:app config ./config
COPY --chown=app:app examples ./examples
COPY --chown=app:app LICENSE THIRD_PARTY_NOTICES.md ./

ENV APP_BIND=0.0.0.0 \
    APP_PORT=8080 \
    HAPROXY_LOG_FILE=/logs/haproxy.log \
    GEOIP_CITY_DB=/geoip/GeoLite2-City.mmdb \
    GEOIP_ASN_DB=/geoip/GeoLite2-ASN.mmdb \
    GOACCESS_BINARY=goaccess \
    GOACCESS_CONFIG=/app/config/goaccess-haproxy.conf

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]

ENTRYPOINT ["python3", "-m", "haproxy_analytics"]
