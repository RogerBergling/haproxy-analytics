#!/usr/bin/env python3
"""Repository verification for the public HAProxy Analytics repository.

This is intentionally conservative. It catches accidental private data,
missing hardening, unsafe frontend patterns and packaging drift before CI.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED = [
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "Dockerfile",
    "compose.yaml",
    ".env.example",
    ".dockerignore",
    ".gitignore",
    "requirements.txt",
    "haproxy_analytics/__main__.py",
    "haproxy_analytics/config.py",
    "haproxy_analytics/server.py",
    "haproxy_analytics/parser.py",
    "haproxy_analytics/snapshot.py",
    "haproxy_analytics/livestats.py",
    "haproxy_analytics/syslog_store.py",
    "public/index.html",
    "public/assets/app.css",
    "public/assets/app.js",
    "public/assets/world-dark.svg",
    "public/assets/world-light.svg",
    "examples/demo-haproxy.log",
    "tests/test_parser.py",
    "tests/test_livestats.py",
    "tests/test_server.py",
    "docs/haproxy.md",
    "docs/external-logs.md",
    "docs/security.md",
    "docs/deployment.md",
    ".github/workflows/ci.yml",
    ".github/workflows/docker-publish.yml",
    ".gitleaks.toml",
]

TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".py",
    ".js",
    ".css",
    ".html",
    ".yml",
    ".yaml",
    ".toml",
    ".json",
    ".conf",
    ".example",
    ".cfg",
    ".log",
    ".svg",
    ".sh",
    "",
}

# Built from parts so the public verifier does not repeat private infrastructure
# names as literal strings. The RFC1918 expression below covers private IPv4.
FORBIDDEN_TOKENS = [
    "bergling" + ".net",
    "jordbruks" + "verket",
]

RFC1918 = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3})\b"
)
EXTERNAL_URL = re.compile(r"https?://[^\s\"'<>)]+")


def tracked_files() -> list[Path]:
    try:
        tracked = subprocess.check_output(
            ["git", "ls-files", "-z"], cwd=ROOT, stderr=subprocess.DEVNULL
        ).decode("utf-8")
        untracked = subprocess.check_output(
            ["git", "ls-files", "--others", "--exclude-standard", "-z"],
            cwd=ROOT,
            stderr=subprocess.DEVNULL,
        ).decode("utf-8")
        names = [item for item in (tracked + untracked).split("\0") if item]
        return [ROOT / item for item in dict.fromkeys(names)]
    except (OSError, subprocess.CalledProcessError):
        return [
            path
            for path in ROOT.rglob("*")
            if path.is_file()
            and ".git" not in path.parts
            and "target" not in path.parts
            and "__pycache__" not in path.parts
        ]


def text_files(files: list[Path]) -> list[Path]:
    return [path for path in files if path.suffix.lower() in TEXT_SUFFIXES or path.name == ".env.example"]


def fail(message: str, errors: list[str]) -> None:
    errors.append(message)


def main() -> int:
    errors: list[str] = []
    files = tracked_files()

    for relative in REQUIRED:
        if not (ROOT / relative).is_file():
            fail(f"missing required file: {relative}", errors)

    tracked_names = {path.relative_to(ROOT).as_posix() for path in files}
    if ".env" in tracked_names:
        fail(".env must never be tracked; use .env.example", errors)
    if any(name.startswith("target/") for name in tracked_names):
        fail("target/ must never be tracked; it contains the private reproduction bundle", errors)
    if any(name.lower().endswith(".mmdb") for name in tracked_names):
        fail("MaxMind databases must not be committed", errors)

    for path in text_files(files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = path.relative_to(ROOT).as_posix()
        if relative == "scripts/verify.py":
            continue
        lowered = text.lower()
        for token in FORBIDDEN_TOKENS:
            if token in lowered:
                fail(f"private token {token!r} found in {relative}", errors)
        for match in RFC1918.finditer(text):
            fail(f"private RFC1918 address {match.group(0)!r} found in {relative}", errors)

    version_file = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    init_file = (ROOT / "haproxy_analytics/__init__.py").read_text(encoding="utf-8")
    if f'__version__ = "{version_file}"' not in init_file:
        fail("VERSION and haproxy_analytics/__init__.py disagree", errors)
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if f'version = "{version_file}"' not in pyproject:
        fail("VERSION and pyproject.toml disagree", errors)
    try:
        public_version = json.loads(
            (ROOT / "public/version.json").read_text(encoding="utf-8")
        ).get("version")
    except (OSError, ValueError):
        public_version = None
    if public_version != version_file:
        fail("VERSION and public/version.json disagree", errors)

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    for token in ("USER ", "HEALTHCHECK", "WORKDIR", "PYTHONDONTWRITEBYTECODE"):
        if token not in dockerfile:
            fail(f"Dockerfile is missing {token!r}", errors)

    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    for token in ("read_only: true", "cap_drop:", "no-new-privileges:true", "127.0.0.1"):
        if token not in compose:
            fail(f"compose.yaml is missing {token!r}", errors)

    server = (ROOT / "haproxy_analytics/server.py").read_text(encoding="utf-8")
    for token in ("default-src 'none'", "frame-ancestors 'none'", "X-Content-Type-Options", "no-store"):
        if token not in server:
            fail(f"server.py is missing security token {token!r}", errors)

    js = (ROOT / "public/assets/app.js").read_text(encoding="utf-8")
    for token in ("innerHTML", "document.write", "eval(", "new Function"):
        if token in js:
            fail(f"unsafe frontend pattern {token!r} found in app.js", errors)
    for match in EXTERNAL_URL.finditer(js):
        url = match.group(0)
        if url.startswith("http://www.w3.org/2000/svg"):
            continue
        fail(f"external URL in app.js: {url}", errors)

    html = (ROOT / "public/index.html").read_text(encoding="utf-8")
    if re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html):
        fail("index.html contains an inline script", errors)
    if re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE):
        fail("index.html contains an inline event handler", errors)
    for asset_name in ("public/index.html", "public/assets/app.css"):
        asset_text = (ROOT / asset_name).read_text(encoding="utf-8")
        for match in EXTERNAL_URL.finditer(asset_text):
            url = match.group(0)
            if url.startswith("http://www.w3.org/2000/svg"):
                continue
            fail(f"external URL in {asset_name}: {url}", errors)

    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    if "YOUR_MAXMIND_ACCOUNT_ID" not in env_example and "GEOIP_ACCOUNT_ID" not in env_example:
        fail(".env.example does not document the optional GeoIP account variables", errors)
    if "HAPROXY_STATS_SOCKET" not in env_example:
        fail(".env.example does not document HAPROXY_STATS_SOCKET", errors)
    if "EXCLUDED_DOMAINS" not in env_example:
        fail(".env.example does not document EXCLUDED_DOMAINS", errors)
    if "DOMAIN_ONLY_DOMAINS" not in env_example:
        fail(".env.example does not document DOMAIN_ONLY_DOMAINS", errors)

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for token in ("docker compose", "ghcr.io/rogerbergling/haproxy-analytics", "docs/security.md", "docs/haproxy.md"):
        if token not in readme:
            fail(f"README.md is missing {token!r}", errors)

    if errors:
        print("Repository verification failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"Repository verification passed ({len(files)} tracked files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
