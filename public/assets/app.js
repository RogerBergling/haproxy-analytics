const state = {
  snapshot: null,
  version: null,
  myIp: null,
  whoamiMasked: false,
  maskedIp: null,
  view: "overview",
  visitorFilter: "",
  countryFilter: "",
  cityFilter: "",
  refreshTimer: null,
  goaccessStamp: null,
};

const VIEW_TITLES = {
  overview: "Overview",
  visitors: "Visitors",
  geo: "Geo access",
  tls: "TLS / SNI",
  http: "HTTP analytics",
  goaccess: "GoAccess",
  security: "Security & privacy",
};

const numberFormat = new Intl.NumberFormat();
const timeFormat = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "medium",
});

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

function el(tag, options = {}) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined && options.text !== null) node.textContent = String(options.text);
  if (options.attrs) {
    for (const [name, value] of Object.entries(options.attrs)) {
      if (value !== null && value !== undefined) node.setAttribute(name, String(value));
    }
  }
  if (options.children) {
    for (const child of options.children) {
      if (child) node.append(child);
    }
  }
  return node;
}

function svgEl(tag, attrs = {}) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [name, value] of Object.entries(attrs)) {
    node.setAttribute(name, String(value));
  }
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function fmt(value) {
  return numberFormat.format(Number(value) || 0);
}

function formatBytes(value) {
  let bytes = Number(value) || 0;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let index = 0;
  while (bytes >= 1024 && index < units.length - 1) {
    bytes /= 1024;
    index += 1;
  }
  if (index === 0) return `${Math.round(bytes)} B`;
  return `${bytes.toFixed(bytes >= 100 ? 0 : 1)} ${units[index]}`;
}

function formatWhen(value) {
  if (!value || value === "-") return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return timeFormat.format(date);
}

function formatShare(value) {
  const share = Number(value) || 0;
  return `${share.toFixed(share >= 10 ? 1 : 2)}%`;
}

function countryFlag(code) {
  if (!code || code.length !== 2) return "🌐";
  return String.fromCodePoint(
    ...[...code.toUpperCase()].map((character) => 0x1f1e6 + character.charCodeAt(0) - 65)
  );
}

function show(node, visible) {
  if (node) node.classList.toggle("hidden", !visible);
}

function emptyState(title, text) {
  return el("div", {
    className: "empty-state",
    children: [el("strong", { text: title }), el("span", { text })],
  });
}

async function fetchJSON(url) {
  const response = await fetch(url, {
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error(`${url} returned ${response.status}`);
  return response.json();
}

function showAlert(message, kind = "error") {
  const alert = $("#alert");
  if (!alert) return;
  alert.textContent = message;
  alert.classList.toggle("warn", kind === "warn");
  alert.classList.toggle("ok", kind === "ok");
  alert.classList.remove("hidden");
}

function hideAlert() {
  const alert = $("#alert");
  if (alert) alert.classList.add("hidden");
}

function publicCountries(items) {
  return (items || []).filter((item) => item.name !== "Private network" && item.name !== "Unknown");
}

function renderBarList(container, items, kind = "blue", emptyTitle = "No events recorded") {
  clear(container);
  if (!items || items.length === 0) {
    container.append(emptyState(emptyTitle, "The current snapshot has no matching events."));
    return;
  }
  const max = Math.max(...items.map((item) => Number(item.count) || 0), 1);
  const list = el("div", { className: "bar-list" });
  for (const item of items) {
    const count = Number(item.count) || 0;
    const width = Math.max(2, (100 * count) / max);
    const meta = el("div", {
      className: "bar-meta",
      children: [
        el("span", { text: item.name, attrs: { title: item.name } }),
        el("b", { text: fmt(count) }),
      ],
    });
    const fill = el("div", { className: `bar-fill ${kind}` });
    fill.style.width = `${width.toFixed(2)}%`;
    const track = el("div", { className: "bar-track", children: [fill] });
    list.append(el("div", { className: "bar-line", children: [meta, track] }));
  }
  container.append(list);
}

function statCard(label, value, note) {
  return el("div", {
    className: "stat",
    children: [
      el("div", { className: "stat-label", text: label }),
      el("div", { className: "stat-number", text: value }),
      el("div", { className: "stat-note", text: note }),
    ],
  });
}

function renderStats() {
  const container = $("#stats");
  if (!container || !state.snapshot) return;
  const kpis = state.snapshot.kpis;
  clear(container);
  container.append(
    statCard("HTTP requests", fmt(kpis.http_total), "Decrypted web traffic"),
    statCard("TLS connections", fmt(kpis.tls_total), "SNI-observed TCP events"),
    statCard("Unique client IPs", fmt(kpis.unique_ips), "Across HTTP + TLS"),
    statCard("Countries", fmt(kpis.countries), "Geolocated locations"),
    statCard("HTTP 4xx / 5xx", fmt(kpis.errors), "Errors and denials"),
    statCard("HTTP bandwidth", formatBytes(kpis.bytes), "Logged response bytes")
  );
}

function renderHttpStats() {
  const container = $("#http-stats");
  if (!container || !state.snapshot) return;
  const http = state.snapshot.http;
  clear(container);
  container.append(
    statCard("HTTP requests", fmt(http.total), "Decrypted requests"),
    statCard("Bandwidth", formatBytes(http.bandwidth), "Logged response bytes"),
    statCard("4xx / 5xx", fmt(http.errors), "Errors and denials"),
    statCard("Backends", fmt(http.backends.length), "Observed destinations")
  );
}

function renderGeoSummary() {
  const container = $("#geo-summary");
  if (!container || !state.snapshot) return;
  const countries = (state.snapshot.geo.countries || []).filter(
    (country) => country.country !== "Private network" && country.country !== "Unknown"
  );
  if (countries.length === 0) {
    const message = state.snapshot.meta.geoip.city
      ? "No geolocated client addresses in this snapshot."
      : "GeoIP City database not loaded. Mount a GeoLite2-City.mmdb to enable geography.";
    clear(container);
    container.append(emptyState("Geo access is empty", message));
    return;
  }
  const items = countries.slice(0, 6).map((country) => ({
    name: `${countryFlag(country.country_code)} ${country.country}`,
    count: country.total,
  }));
  renderBarList(container, items, "blue", "No geolocated countries");
}

function markerRadius(total) {
  return Math.min(15, 3.2 + Math.pow(Math.max(1, total), 0.4));
}

function renderMap(which) {
  const overlay = $(`#map-overlay-${which}`);
  if (!overlay || !state.snapshot) return;
  clear(overlay);
  const points = state.snapshot.geo.points || [];
  if (points.length === 0) {
    const text = svgEl("text", {
      x: "540",
      y: "260",
      "text-anchor": "middle",
      class: "map-empty",
    });
    text.textContent = "No geolocated positions in this snapshot";
    overlay.append(text);
    return;
  }
  const myIp = state.myIp;
  for (const point of points) {
    const lat = Number(point.lat);
    const lon = Number(point.lon);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue;
    const x = Math.min(1080, Math.max(0, (lon + 180) * 3));
    const y = Math.min(520, Math.max(0, ((90 - lat) * 520) / 180));
    const total = Number(point.total) || 0;
    const radius = markerRadius(total);
    const location = [point.city, point.country].filter((value) => value && value !== "-").join(", ");
    const titleText = `${location || "Unknown"} · ${fmt(point.http)} HTTP · ${fmt(point.tls)} TLS`;
    const kinds = [
      ["tls", Number(point.tls) || 0, -3],
      ["http", Number(point.http) || 0, 3],
    ];
    for (const [kind, count, offset] of kinds) {
      if (!count) continue;
      const circle = svgEl("circle", {
        cx: (x + offset).toFixed(1),
        cy: y.toFixed(1),
        r: radius.toFixed(1),
        class: `pin ${kind}${myIp && point.ips && point.ips.includes(myIp) ? " is-you" : ""}`,
      });
      const title = svgEl("title");
      title.textContent = `${titleText} · ${kind.toUpperCase()} events: ${fmt(count)}`;
      circle.append(title);
      overlay.append(circle);
    }
  }
}

function shareCell(share) {
  const fill = el("div", { className: "bar-fill blue" });
  fill.style.width = `${Math.min(100, Math.max(0, Number(share) || 0)).toFixed(2)}%`;
  const track = el("div", { className: "bar-track share-track", children: [fill] });
  return el("div", {
    className: "share-cell",
    children: [track, el("span", { text: formatShare(share) })],
  });
}

function renderCountryTable() {
  const body = $("#country-rows");
  if (!body || !state.snapshot) return;
  clear(body);
  const countries = (state.snapshot.geo.countries || []).filter(
    (country) => country.country !== "Private network" && country.country !== "Unknown"
  );
  const term = state.countryFilter.toLowerCase().trim();
  const visible = countries.filter((country) => {
    if (!term) return true;
    const cities = (country.top_cities || []).map(([city]) => city).join(" ");
    return `${country.country} ${country.country_code} ${cities}`.toLowerCase().includes(term);
  });
  for (const country of visible) {
    const row = el("tr", {
      children: [
        el("td", { children: [el("span", { className: "country-flag", text: countryFlag(country.country_code) }), el("span", { text: country.country })] }),
        el("td", { className: "number-cell", text: fmt(country.http) }),
        el("td", { className: "number-cell", text: fmt(country.tls) }),
        el("td", { className: "number-cell", text: fmt(country.ips) }),
        el("td", { children: [shareCell(country.share)] }),
        el("td", { className: "mono", text: country.last_seen || "-" }),
      ],
    });
    body.append(row);
  }
  if (visible.length === 0) {
    const message = countries.length ? "No countries match the filter." : "No public geolocations in this snapshot.";
    const row = el("tr", { children: [el("td", { attrs: { colspan: "6" }, className: "muted", text: message })] });
    body.append(row);
  }
  const count = $("#country-count");
  if (count) count.textContent = term ? `${visible.length} of ${countries.length} countries` : `${countries.length} countries`;
  const pill = $("#geo-pill");
  if (pill) pill.textContent = `${fmt(state.snapshot.geo.country_count)} countries`;
}

function renderCityTable() {
  const body = $("#city-rows");
  if (!body || !state.snapshot) return;
  clear(body);
  const cities = state.snapshot.geo.cities || [];
  const term = state.cityFilter.toLowerCase().trim();
  const visible = cities.filter((city) => {
    if (!term) return true;
    return `${city.city} ${city.country} ${city.country_code}`.toLowerCase().includes(term);
  });
  for (const city of visible) {
    body.append(
      el("tr", {
        children: [
          el("td", { children: [el("span", { className: "country-flag", text: countryFlag(city.country_code) }), el("span", { text: city.city })] }),
          el("td", { text: city.country }),
          el("td", { className: "number-cell", text: fmt(city.total) }),
          el("td", { className: "number-cell", text: fmt(city.ips) }),
          el("td", { className: "mono", text: city.last_seen || "-" }),
        ],
      })
    );
  }
  if (visible.length === 0) {
    body.append(el("tr", { children: [el("td", { attrs: { colspan: "5" }, className: "muted", text: "No cities match the filter." })] }));
  }
  const count = $("#city-count");
  if (count) count.textContent = term ? `${visible.length} of ${cities.length} cities` : `${cities.length} cities`;
}

function renderGeo() {
  renderGeoSummary();
  renderMap("overview");
  renderMap("geo");
  renderCountryTable();
  renderCityTable();
  const snapshot = state.snapshot;
  const points = snapshot && snapshot.geo && snapshot.geo.points ? snapshot.geo.points.length : 0;
  const mapNote =
    snapshot && snapshot.meta && snapshot.meta.geoip && snapshot.meta.geoip.city
      ? `${fmt(points)} geolocated positions`
      : "GeoIP City database not loaded";
  const overviewSub = $("#map-sub-overview");
  const geoSub = $("#map-sub-geo");
  if (overviewSub) overviewSub.textContent = mapNote;
  if (geoSub) geoSub.textContent = mapNote;
}

function youTag() {
  return el("span", { className: "badge you", text: "This is you" });
}

function renderVisitors() {
  const body = $("#visitor-rows");
  if (!body || !state.snapshot) return;
  clear(body);
  const visitors = state.snapshot.visitors.rows || [];
  const masked = Boolean(state.snapshot.visitors.masked);
  const unit = masked ? "masked IP groups" : "IP addresses";
  const rawTotal = Number(state.snapshot.visitors.raw_total) || state.snapshot.visitors.total;
  const rawSuffix = masked ? ` · ${fmt(rawTotal)} observed IPs` : "";
  const term = state.visitorFilter.toLowerCase().trim();
  const visible = visitors.filter((visitor) => !term || String(visitor.search || "").includes(term));
  for (const visitor of visible) {
    const isYou = visitor.ip === state.myIp;
    const ipCell = el("td", {
      className: "mono",
      children: [el("span", { text: visitor.ip })],
    });
    if (isYou) ipCell.append(youTag());
    const snis = (visitor.snis || []).map(([name, count]) => `${name} (${fmt(count)})`).join(", ") || "-";
    const backends = (visitor.backends || []).map(([name, count]) => `${name} (${fmt(count)})`).join(", ") || "-";
    const row = el("tr", {
      className: isYou ? "is-you" : "",
      attrs: { "data-ip": visitor.ip, "data-search": visitor.search, tabindex: "-1" },
      children: [
        ipCell,
        el("td", { text: visitor.location }),
        el("td", { text: visitor.asn || "-" }),
        el("td", { className: "wrap-cell", text: snis, attrs: { title: snis } }),
        el("td", { className: "wrap-cell", text: backends, attrs: { title: backends } }),
        el("td", { className: "number-cell", text: fmt(visitor.tls) }),
        el("td", { className: "number-cell", text: fmt(visitor.http) }),
        el("td", { className: "mono", text: visitor.last_seen || "-" }),
      ],
    });
    body.append(row);
  }
  if (visible.length === 0) {
    body.append(
      el("tr", {
        children: [
          el("td", {
            attrs: { colspan: "8" },
            className: "muted",
            text: visitors.length ? "No visitors match the filter." : "No client traffic recorded in this snapshot.",
          }),
        ],
      })
    );
  }
  const count = $("#visitor-count");
  const truncated = state.snapshot.visitors.truncated;
  const capSuffix = truncated
    ? ` · showing ${fmt(visitors.length)} of ${fmt(state.snapshot.visitors.total)}`
    : "";
  if (count) {
    count.textContent = term
      ? `${fmt(visible.length)} of ${fmt(visitors.length)} ${unit}${capSuffix}${rawSuffix}`
      : `${fmt(visitors.length)} ${unit}${capSuffix}${rawSuffix}`;
  }
  const pill = $("#visitor-total-pill");
  if (pill) pill.textContent = `${fmt(state.snapshot.visitors.total)} ${unit}`;
  const navBadge = $("#nav-visitor-count");
  if (navBadge) navBadge.textContent = fmt(state.snapshot.visitors.total);
  const maskBadge = $("#visitor-mask-badge");
  if (maskBadge) maskBadge.classList.toggle("hidden", !masked);
}

function renderRecentTls(target, rows) {
  const body = $(target);
  if (!body) return;
  clear(body);
  const recent = rows || [];
  if (recent.length === 0) {
    body.append(el("tr", { children: [el("td", { attrs: { colspan: "5" }, className: "muted", text: "No TLS entries recorded." })] }));
    return;
  }
  for (const row of recent) {
    body.append(
      el("tr", {
        children: [
          el("td", { className: "mono", text: row.time }),
          el("td", { className: "mono", text: row.ip }),
          el("td", { text: row.sni }),
          el("td", { text: row.country }),
          el("td", { text: row.city }),
        ],
      })
    );
  }
}

function renderTls() {
  if (!state.snapshot) return;
  const tls = state.snapshot.tls;
  const pill = $("#tls-pill");
  if (pill) pill.textContent = `${fmt(tls.total)} connections`;
  renderBarList($("#tls-snis"), (tls.snis || []).map((item) => ({ name: item.name, count: item.count })), "gold", "No SNI hostnames");
  renderBarList($("#tls-asns"), (tls.asns || []).map((item) => ({ name: item.name, count: item.count })), "violet", "No ASN data");
  renderBarList(
    $("#tls-countries"),
    publicCountries(tls.countries).map((item) => ({ name: item.name, count: item.count })),
    "blue",
    "No country data"
  );
  renderRecentTls("#tls-recent", (tls.recent || []).map((row) => ({ ...row, city: row.city || "-" })));
  renderRecentTls("#recent-tls-overview", tls.recent || []);
}

function renderHttp() {
  if (!state.snapshot) return;
  const http = state.snapshot.http;
  const pill = $("#http-pill");
  if (pill) pill.textContent = `${fmt(http.total)} requests`;
  renderHttpStats();
  renderBarList($("#http-methods"), http.methods, "blue", "No HTTP methods");
  renderBarList($("#http-statuses"), http.statuses, "violet", "No response codes");
  renderBarList($("#http-backends"), http.backends, "green", "No backends");
  renderBarList($("#http-countries"), publicCountries(http.countries), "blue", "No country data");
  renderBarList($("#http-asns"), http.asns, "violet", "No ASN data");
  const body = $("#http-paths");
  if (!body) return;
  clear(body);
  const paths = http.paths || [];
  if (paths.length === 0) {
    body.append(el("tr", { children: [el("td", { attrs: { colspan: "2" }, className: "muted", text: "No requested paths recorded." })] }));
  } else {
    for (const path of paths) {
      body.append(
        el("tr", {
          children: [
            el("td", { className: "mono wrap-cell", text: path.name, attrs: { title: path.name } }),
            el("td", { className: "number-cell", text: fmt(path.count) }),
          ],
        })
      );
    }
  }
}

function renderGoAccess() {
  if (!state.snapshot) return;
  const meta = state.snapshot.meta;
  const status = meta.goaccess || {};
  const badge = $("#goaccess-status");
  const container = $("#goaccess-container");
  if (!badge || !container) return;
  badge.className = "badge";
  if (status.generated) {
    badge.classList.add("ok");
    badge.textContent = "Report ready";
  } else if (status.enabled) {
    badge.classList.add("warn");
    badge.textContent = "Not available";
  } else {
    badge.classList.add("info");
    badge.textContent = "Not enabled";
  }

  if (status.generated) {
    const stamp = meta.generated_at;
    let frame = $("#goaccess-container iframe");
    if (!frame) {
      clear(container);
      frame = el("iframe", {
        className: "goaccess-frame",
        attrs: {
          title: "Detailed GoAccess HTTP analytics",
          sandbox: "allow-scripts",
          loading: "lazy",
        },
      });
      container.append(frame);
    }
    const privacy = meta.privacy || {};
    const masking =
      privacy.mask_internal_ips ||
      (Array.isArray(privacy.mask_networks) && privacy.mask_networks.length > 0);
    const skipped = Number(status.skipped_lines || 0);
    let note = $(".goaccess-note", container);
    if (!note) {
      note = el("p", { className: "goaccess-note" });
      container.append(note);
    }
    note.textContent =
      "This report is generated by GoAccess and displayed in a sandboxed iframe. It cannot read this page or make network requests." +
      (masking
        ? " Masked internal clients appear as 0.0.0.0 (or ::) because GoAccess requires a valid address."
        : "") +
      (skipped > 0
        ? ` ${fmt(skipped)} HTTP line(s) were omitted because they do not match the GoAccess log-format.`
        : "");
    if (frame.dataset.snapshot !== stamp) {
      frame.dataset.snapshot = stamp;
      frame.src = `/goaccess?t=${encodeURIComponent(stamp)}`;
    }
    return;
  }

  clear(container);
  if (status.enabled && status.error) {
    container.append(
      emptyState(
        "GoAccess is enabled but did not produce a report",
        status.error + (status.detail ? ` ${status.detail}` : "")
      )
    );
  } else if (status.enabled) {
    container.append(emptyState("GoAccess is starting", "The first report will appear after the next refresh."));
  } else {
    container.append(
      emptyState(
        "GoAccess is optional",
        "Set GOACCESS_ENABLED=true in .env to generate a detailed HTTP report. The built-in HTTP view already works without GoAccess."
      )
    );
  }
}

function renderYouBanners() {
  const banners = $$("[data-you-banner]");
  if (banners.length === 0) return;
  const myIp = state.myIp;
  const visitor = myIp && state.snapshot ? state.snapshot.visitors.rows.find((row) => row.ip === myIp) : null;
  for (const banner of banners) {
    banner.classList.remove("hidden");
    const headline = $("[data-you-headline]", banner);
    const description = $("[data-you-description]", banner);
    const button = $("[data-find-me]", banner);
    if (state.whoamiMasked) {
      banner.classList.add("no-match");
      if (headline) headline.textContent = "Your internal address is masked";
      if (description) description.textContent = `Self-highlight is disabled while ${state.maskedIp || "your internal address"} is masked. Public addresses remain unmasked.`;
      if (button) button.classList.add("hidden");
      continue;
    }
    if (!myIp) {
      banner.classList.add("hidden");
      continue;
    }
    banner.classList.toggle("no-match", !visitor);
    if (visitor) {
      if (headline) headline.textContent = `You are in this snapshot: ${myIp}`;
      if (description) description.textContent = "This IP appears in the HAProxy log. NAT, a VPN or a proxy can make one IP represent several people.";
      if (button) button.classList.remove("hidden");
    } else {
      if (headline) headline.textContent = `Hello, ${myIp}`;
      if (description) description.textContent = "This IP is not present in the current snapshot. Opening the dashboard does not create HAProxy traffic.";
      if (button) button.classList.add("hidden");
    }
  }
}

function renderServerCard() {
  if (!state.snapshot) return;
  const meta = state.snapshot.meta;
  const version = meta.version || state.version || {};
  const generated = formatWhen(meta.generated_at);
  const warnings = meta.warnings || [];
  const dot = $("#server-dot");
  if (dot) {
    dot.classList.toggle("ok", warnings.length === 0);
    dot.classList.toggle("warn", warnings.length > 0);
  }
  const source = meta.source || {};
  const active = source.active || [];
  let sourceText = "no active source";
  if (meta.demo) sourceText = "demo data";
  else if (active.includes("file") && active.includes("syslog")) sourceText = "file + syslog";
  else if (active.includes("file")) sourceText = "file log";
  else if (active.includes("syslog")) sourceText = "syslog";
  const sourceNode = $("#server-source");
  if (sourceNode) sourceNode.textContent = sourceText;

  const versionNode = $("#server-version");
  if (versionNode) versionNode.textContent = version.version || "dev";
  const buildNode = $("#server-build");
  if (buildNode) buildNode.textContent = `build ${version.buildNumber || "local"} · ${version.commit || "local"}`;

  const lastUpdated = $("#last-updated");
  if (lastUpdated) lastUpdated.textContent = `Snapshot ${generated}`;
  const snapshotPill = $("#snapshot-pill");
  if (snapshotPill) snapshotPill.textContent = `Snapshot · ${generated}`;

  const footerVersion = $("#footer-version");
  if (footerVersion) footerVersion.textContent = version.version || "dev";
  const footerBuild = $("#footer-build");
  if (footerBuild) footerBuild.textContent = version.buildNumber || "local";
  const footerCommit = $("#footer-commit");
  if (footerCommit) footerCommit.textContent = version.commit || "local";
  const footerImage = $("#footer-image");
  if (footerImage) footerImage.textContent = version.imageTag || "local";

  const overviewSub = $("#overview-sub");
  if (overviewSub) {
    const kpis = state.snapshot.kpis;
    overviewSub.textContent = `${fmt(kpis.http_total)} HTTP requests · ${fmt(kpis.tls_total)} TLS connections · ${fmt(kpis.unique_ips)} unique IPs`;
  }
}

function renderWarnings() {
  if (!state.snapshot) return;
  const meta = state.snapshot.meta;
  const warnings = meta.warnings || [];
  const demoBanner = $("#demo-banner");
  show(demoBanner, Boolean(meta.demo));
  if (warnings.length === 0) {
    hideAlert();
    return;
  }
  const shown = warnings.slice(0, 3).join(" ");
  const suffix = warnings.length > 3 ? ` (+${warnings.length - 3} more; see the container log)` : "";
  showAlert(`${shown}${suffix}`, "warn");
}

function renderSyslogStore() {
  const status = $("#syslog-store-status");
  const button = $("#clear-syslog-button");
  if (!status || !button) return;
  const snapshot = state.snapshot;
  const meta = snapshot && snapshot.meta ? snapshot.meta : {};
  const source = meta.source || {};
  const syslog = source.syslog || {};
  const store = syslog.store || {};
  if (!store.enabled) {
    status.textContent = "No persistent syslog store configured. Set SYSLOG_STORE_FILE and mount the data directory.";
    button.disabled = true;
    return;
  }
  const files = Array.isArray(store.files) ? store.files.length : 0;
  status.textContent = `${store.path} · ${formatBytes(store.total_bytes)} · ${fmt(files)} file(s) · ${fmt(store.write_errors)} write error(s)`;
  button.disabled = false;
}

function setupClearSyslog() {
  const button = $("#clear-syslog-button");
  if (!button) return;
  button.addEventListener("click", async () => {
    if (!window.confirm("Delete the persisted syslog history and all backups? This cannot be undone.")) {
      return;
    }
    button.disabled = true;
    button.textContent = "Clearing…";
    const resultNode = $("#clear-syslog-result");
    if (resultNode) resultNode.textContent = "";
    try {
      const token = await fetchJSON("/api/clear-token");
      const response = await fetch("/api/syslog/clear", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "X-CSRF-Token": token.token,
        },
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok || !result.cleared) {
        throw new Error(result.error || `HTTP ${response.status}`);
      }
      await refreshSnapshot(true);
      if (resultNode) resultNode.textContent = "Persisted syslog history cleared.";
      showAlert("Persisted syslog history cleared.", "ok");
    } catch (error) {
      if (resultNode) resultNode.textContent = `Could not clear history: ${error.message}`;
      showAlert(`Could not clear syslog history: ${error.message}`);
    } finally {
      button.textContent = "Clear syslog history";
      button.disabled = false;
    }
  });
}

function renderAll() {
  if (!state.snapshot) return;
  renderStats();
  renderGeo();
  renderVisitors();
  renderTls();
  renderHttp();
  renderGoAccess();
  renderYouBanners();
  renderServerCard();
  renderWarnings();
  renderSyslogStore();
}

function showView(name) {
  const view = VIEW_TITLES[name] ? name : "overview";
  state.view = view;
  for (const panel of $$("[data-view-panel]")) {
    panel.classList.toggle("hidden", panel.dataset.viewPanel !== view);
  }
  for (const item of $$("[data-view]")) {
    const active = item.dataset.view === view;
    item.classList.toggle("active", active);
    if (active) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  }
  const crumb = $("#crumb-view");
  if (crumb) crumb.textContent = VIEW_TITLES[view];
  if (location.hash !== `#${view}`) {
    history.replaceState(null, "", `#${view}`);
  }
  if (view === "visitors") renderVisitors();
  if (view === "geo") renderGeo();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function setupNavigation() {
  for (const item of $$("[data-view]")) {
    item.addEventListener("click", () => showView(item.dataset.view));
  }
  for (const link of $$("[data-view-link]")) {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      showView(link.dataset.viewLink);
    });
  }
  window.addEventListener("hashchange", () => {
    showView(location.hash.replace(/^#/, "") || "overview");
  });
  showView(location.hash.replace(/^#/, "") || "overview");
}

function setupFilters() {
  const visitorSearch = $("#visitor-search");
  if (visitorSearch) {
    visitorSearch.addEventListener("input", () => {
      state.visitorFilter = visitorSearch.value;
      renderVisitors();
    });
  }
  const countrySearch = $("#country-search");
  if (countrySearch) {
    countrySearch.addEventListener("input", () => {
      state.countryFilter = countrySearch.value;
      renderCountryTable();
    });
  }
  const citySearch = $("#city-search");
  if (citySearch) {
    citySearch.addEventListener("input", () => {
      state.cityFilter = citySearch.value;
      renderCityTable();
    });
  }
}

function focusMyRow() {
  showView("visitors");
  const search = $("#visitor-search");
  if (search) search.value = "";
  state.visitorFilter = "";
  renderVisitors();
  const row = state.myIp
    ? Array.from(document.querySelectorAll("#visitor-rows tr[data-ip]")).find(
        (candidate) => candidate.dataset.ip === state.myIp
      )
    : null;
  if (row) {
    row.scrollIntoView({ behavior: "smooth", block: "center" });
    row.focus({ preventScroll: true });
  }
}

function setupFindMe() {
  for (const button of $$("[data-find-me]")) {
    button.addEventListener("click", focusMyRow);
  }
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const sun = $(".icon-sun");
  const moon = $(".icon-moon");
  show(sun, theme !== "light");
  show(moon, theme === "light");
  const suffix = theme === "light" ? "light" : "dark";
  for (const image of $$("img[id^='world-map-']")) {
    image.src = `/assets/world-${suffix}.svg`;
  }
  try {
    localStorage.setItem("haproxy-analytics-theme", theme);
  } catch (error) {
    // Storage can be disabled; the in-page theme still works.
  }
}

function setupTheme() {
  let theme = null;
  try {
    theme = localStorage.getItem("haproxy-analytics-theme");
  } catch (error) {
    theme = null;
  }
  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  applyTheme(theme);
  const toggle = $("#theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", () => {
      applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
    });
  }
}

async function loadWhoami() {
  try {
    const answer = await fetchJSON("/api/whoami");
    if (answer && typeof answer.ip === "string" && answer.ip) {
      if (answer.masked) {
        state.myIp = null;
        state.maskedIp = answer.ip;
        state.whoamiMasked = true;
      } else {
        state.myIp = answer.ip;
        state.maskedIp = null;
        state.whoamiMasked = false;
      }
      renderYouBanners();
      renderVisitors();
      renderMap("overview");
      renderMap("geo");
    }
  } catch (error) {
    state.myIp = null;
    state.maskedIp = null;
    state.whoamiMasked = false;
  }
}

function scheduleRefresh() {
  if (state.refreshTimer) clearTimeout(state.refreshTimer);
  const snapshot = state.snapshot;
  const refreshSeconds =
    snapshot && snapshot.meta && snapshot.meta.refresh_seconds ? snapshot.meta.refresh_seconds : 60;
  const seconds = Math.max(5, Number(refreshSeconds) || 60);
  state.refreshTimer = setTimeout(async () => {
    if (document.visibilityState === "visible") {
      await refreshSnapshot(true);
    }
    scheduleRefresh();
  }, seconds * 1000);
}

async function refreshSnapshot(silent = false) {
  try {
    state.snapshot = await fetchJSON("/api/snapshot");
    if (!silent) hideAlert();
    renderAll();
    scheduleRefresh();
  } catch (error) {
    if (!silent) showAlert(`Could not load the snapshot: ${error.message}`);
  }
}

async function initialLoad() {
  try {
    const [snapshot, version] = await Promise.all([
      fetchJSON("/api/snapshot"),
      fetchJSON("/version.json").catch(() => null),
    ]);
    state.snapshot = snapshot;
    state.version = version;
    renderAll();
    scheduleRefresh();
    await loadWhoami();
  } catch (error) {
    showAlert(`Could not load the dashboard: ${error.message}. Check the container health endpoint.`);
  }
}

function setupRefresh() {
  const button = $("#refresh-button");
  if (button) {
    button.addEventListener("click", async () => {
      button.disabled = true;
      button.textContent = "Refreshing…";
      await refreshSnapshot(false);
      button.disabled = false;
      button.textContent = "Refresh";
    });
  }
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") refreshSnapshot(true);
  });
}

setupTheme();
setupNavigation();
setupFilters();
setupFindMe();
setupRefresh();
setupClearSyslog();
initialLoad();
