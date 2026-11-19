const state = {
  snapshot: null,
  version: null,
  live: null,
  myIp: null,
  whoamiMasked: false,
  maskedIp: null,
  view: "overview",
  visitorFilter: "",
  countryFilter: "",
  cityFilter: "",
  httpIpFilter: "",
  refreshTimer: null,
  liveTimer: null,
};

const VIEW_TITLES = {
  overview: "Overview",
  live: "Live stats",
  visitors: "Visitors",
  geo: "Geo access",
  tls: "TLS / SNI",
  http: "HTTP analytics",
  requests: "Requests",
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

function formatSeconds(value) {
  const total = Math.max(0, Math.floor(Number(value) || 0));
  if (!total) return "—";
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
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
    statCard("Unique HTTP IPs", fmt(http.unique_ips || 0), "Distinct client addresses"),
    statCard("Bandwidth", formatBytes(http.bandwidth), "Logged response bytes"),
    statCard("4xx / 5xx", fmt(http.errors), `${fmt(http.error_rate || 0)}% of requests`),
    statCard("Average response", formatBytes(http.avg_bytes || 0), "Bytes per request"),
    statCard("Protocols", fmt((http.protocols || []).length), "Observed HTTP versions")
  );
}

function liveBadge(status) {
  const text = String(status || "unknown");
  const upper = text.toUpperCase();
  let kind = "info";
  if (upper === "UP" || upper === "OPEN" || upper.startsWith("UP ")) kind = "ok";
  else if (upper === "DOWN" || upper.startsWith("DOWN ")) kind = "err";
  else if (upper.startsWith("MAINT") || upper.startsWith("DRAIN") || upper.startsWith("NOLB")) kind = "warn";
  return el("span", { className: `badge ${kind}`, text });
}

function renderLiveSummary(payload) {
  const container = $("#live-summary");
  if (!container) return;
  const info = payload.info || {};
  const summary = payload.summary || {};
  clear(container);
  container.append(
    statCard("HAProxy", info.version || "—", `Uptime ${info.uptime || "—"}`),
    statCard(
      "Current sessions",
      fmt(summary.current_sessions),
      `${fmt(summary.session_rate)}/s · max ${fmt(info.max_connections)}`
    ),
    statCard(
      "Requests",
      fmt(summary.requests_total),
      `${fmt(summary.request_rate)}/s live rate`
    ),
    statCard(
      "Servers",
      `${fmt(summary.servers_up)} up`,
      `${fmt(summary.servers_down)} down · ${fmt(summary.servers_maintenance)} maint · ${fmt(summary.servers_no_check)} no check`
    ),
    statCard(
      "SSL connections",
      fmt(info.current_ssl_connections),
      `${fmt(info.ssl_connection_rate)}/s`
    ),
    statCard(
      "Traffic",
      formatBytes(summary.bytes_out),
      `in ${formatBytes(summary.bytes_in)} · 5xx ${fmt(summary.http_5xx)}`
    )
  );
}

function renderLiveRuntime(info) {
  const container = $("#live-runtime");
  if (!container) return;
  clear(container);
  const valueOrDash = (value) => (value === null || value === undefined || value === "-" ? "—" : value);
  const entries = [
    ["Version", valueOrDash(info.version)],
    ["Release date", valueOrDash(info.release_date)],
    ["Uptime", valueOrDash(info.uptime)],
    ["Processes / threads", `${fmt(info.processes)} / ${fmt(info.threads)}`],
    ["Current / max connections", `${fmt(info.current_connections)} / ${fmt(info.max_connections)}`],
    ["Connection rate", `${fmt(info.connection_rate)}/s`],
    ["Cumulative connections", fmt(info.cumulative_connections)],
    ["SSL current / rate", `${fmt(info.current_ssl_connections)} / ${fmt(info.ssl_connection_rate)}/s`],
    ["Tasks / run queue", `${fmt(info.tasks)} / ${fmt(info.run_queue)}`],
    ["Idle", info.idle_percent === null || info.idle_percent === undefined ? "—" : `${info.idle_percent}%`],
    ["Memory pool", `${fmt(info.pool_used_mb)} MB used / ${fmt(info.pool_allocated_mb)} MB allocated`],
    ["Dropped logs / failed resolutions", `${fmt(info.dropped_logs)} / ${fmt(info.failed_resolutions)}`],
  ];
  for (const [label, value] of entries) {
    container.append(
      el("div", {
        className: "live-kv",
        children: [el("span", { text: label }), el("b", { text: String(value) })],
      })
    );
  }
}

function liveEmptyRow(body, colspan, text) {
  body.append(
    el("tr", {
      children: [el("td", { className: "muted", attrs: { colspan: String(colspan) }, text })],
    })
  );
}

function renderLiveRows(payload) {
  const frontends = payload.frontends || [];
  const backends = payload.backends || [];
  const servers = payload.servers || [];

  const frontendBody = $("#live-frontends");
  if (frontendBody) {
    clear(frontendBody);
    if (!frontends.length) liveEmptyRow(frontendBody, 8, "No frontend rows returned.");
    for (const row of frontends) {
      frontendBody.append(
        el("tr", {
          children: [
            el("td", { className: "mono", text: row.name }),
            el("td", { children: [liveBadge(row.status)] }),
            el("td", { className: "number-cell", text: fmt(row.current_sessions) }),
            el("td", { className: "number-cell", text: fmt(row.session_limit) }),
            el("td", { className: "number-cell", text: fmt(row.session_rate) }),
            el("td", { className: "number-cell", text: fmt(row.requests_total) }),
            el("td", { className: "number-cell", text: `${fmt(row.http_4xx)} / ${fmt(row.http_5xx)}` }),
            el("td", {
              className: "number-cell",
              text: `${formatBytes(row.bytes_in)} / ${formatBytes(row.bytes_out)}`,
            }),
          ],
        })
      );
    }
  }

  const backendBody = $("#live-backends");
  if (backendBody) {
    clear(backendBody);
    if (!backends.length) liveEmptyRow(backendBody, 7, "No backend rows returned.");
    for (const row of backends) {
      backendBody.append(
        el("tr", {
          children: [
            el("td", { className: "mono", text: row.name }),
            el("td", { children: [liveBadge(row.status)] }),
            el("td", { className: "number-cell", text: fmt(row.current_sessions) }),
            el("td", { className: "number-cell", text: fmt(row.session_rate) }),
            el("td", { className: "number-cell", text: fmt(row.requests_total) }),
            el("td", { className: "number-cell", text: `${fmt(row.http_4xx)} / ${fmt(row.http_5xx)}` }),
            el("td", {
              className: "number-cell",
              text: `${formatBytes(row.bytes_in)} / ${formatBytes(row.bytes_out)}`,
            }),
          ],
        })
      );
    }
  }

  const serverBody = $("#live-servers");
  if (serverBody) {
    clear(serverBody);
    if (!servers.length) liveEmptyRow(serverBody, 8, "No server rows returned.");
    for (const row of servers) {
      let check = row.check_status && row.check_status !== "-" ? row.check_status : "—";
      if (row.check_health !== null && row.check_health !== undefined) {
        check = `${check} · ${fmt(row.check_health)}`;
      }
      serverBody.append(
        el("tr", {
          children: [
            el("td", {
              children: [
                el("span", { className: "mono", text: row.backend }),
                el("span", { className: "muted", text: " / " }),
                el("span", { className: "mono", text: row.name }),
              ],
            }),
            el("td", { children: [liveBadge(row.status)] }),
            el("td", { className: "mono", text: check }),
            el("td", { className: "number-cell", text: fmt(row.current_sessions) }),
            el("td", { className: "number-cell", text: fmt(row.session_rate) }),
            el("td", { className: "number-cell", text: fmt(row.http_5xx) }),
            el("td", {
              className: "number-cell",
              text: `${formatBytes(row.bytes_in)} / ${formatBytes(row.bytes_out)}`,
            }),
            el("td", { className: "number-cell", text: formatSeconds(row.last_change_seconds) }),
          ],
        })
      );
    }
  }
}

function renderLive() {
  const payload = state.live;
  const nav = $("#nav-live-status");
  const pill = $("#live-pill");
  const note = $("#live-status-note");
  const empty = $("#live-empty");
  const emptyBody = $("#live-empty-body");
  const content = $("#live-content");
  if (!payload || !payload.meta) {
    if (nav) nav.textContent = "…";
    if (pill) pill.textContent = "Live —";
    show(note, false);
    show(content, false);
    show(empty, true);
    if (emptyBody) {
      clear(emptyBody);
      emptyBody.append(emptyState("Loading live stats…", "Waiting for the first runtime response."));
    }
    return;
  }

  const meta = payload.meta;
  if (!meta.enabled) {
    if (nav) nav.textContent = "off";
    if (pill) pill.textContent = "Disabled";
    show(note, false);
    show(content, false);
    show(empty, true);
    if (emptyBody) {
      clear(emptyBody);
      emptyBody.append(
        emptyState(
          "Live stats are not configured",
          "Set HAPROXY_STATS_SOCKET to the read-only HAProxy stats socket host:port, then restart the container."
        )
      );
    }
    return;
  }

  show(empty, false);
  show(content, true);
  if (nav) nav.textContent = meta.connected ? "live" : "offline";
  if (pill) pill.textContent = `Live · ${fmt(meta.refresh_seconds || 5)}s`;
  if (!meta.connected) {
    if (note) {
      note.className = "live-note warn";
      note.textContent = meta.last_error
        ? `Live stats disconnected: ${meta.last_error}`
        : "Waiting for the first live stats poll.";
    }
    show(note, true);
  } else {
    show(note, false);
  }
  renderLiveSummary(payload);
  renderLiveRuntime(payload.info || {});
  renderLiveRows(payload);
}

async function refreshLive(silent = false) {
  try {
    state.live = await fetchJSON("/api/live");
    renderLive();
  } catch (error) {
    if (state.live && state.live.meta) {
      state.live = {
        ...state.live,
        meta: {
          ...state.live.meta,
          connected: false,
          last_error: error.message,
        },
      };
      renderLive();
    }
    if (!silent) showAlert(`Could not load live stats: ${error.message}`);
  }
}

function scheduleLiveRefresh() {
  if (state.liveTimer) {
    clearTimeout(state.liveTimer);
    state.liveTimer = null;
  }
  const meta = state.live && state.live.meta ? state.live.meta : null;
  if (!meta || !meta.enabled) return;
  if (state.view !== "live" || document.visibilityState === "hidden") return;
  const seconds = Math.max(2, Number(meta.refresh_seconds) || 5);
  state.liveTimer = setTimeout(async () => {
    if (state.view === "live" && document.visibilityState === "visible") {
      await refreshLive(true);
    }
    scheduleLiveRefresh();
  }, seconds * 1000);
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
  renderBarList(
    $("#http-status-classes"),
    (http.status_classes || []).filter((item) => item.count > 0),
    "green",
    "No status-class data"
  );
  renderBarList($("#http-protocols"), http.protocols, "blue", "No protocol data");
  renderBarList(
    $("#http-hourly"),
    (http.hourly || []).filter((item) => item.count > 0),
    "violet",
    "No hourly data"
  );
  renderHttpIps();
  renderHttpLatestRequests();
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
            el("td", { className: "number-cell", text: fmt(path.visitors || 0) }),
            el("td", { className: "number-cell", text: formatBytes(path.bytes || 0) }),
          ],
        })
      );
    }
  }
}

function statusBadgeClass(status) {
  const code = String(status || "");
  if (code.startsWith("2")) return "ok";
  if (code.startsWith("3")) return "info";
  if (code.startsWith("4")) return "warn";
  if (code.startsWith("5")) return "err";
  return "info";
}

function viewRequestsFor(ip) {
  showView("requests");
  const search = $("#request-search");
  if (search) search.value = ip;
  renderRequests();
}

function renderHttpLatestRequests() {
  if (!state.snapshot) return;
  const tbody = $("#http-latest-requests");
  if (!tbody) return;
  const rows = (state.snapshot.http.recent || []).slice(0, 25);
  clear(tbody);
  if (!rows.length) {
    tbody.append(
      el("tr", {
        children: [
          el("td", {
            className: "muted",
            attrs: { colspan: "8" },
            text: "No HTTP requests are available yet.",
          }),
        ],
      })
    );
    return;
  }
  for (const item of rows) {
    const requestCell = el("td", {
      className: "wrap-cell",
      text: item.path,
      attrs: { title: item.path },
    });
    if (item.count > 1) {
      requestCell.append(el("span", { className: "badge info", text: ` ×${fmt(item.count)}` }));
    }
    tbody.append(
      el("tr", {
        children: [
          el("td", { className: "mono", text: item.time }),
          el("td", {
            className: "mono",
            text: item.port && item.port !== "-" ? `${item.ip}:${item.port}` : item.ip,
          }),
          el("td", { className: "mono", text: item.method }),
          el("td", { children: [el("span", { className: `badge ${statusBadgeClass(item.status)}`, text: item.status })] }),
          requestCell,
          el("td", { className: "number-cell", text: fmt(item.bytes * (item.count || 1)) }),
          el("td", { text: item.server && item.server !== "-" ? `${item.backend}/${item.server}` : item.backend }),
          el("td", { text: item.protocol }),
        ],
      })
    );
  }
}

function renderHttpIps() {
  if (!state.snapshot) return;
  const http = state.snapshot.http || {};
  const rows = http.ip_details || [];
  const tbody = $("#http-ip-rows");
  if (!tbody) return;
  const search = state.httpIpFilter.trim().toLowerCase();
  clear(tbody);
  let shown = 0;
  for (const row of rows) {
    const haystack = [
      row.ip,
      row.country,
      row.city,
      row.asn,
      ...(row.methods || []).map((item) => item.name),
      ...(row.top_paths || []).map((item) => item.name),
      ...(row.backends || []).map((item) => item.name),
    ]
      .join(" ")
      .toLowerCase();
    if (search && !haystack.includes(search)) continue;
    shown += 1;
    const location = [row.city, row.country].filter((part) => part && part !== "-").join(", ") || "Unknown";
    let statusText = `2xx ${fmt(row.status_2xx)} · 3xx ${fmt(row.status_3xx)} · 4xx ${fmt(row.status_4xx)} · 5xx ${fmt(row.status_5xx)}`;
    if (row.status_other) statusText += ` · other ${fmt(row.status_other)}`;
    const methods = (row.methods || []).map((item) => `${item.name} ${fmt(item.count)}`).join(" · ") || "-";
    const paths = (row.top_paths || []).map((item) => `${item.name} (${fmt(item.count)})`).join(" · ") || "-";
    const backends = (row.backends || []).map((item) => `${item.name} (${fmt(item.count)})`).join(" · ") || "-";
    const view = el("button", { className: "link-button", text: "View requests", attrs: { type: "button" } });
    view.addEventListener("click", () => viewRequestsFor(row.ip));
    tbody.append(
      el("tr", {
        children: [
          el("td", { className: "mono", text: row.ip }),
          el("td", { text: location }),
          el("td", { text: row.asn }),
          el("td", { className: "number-cell", text: fmt(row.requests) }),
          el("td", { className: "number-cell", text: formatBytes(row.bytes) }),
          el("td", { className: "number-cell", text: fmt(row.errors) }),
          el("td", { className: "wrap-cell", text: statusText }),
          el("td", { className: "wrap-cell", text: methods }),
          el("td", { className: "wrap-cell", text: paths, attrs: { title: paths } }),
          el("td", { className: "wrap-cell", text: backends, attrs: { title: backends } }),
          el("td", { className: "mono", text: row.first_seen }),
          el("td", { className: "mono", text: row.last_seen }),
          el("td", { children: [view] }),
        ],
      })
    );
  }
  if (!shown) {
    tbody.append(
      el("tr", {
        children: [
          el("td", {
            className: "muted",
            attrs: { colspan: "13" },
            text: search ? "No IPs match the filter." : "No HTTP IP details are available yet.",
          }),
        ],
      })
    );
  }
  const count = $("#http-ip-count");
  if (count) count.textContent = `${fmt(shown)} of ${fmt(rows.length)} IPs`;
  const privacy = state.snapshot.meta.privacy || {};
  const masked =
    privacy.mask_internal_ips ||
    (Array.isArray(privacy.mask_networks) && privacy.mask_networks.length > 0);
  const badge = $("#http-ip-mask-badge");
  if (badge) badge.classList.toggle("hidden", !masked);
  const note = $("#http-ip-note");
  if (note) {
    note.textContent = masked
      ? "Masked clients are grouped by their displayed address. To distinguish private IPs, set MASK_INTERNAL_IPS=false, MASK_NETWORKS= and MASK_FULL=false, then restart."
      : "Showing raw client addresses. Keep the dashboard behind the authenticated HAProxy frontend.";
  }
}

function renderRequests() {
  if (!state.snapshot) return;
  const http = state.snapshot.http || {};
  const rows = http.recent || [];
  const tbody = $("#request-rows");
  if (!tbody) return;
  const requestSearch = $("#request-search");
  const search = (requestSearch ? requestSearch.value : "").trim().toLowerCase();
  clear(tbody);
  let shown = 0;
  for (const item of rows) {
    const haystack = [
      item.time,
      item.ip,
      item.country,
      item.city,
      item.method,
      item.path,
      item.status,
      item.frontend,
      item.backend,
      item.protocol,
    ]
      .join(" ")
      .toLowerCase();
    if (search && !haystack.includes(search)) continue;
    shown += 1;
    const location = [item.city, item.country].filter((part) => part && part !== "-").join(", ") || "Unknown";
    const requestCell = el("td", {
      className: "wrap-cell",
      text: item.path,
      attrs: { title: item.path },
    });
    if (item.count > 1) {
      requestCell.append(el("span", { className: "badge info", text: ` ×${fmt(item.count)}` }));
    }
    tbody.append(
      el("tr", {
        children: [
          el("td", { className: "mono", text: item.time }),
          el("td", {
            className: "mono",
            text: item.port && item.port !== "-" ? `${item.ip}:${item.port}` : item.ip,
          }),
          el("td", { text: location }),
          el("td", { className: "mono", text: item.method }),
          el("td", { children: [el("span", { className: `badge ${statusBadgeClass(item.status)}`, text: item.status })] }),
          requestCell,
          el("td", { className: "number-cell", text: fmt(item.bytes * (item.count || 1)) }),
          el("td", { text: item.frontend }),
          el("td", { text: item.server && item.server !== "-" ? `${item.backend}/${item.server}` : item.backend }),
          el("td", { text: item.protocol }),
        ],
      })
    );
  }
  if (!shown) {
    tbody.append(
      el("tr", {
        children: [
          el("td", {
            className: "muted",
            attrs: { colspan: "10" },
            text: search ? "No requests match the filter." : "No HTTP requests are available yet.",
          }),
        ],
      })
    );
  }
  const count = $("#request-count");
  if (count) count.textContent = `${fmt(shown)} of ${fmt(rows.length)} rows`;
  const pill = $("#requests-pill");
  if (pill) pill.textContent = `${fmt(shown)} rows`;
  const note = $("#requests-note");
  if (note) {
    note.textContent = `Newest first · up to ${fmt(http.recent_limit || rows.length)} rows · ${fmt(http.total || 0)} HTTP requests in the parsed window`;
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

function renderDomainFilter() {
  const node = $("#domain-filter-status");
  if (!node || !state.snapshot) return;
  const privacy = (state.snapshot.meta && state.snapshot.meta.privacy) || {};
  const domains = Number(privacy.excluded_domains) || 0;
  const domainOnly = Number(privacy.domain_only_domains) || 0;
  const events = Number(privacy.excluded_events) || 0;
  const redacted = Number(privacy.redacted_paths) || 0;
  if (!domains && !domainOnly) {
    node.textContent = "No domain filtering is active. Set EXCLUDED_DOMAINS to drop domains entirely or DOMAIN_ONLY_DOMAINS to keep domain-level statistics with the URI removed.";
    return;
  }
  const parts = [];
  if (domains) parts.push(`${fmt(domains)} domain(s) excluded entirely.`);
  if (domainOnly) {
    parts.push(
      `${fmt(domainOnly)} domain(s) kept at domain-only granularity; ${fmt(redacted)} request path(s) redacted.`
    );
  }
  parts.push(`${fmt(events)} event(s) skipped in this snapshot.`);
  parts.push(
    "HTTP matching uses a captured Host header or an absolute URL. Raw log lines and the persistent syslog store are not redacted."
  );
  node.textContent = parts.join(" ");
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
  renderRequests();
  renderYouBanners();
  renderServerCard();
  renderWarnings();
  renderDomainFilter();
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
  if (view === "live") {
    renderLive();
    refreshLive(true).finally(scheduleLiveRefresh);
  } else if (state.liveTimer) {
    clearTimeout(state.liveTimer);
    state.liveTimer = null;
  }
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
  const requestSearch = $("#request-search");
  if (requestSearch) {
    requestSearch.addEventListener("input", () => renderRequests());
  }
  const httpIpSearch = $("#http-ip-search");
  if (httpIpSearch) {
    httpIpSearch.addEventListener("input", () => {
      state.httpIpFilter = httpIpSearch.value;
      renderHttpIps();
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
    const [snapshot, version, live] = await Promise.all([
      fetchJSON("/api/snapshot"),
      fetchJSON("/version.json").catch(() => null),
      fetchJSON("/api/live").catch(() => null),
    ]);
    state.snapshot = snapshot;
    state.version = version;
    state.live = live;
    renderAll();
    renderLive();
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
      if (state.view === "live") {
        await refreshLive(false);
        scheduleLiveRefresh();
      }
      button.disabled = false;
      button.textContent = "Refresh";
    });
  }
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      refreshSnapshot(true);
      if (state.view === "live") refreshLive(true).finally(scheduleLiveRefresh);
    } else if (state.liveTimer) {
      clearTimeout(state.liveTimer);
      state.liveTimer = null;
    }
  });
}

setupTheme();
setupNavigation();
setupFilters();
setupFindMe();
setupRefresh();
setupClearSyslog();
initialLoad();
