const qs = (selector, root = document) => root.querySelector(selector);
const qsa = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const routes = [
  { id: "overview", path: "/", title: "Overview", subtitle: "Real-time operations across your OriginPulse estate.", icon: "fa-grid-2" },
  { id: "sites", path: "/sites", title: "Projects / Sites", subtitle: "Monitor and manage project health across environments.", icon: "fa-diagram-project" },
  { id: "logs", path: "/logs", title: "Live Logs", subtitle: "Recent evidence, source IPs, paths, and status pressure.", icon: "fa-rectangle-list" },
  { id: "search", path: "/search", title: "Advanced Log Search", subtitle: "Facet access events by status, host, path, and source.", icon: "fa-magnifying-glass" },
  { id: "traffic", path: "/traffic", title: "Traffic", subtitle: "Request volume, status mix, and top paths by range.", icon: "fa-chart-line" },
  { id: "errors", path: "/errors", title: "Errors", subtitle: "4xx, 5xx, and reliability hot spots.", icon: "fa-circle-exclamation", badge: true },
  { id: "php", path: "/php", title: "PHP", subtitle: "PHP-facing signals and slow application requests.", icon: "fa-brands fa-php" },
  { id: "mysql", path: "/mysql", title: "MySQL", subtitle: "Database-adjacent issues and slow query indicators.", icon: "fa-database" },
  { id: "slow", path: "/slow", title: "Slow Queries", subtitle: "Slow paths, high p95 latency, and lagging responses.", icon: "fa-stopwatch" },
  { id: "security", path: "/security", title: "Security", subtitle: "Suspicious actors, probes, Tor sources, and verified services.", icon: "fa-shield-halved" },
  { id: "bots", path: "/bots", title: "Bot / Crawler Analysis", subtitle: "Verified services, suspicious crawlers, and scripted clients.", icon: "fa-robot" },
  { id: "reports", path: "/reports", title: "Reports", subtitle: "Recent generated summaries and operational narratives.", icon: "fa-file-lines" },
  { id: "alerts", path: "/alerts", title: "Alert Center", subtitle: "Detect, triage, and respond to active issues.", icon: "fa-bell" },
  { id: "pulse", path: "/pulse-logs", title: "Pulse Logs", subtitle: "Collector jobs, indexed segments, raw files, and delivery history.", icon: "fa-wave-pulse" },
  { id: "settings", path: "/settings", title: "Settings", subtitle: "User, notification, collection, and system status.", icon: "fa-gear" },
];

const routeById = Object.fromEntries(routes.map((route) => [route.id, route]));
const pathToRoute = Object.fromEntries(routes.map((route) => [route.path, route.id]));
const reportCatalogLimit = 500;
const pulseHistoryLimit = 500;
const alertHistoryLimit = 500;
const drawerHistoryLimit = 500;
const analysisHistoryLimit = 500;

const state = {
  route: pathToRoute[location.pathname] || "overview",
  range: new URLSearchParams(location.search).get("range") || "24h",
  siteID: new URLSearchParams(location.search).get("site_id") || "",
  search: "",
  reportType: "all",
  currentUser: null,
  loading: false,
  securityAnalysisLoading: false,
  securityAnalysisKey: "",
  localReports: [],
  detailCache: {},
  pages: {
    trafficPaths: 1,
    trafficIPs: 1,
    searchTopPaths: 1,
    searchMatchedEvents: 1,
    logRecentEvidence: 1,
    logTopPaths: 1,
    logSourceIPs: 1,
    logUserAgents: 1,
    pulseArchives: 1,
    pulseArchiveImports: 1,
  },
  drawer: {
    kind: null,
    title: "",
    data: null,
    summary: null,
    pages: {},
  },
  data: {
    overview: {},
    analysis: {},
    estateAnalysis: {},
    traffic: {},
    estateTraffic: {},
    sites: [],
    alerts: [],
    reports: [],
    jobs: [],
    credentials: {},
    collectorHealth: {},
    retention: {},
    storage: {},
    archives: [],
    archiveImports: [],
    notifications: {},
    webPush: {},
    users: [],
    segments: [],
  },
  fetchErrors: [],
};

class AuthError extends Error {}

async function fetchJSON(path, options = {}) {
  const { timeoutMs = 0, ...fetchOptions } = options;
  const controller = timeoutMs ? new AbortController() : null;
  const timeout = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(fetchOptions.headers || {}) },
    ...fetchOptions,
    ...(controller ? { signal: controller.signal } : {}),
  });
  if (timeout) clearTimeout(timeout);
  if (response.status === 401) throw new AuthError();
  if (!response.ok) {
    const detail = await response.json().catch(() => null);
    throw new Error(detail?.error?.message || `${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function safeFetch(path, fallback, timeoutMs = 30000) {
  try {
    return await fetchJSON(path, { timeoutMs });
  } catch (error) {
    if (error instanceof AuthError) throw error;
    console.warn(path, error);
    state.fetchErrors.push({ path, message: error.message || "Request failed" });
    return fallback;
  }
}

async function boot() {
  renderNav();
  wireEvents();
  try {
    const session = await fetchJSON("/api/v1/auth/me");
    state.currentUser = session.user || null;
    showApp();
    await refreshAll();
  } catch (error) {
    if (error instanceof AuthError) {
      showLogin();
      return;
    }
    showApp();
    toast(error.message, true);
    render();
  }
}

function wireEvents() {
  document.addEventListener("click", async (event) => {
    const nav = event.target.closest("[data-route]");
    if (nav) {
      event.preventDefault();
      showRoute(nav.dataset.route, true);
      return;
    }
    const action = event.target.closest("[data-action]");
    if (action) {
      if (action.id === "modalBackdrop" && event.target !== action) return;
      await handleAction(action);
      return;
    }
    const detail = event.target.closest("[data-detail]");
    if (detail) {
      await openDrawer(detail.dataset.detail, detail.dataset.index, detail.dataset.value);
    }
  });

  window.addEventListener("popstate", () => {
    state.route = pathToRoute[location.pathname] || "overview";
    const params = new URLSearchParams(location.search);
    state.range = params.get("range") || state.range;
    state.siteID = params.get("site_id") || "";
    render();
    void ensureRouteData();
  });

  qs("#rangeSelect").addEventListener("change", async (event) => {
    state.range = event.target.value;
    resetPagination();
    updateURL(false);
    await refreshAll();
  });
  qs("#siteSelect").addEventListener("change", async (event) => {
    state.siteID = event.target.value;
    resetPagination();
    updateURL(false);
    await refreshAll();
  });
  qs("#searchInput").addEventListener("input", (event) => {
    state.search = event.target.value.trim().toLowerCase();
    resetPagination();
    render();
  });
  document.addEventListener("change", (event) => {
    const reportType = event.target.closest("[data-report-type-filter]");
    if (reportType) {
      state.reportType = reportType.value || "all";
      state.pages.reportCatalog = 1;
      render();
    }
  });
  qs("#refreshButton").addEventListener("click", () => refreshAll());
  qs("#collectButton").addEventListener("click", () => runButton(qs("#collectButton"), "Collection queued", async () => {
    await fetchJSON("/api/v1/system/collect", { method: "POST" });
  }));
  qs("#pipelineButton").addEventListener("click", () => runButton(qs("#pipelineButton"), "Pipeline complete", async () => {
    await fetchJSON("/api/v1/system/pipeline", { method: "POST", body: "{}" });
  }));
  qs("#logoutButton").addEventListener("click", logout);
  qs("#loginForm").addEventListener("submit", login);
  qs("#drawerClose").addEventListener("click", closeDrawer);
  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeModal();
  });
  window.addEventListener("resize", drawCharts);
}

async function refreshAll() {
  if (state.loading) return;
  state.loading = true;
  state.fetchErrors = [];
  document.body.classList.add("busy");
  try {
    const filter = buildFilterQuery();
    const analysisFilter = buildFilterQuery({ limit: analysisHistoryLimit });
    const estateAnalysisFilter = buildFilterQuery({ limit: analysisHistoryLimit }, { includeSite: false });
    const estateTrafficFilter = buildFilterQuery({ limit: analysisHistoryLimit }, { includeSite: false });
    const analysisRequest = safeFetch(`/api/v1/analysis/access-log?${analysisFilter}`, {}, 30000);
    const estateAnalysisRequest = analysisFilter === estateAnalysisFilter
      ? analysisRequest
      : safeFetch(`/api/v1/analysis/access-log?${estateAnalysisFilter}`, {}, 30000);
    const [overview, analysis, estateAnalysis, traffic, estateTraffic, sites, alerts, reports, jobs, credentials, collectorHealth, retention, storage, archives, archiveImports, archiveCoverage, notifications, webPush, users, segments] = await Promise.all([
      safeFetch(`/api/v1/dashboard/overview?${filter}`, {}),
      analysisRequest,
      estateAnalysisRequest,
      safeFetch(`/api/v1/investigate/traffic?${buildFilterQuery({ limit: analysisHistoryLimit })}`, {}),
      safeFetch(`/api/v1/investigate/traffic?${estateTrafficFilter}`, {}),
      safeFetch("/api/v1/sites", { sites: [] }),
      safeFetch(`/api/v1/alerts?limit=${alertHistoryLimit}`, { alerts: [] }),
      safeFetch(`/api/v1/reports/recent?${buildFilterQuery({ limit: reportCatalogLimit })}`, { reports: [] }),
      safeFetch(`/api/v1/system/jobs?limit=${pulseHistoryLimit}`, { jobs: [] }),
      safeFetch("/api/v1/system/credentials", {}),
      safeFetch(`/api/v1/system/collector-health?limit=${pulseHistoryLimit}`, {}),
      safeFetch("/api/v1/system/retention", {}),
      safeFetch("/api/v1/system/storage", {}),
      safeFetch(`/api/v1/system/archives?limit=${pulseHistoryLimit}`, { archives: [] }),
      safeFetch(`/api/v1/system/archive-imports?limit=${pulseHistoryLimit}`, { imports: [] }),
      safeFetch(`/api/v1/system/archive-coverage?${filter}`, { archives: [], active_temporary_imports: [] }),
      safeFetch(`/api/v1/notifications?limit=${pulseHistoryLimit}`, {}),
      safeFetch("/api/v1/notifications/web-push/public-key", {}),
      safeFetch("/api/v1/users", { users: [] }),
      safeFetch(`/api/v1/system/segments?limit=${pulseHistoryLimit}`, { segments: [] }),
    ]);
    state.data = {
      overview,
      analysis,
      estateAnalysis,
      traffic,
      estateTraffic,
      sites: sites.sites || [],
      alerts: alerts.alerts || [],
      reports: reports.reports || [],
      jobs: jobs.jobs || [],
      credentials,
      collectorHealth,
      retention,
      storage,
      archives: archives.archives || [],
      archiveImports: archiveImports.imports || [],
      archiveCoverage,
      notifications,
      webPush,
      users: users.users || [],
      segments: segments.segments || [],
    };
    render();
    void ensureRouteData();
  } catch (error) {
    if (error instanceof AuthError) {
      showLogin();
      return;
    }
    toast(error.message, true);
  } finally {
    state.loading = false;
    document.body.classList.remove("busy");
  }
}

async function ensureRouteData() {
  if (state.route === "security" || state.route === "mysql") {
    await refreshSecurityAnalysis(state.route);
  }
}

async function refreshSecurityAnalysis(route = state.route) {
  const key = route === "mysql"
    ? buildFilterQuery({ limit: analysisHistoryLimit, include_injection: "1", security_only: "1", probe_category: "sql_injection" })
    : buildFilterQuery({ limit: analysisHistoryLimit, include_security: "1", security_only: "1" });
  if (state.securityAnalysisKey === key || state.securityAnalysisLoading) return;
  state.securityAnalysisLoading = true;
  render();
  try {
    const analysis = await fetchJSON(`/api/v1/analysis/access-log?${key}`, { timeoutMs: 120000 });
    const latestKey = route === "mysql"
      ? buildFilterQuery({ limit: analysisHistoryLimit, include_injection: "1", security_only: "1", probe_category: "sql_injection" })
      : buildFilterQuery({ limit: analysisHistoryLimit, include_security: "1", security_only: "1" });
    if (key === latestKey) {
      state.data.analysis = mergeSecurityAnalysis(state.data.analysis || {}, analysis || {});
      state.securityAnalysisKey = key;
    }
  } catch (error) {
    if (error instanceof AuthError) {
      showLogin();
      return;
    }
    toast(`Security analysis failed: ${error.message}`, true);
  } finally {
    state.securityAnalysisLoading = false;
    render();
  }
}

function mergeSecurityAnalysis(base, security) {
  return {
    ...base,
    admin_probes: security.admin_probes || base.admin_probes || [],
    injection_probes: security.injection_probes || base.injection_probes || [],
    tor_sources: security.tor_sources || base.tor_sources || [],
    issues: mergeIssues(base.issues || [], security.issues || []),
  };
}

function mergeIssues(base, extra) {
  return uniqueBy([...base, ...extra], (item) => [
    item.rule_key,
    item.site_id,
    item.env,
    item.actor_type,
    item.actor_value,
    item.first_seen,
    item.last_seen,
  ].join("|"));
}

function render() {
  renderNav();
  renderChrome();
  const renderers = {
    overview: renderOverview,
    sites: renderSites,
    logs: renderLogs,
    search: renderSearch,
    traffic: renderTraffic,
    errors: () => renderIssueWorkspace("errors"),
    php: renderPHP,
    mysql: renderMySQL,
    slow: renderSlow,
    security: renderSecurity,
    bots: renderBots,
    reports: renderReports,
    alerts: renderAlerts,
    pulse: renderPulseLogs,
    settings: renderSettings,
  };
  qs("#content").innerHTML = readinessBanner() + (renderers[state.route] || renderOverview)();
  requestAnimationFrame(drawCharts);
}

function renderNav() {
  const alertCount = openProblemCount();
  qs("#primaryNav").innerHTML = routes.map((route) => `
    <a href="${route.path}" class="nav-item ${state.route === route.id ? "active" : ""}" data-route="${route.id}">
      <span class="nav-icon">${iconHTML(route.icon)}</span>
      <span>${escapeHTML(route.title)}</span>
      ${route.badge && alertCount ? `<b class="nav-badge danger">${alertCount}</b>` : ""}
    </a>
  `).join("");
}

function renderChrome() {
  const route = routeById[state.route] || routeById.overview;
  qs("#pageTitle").textContent = route.title;
  qs("#pageSubtitle").textContent = route.subtitle;
  qs("#rangeSelect").value = state.range;
  syncSiteSelect();
  qs("#logoutButton").classList.toggle("hidden", !state.currentUser);
  const initials = state.currentUser?.display_name || state.currentUser?.email || "OP";
  qs("#userBadge").textContent = initials.split(/\s|@/).filter(Boolean).slice(0, 2).map((part) => part[0]).join("").toUpperCase() || "OP";
  const health = collectorHealth();
  qs("#collectorState").textContent = health.state;
  qs("#collectorUptime").textContent = health.uptime;
  qs("#collectorRate").textContent = `${formatNumber(Math.round(requestsPerMinute()))}/m`;
  qs("#pageActions").innerHTML = pageActions();
}

function syncSiteSelect() {
  const select = qs("#siteSelect");
  const known = new Set(state.data.sites.map((site) => site.id));
  select.innerHTML = [`<option value="">All Projects</option>`].concat(
    state.data.sites.map((site) => `<option value="${escapeAttr(site.id)}">${escapeHTML(site.name || site.id)}</option>`)
  ).join("");
  if (state.siteID && !known.has(state.siteID)) {
    select.insertAdjacentHTML("beforeend", `<option value="${escapeAttr(state.siteID)}">${escapeHTML(state.siteID)}</option>`);
  }
  select.value = state.siteID;
}

function pageActions() {
  if (state.route === "alerts") {
    return `
      <button class="button outline" type="button" data-action="evaluate-alerts">${iconHTML("fa-wave-pulse")}Evaluate Alerts</button>
      <button class="button primary" type="button" data-action="send-notifications">${iconHTML("fa-paper-plane")}Notify</button>
    `;
  }
  if (state.route === "security" || state.route === "logs") {
    return `<button class="button outline" type="button" data-action="refresh-ip-intel">${iconHTML("fa-location-crosshairs")}Refresh IP Intel</button>`;
  }
  if (state.route === "reports") {
    return `<button class="button primary" type="button" data-action="generate-report">${iconHTML("fa-file-circle-plus")}Generate ${escapeHTML(state.range)} Report</button>`;
  }
  if (state.route === "pulse") {
    return `
      <button class="button outline" type="button" data-action="refresh">${iconHTML("fa-rotate-right")}Refresh</button>
      <button class="button primary" type="button" data-action="run-pipeline">${iconHTML("fa-code-merge")}Run Pipeline</button>
    `;
  }
  return `<button class="button outline" type="button" data-action="refresh">${iconHTML("fa-rotate-right")}Refresh</button>`;
}

function renderOverview() {
  const a = state.data.analysis || {};
  const totals = a.totals || {};
  const overview = state.data.overview.analytics || {};
  const issues = filtered(searchItems(a.issues || [], issueSearchText));
  const issuePage = paginate(issues, state.pages.overviewSignals, 6);
  state.pages.overviewSignals = issuePage.page;
  const sites = siteRows().slice(0, 7);
  return `
    ${metricGrid([
      metric("Requests", overview.requests || totals.requests, "fa-arrow-trend-up", "green"),
      metric("Unique IPs", overview.unique_ips || totals.unique_ips, "fa-network-wired", "cyan"),
      metric("4xx Rate", formatPercent(overview.status_4xx_rate || totals.status_4xx_rate), "fa-triangle-exclamation", "amber"),
      metric("5xx Rate", formatPercent(overview.status_5xx_rate || totals.status_5xx_rate), "fa-bolt", "red"),
      metric("Active Alerts", state.data.alerts.length, "fa-bell", "red"),
      metric("Sites", state.data.sites.length || state.data.overview.sites_enabled, "fa-diagram-project", "purple"),
    ])}
    <section class="overview-second-row">
      ${systemPanel()}
      <article class="panel chart-card">
        <div class="panel-head">
          <div><h2>Traffic Volume</h2><p>${escapeHTML(activeRangeLabel())}</p></div>
          <strong>${formatNumber(overview.requests || totals.requests || 0)}</strong>
        </div>
        <canvas id="trafficLine" class="large-chart"></canvas>
      </article>
      <article class="panel">
        <div class="panel-head">
          <div><h2>Projects / Sites Overview</h2><p>Health sorted by current activity.</p></div>
          <button class="button small" type="button" data-action-route="sites" data-route="sites">${iconHTML("fa-arrow-up-right-from-square")}Open Sites</button>
        </div>
        ${overviewSitesTable(sites)}
      </article>
    </section>
    <section class="overview-third-row">
      <article class="panel">
        <div class="panel-head">
          <div><h2>Priority Signals</h2><p>Ranked findings from the selected range.</p></div>
          <span class="pill">${formatNumber(issues.length)} signals</span>
        </div>
        <div class="list">${issuePage.rows.length ? issuePage.rows.map(issueRow).join("") : empty("No active signals in this range.")}</div>
        ${pager("overviewSignals", issuePage)}
      </article>
      ${recentIncidentsPaginatedPanel()}
      ${overviewTopPathsPaginatedPanel()}
    </section>
  `;
}

function renderSites() {
  const rows = siteRows({ estate: true });
  return `
    ${metricGrid([
      metric("Total Projects", state.data.sites.length || state.data.overview.sites_enabled, "fa-diagram-project", "cyan"),
      metric("Healthy Sites", rows.filter((site) => site.health === "healthy").length, "fa-circle-check", "green"),
      metric("Warning Sites", rows.filter((site) => site.health === "warning").length, "fa-triangle-exclamation", "amber"),
      metric("Critical Sites", rows.filter((site) => site.health === "critical").length, "fa-circle-exclamation", "red"),
      metric("Requests", state.data.analysis?.totals?.requests, "fa-arrow-trend-up", "purple"),
      metric("Alerts", state.data.alerts.length, "fa-bell", "red"),
    ])}
    <article class="panel">
      <div class="panel-head">
        <div><h2>Projects / Sites</h2><p>Operational health and traffic across configured projects.</p></div>
        <span class="pill">Table View</span>
      </div>
      ${sitesTable(rows)}
    </article>
  `;
}

function renderLogs() {
  const recent = filtered(searchItems(state.data.traffic.recent_errors || [], (item) => `${item.site_id} ${item.client_ip} ${item.path} ${item.user_agent}`));
  return `
    ${metricGrid([
      metric("Events Parsed", state.data.analysis?.totals?.requests, "fa-code-merge", "cyan"),
      metric("Unparsed Lines", 0, "fa-file-circle-question", "amber"),
      metric("Parser Errors", state.data.analysis?.totals?.status_5xx, "fa-bug", "red"),
      metric("Ingestion Lag", "Live", "fa-clock", "green"),
    ])}
    <section class="layout-3">
      ${statusPanel()}
      ${logSourceIPsPanel()}
      ${logUserAgentsPanel()}
    </section>
    <section class="layout-2">
      ${logRecentEvidencePanel(recent)}
      ${logTopPathsPanel()}
    </section>
  `;
}

function renderSearch() {
  const events = filtered(searchItems(state.data.traffic.recent_errors || [], (item) => `${item.status} ${item.site_id} ${item.env} ${item.client_ip} ${item.method} ${item.path} ${item.user_agent}`));
  const statuses = state.data.traffic.status_breakdown || state.data.analysis.status_breakdown || [];
  const hosts = groupCount(events, (item) => item.site_id || "unknown");
  const paths = groupCount(events, (item) => item.path || "/");
  return `
    <section class="search-console">
      <article class="panel facet-panel">
        <div class="panel-head"><div><h2>Refine Results</h2><p>${formatNumber(events.length)} indexed matches</p></div></div>
        ${facetBlock("Severity", [
          ["5xx", events.filter((event) => Number(event.status) >= 500).length, "red"],
          ["4xx", events.filter((event) => Number(event.status) >= 400 && Number(event.status) < 500).length, "amber"],
          ["Other", events.filter((event) => Number(event.status) < 400).length, "green"],
        ])}
        ${facetBlock("Status Code", statuses.slice(0, 6).map((item) => [item.status, item.requests, statusColorName(item.status)]))}
        ${facetBlock("Host", hosts.slice(0, 6).map((item) => [item.label, item.count, "cyan"]))}
      </article>
      <section class="content-grid">
        <article class="panel query-panel">
          <div class="query-string">
            <span>${escapeHTML(state.search || "status:>=400 OR severity:error OR path:/wp-*")}</span>
            <button class="icon-button" type="button" data-action="query-guide" aria-label="Query guide" title="Query guide">${iconHTML("fa-circle-info")}</button>
          </div>
          <div class="toolbar">
            <span class="pill">${escapeHTML(activeRangeLabel())}</span>
            <span class="pill">${state.siteID ? escapeHTML(state.siteID) : "All Projects"}</span>
            <button class="button small" type="button" data-action="refresh">${iconHTML("fa-magnifying-glass")}Search</button>
          </div>
        </article>
        <section class="layout-2">
          <article class="panel chart-card">
            <div class="panel-head">
              <div><h2>Events Over Time</h2><p>Matched access events by bucket. Hover the chart for bucket values.</p></div>
              ${chartLegend([["Requests", "cyan"], ["Errors", "red"]])}
            </div>
            <canvas id="trafficLine" class="large-chart"></canvas>
          </article>
          ${searchTopPathsPanel(paths)}
        </section>
        ${searchMatchedEventsPanel(events)}
      </section>
    </section>
  `;
}

function renderTraffic() {
  return `
    ${metricGrid([
      metric("Requests", state.data.analysis?.totals?.requests, "fa-arrow-trend-up", "cyan"),
      metric("Req / Min", requestsPerMinute().toFixed(1), "fa-gauge-high", "green"),
      metric("Bytes Sent", formatBytes(state.data.analysis?.totals?.bytes_sent), "fa-hard-drive", "purple"),
      metric("P95 Time", formatMs(state.data.analysis?.totals?.p95_request_time_ms), "fa-stopwatch", "amber"),
    ])}
    <section class="layout-2">
      <article class="panel chart-card">
        <div class="panel-head">
          <div><h2>Traffic Timeline</h2><p>Requests with 4xx/5xx pressure. Hover the chart for bucket values.</p></div>
          ${chartLegend([["Requests", "cyan"], ["Errors", "red"]])}
        </div>
        <canvas id="trafficLine" class="large-chart"></canvas>
      </article>
      ${statusPanel()}
    </section>
    <section class="layout-2">
      ${topPathsPaginatedPanel()}
      ${topIPTrafficPanel()}
    </section>
  `;
}

function searchTopPathsPanel(rows) {
  const page = paginate(rows, state.pages.searchTopPaths, 8);
  state.pages.searchTopPaths = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Top Paths</h2><p>Most common matching targets.</p></div>
        <span class="pill">${formatNumber(rows.length)} paths</span>
      </div>
      <div class="list">${page.rows.map((item) => compactRow(item.label, `${formatNumber(item.count)} events`, item.count)).join("") || empty("No path facets.")}</div>
      ${pager("searchTopPaths", page)}
    </article>
  `;
}

function searchMatchedEventsPanel(events) {
  const page = paginate(events, state.pages.searchMatchedEvents, 20);
  state.pages.searchMatchedEvents = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Matched Events</h2><p>Open trace or IP detail from each row.</p></div>
        <span class="pill">${formatNumber(events.length)} events</span>
      </div>
      ${eventsTable(page.rows)}
      ${pager("searchMatchedEvents", page)}
    </article>
  `;
}

function renderIssueWorkspace(kind) {
  const issues = issuesFor(kind);
  return `
    ${metricGrid([
      metric("Findings", issues.length, "fa-magnifying-glass-chart", kind === "errors" ? "red" : "amber"),
      metric("4xx", state.data.analysis?.totals?.status_4xx, "fa-triangle-exclamation", "amber"),
      metric("5xx", state.data.analysis?.totals?.status_5xx, "fa-bolt", "red"),
      metric("Slow", state.data.analysis?.totals?.slow_requests, "fa-stopwatch", "purple"),
    ])}
    <section class="layout-2">
      ${issueFindingsPanel(kind, issues)}
      ${issueTopPathsPanel(kind)}
    </section>
    <section class="layout-2">
      ${issueEventsPanel(kind)}
      ${issueAgentsPanel(kind)}
    </section>
  `;
}

function renderPHP() {
  const issues = issuesFor("php");
  const paths = filtered(searchItems((state.data.traffic.top_paths || state.data.analysis.slow_paths || []).filter(isPHPPathRow), (item) => `${item.path} ${item.site_id} ${item.requests}`));
  const events = filtered(searchItems((state.data.traffic.recent_errors || []).filter(isPHPEventRow), (item) => `${item.status} ${item.site_id} ${item.env} ${item.client_ip} ${item.method} ${item.path} ${item.user_agent}`));
  const agents = filtered(searchItems(userAgentsFromEvents(events), (item) => `${item.family} ${item.sample} ${item.known_actor} ${item.actor_type}`));
  const requests = sum(paths, "requests") || events.length;
  const errors = sum(paths, "status_4xx") + sum(paths, "status_5xx") || events.length;
  return `
    ${metricGrid([
      metric("PHP Findings", issues.length, "fa-brands fa-php", "purple"),
      metric("PHP Paths", paths.length, "fa-route", "cyan"),
      metric("PHP Events", events.length, "fa-rectangle-list", "amber"),
      metric("Error Pressure", formatPercent(ratio(errors, requests)), "fa-triangle-exclamation", "red"),
    ])}
    <section class="layout-2">
      ${issueFindingsPanel("php", issues)}
      ${issueTopPathsPanel("php", paths)}
    </section>
    <section class="layout-2">
      ${issueEventsPanel("php", events)}
      ${issueAgentsPanel("php", agents)}
    </section>
  `;
}

function renderMySQL() {
  const issues = issuesFor("mysql");
  const probes = filtered(searchItems((state.data.analysis.injection_probes || []).filter(isMySQLProbeRow), mysqlProbeSearchText));
  const slowPaths = filtered(searchItems((state.data.analysis.slow_paths || []).filter(isMySQLPathRow), (item) => `${item.site_id} ${item.path}`));
  const sourceIPs = mysqlProbeSourceIPs(probes);
  const loading = state.securityAnalysisLoading ? securityLoadingPanel("SQL probe analysis is still running for this range.") : "";
  return `
    ${metricGrid([
      metric("MySQL Findings", issues.length, "fa-database", "purple"),
      metric("SQL Probes", sum(probes, "requests"), "fa-syringe", "red"),
      metric("Slow DB Paths", slowPaths.length, "fa-stopwatch", "amber"),
      metric("Source IPs", sourceIPs.length, "fa-network-wired", "cyan"),
    ])}
    ${loading}
    <section class="layout-2">
      ${issueFindingsPanel("mysql", issues)}
      ${mysqlProbePanel(probes)}
    </section>
    <section class="layout-2">
      ${mysqlSlowPathsPanel(slowPaths)}
      ${mysqlSourceIPsPanel(sourceIPs)}
    </section>
  `;
}

function mysqlProbePanel(rows) {
  const key = "mysqlProbes";
  const page = paginate(rows, state.pages[key], 5);
  state.pages[key] = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>SQL Injection Probes</h2><p>Requests matching database attack signatures.</p></div>
        <span class="pill">${formatNumber(rows.length)} probes</span>
      </div>
      <div class="list">${page.rows.map((item) => `
        <div class="list-row">
          <div><strong>${escapeHTML(`${item.method || "GET"} ${item.path || "/"}`)}</strong><span>${escapeHTML([item.site_id, item.env, item.match_reason || item.category, item.sample_query || ""].filter(Boolean).join(" / "))}</span></div>
          <span class="severity ${Number(item.risk_score || 0) >= 70 ? "critical" : "high"}">${formatNumber(item.requests)} req</span>
        </div>
      `).join("") || empty("No SQL injection probes found.")}</div>
      ${pager(key, page)}
    </article>
  `;
}

function mysqlSlowPathsPanel(rows) {
  const key = "mysqlSlowPaths";
  const page = paginate(rows, state.pages[key], 7);
  state.pages[key] = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Database Slow Paths</h2><p>Slow paths with database or query indicators.</p></div>
        <span class="pill">${formatNumber(rows.length)} paths</span>
      </div>
      <div class="list">${page.rows.map((item) => `
        <div class="list-row"><div><strong>${escapeHTML(item.path || "/")}</strong><span>${escapeHTML(item.site_id || "-")} / ${formatNumber(item.requests)} requests / avg ${formatMs(item.avg_request_time_ms)}</span></div><b>${formatMs(item.p95_request_time_ms)}</b></div>
      `).join("") || empty("No database slow paths in this range.")}</div>
      ${pager(key, page)}
    </article>
  `;
}

function mysqlSourceIPsPanel(rows) {
  const key = "mysqlSourceIPs";
  const page = paginate(rows, state.pages[key], 7);
  state.pages[key] = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Source IPs</h2><p>Actors responsible for SQL/database probes.</p></div>
        <span class="pill">${formatNumber(rows.length)} IPs</span>
      </div>
      <div class="list">${page.rows.map((item) => `
        <div class="list-row">
          <div><strong>${ipLink(item.ip)}</strong><span>${formatNumber(item.requests)} requests / ${formatNumber(item.status_4xx + item.status_5xx)} errors / ${escapeHTML(item.sites.join(", ") || "-")}</span></div>
          <span class="severity ${item.risk_score >= 70 ? "critical" : "high"}">${formatNumber(item.risk_score)}</span>
        </div>
      `).join("") || empty("No SQL probe source IPs found.")}</div>
      ${pager(key, page)}
    </article>
  `;
}

function renderSlow() {
  const slow = filtered(searchItems(state.data.analysis.slow_paths || [], (item) => `${item.site_id} ${item.path}`));
  const page = paginate(slow, state.pages.slowPaths, 10);
  state.pages.slowPaths = page.page;
  return `
    ${metricGrid([
      metric("Slow Requests", state.data.analysis?.totals?.slow_requests, "fa-stopwatch", "amber"),
      metric("Slow Rate", formatPercent(state.data.analysis?.totals?.slow_requests_rate), "fa-gauge", "amber"),
      metric("P95", formatMs(state.data.analysis?.totals?.p95_request_time_ms), "fa-timer", "purple"),
      metric("Avg Time", formatMs(state.data.analysis?.totals?.avg_request_time_ms), "fa-clock", "cyan"),
    ])}
    <article class="panel">
      <div class="panel-head">
        <div><h2>Slow Paths</h2><p>Highest latency paths by p95 and request count.</p></div>
        <span class="pill">${formatNumber(slow.length)} paths</span>
      </div>
      ${slowPathsTable(page.rows)}
      ${pager("slowPaths", page)}
    </article>
  `;
}

function renderSecurity() {
  const admin = state.data.analysis.admin_probes || [];
  const injection = state.data.analysis.injection_probes || [];
  const tor = state.data.analysis.tor_sources || [];
  const ips = filtered(searchItems(state.data.analysis.source_ips || [], (item) => `${item.ip} ${item.known_actor} ${item.actor_type} ${item.country_code}`));
  const actorPage = paginate(ips, state.pages.securityActors, 7);
  const signals = filtered(searchItems(securitySignalRows(), securitySignalSearchText));
  const signalPage = paginate(signals, state.pages.securitySignals, 7);
  state.pages.securityActors = actorPage.page;
  state.pages.securitySignals = signalPage.page;
  return `
    ${metricGrid([
      metric("Security Issues", issuesFor("security").length, "fa-shield-halved", "red"),
      metric("Admin Probes", admin.length, "fa-user-secret", "amber"),
      metric("Injection Probes", injection.length, "fa-syringe", "red"),
      metric("Tor Sources", tor.length, "fa-mask", "purple"),
    ])}
    ${state.securityAnalysisLoading ? securityLoadingPanel("Probe and Tor analysis is still running for this range.") : ""}
    <section class="layout-2">
      <article class="panel">
        <div class="panel-head">
          <div><h2>Actor Verification</h2><p>Known services, countries, and suspicious clients.</p></div>
          <span class="pill">${formatNumber(ips.length)} IPs</span>
        </div>
        <div class="list">${actorPage.rows.map(ipRow).join("") || empty("No actors found.")}</div>
        ${pager("securityActors", actorPage)}
      </article>
      <article class="panel">
        <div class="panel-head">
          <div><h2>Security Signals</h2><p>Probes, Tor, and suspicious patterns.</p></div>
          <span class="pill">${formatNumber(signals.length)} signals</span>
        </div>
        <div class="list">${signalPage.rows.map(securitySignalRow).join("") || empty("No security signals found.")}</div>
        ${pager("securitySignals", signalPage)}
      </article>
    </section>
  `;
}

function securityLoadingPanel(message) {
  return `
    <article class="panel compact-panel">
      <div class="panel-head">
        <div><h2>${iconHTML("fa-spinner")} Security Analysis</h2><p>${escapeHTML(message)}</p></div>
        <span class="pill">Loading</span>
      </div>
    </article>
  `;
}

function renderBots() {
  const analysisAgents = state.data.analysis.user_agents || [];
  const fallbackAgents = analysisAgents.length ? analysisAgents : userAgentsFromEvents(state.data.traffic.recent_errors || []);
  const agents = filtered(searchItems(fallbackAgents, (item) => `${item.family} ${item.known_actor} ${item.actor_type} ${item.sample}`));
  const verified = agents.filter((item) => /bot|crawler|search|google|bing|claude|gpt/i.test(`${item.family} ${item.known_actor} ${item.actor_type} ${item.sample}`));
  const suspicious = agents.filter((item) => /python|curl|scrapy|aiohttp|bot|scanner/i.test(`${item.family} ${item.sample}`) && !/google|bing/i.test(`${item.known_actor} ${item.sample}`));
  const sourceRows = (state.data.analysis.source_ips || []).length ? state.data.analysis.source_ips : (state.data.traffic.top_ips || []);
  const ips = filtered(searchItems(sourceRows.filter((ip) => /bot|crawler|script|service|unknown/i.test(`${ip.actor_type} ${ip.known_actor} ${ip.reverse_dns}`)), (ip) => `${ip.ip} ${ip.actor_type} ${ip.known_actor} ${ip.reverse_dns}`));
  return `
    ${metricGrid([
      metric("Bot Traffic Ratio", formatPercent(ratio(sum(agents, "requests"), state.data.analysis?.totals?.requests)), "fa-robot", "green"),
      metric("Verified Bots", sum(verified, "requests"), "fa-shield-check", "green"),
      metric("Suspicious Bots", sum(suspicious, "requests"), "fa-triangle-exclamation", "amber"),
      metric("Blocked / Watch", ips.filter((item) => item.manual_action === "suspicious" || item.risk_score >= 70).length, "fa-ban", "red"),
    ])}
    <section class="layout-2">
      <article class="panel chart-card">
        <div class="panel-head"><div><h2>Bot Traffic Over Time</h2><p>Known and scripted clients within selected range.</p></div></div>
        <canvas id="trafficLine" class="large-chart"></canvas>
      </article>
      ${botRecommendationsPanel(verified, suspicious, ips)}
    </section>
    <section class="layout-2">
      ${botDetectedAgentsPanel(agents)}
      ${botSourceIPsPanel(ips)}
    </section>
  `;
}

function botRecommendationsPanel(verified, suspicious, ips) {
  const rows = [
    {
      title: "Allow verified search bots",
      meta: `${formatNumber(sum(verified, "requests"))} requests from known crawler families`,
      value: "Allow",
    },
    {
      title: "Challenge suspicious crawlers",
      meta: `${formatNumber(sum(suspicious, "requests"))} requests from scripted or scanner-like agents`,
      value: "Review",
    },
    {
      title: "Rate limit aggressive crawler IPs",
      meta: `${formatNumber(ips.filter((item) => Number(item.requests || 0) > 1000).length)} source IPs exceed 1K requests`,
      value: "Limit",
    },
  ];
  const page = paginate(rows, state.pages.botRecommendations, 3);
  state.pages.botRecommendations = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Bot Control Recommendations</h2><p>Operational actions for verified and suspicious automation.</p></div>
        <span class="pill">${formatNumber(rows.length)} actions</span>
      </div>
      <div class="list">${page.rows.map((item) => compactRow(item.title, item.meta, item.value)).join("")}</div>
      ${pager("botRecommendations", page)}
    </article>
  `;
}

function botDetectedAgentsPanel(rows) {
  const page = paginate(rows, state.pages.botAgents, 7);
  state.pages.botAgents = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Detected Bots</h2><p>Verified and suspicious user-agent families.</p></div>
        <span class="pill">${formatNumber(rows.length)} agents</span>
      </div>
      <div class="list">${page.rows.map((item) => `
        <div class="list-row">
          <div>${userAgentListLabel(item)}</div>
          <b>${formatNumber(item.requests)}</b>
        </div>
      `).join("") || empty("No bot user agents found.")}</div>
      ${pager("botAgents", page)}
    </article>
  `;
}

function botSourceIPsPanel(rows) {
  const page = paginate(rows, state.pages.botSourceIPs, 7);
  state.pages.botSourceIPs = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Countries / ASNs</h2><p>Bot-like source IPs grouped by intelligence labels.</p></div>
        <span class="pill">${formatNumber(rows.length)} IPs</span>
      </div>
      <div class="list">${page.rows.map(ipRow).join("") || empty("No crawler source IPs found.")}</div>
      ${pager("botSourceIPs", page)}
    </article>
  `;
}

function renderReports() {
  const all = filtered(searchItems(allReports(), reportSearchText));
  const types = reportTypes(all);
  if (state.reportType !== "all" && !types.includes(state.reportType)) state.reportType = "all";
  const reports = state.reportType === "all" ? all : all.filter((item) => reportKind(item) === state.reportType);
  const page = paginate(reports, state.pages.reportCatalog, 8);
  state.pages.reportCatalog = page.page;
  const selected = page.rows[0] || reports[0] || {};
  return `
    ${metricGrid([
      metric("Reports", all.length, "fa-file-lines", "cyan"),
      metric("Daily", all.filter((r) => reportKind(r).includes("daily")).length, "fa-calendar-day", "green"),
      metric("Weekly", all.filter((r) => reportKind(r).includes("weekly")).length, "fa-calendar-week", "purple"),
      metric("Recent Alerts", state.data.alerts.length, "fa-bell", "red"),
    ])}
    <section class="layout-2">
      <article class="panel">
        <div class="panel-head">
          <div><h2>Report Catalog</h2><p>Generated summaries for the selected project.</p></div>
          <div class="toolbar">
            <select class="select compact-select" data-report-type-filter aria-label="Report type">
              <option value="all" ${state.reportType === "all" ? "selected" : ""}>All types</option>
              ${types.map((type) => `<option value="${escapeAttr(type)}" ${state.reportType === type ? "selected" : ""}>${escapeHTML(formatReportType(type))}</option>`).join("")}
            </select>
          </div>
        </div>
        <div class="list">${page.rows.length ? page.rows.map(reportRow).join("") : empty("No reports match this filter.")}</div>
        ${pager("reportCatalog", page)}
      </article>
      ${reportPreviewPanel(selected)}
    </section>
  `;
}

function reportPreviewPanel(item) {
  if (!item || !Object.keys(item).length) {
    return `<article class="panel">${empty("Generate or select a report to preview.")}</article>`;
  }
  const summary = item.summary || {};
  const reportKey = cacheDetail("report", item, item.id || item.created_at || "selected-report");
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>${escapeHTML(reportTitle(item))}</h2><p>${escapeHTML([item.range, item.model, shortTime(item.created_at || item.generated_at)].filter(Boolean).join(" / "))}</p></div>
        <button class="button small" type="button" data-detail="report" data-value="${escapeAttr(reportKey)}">${iconHTML("fa-up-right-from-square")}Open</button>
      </div>
      <div class="panel-body">
        ${facts([
          ["Requests", formatNumber(summary.requests)],
          ["Unique IPs", formatNumber(summary.unique_ips)],
          ["5xx Rate", formatPercent(summary.status_5xx_rate)],
          ["Open Alerts", formatNumber(summary.open_alerts)],
        ])}
      </div>
      <div class="report-preview markdown-body compact">
        ${renderMarkdown(reportSummaryText(item))}
      </div>
    </article>
  `;
}

function renderAlerts() {
  const alerts = filtered(searchItems(state.data.alerts || [], alertSearchText));
  const alertPage = paginate(alerts, state.pages.alertsActive, 10);
  const rules = alertRuleRows(alerts);
  const rulePage = paginate(rules, state.pages.alertRules, 8);
  state.pages.alertsActive = alertPage.page;
  state.pages.alertRules = rulePage.page;
  return `
    ${metricGrid([
      metric("Active Alerts", alerts.length, "fa-bell", "red"),
      metric("Critical", alerts.filter((a) => a.severity === "critical").length, "fa-circle-exclamation", "red"),
      metric("High", alerts.filter((a) => a.severity === "high").length, "fa-triangle-exclamation", "amber"),
      metric("Rules", unique(alerts.map((a) => a.rule_key)).length, "fa-list-check", "purple"),
    ])}
    <section class="layout-2">
      <article class="panel">
        <div class="panel-head">
          <div><h2>Active Alerts</h2><p>Open alert records from the backend.</p></div>
          <span class="pill">${formatNumber(alerts.length)} alerts</span>
        </div>
        <div class="list">${alertPage.rows.length ? alertPage.rows.map(alertRow).join("") : empty("No open alerts.")}</div>
        ${pager("alertsActive", alertPage)}
      </article>
      <article class="panel">
        <div class="panel-head">
          <div><h2>Alert Rules</h2><p>Rules currently represented by open alerts.</p></div>
          <span class="pill">${formatNumber(rules.length)} rules</span>
        </div>
        <div class="list">${rulePage.rows.map(alertRuleRow).join("") || empty("No firing rules.")}</div>
        ${pager("alertRules", rulePage)}
      </article>
    </section>
  `;
}

function renderSettings() {
  const credentials = state.data.credentials.summary || {};
  const retention = state.data.retention || {};
  return `
    <section class="layout-3">
      <article class="panel">
        <div class="panel-head"><div><h2>Profile</h2><p>${escapeHTML(state.currentUser?.email || "Auth disabled")}</p></div></div>
        <div class="panel-body">${facts([
          ["Display", state.currentUser?.display_name || "-"],
          ["Access", state.currentUser ? "Operator" : "-"],
          ["Session", state.currentUser ? "Authenticated" : "Not required"],
        ])}</div>
      </article>
      <article class="panel">
        <div class="panel-head"><div><h2>Pantheon Access</h2><p>Collection credential state.</p></div></div>
        <div class="panel-body">${facts([
          ["Machine token", yesNo(credentials.machine_token_configured)],
          ["Email", yesNo(credentials.email_configured)],
          ["SSH key", yesNo(credentials.ssh_key_configured)],
          ["Known hosts", yesNo(credentials.known_hosts_configured)],
        ])}</div>
      </article>
      <article class="panel">
        <div class="panel-head"><div><h2>Retention</h2><p>Storage cleanup policy.</p></div></div>
        <div class="panel-body">${facts([
          ["Enabled", yesNo(retention.enabled ?? state.data.overview.retention_enabled)],
          ["Max age", state.data.overview.retention_max_age || "-"],
          ["Hot events cutoff", shortTime(retention.hot_event_cutoff)],
          ["Archive cutoff", shortTime(retention.archive_cutoff)],
          ["Expired imports", formatNumber(retention.temporary_imports_matched)],
          ["Expired imported events", formatNumber(retention.temporary_events_matched)],
          ["Raw dir", state.data.overview.raw_dir || "-"],
        ])}</div>
      </article>
    </section>
    <section class="layout-2">
      <article class="panel">
        <div class="panel-head"><div><h2>Users</h2><p>Active application accounts.</p></div></div>
        ${usersTable(state.data.users)}
      </article>
      ${notificationsPanel()}
    </section>
  `;
}

function renderPulseLogs() {
  const rawFiles = state.data.collectorHealth?.raw_files?.recent || [];
  const deliveries = state.data.notifications?.recent || [];
  const archives = state.data.archives || [];
  const archiveImports = state.data.archiveImports || [];
  const storage = state.data.storage || {};
  return `
    ${metricGrid([
      metric("Jobs", state.data.jobs.length, "fa-briefcase", "cyan"),
      metric("Database", formatBytes(storage.storage?.database_bytes), "fa-hard-drive", "purple"),
      metric("Hot Events", storage.events?.hot_events || 0, "fa-database", "green"),
      metric("Backfill", storage.events?.backfill_remaining || 0, "fa-rotate", "amber"),
      metric("Archives", storage.archives?.ready_archives ?? archives.length, "fa-box-archive", "amber"),
      metric("Temporary Imports", storage.temporary_imports?.active_imports ?? archiveImports.length, "fa-clock-rotate-left", "cyan"),
    ])}
    ${storageReadinessPanel(storage)}
    <article class="panel">
      <div class="panel-head">
        <div><h2>Log Parser & Ingestion</h2><p>Pipeline quality from combined segments and recent jobs.</p></div>
        <div class="toolbar">
          <button class="button small" type="button" data-action="refresh">${iconHTML("fa-rotate-right")}Refresh</button>
          <button class="button small" type="button" data-action="run-pipeline">${iconHTML("fa-code-merge")}Run Pipeline</button>
          <button class="button small" type="button" data-action="run-backfill">${iconHTML("fa-database")}Backfill Batch</button>
          <button class="button small" type="button" data-action="run-archive-dry">${iconHTML("fa-box-archive")}Archive Check</button>
          <button class="button small" type="button" data-action="run-archive">${iconHTML("fa-file-zipper")}Archive</button>
        </div>
      </div>
      <div class="ingestion-pipeline">
        ${pipelineStep("Downloaded", state.data.segments.length, "fa-cloud-arrow-down", "green")}
        ${pipelineStep("Combined", state.data.segments.filter((item) => item.status).length, "fa-code-merge", "cyan")}
        ${pipelineStep("Indexed", state.data.segments.filter((item) => item.status === "indexed").length, "fa-database", "purple")}
        ${pipelineStep("Stored", state.data.analysis?.totals?.requests || 0, "fa-chart-simple", "green")}
      </div>
    </article>
    <section class="layout-2">
      ${pulseJobsPanel()}
      ${pulseSegmentsPanel()}
    </section>
    <section class="layout-2">
      ${pulseArchivesPanel(archives)}
      ${pulseArchiveImportsPanel(archiveImports)}
    </section>
    <section class="layout-2">
      ${pulseRawFilesPanel(rawFiles)}
      ${pulseDeliveriesPanel(deliveries)}
    </section>
  `;
}

function storageReadinessPanel(storage) {
  const readiness = storage.readiness || {};
  const storageBytes = storage.storage || {};
  const events = storage.events || {};
  const archives = storage.archives || {};
  const dimensions = storage.dimensions || {};
  const temporary = storage.temporary_imports || {};
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Storage Readiness</h2><p>Hot events, rollups, archives, and retention posture.</p></div>
        <span class="pill">${readiness.backfill_ready && readiness.temporary_clean && readiness.hot_events_within_window ? "Ready" : "Needs work"}</span>
      </div>
      <div class="panel-body layout-4 compact-grid">
        ${facts([
          ["Backfill ready", yesNo(readiness.backfill_ready)],
          ["Backfill remaining", formatNumber(events.backfill_remaining)],
          ["Hot window clean", yesNo(readiness.hot_events_within_window)],
          ["Older hot events", formatNumber(events.events_older_than_hot_cutoff)],
        ])}
        ${facts([
          ["Access events table", formatBytes(storageBytes.access_events_bytes)],
          ["Estimated hot events", formatBytes(storageBytes.estimated_hot_bytes)],
          ["Dimensions", formatBytes(storageBytes.dimensions_bytes)],
          ["Rollups", formatBytes(storageBytes.rollups_bytes)],
        ])}
        ${facts([
          ["IPs", formatNumber(dimensions.ips)],
          ["Paths", formatNumber(dimensions.paths)],
          ["Queries", formatNumber(dimensions.queries)],
          ["User agents", formatNumber(dimensions.user_agents)],
        ])}
        ${facts([
          ["Ready archives", formatNumber(archives.ready_archives)],
          ["Pending daily", formatNumber(archives.pending_daily_groups)],
          ["Pending weekly", formatNumber(archives.pending_weekly_groups)],
          ["Temporary facts", formatNumber(temporary.imported_facts)],
        ])}
      </div>
    </article>
  `;
}

function pulseArchivesPanel(rows) {
  const filteredRows = filtered(searchItems(rows || [], (item) => `${item.log_type || ""} ${item.granularity || ""} ${item.status || ""} ${item.path || ""}`));
  const page = paginate(filteredRows, state.pages.pulseArchives, 8);
  state.pages.pulseArchives = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Archives</h2><p>Daily and weekly packed combined logs available for rehydration.</p></div>
        <span class="pill">${formatNumber(filteredRows.length)} archives</span>
      </div>
      ${archivesTable(page.rows)}
      ${pager("pulseArchives", page)}
    </article>
  `;
}

function pulseArchiveImportsPanel(rows) {
  const filteredRows = filtered(searchItems(rows || [], (item) => `${item.status || ""} ${item.reason || ""} ${(item.archive_paths || []).join(" ")}`));
  const page = paginate(filteredRows, state.pages.pulseArchiveImports, 8);
  state.pages.pulseArchiveImports = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Temporary Imports</h2><p>Archived data rehydrated for short investigations.</p></div>
        <span class="pill">${formatNumber(filteredRows.length)} imports</span>
      </div>
      ${archiveImportsTable(page.rows)}
      ${pager("pulseArchiveImports", page)}
    </article>
  `;
}

function notificationsPanel() {
  const status = state.data.notifications || {};
  const channels = status.channels || [];
  const recent = status.recent || [];
  const webPush = state.data.webPush || {};
  const warnings = status.warnings || [];
  const page = paginate(recent, state.pages.notificationsRecent, 5);
  state.pages.notificationsRecent = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Notifications</h2><p>Email, webhook push, and browser push delivery.</p></div>
        <div class="toolbar">
          <button class="button small" type="button" data-action="test-notifications">${iconHTML("fa-vial")}Test</button>
          <button class="button small" type="button" data-action="send-notifications">${iconHTML("fa-paper-plane")}Send Alerts</button>
        </div>
      </div>
      <div class="panel-body">
        ${facts([
          ["Enabled", yesNo(status.enabled)],
          ["Ready", yesNo(status.ready)],
          ["Targets", formatNumber(status.target_count || 0)],
          ["Minimum severity", status.min_severity || "-"],
          ["Browser push", webPush.configured ? `${webPush.active_subscriptions || 0} active` : "Not configured"],
        ])}
        ${warnings.length ? `<div class="list compact-list">${warnings.map((warning) => `
          <div class="list-row">
            <div><strong>${iconHTML("fa-circle-info")} Attention</strong><span>${escapeHTML(warning)}</span></div>
          </div>
        `).join("")}</div>` : ""}
        <div class="toolbar inline-toolbar">
          <button class="button outline small" type="button" data-action="enable-web-push">${iconHTML("fa-bell")}Enable Browser Push</button>
          <button class="button outline small" type="button" data-action="disable-web-push">${iconHTML("fa-bell-slash")}Disable Browser Push</button>
        </div>
      </div>
      <div class="list">${channels.map(channelRow).join("") || empty("No notification channels configured.")}</div>
      <div class="list">${page.rows.map(deliveryRow).join("") || empty("No recent deliveries.")}</div>
      ${pager("notificationsRecent", page)}
    </article>
  `;
}

function pipelineStep(label, value, icon, color) {
  return `
    <div class="pipeline-step">
      <span style="color: var(--${color})">${iconHTML(icon)}</span>
      <div><strong>${escapeHTML(label)}</strong><small>${formatCompact(value)}</small></div>
    </div>
  `;
}

function pulseJobsPanel() {
  const rows = filtered(searchItems(state.data.jobs || [], (item) => `${item.type || ""} ${item.status || ""} ${item.message || ""}`));
  const page = paginate(rows, state.pages.pulseJobs, 10);
  state.pages.pulseJobs = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Jobs</h2><p>Recent background work and scheduler activity.</p></div>
        <span class="pill">${formatNumber(rows.length)} jobs</span>
      </div>
      ${jobsTable(page.rows)}
      ${pager("pulseJobs", page)}
    </article>
  `;
}

function pulseSegmentsPanel() {
  const rows = filtered(searchItems(state.data.segments || [], (item) => `${item.log_type || ""} ${item.status || ""} ${item.path || ""} ${item.bucket_ts || item.bucket_start || ""}`));
  const page = paginate(rows, state.pages.pulseSegments, 10);
  state.pages.pulseSegments = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Indexed Segments</h2><p>Combined files registered for indexing.</p></div>
        <span class="pill">${formatNumber(rows.length)} segments</span>
      </div>
      ${segmentsTable(page.rows)}
      ${pager("pulseSegments", page)}
    </article>
  `;
}

function pulseRawFilesPanel(rows) {
  const filteredRows = filtered(searchItems(rows || [], (item) => `${item.site_id || ""} ${item.env || ""} ${item.container_id || ""} ${item.log_type || ""} ${item.remote_path || ""} ${item.status || ""}`));
  const page = paginate(filteredRows, state.pages.pulseRawFiles, 10);
  state.pages.pulseRawFiles = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Raw File Activity</h2><p>Recently discovered or downloaded source files.</p></div>
        <span class="pill">${formatNumber(filteredRows.length)} files</span>
      </div>
      ${rawFilesTable(page.rows)}
      ${pager("pulseRawFiles", page)}
    </article>
  `;
}

function pulseDeliveriesPanel(rows) {
  const filteredRows = filtered(searchItems(rows || [], (item) => `${item.title || ""} ${item.channel || ""} ${item.target || ""} ${item.status || ""} ${item.error || ""}`));
  const page = paginate(filteredRows, state.pages.pulseDeliveries, 8);
  state.pages.pulseDeliveries = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Notification Deliveries</h2><p>Recent email, webhook push, and browser push attempts.</p></div>
        <span class="pill">${formatNumber(filteredRows.length)} deliveries</span>
      </div>
      <div class="list">${page.rows.map(deliveryRow).join("") || empty("No recent deliveries.")}</div>
      ${pager("pulseDeliveries", page)}
    </article>
  `;
}

function metricGrid(items) {
  return `<section class="metric-grid">${items.join("")}</section>`;
}

function metric(label, value, icon, color = "cyan") {
  const amount = value === undefined || value === null || value === "" ? "-" : value;
  return `
    <article class="metric-card">
      <div class="metric-top">
        <span class="metric-icon" style="color: var(--${color})">${iconHTML(icon)}</span>
        <span class="metric-label">${escapeHTML(label)}</span>
      </div>
      <strong class="metric-value">${typeof amount === "number" ? formatCompact(amount) : escapeHTML(amount)}</strong>
      <div class="metric-trend">
        <span>Live range</span>
        <canvas class="sparkline" data-spark="${sparkValues().join(",")}" data-color="${color}"></canvas>
      </div>
    </article>
  `;
}

function sitesTable(rows) {
  if (!rows.length) return empty("No projects match this view.");
  return `
    <div class="table-wrap">
      <table>
        <thead><tr><th>Project / Site</th><th>Status</th><th>Requests</th><th>Error Rate</th><th></th></tr></thead>
        <tbody>${rows.map((site, index) => `
          <tr>
            <td><span class="row-title"><strong>${escapeHTML(site.name)}</strong><span>${escapeHTML(site.id)}</span></span></td>
            <td><span class="status ${site.health === "healthy" ? "good" : site.health === "critical" ? "bad" : "warn"}">${site.health}</span></td>
            <td>${formatNumber(site.requests)}</td>
            <td>${formatPercent(site.errorRate)}</td>
            <td><button class="button small" type="button" data-detail="site" data-index="${index}" data-value="${escapeAttr(site.id)}">View</button></td>
          </tr>
        `).join("")}</tbody>
      </table>
    </div>
  `;
}

function overviewSitesTable(rows) {
  if (!rows.length) return empty("No projects match this view.");
  return `
    <div class="table-wrap">
      <table class="overview-sites-table">
        <thead><tr><th>Project / Site</th><th>Status</th><th>Requests</th><th>Error Rate</th><th></th></tr></thead>
        <tbody>${rows.map((site, index) => `
          <tr>
            <td><span class="row-title"><strong>${escapeHTML(site.name)}</strong><span>${escapeHTML(site.id)}</span></span></td>
            <td><span class="status ${site.health === "healthy" ? "good" : site.health === "critical" ? "bad" : "warn"}">${site.health}</span></td>
            <td>${formatNumber(site.requests)}</td>
            <td>${formatPercent(site.errorRate)}</td>
            <td><button class="button small" type="button" data-detail="site" data-index="${index}" data-value="${escapeAttr(site.id)}">View</button></td>
          </tr>
        `).join("")}</tbody>
      </table>
    </div>
  `;
}

function eventsTable(rows) {
  if (!rows.length) return empty("No recent error events found.");
  return `
    <div class="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>Site</th><th>Source</th><th>Path</th><th>Status</th><th></th></tr></thead>
        <tbody>${rows.map((event, index) => {
          const requestKey = cacheDetail("request", event, `${event.ts || ""}:${event.site_id || ""}:${event.client_ip || ""}:${event.path || ""}:${index}`);
          return `
          <tr>
            <td>${shortTime(event.ts)}</td>
            <td>${escapeHTML(event.site_id || "-")}<br><span class="subtle">${escapeHTML(event.env || "")}</span></td>
            <td>${ipLink(event.client_ip)}</td>
            <td><span class="row-title"><strong>${escapeHTML(event.method || "GET")} ${escapeHTML(event.path || "/")}</strong><span>${event.user_agent ? userAgentLink(event.user_agent, event.user_agent) : ""}</span></span></td>
            <td><span class="severity ${Number(event.status) >= 500 ? "critical" : "high"}">${escapeHTML(event.status || "-")}</span></td>
            <td><button class="button small" type="button" data-detail="request" data-value="${escapeAttr(requestKey)}">Trace</button></td>
          </tr>
        `}).join("")}</tbody>
      </table>
    </div>
  `;
}

function slowPathsTable(rows) {
  if (!rows.length) return empty("No slow paths in this range.");
  return `
    <div class="table-wrap">
      <table>
        <thead><tr><th>Path</th><th>Site</th><th>Requests</th><th>P95</th><th>Avg</th><th>5xx</th></tr></thead>
        <tbody>${rows.map((item) => `
          <tr>
            <td><span class="row-title"><strong>${escapeHTML(item.path || "/")}</strong><span>${shortTime(item.last_seen)}</span></span></td>
            <td>${escapeHTML(item.site_id || "-")} / ${escapeHTML(item.env || "-")}</td>
            <td>${formatNumber(item.requests)}</td>
            <td>${formatMs(item.p95_request_time_ms)}</td>
            <td>${formatMs(item.avg_request_time_ms)}</td>
            <td>${formatNumber(item.status_5xx)}</td>
          </tr>
        `).join("")}</tbody>
      </table>
    </div>
  `;
}

function usersTable(rows) {
  if (!rows.length) return empty("No users returned.");
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>User</th><th>Access</th><th>Status</th><th>Last Login</th></tr></thead>
      <tbody>${rows.map((user) => `
        <tr><td>${escapeHTML(user.email || "-")}<br><span class="subtle">${escapeHTML(user.display_name || "")}</span></td><td>Operator</td><td>${user.is_active === false ? "Inactive" : "Active"}</td><td>${shortTime(user.last_login_at)}</td></tr>
      `).join("")}</tbody>
    </table></div>
  `;
}

function jobsTable(rows) {
  if (!rows.length) return empty("No recent jobs.");
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>Type</th><th>Status</th><th>Message</th><th>Started</th></tr></thead>
      <tbody>${rows.map((job) => `
        <tr><td>${escapeHTML(job.type || "-")}</td><td>${escapeHTML(job.status || "-")}</td><td>${escapeHTML(job.message || "")}</td><td>${shortTime(job.started_at)}</td></tr>
      `).join("")}</tbody>
    </table></div>
  `;
}

function issueRow(item, index = 0) {
  const sev = normalizeSeverity(item.severity);
  const summary = item.summary || item.actor_value || item.site_id || "No summary";
  const actor = issueActorLink(item);
  return `
    <div class="list-row">
      <div>
        <strong>${escapeHTML(item.title || item.rule_key || "Signal")}</strong>
        <span>${linkifyIPs(summary)}${actor !== "-" ? ` / ${actor}` : ""}</span>
      </div>
      <span class="severity ${sev}">${escapeHTML(sev)}</span>
    </div>
  `;
}

function issueActorLink(item) {
  if (item.actor_type === "ip" && item.actor_value) return ipLink(item.actor_value);
  if (isUserAgentActor(item.actor_type) && item.actor_value) return userAgentLink(item.actor_value);
  return "-";
}

function alertRow(item, index = 0) {
  const sev = normalizeSeverity(item.severity);
  const meta = [
    escapeHTML(item.site_id || ""),
    escapeHTML(item.env || ""),
    alertActorLink(item),
    escapeHTML(shortTime(item.last_seen_at)),
  ].filter((part) => part && part !== "-").join(" / ");
  const alertKey = cacheDetail("alert", item, item.id || `${item.rule_key || ""}:${item.actor_type || ""}:${item.actor_value || ""}:${index}`);
  return `
    <div class="list-row">
      <div>
        <strong>${escapeHTML(item.title || item.rule_key || "Alert")}</strong>
        <span>${meta || "-"}</span>
      </div>
      <button class="button small" type="button" data-detail="alert" data-value="${escapeAttr(alertKey)}">${escapeHTML(sev)}</button>
    </div>
  `;
}

function ipRow(item, index = 0) {
  const risk = item.risk_score ?? item.riskScore ?? 0;
  const meta = [item.known_actor || item.actor_type, item.country_code, item.reverse_dns].filter(Boolean).join(" / ");
  return `
    <div class="list-row">
      <div>
        <strong>${ipLink(item.ip)}</strong>
        <span>${escapeHTML(meta || "Unattributed source")} - ${formatNumber(item.requests)} requests</span>
      </div>
      <button class="button small" type="button" data-detail="ip" data-index="${index}" data-value="${escapeAttr(item.ip || "")}">${risk || "View"}</button>
    </div>
  `;
}

function reportRow(item, index) {
  const reportKey = cacheDetail("report", item, item.id || `${item.created_at || item.generated_at || ""}:${index}`);
  return `
    <div class="list-row report-row">
      <div>
        <strong>${escapeHTML(reportTitle(item))}</strong>
        <span>${escapeHTML([formatReportType(reportKind(item)), shortTime(item.created_at || item.generated_at)].filter(Boolean).join(" / "))}</span>
        <div class="markdown-body catalog-summary">${renderMarkdown(reportCatalogSummary(item))}</div>
      </div>
      <button class="button small" type="button" data-detail="report" data-index="${index}" data-value="${escapeAttr(reportKey)}">Open</button>
    </div>
  `;
}

function reportSummaryText(item) {
  if (typeof item.summary === "string") return item.summary;
  if (item.output) return item.output;
  if (item.output_preview) return item.output_preview;
  if (item.summary?.headline) return item.summary.headline;
  if (item.summary?.top_issue) return item.summary.top_issue;
  return deterministicReportSummary(item);
}

function reportCatalogSummary(item) {
  const text = reportSummaryText(item).trim();
  return text.length > 420 ? `${text.slice(0, 417)}...` : text || "Generated report";
}

function channelRow(channel) {
  const status = channel.enabled && channel.configured ? "good" : channel.enabled ? "warn" : "bad";
  const targets = (channel.targets || []).join(", ") || "No targets";
  return `
    <div class="list-row">
      <div>
        <strong>${escapeHTML(formatChannel(channel.name))}</strong>
        <span>${escapeHTML(targets)}</span>
      </div>
      <span class="status ${status}">${channel.enabled ? (channel.configured ? "ready" : "needs config") : "off"}</span>
    </div>
  `;
}

function deliveryRow(item) {
  const status = item.status === "sent" ? "good" : item.status === "failed" ? "bad" : "warn";
  return `
    <div class="list-row">
      <div>
        <strong>${escapeHTML(item.title || formatChannel(item.channel))}</strong>
        <span>${escapeHTML(formatChannel(item.channel))} / ${escapeHTML(item.target || "-")} / ${shortTime(item.created_at)}${item.error ? ` / ${item.error}` : ""}</span>
      </div>
      <span class="status ${status}">${escapeHTML(item.status || "pending")}</span>
    </div>
  `;
}

function notificationResultMessage(result, fallback) {
  if (result?.message) return result.message;
  const warnings = result?.warnings || [];
  if (warnings.length) return warnings[0];
  return `${fallback}: ${formatNumber(result?.sent || 0)} sent / ${formatNumber(result?.skipped || 0)} skipped / ${formatNumber(result?.failed || 0)} failed`;
}

function segmentsTable(rows) {
  if (!rows.length) return empty("No indexed segment records returned.");
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>Bucket</th><th>Status</th><th>Lines</th><th>Indexed</th></tr></thead>
      <tbody>${rows.map((item) => `
        <tr>
          <td>${escapeHTML(item.bucket_ts || item.bucket_start || item.path || "-")}<br><span class="subtle">${escapeHTML(item.log_type || "")}</span></td>
          <td>${escapeHTML(item.status || (item.indexed ? "indexed" : "-"))}</td>
          <td>${formatNumber(item.line_count || item.lines_seen || item.lines_combined || item.valid_events || 0)}</td>
          <td>${item.indexed ? "Yes" : shortTime(item.indexed_at || item.updated_at || item.created_at)}</td>
        </tr>
      `).join("")}</tbody>
    </table></div>
  `;
}

function archivesTable(rows) {
  if (!rows.length) return empty("No archives created yet.");
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>Range</th><th>Archive</th><th>Size</th><th>Status</th><th></th></tr></thead>
      <tbody>${rows.map((item) => `
        <tr>
          <td>${shortTime(item.range_start)}<br><span class="subtle">${shortTime(item.range_end)}</span></td>
          <td>${escapeHTML(item.granularity || "-")} / ${escapeHTML(item.log_type || "")}<br><span class="subtle">${escapeHTML(item.path || "")}</span></td>
          <td>${formatBytes(item.compressed_bytes || 0)}<br><span class="subtle">${formatNumber(item.source_file_count || 0)} files</span></td>
          <td>${escapeHTML(item.status || "-")}<br><span class="subtle">expires ${shortTime(item.expires_at)}</span></td>
          <td><button class="button small" type="button" data-action="import-archive" data-archive-id="${escapeAttr(item.id || "")}">${iconHTML("fa-clock-rotate-left")}Import</button></td>
        </tr>
      `).join("")}</tbody>
    </table></div>
  `;
}

function archiveImportsTable(rows) {
  if (!rows.length) return empty("No temporary archive imports.");
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>Import</th><th>Range</th><th>Events</th><th>Expires</th></tr></thead>
      <tbody>${rows.map((item) => `
        <tr>
          <td>${escapeHTML(item.status || "-")}<br><span class="subtle">${escapeHTML(item.reason || item.id || "")}</span></td>
          <td>${shortTime(item.range_start)}<br><span class="subtle">${shortTime(item.range_end)}</span></td>
          <td>${formatNumber(item.imported_event_count || 0)} imported<br><span class="subtle">${formatNumber(item.security_probe_count || 0)} probes / ${formatNumber(item.invalid_event_count || 0)} invalid</span></td>
          <td>${shortTime(item.expires_at)}${item.last_error ? `<br><span class="subtle">${escapeHTML(item.last_error)}</span>` : ""}</td>
        </tr>
      `).join("")}</tbody>
    </table></div>
  `;
}

function rawFilesTable(rows) {
  if (!rows.length) return empty("No raw file activity returned.");
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>Source</th><th>File</th><th>Status</th><th>Size</th><th>Seen</th></tr></thead>
      <tbody>${rows.map((item) => `
        <tr>
          <td>${escapeHTML([item.site_id, item.env].filter(Boolean).join(" / ") || "-")}<br><span class="subtle">${escapeHTML(item.container_id || "")}</span></td>
          <td>${escapeHTML(item.remote_path || item.local_path || "-")}<br><span class="subtle">${escapeHTML(item.log_type || "")}</span></td>
          <td>${escapeHTML(item.status || "-")}</td>
          <td>${formatBytes(item.remote_size || item.local_size || 0)}</td>
          <td>${shortTime(item.last_seen_at || item.downloaded_at || item.remote_mtime)}</td>
        </tr>
      `).join("")}</tbody>
    </table></div>
  `;
}

function topPathsPaginatedPanel() {
  const rows = filtered(searchItems(state.data.traffic.top_paths || [], (item) => `${item.path} ${item.requests}`));
  const page = paginate(rows, state.pages.trafficPaths, 10);
  state.pages.trafficPaths = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Top Paths</h2><p>Most requested paths in ${escapeHTML(activeRangeLabel())}.</p></div>
        <span class="pill">${formatNumber(rows.length)} paths</span>
      </div>
      ${pathsTable(page.rows)}
      ${pager("trafficPaths", page)}
    </article>
  `;
}

function topIPTrafficPanel() {
  const rows = filtered(searchItems(state.data.traffic.top_ips || [], (item) => `${item.ip} ${item.reverse_dns} ${item.known_actor} ${item.actor_type}`));
  const page = paginate(rows, state.pages.trafficIPs, 10);
  state.pages.trafficIPs = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div>
          <h2>Top IP Traffic</h2>
          <p>Request-heavy source IPs. ${riskScoreHelp()}</p>
        </div>
        <span class="pill">${formatNumber(rows.length)} IPs</span>
      </div>
      ${ipTrafficTable(page.rows)}
      ${pager("trafficIPs", page)}
    </article>
  `;
}

function pathsTable(rows) {
  if (!rows.length) return empty("No path data.");
  return `
    <div class="table-wrap">
      <table>
        <thead><tr><th>Path</th><th>Requests</th><th>4xx</th><th>5xx</th><th>Bytes</th></tr></thead>
        <tbody>${rows.map((item) => `
          <tr>
            <td><span class="row-title"><strong>${escapeHTML(item.path || "/")}</strong><span>${formatPercent(ratio(item.requests, state.data.analysis?.totals?.requests))} of selected traffic</span></span></td>
            <td>${formatNumber(item.requests)}</td>
            <td>${formatNumber(item.status_4xx)}</td>
            <td>${formatNumber(item.status_5xx)}</td>
            <td>${formatBytes(item.bytes_sent)}</td>
          </tr>
        `).join("")}</tbody>
      </table>
    </div>
  `;
}

function ipTrafficTable(rows) {
  if (!rows.length) return empty("No IP traffic found.");
  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Requests</th>
            <th>4xx</th>
            <th>5xx</th>
            <th>Bytes</th>
            <th><span class="help-label" title="${escapeAttr(riskScoreDescription())}">Risk Score ${iconHTML("fa-circle-info")}</span></th>
          </tr>
        </thead>
        <tbody>${rows.map((item) => `
          <tr>
            <td><span class="row-title"><strong>${ipLink(item.ip)}</strong><span>${escapeHTML([item.known_actor || item.actor_type, item.reverse_dns].filter(Boolean).join(" / ") || "Unattributed source")}</span></span></td>
            <td>${formatNumber(item.requests)}</td>
            <td>${formatNumber(item.status_4xx)}</td>
            <td>${formatNumber(item.status_5xx)}</td>
            <td>${formatBytes(item.bytes_sent)}</td>
            <td>${riskScoreBadge(item.risk_score)}</td>
          </tr>
        `).join("")}</tbody>
      </table>
    </div>
  `;
}

function riskScoreBadge(score) {
  const value = Number(score ?? 0);
  const level = value >= 70 ? "critical" : value >= 40 ? "high" : value > 0 ? "medium" : "low";
  const label = value ? `${value}/100` : "Not scored";
  return `<span class="severity ${level}" title="${escapeAttr(riskScoreDescription())}">${escapeHTML(label)}</span>`;
}

function riskScoreHelp() {
  return `<span class="inline-help" title="${escapeAttr(riskScoreDescription())}">Risk Score combines error rate, request volume, suspicious patterns, verified actor status, Tor/datacenter hints, and manual intel.</span>`;
}

function riskScoreDescription() {
  return "0-39 low, 40-69 elevated, 70-100 high. The score is derived from OriginPulse IP intelligence: request volume, 4xx/5xx pressure, suspicious path patterns, user-agent classification, Tor/datacenter signals, verified actor matches, and manual labels.";
}

function userAgentsTable(rows) {
  if (!rows.length) return empty("No user-agent rows returned.");
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>User Agent</th><th>Actor</th><th>Requests</th><th>Errors</th></tr></thead>
      <tbody>${rows.map((item) => `
        <tr>
          <td><span class="row-title">${userAgentListLabel(item)}</span></td>
          <td>${escapeHTML(item.known_actor || item.actor_type || "-")}</td>
          <td>${formatNumber(item.requests)}</td>
          <td>${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))}</td>
        </tr>
      `).join("")}</tbody>
    </table></div>
  `;
}

function facetBlock(title, rows) {
  return `
    <div class="facet-block">
      <h3>${escapeHTML(title)}</h3>
      <div class="list">${rows.map(([label, count, color]) => {
        const amount = Number(count || 0);
        return `<div class="facet-row"><span><i style="background: var(--${color || "cyan"})"></i>${escapeHTML(label)}</span><b>${formatCompact(amount)}</b></div>`;
      }).join("") || empty("No facets.")}</div>
    </div>
  `;
}

function compactRow(label, meta, value = "") {
  return `<div class="list-row"><div><strong>${linkifyIPs(label || "-")}</strong><span>${linkifyIPs(meta || "")}</span></div><b>${linkifyIPs(String(value ?? ""))}</b></div>`;
}

function ipLink(ip, label = ip) {
  if (!ip) return "-";
  return `<button class="link-button" type="button" data-detail="ip" data-value="${escapeAttr(ip)}">${escapeHTML(label || ip)}</button>`;
}

function userAgentLink(agent, label = "") {
  const item = typeof agent === "string" ? { family: userAgentFamily(agent), sample: agent } : (agent || {});
  const sample = item.sample || item.user_agent || item.family || "Unknown";
  const info = parseUserAgent(item);
  const key = cacheDetail("user-agent", item, sample);
  return `<button class="link-button" type="button" data-detail="user-agent" data-value="${escapeAttr(key)}">${escapeHTML(label || info.label || item.family || sample || "Unknown")}</button>`;
}

function userAgentListLabel(agent) {
  const info = parseUserAgent(agent);
  return `
    <strong>${userAgentLink(agent, info.label)}</strong>
    <span>${escapeHTML(userAgentMetaLine(agent, info))}</span>
    <span class="ua-sample">${escapeHTML(shortUserAgentSample(info.sample))}</span>
  `;
}

function userAgentMetaLine(agent, info = parseUserAgent(agent)) {
  const item = typeof agent === "string" ? {} : (agent || {});
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  return [
    info.classification,
    info.osLabel,
    info.device,
    info.engine,
    item.known_actor ? `Actor: ${item.known_actor}` : "",
    errors ? `${formatNumber(errors)} errors` : "",
  ].filter(Boolean).join(" / ");
}

function linkifyIPs(value) {
  const text = escapeHTML(String(value ?? ""));
  if (!text) return "";
  return linkifyEscapedIPs(text);
}

function linkifyEscapedIPs(text) {
  const pattern = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
  let html = "";
  let last = 0;
  for (const match of text.matchAll(pattern)) {
    html += text.slice(last, match.index);
    html += ipLink(match[0]);
    last = match.index + match[0].length;
  }
  html += text.slice(last);
  return html;
}

function linkifyIPsInHTML(html) {
  let skip = 0;
  return String(html || "").split(/(<[^>]+>)/g).map((part) => {
    if (!part) return "";
    if (part.startsWith("<")) {
      const tag = part.toLowerCase();
      if (/^<(a|code)\b/.test(tag)) skip++;
      if (/^<\/(a|code)>/.test(tag)) skip = Math.max(0, skip - 1);
      return part;
    }
    return skip ? part : linkifyEscapedIPs(part);
  }).join("");
}

function groupCount(rows, pick) {
  const counts = new Map();
  rows.forEach((row) => {
    const label = String(pick(row) || "unknown");
    counts.set(label, (counts.get(label) || 0) + 1);
  });
  return Array.from(counts, ([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

function resetPagination() {
  state.pages = {
    trafficPaths: 1,
    trafficIPs: 1,
    botRecommendations: 1,
    botAgents: 1,
    botSourceIPs: 1,
    logRecentEvidence: 1,
    logTopPaths: 1,
    logSourceIPs: 1,
    logUserAgents: 1,
    overviewIncidents: 1,
    overviewTopPaths: 1,
    searchTopPaths: 1,
    searchMatchedEvents: 1,
    reportCatalog: 1,
    alertsActive: 1,
    alertRules: 1,
    pulseJobs: 1,
    pulseSegments: 1,
    pulseRawFiles: 1,
    pulseDeliveries: 1,
  };
  if (state.drawer) state.drawer.pages = {};
}

function paginate(rows, page, pageSize = 10) {
  const total = rows.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = clamp(Number(page || 1), 1, totalPages);
  const start = (safePage - 1) * pageSize;
  return {
    rows: rows.slice(start, start + pageSize),
    page: safePage,
    pageSize,
    total,
    totalPages,
    start: total ? start + 1 : 0,
    end: Math.min(total, start + pageSize),
  };
}

function pager(key, page) {
  if (page.totalPages <= 1) {
    return `<div class="pager"><span>Showing ${formatNumber(page.total)} rows</span></div>`;
  }
  const pages = pagerPages(page.page, page.totalPages);
  return `
    <div class="pager">
      <span>Showing ${formatNumber(page.start)}-${formatNumber(page.end)} of ${formatNumber(page.total)}</span>
      <div class="pager-buttons">
        <button class="icon-button" type="button" data-action="page" data-page-kind="previous" data-page-key="${escapeAttr(key)}" data-page="${page.page - 1}" ${page.page <= 1 ? "disabled" : ""} title="Previous page">${iconHTML("fa-chevron-left")}</button>
        ${pages.map((item) => item === "..." ? `<span class="pager-gap">...</span>` : `<button class="button small ${item === page.page ? "primary" : ""}" type="button" data-action="page" data-page-kind="number" data-page-key="${escapeAttr(key)}" data-page="${item}">${item}</button>`).join("")}
        <button class="icon-button" type="button" data-action="page" data-page-kind="next" data-page-key="${escapeAttr(key)}" data-page="${page.page + 1}" ${page.page >= page.totalPages ? "disabled" : ""} title="Next page">${iconHTML("fa-chevron-right")}</button>
      </div>
    </div>
  `;
}

function pagerPages(current, total) {
  if (total <= 5) return Array.from({ length: total }, (_, index) => index + 1);
  const pages = [1];
  const start = Math.max(2, current - 1);
  const end = Math.min(total - 1, current + 1);
  if (start > 2) pages.push("...");
  for (let page = start; page <= end; page += 1) pages.push(page);
  if (end < total - 1) pages.push("...");
  pages.push(total);
  return pages;
}

function statusColorName(status) {
  const value = Number(status);
  if (value >= 500) return "red";
  if (value >= 400) return "amber";
  if (value >= 300) return "purple";
  return "green";
}

function topPathsPanel(kind = "") {
  const rows = filtered(searchItems(state.data.traffic.top_paths || state.data.analysis.slow_paths || [], (item) => `${item.path} ${item.site_id}`)).slice(0, 8);
  return `
    <article class="panel">
      <div class="panel-head"><div><h2>Top Paths</h2><p>${kind ? "Filtered operational pressure." : "Most active request paths."}</p></div></div>
      <div class="list">${rows.map((item) => `
        <div class="list-row"><div><strong>${escapeHTML(item.path || "/")}</strong><span>${formatNumber(item.requests)} requests / ${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))} errors</span></div><b>${formatBytes(item.bytes_sent)}</b></div>
      `).join("") || empty("No path data.")}</div>
    </article>
  `;
}

function issuePageKey(kind, name) {
  return `${kind || "issue"}${name}`;
}

function issueFindingsPanel(kind, issues) {
  const key = issuePageKey(kind, "Findings");
  const page = paginate(issues, state.pages[key], 7);
  state.pages[key] = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>${escapeHTML(routeById[state.route].title)} Findings</h2><p>Filtered from access analysis signals.</p></div>
        <span class="pill">${formatNumber(issues.length)} findings</span>
      </div>
      <div class="list">${page.rows.length ? page.rows.map(issueRow).join("") : empty("No findings for this section.")}</div>
      ${pager(key, page)}
    </article>
  `;
}

function issueTopPathsPanel(kind, sourceRows = null) {
  const rows = sourceRows || filtered(searchItems(state.data.traffic.top_paths || state.data.analysis.slow_paths || [], (item) => `${item.path} ${item.site_id} ${item.requests}`));
  const key = issuePageKey(kind, "TopPaths");
  const page = paginate(rows, state.pages[key], 7);
  state.pages[key] = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Top Paths</h2><p>${kind ? "Filtered operational pressure." : "Most active request paths."}</p></div>
        <span class="pill">${formatNumber(rows.length)} paths</span>
      </div>
      <div class="list">${page.rows.map((item) => `
        <div class="list-row"><div><strong>${escapeHTML(item.path || "/")}</strong><span>${formatNumber(item.requests)} requests / ${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))} errors</span></div><b>${formatBytes(item.bytes_sent)}</b></div>
      `).join("") || empty("No path data.")}</div>
      ${pager(key, page)}
    </article>
  `;
}

function issueEventsPanel(kind, sourceRows = null) {
  const rows = sourceRows || filtered(searchItems(state.data.traffic.recent_errors || [], (item) => `${item.status} ${item.site_id} ${item.env} ${item.client_ip} ${item.method} ${item.path} ${item.user_agent}`));
  const key = issuePageKey(kind, "Events");
  const page = paginate(rows, state.pages[key], 4);
  state.pages[key] = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Recent Error Rows</h2><p>Latest 4xx/5xx evidence.</p></div>
        <span class="pill">${formatNumber(rows.length)} events</span>
      </div>
      ${eventsTable(page.rows)}
      ${pager(key, page)}
    </article>
  `;
}

function issueAgentsPanel(kind, sourceRows = null) {
  const rows = sourceRows || filtered(searchItems(state.data.analysis.user_agents || [], (item) => `${item.family} ${item.sample} ${item.known_actor} ${item.actor_type}`));
  const key = issuePageKey(kind, "Agents");
  const page = paginate(rows, state.pages[key], 7);
  state.pages[key] = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>User Agents</h2><p>Dominant agent families.</p></div>
        <span class="pill">${formatNumber(rows.length)} agents</span>
      </div>
      <div class="list">${page.rows.map((item) => `
        <div class="list-row"><div>${userAgentListLabel(item)}</div><b>${formatNumber(item.requests)}</b></div>
      `).join("") || empty("No user agents.")}</div>
      ${pager(key, page)}
    </article>
  `;
}

function logRecentEvidencePanel(rows) {
  const page = paginate(rows, state.pages.logRecentEvidence, 10);
  state.pages.logRecentEvidence = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Recent Error Evidence</h2><p>Latest matching rows from access logs.</p></div>
        <span class="pill">${formatNumber(rows.length)} events</span>
      </div>
      ${eventsTable(page.rows)}
      ${pager("logRecentEvidence", page)}
    </article>
  `;
}

function logTopPathsPanel() {
  const rows = filtered(searchItems(state.data.traffic.top_paths || state.data.analysis.slow_paths || [], (item) => `${item.path} ${item.site_id} ${item.requests}`));
  const page = paginate(rows, state.pages.logTopPaths, 8);
  state.pages.logTopPaths = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Top Paths</h2><p>Most active request targets.</p></div>
        <span class="pill">${formatNumber(rows.length)} paths</span>
      </div>
      <div class="list">${page.rows.map((item) => `
        <div class="list-row"><div><strong>${escapeHTML(item.path || "/")}</strong><span>${formatNumber(item.requests)} requests / ${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))} errors</span></div><b>${formatBytes(item.bytes_sent)}</b></div>
      `).join("") || empty("No path data.")}</div>
      ${pager("logTopPaths", page)}
    </article>
  `;
}

function logSourceIPsPanel() {
  const rows = filtered(searchItems(state.data.analysis.source_ips || [], (item) => `${item.ip} ${item.reverse_dns} ${item.known_actor} ${item.country_code}`));
  const page = paginate(rows, state.pages.logSourceIPs, 6);
  state.pages.logSourceIPs = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Source IPs</h2><p>Top actors with cached intelligence.</p></div>
        <span class="pill">${formatNumber(rows.length)} IPs</span>
      </div>
      <div class="list">${page.rows.length ? page.rows.map(ipRow).join("") : empty("No source IPs found.")}</div>
      ${pager("logSourceIPs", page)}
    </article>
  `;
}

function logUserAgentsPanel() {
  const rows = filtered(searchItems(state.data.analysis.user_agents || [], (item) => `${item.family} ${item.sample} ${item.known_actor} ${item.actor_type}`));
  const page = paginate(rows, state.pages.logUserAgents, 6);
  state.pages.logUserAgents = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>User Agents</h2><p>Dominant agent families.</p></div>
        <span class="pill">${formatNumber(rows.length)} agents</span>
      </div>
      <div class="list">${page.rows.map((item) => `
        <div class="list-row"><div>${userAgentListLabel(item)}</div><b>${formatNumber(item.requests)}</b></div>
      `).join("") || empty("No user agents.")}</div>
      ${pager("logUserAgents", page)}
    </article>
  `;
}

function overviewTopPathsPaginatedPanel() {
  const rows = filtered(searchItems(state.data.traffic.top_paths || [], (item) => `${item.path} ${item.site_id} ${item.requests}`));
  const page = paginate(rows, state.pages.overviewTopPaths, 6);
  state.pages.overviewTopPaths = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Top Paths</h2><p>Most active request targets.</p></div>
        <span class="pill">${formatNumber(rows.length)} paths</span>
      </div>
      <div class="list">${page.rows.map((item) => `
        <div class="list-row">
          <div><strong>${escapeHTML(item.path || "/")}</strong><span>${formatNumber(item.requests)} requests / ${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))} errors</span></div>
          <b>${formatBytes(item.bytes_sent)}</b>
        </div>
      `).join("") || empty("No path data.")}</div>
      ${pager("overviewTopPaths", page)}
    </article>
  `;
}

function topAgentsPanel() {
  const rows = (state.data.analysis.user_agents || []).slice(0, 8);
  return `
    <article class="panel">
      <div class="panel-head"><div><h2>User Agents</h2><p>Dominant agent families.</p></div></div>
      <div class="list">${rows.map((item) => `
        <div class="list-row"><div>${userAgentListLabel(item)}</div><b>${formatNumber(item.requests)}</b></div>
      `).join("") || empty("No user agents.")}</div>
    </article>
  `;
}

function statusPanel() {
  return `
    <article class="panel chart-card">
      <div class="panel-head">
        <div><h2>Status Mix</h2><p>HTTP status classes in range. Hover bars for counts.</p></div>
        ${chartLegend([["2xx", "green"], ["3xx", "purple"], ["4xx", "amber"], ["5xx", "red"]])}
      </div>
      <canvas id="statusBars" class="large-chart"></canvas>
    </article>
  `;
}

function chartLegend(items) {
  return `<div class="chart-legend">${items.map(([label, color]) => `<span><i style="background: var(--${color})"></i>${escapeHTML(label)}</span>`).join("")}</div>`;
}

function systemPanel() {
  const configured = state.data.overview.database_configured;
  return `
    <article class="panel">
      <div class="panel-head"><div><h2>System Health</h2><p>Collector and storage readiness.</p></div></div>
      <div class="panel-body">${facts([
        ["Database", configured ? "Configured" : "Not configured"],
        ["Collection", state.data.overview.collection_enabled ? "Enabled" : "Manual"],
        ["Machine token", state.data.overview.machine_token ? "Ready" : "Missing"],
        ["SSH key", state.data.overview.ssh_key ? "Ready" : "Missing"],
      ])}</div>
    </article>
  `;
}

function eventsPanel() {
  return `
    <article class="panel">
      <div class="panel-head"><div><h2>Recent Error Rows</h2><p>Latest 4xx/5xx evidence.</p></div></div>
      ${eventsTable((state.data.traffic.recent_errors || []).slice(0, 8))}
    </article>
  `;
}

function alertRuleRows(alerts = state.data.alerts || []) {
  return Object.entries(groupBy(alerts, (item) => item.rule_key || "unknown")).map(([rule, items]) => {
    const sorted = [...items].sort((a, b) => new Date(b.last_seen_at || b.created_at || 0) - new Date(a.last_seen_at || a.created_at || 0));
    const critical = sorted.filter((item) => normalizeSeverity(item.severity) === "critical").length;
    const high = sorted.filter((item) => normalizeSeverity(item.severity) === "high").length;
    const severity = sorted.some((item) => normalizeSeverity(item.severity) === "critical") ? "critical" : sorted.some((item) => normalizeSeverity(item.severity) === "high") ? "high" : normalizeSeverity(sorted[0]?.severity);
    return {
      rule_key: rule,
      title: sorted[0]?.title || rule,
      severity,
      count: sorted.length,
      critical,
      high,
      last_seen_at: sorted[0]?.last_seen_at,
      alerts: sorted,
    };
  }).sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.count - a.count || a.rule_key.localeCompare(b.rule_key));
}

function alertRuleRow(item, index = 0) {
  const key = cacheDetail("alert-rule", item, `${item.rule_key || "unknown"}:${index}`);
  return `
    <div class="list-row">
      <div>
        <strong>${escapeHTML(item.title || item.rule_key || "Rule")}</strong>
        <span>${formatNumber(item.count)} firing / ${formatNumber(item.critical)} critical / ${formatNumber(item.high)} high / last ${shortTime(item.last_seen_at)}</span>
      </div>
      <button class="button small" type="button" data-detail="alert-rule" data-value="${escapeAttr(key)}">${escapeHTML(item.severity || "open")}</button>
    </div>
  `;
}

function severityRank(value) {
  const sev = normalizeSeverity(value);
  if (sev === "critical") return 4;
  if (sev === "high") return 3;
  if (sev === "medium") return 2;
  return 1;
}

function alertSearchText(item) {
  return `${item.id || ""} ${item.rule_key || ""} ${item.title || ""} ${item.severity || ""} ${item.status || ""} ${item.site_id || ""} ${item.env || ""} ${item.actor_type || ""} ${item.actor_value || ""} ${item.summary || ""}`;
}

function renderAlertDetail(item) {
  const details = item.details || {};
  const requests = (item.requests || item.related_requests || []).length ? (item.requests || item.related_requests || []) : alertRelatedRequests(item);
  const requestPage = drawerPage("alertRequests", requests, 6);
  const sev = normalizeSeverity(item.severity);
  return `
    ${miniMetrics([
      ["Score", formatNumber(item.score || 0), "fa-gauge-high"],
      ["Requests", formatNumber(details.requests || requests.length), "fa-arrow-trend-up"],
      ["4xx", formatNumber(details.status_4xx), "fa-triangle-exclamation"],
      ["5xx", formatNumber(details.status_5xx), "fa-bolt"],
    ])}
    <section class="detail-grid two">
      <article class="detail-card">
        <h3>Alert Context</h3>
        ${factsRich([
          ["Title", escapeHTML(item.title || item.rule_key || "Alert")],
          ["Severity", `<span class="severity ${sev}">${escapeHTML(sev)}</span>`],
          ["Status", escapeHTML(item.status || "open")],
          ["Rule", escapeHTML(item.rule_key || "-")],
          ["Project", escapeHTML(item.site_id || "-")],
          ["Environment", escapeHTML(item.env || "-")],
          ["Actor", alertActorLink(item)],
        ])}
      </article>
      <article class="detail-card">
        <h3>Evidence Window</h3>
        ${facts([
          ["Summary", item.summary || "-"],
          ["First Seen", shortTime(item.first_seen_at || details.range?.first_seen)],
          ["Last Seen", shortTime(item.last_seen_at || details.range?.last_seen)],
          ["Created", shortTime(item.created_at)],
          ["Window Start", shortTime(details.range?.first_seen)],
          ["Window End", shortTime(details.range?.last_seen)],
        ])}
      </article>
    </section>
    <article class="detail-card">
      <div class="detail-card-head"><h3>Related Requests</h3><span>${formatNumber(requestPage.total)} rows</span></div>
      ${securityRequestRows(requestPage.rows)}
      ${drawerPager("alertRequests", requestPage)}
    </article>
    <article class="detail-card">
      <h3>Actions</h3>
      <div class="toolbar inline-toolbar">
        ${item.actor_type === "ip" && item.actor_value ? `<button class="button small" type="button" data-detail="ip" data-value="${escapeAttr(item.actor_value)}">${iconHTML("fa-location-crosshairs")}Open IP</button>` : ""}
        ${isUserAgentActor(item.actor_type) && item.actor_value ? `<button class="button small" type="button" data-detail="user-agent" data-value="${escapeAttr(cacheDetail("user-agent", { sample: item.actor_value }, item.actor_value))}">${iconHTML("fa-robot")}Open User Agent</button>` : ""}
        <button class="button small" type="button" data-route="logs">${iconHTML("fa-rectangle-list")}Live Logs</button>
        <button class="button small" type="button" data-route="security">${iconHTML("fa-shield-halved")}Security</button>
        <button class="button small" type="button" data-route="reports">${iconHTML("fa-file-lines")}Reports</button>
      </div>
    </article>
  `;
}

function renderAlertRuleDetail(item) {
  const alerts = item.alerts || [];
  const requests = uniqueBy(alerts.flatMap(alertRelatedRequests), (row) => `${row.ts || ""}:${row.client_ip || ""}:${row.path || ""}:${row.status || ""}`);
  const alertPage = drawerPage("alertRuleAlerts", alerts, 7);
  const requestPage = drawerPage("alertRuleRequests", requests, 6);
  return `
    ${miniMetrics([
      ["Open Alerts", formatNumber(item.count || alerts.length), "fa-bell"],
      ["Critical", formatNumber(item.critical || alerts.filter((row) => normalizeSeverity(row.severity) === "critical").length), "fa-circle-exclamation"],
      ["High", formatNumber(item.high || alerts.filter((row) => normalizeSeverity(row.severity) === "high").length), "fa-triangle-exclamation"],
      ["Related Requests", formatNumber(requests.length), "fa-rectangle-list"],
    ])}
    <section class="detail-grid two">
      <article class="detail-card">
        <h3>Rule Context</h3>
        ${factsRich([
          ["Rule", escapeHTML(item.rule_key || "-")],
          ["Title", escapeHTML(item.title || item.rule_key || "Alert rule")],
          ["Severity", `<span class="severity ${normalizeSeverity(item.severity)}">${escapeHTML(normalizeSeverity(item.severity))}</span>`],
          ["Last Seen", escapeHTML(shortTime(item.last_seen_at))],
        ])}
      </article>
      <article class="detail-card">
        <h3>Rule Mix</h3>
        ${facts([
          ["Projects", unique(alerts.map((row) => row.site_id)).join(", ") || "-"],
          ["Environments", unique(alerts.map((row) => row.env)).join(", ") || "-"],
          ["Actor Types", unique(alerts.map((row) => row.actor_type)).join(", ") || "-"],
          ["Total Score", formatNumber(sum(alerts, "score"))],
        ])}
      </article>
    </section>
    <article class="detail-card">
      <div class="detail-card-head"><h3>Alerts</h3><span>${formatNumber(alertPage.total)} rows</span></div>
      <div class="list">${alertPage.rows.map(alertRow).join("") || empty("No alerts found.")}</div>
      ${drawerPager("alertRuleAlerts", alertPage)}
    </article>
    <article class="detail-card">
      <div class="detail-card-head"><h3>Related Requests</h3><span>${formatNumber(requestPage.total)} rows</span></div>
      ${securityRequestRows(requestPage.rows)}
      ${drawerPager("alertRuleRequests", requestPage)}
    </article>
  `;
}

function alertActorLink(item) {
  if (item.actor_type === "ip" && item.actor_value) return ipLink(item.actor_value);
  if (isUserAgentActor(item.actor_type) && item.actor_value) return userAgentLink(item.actor_value);
  return escapeHTML([item.actor_type, item.actor_value].filter(Boolean).join(" / ") || "-");
}

function isUserAgentActor(actorType) {
  return /^(user_agent|user-agent|ua)$/i.test(String(actorType || ""));
}

function alertPeerAlerts(item) {
  return (state.data.alerts || []).filter((row) => row.id !== item.id && (
    (item.rule_key && row.rule_key === item.rule_key) ||
    (item.actor_type && item.actor_value && row.actor_type === item.actor_type && row.actor_value === item.actor_value) ||
    (item.site_id && row.site_id === item.site_id && normalizeSeverity(row.severity) === normalizeSeverity(item.severity))
  )).sort((a, b) => new Date(b.last_seen_at || b.created_at || 0) - new Date(a.last_seen_at || a.created_at || 0));
}

function alertRelatedRequests(item) {
  const actor = String(item.actor_value || "");
  const actorType = String(item.actor_type || "");
  const summary = String(item.summary || "");
  return (state.data.traffic.recent_errors || []).filter((event) => {
    if (item.site_id && event.site_id !== item.site_id) return false;
    if (item.env && event.env && event.env !== item.env) return false;
    if (actorType === "ip" && actor && event.client_ip === actor) return true;
    if (actorType === "path" && actor && event.path === actor) return true;
    if (isUserAgentActor(actorType) && actor && event.user_agent === actor) return true;
    if (actor && (event.path === actor || event.client_ip === actor || event.user_agent === actor)) return true;
    if (item.rule_key && /5xx/.test(item.rule_key) && Number(event.status || 0) >= 500 && summary.includes(event.path || "")) return true;
    if (item.rule_key && /4xx/.test(item.rule_key) && Number(event.status || 0) >= 400 && Number(event.status || 0) < 500 && summary.includes(event.path || "")) return true;
    return false;
  });
}

function alertRelatedIPs(item, requests) {
  const rows = [...requests];
  if (item.actor_type === "ip" && item.actor_value) rows.push({ client_ip: item.actor_value, status: Number(item.details?.status_5xx || 0) ? 500 : 400, ts: item.last_seen_at });
  return groupedRequestIPs(rows);
}

function groupedRequestIPs(rows) {
  return Object.entries(groupBy(rows, (row) => row.client_ip || row.ip)).filter(([ip]) => ip).map(([ip, items]) => ({
    ip,
    requests: items.length,
    errors: items.filter((item) => Number(item.status || 0) >= 400).length,
    last_seen: items[0]?.ts || items[0]?.last_seen_at,
  })).sort((a, b) => b.errors - a.errors || b.requests - a.requests || a.ip.localeCompare(b.ip));
}

function uniqueBy(rows, keyFn) {
  const seen = new Set();
  return rows.filter((row) => {
    const key = keyFn(row);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function securitySignalRows() {
  const rows = [];
  for (const item of (state.data.analysis.admin_probes || [])) rows.push(normalizeSecuritySignal("Admin probe", "admin", item));
  for (const item of (state.data.analysis.injection_probes || [])) rows.push(normalizeSecuritySignal("Injection probe", "injection", item));
  for (const item of (state.data.analysis.tor_sources || [])) rows.push(normalizeSecuritySignal("Tor source", "tor", item));
  return rows;
}

function normalizeSecuritySignal(title, kind, item) {
  const risk = Number(item.risk_score || (kind === "tor" ? 70 : 60));
  return { ...item, title, kind, risk_score: risk };
}

function securitySignalSearchText(item) {
  return `${item.title} ${item.kind} ${item.category} ${item.rule_key} ${item.site_id} ${item.env} ${item.ip} ${item.method} ${item.path} ${item.sample_query} ${item.match_reason}`;
}

function securitySignalRow(item, index = 0) {
  const key = cacheDetail("security-signal", item, `${item.kind}:${item.ip || ""}:${item.path || ""}:${item.site_id || ""}:${index}`);
  const label = item.kind === "tor" ? `${item.title} ${item.ip || ""}` : item.title;
  const meta = [
    item.site_id,
    item.env,
    item.ip,
    item.path,
    `${formatNumber(item.requests)} requests`,
    item.match_reason || item.category,
  ].filter(Boolean).join(" / ");
  const level = Number(item.risk_score || 0) >= 70 ? "critical" : "high";
  return `
    <div class="list-row">
      <div><strong>${linkifyIPs(label)}</strong><span>${linkifyIPs(meta)}</span></div>
      <button class="button small" type="button" data-detail="security-signal" data-value="${escapeAttr(key)}">${escapeHTML(level)}</button>
    </div>
  `;
}

function securityRelatedIPs(item) {
  const byIP = new Map();
  const add = (row, meta = "") => {
    const ip = row.ip || row.client_ip || "";
    if (!ip) return;
    const current = byIP.get(ip) || { ip, requests: 0, status_4xx: 0, status_5xx: 0, risk_score: 0, meta };
    current.requests += Number(row.requests || 1);
    current.status_4xx += Number(row.status_4xx || (Number(row.status) >= 400 && Number(row.status) < 500 ? 1 : 0));
    current.status_5xx += Number(row.status_5xx || (Number(row.status) >= 500 ? 1 : 0));
    current.risk_score = Math.max(current.risk_score, Number(row.risk_score || 0));
    current.meta = current.meta || meta;
    byIP.set(ip, current);
  };
  add(item, item.kind || item.category || "signal");
  securitySignalRows()
    .filter((row) => row.ip && (row.ip === item.ip || row.kind === item.kind || row.category === item.category))
    .forEach((row) => add(row, row.kind || row.category || "peer signal"));
  (state.data.analysis.source_ips || [])
    .filter((row) => row.ip && (row.ip === item.ip || byIP.has(row.ip)))
    .forEach((row) => add(row, [row.actor_type, row.country_code, row.reverse_dns].filter(Boolean).join(" / ")));
  return Array.from(byIP.values()).sort((a, b) => b.risk_score - a.risk_score || b.requests - a.requests);
}

function securityRelatedRequests(item) {
  const events = (state.data.traffic.recent_errors || []).filter((event) => {
    if (item.ip && event.client_ip === item.ip) return true;
    if (item.path && event.path === item.path) return true;
    if (item.site_id && item.kind !== "tor" && event.site_id === item.site_id && securityEventMatchesKind(event, item.kind)) return true;
    return false;
  });
  const aggregateRows = securitySignalRows()
    .filter((row) => row.kind === item.kind && (row.ip === item.ip || row.path === item.path || row.site_id === item.site_id))
    .map(securitySignalAsRequest);
  return events.concat(aggregateRows);
}

function securitySignalAsRequest(row) {
  return {
    ts: row.last_seen || row.first_seen,
    site_id: row.site_id,
    client_ip: row.ip,
    method: row.method || "GET",
    path: row.path || "/",
    status: Number(row.status_5xx || 0) > 0 ? 500 : Number(row.status_4xx || 0) > 0 ? 403 : "-",
    user_agent: `${row.title || row.kind || "Security signal"} / ${row.match_reason || row.category || row.rule_key || "aggregate"} / ${formatNumber(row.requests)} requests`,
  };
}

function securityEventMatchesKind(event, kind) {
  const text = `${event.path || ""} ${event.query || ""} ${event.user_agent || ""}`;
  if (kind === "admin") return /admin|login|wp-login|administrator|manager/i.test(text);
  if (kind === "injection") return /sql|select|union|sleep|benchmark|script|%27|%22|etc\/passwd|information_schema/i.test(text);
  if (kind === "tor") return true;
  return /admin|sql|select|union|script|passwd|wp-login/i.test(text);
}

function findUserAgentByValue(value) {
  const token = String(value || "").replace(/^user-agent:/, "");
  return (state.data.analysis.user_agents || []).find((row) => row.sample === token || row.user_agent === token || row.family === token) || null;
}

function userAgentRelatedRequests(item) {
  const sample = item.sample || item.user_agent || "";
  const family = item.family || userAgentFamily(sample);
  const familyNeedle = String(family || "").toLowerCase();
  const sampleNeedle = String(sample || "").toLowerCase();
  return (state.data.traffic.recent_errors || []).filter((event) => {
    const ua = String(event.user_agent || "").toLowerCase();
    if (!ua) return false;
    if (sampleNeedle && ua === sampleNeedle) return true;
    if (sampleNeedle && sampleNeedle.length > 12 && (ua.includes(sampleNeedle) || sampleNeedle.includes(ua))) return true;
    if (familyNeedle && familyNeedle !== "unknown" && familyNeedle.length > 2 && ua.includes(familyNeedle)) return true;
    return false;
  });
}

function userAgentGroupedRows(rows, keyFn) {
  return Object.entries(groupBy(rows, keyFn)).map(([label, items]) => ({
    label: label || "Unknown",
    requests: items.length,
    errors: items.filter((item) => Number(item.status || 0) >= 400).length,
    last_seen: items[0]?.ts,
    items,
  })).sort((a, b) => b.requests - a.requests || a.label.localeCompare(b.label));
}

function renderUserAgentDetail(item) {
  const agent = item.user_agent || item;
  const traffic = item.traffic || {};
  const sample = agent.sample || agent.user_agent || item.sample || item.family || "Unknown";
  const info = parseUserAgent({ ...agent, sample });
  const family = agent.family || info.family;
  const relatedRequests = item.recent_requests || userAgentRelatedRequests({ ...agent, sample, family });
  const relatedIPs = (item.top_ips || []).length ? item.top_ips : userAgentGroupedRows(relatedRequests, (row) => row.client_ip);
  const relatedPaths = (item.top_paths || []).length ? item.top_paths : userAgentGroupedRows(relatedRequests, (row) => row.path || "/");
  const ipPage = drawerPage("uaIPs", relatedIPs, 6);
  const pathPage = drawerPage("uaPaths", relatedPaths, 6);
  const requestPage = drawerPage("uaRequests", relatedRequests, 6);
  const requests = Number(traffic.requests || agent.requests || item.requests || relatedRequests.length || 0);
  const errors = Number(traffic.status_4xx || agent.status_4xx || item.status_4xx || 0) + Number(traffic.status_5xx || agent.status_5xx || item.status_5xx || 0);
  return `
    ${miniMetrics([
      ["Requests", formatNumber(requests), "fa-arrow-trend-up"],
      ["Errors", formatNumber(errors || relatedRequests.filter((row) => Number(row.status || 0) >= 400).length), "fa-triangle-exclamation"],
      ["Related IPs", formatNumber(relatedIPs.length), "fa-network-wired"],
      ["Related Paths", formatNumber(relatedPaths.length), "fa-route"],
    ])}
    <section class="detail-grid two">
      <article class="detail-card">
        <h3>User Agent Context</h3>
        ${facts([
          ["Name", info.label || "-"],
          ["Classification", info.classification || "-"],
          ["Browser", info.browser ? `${info.browser}${info.browserVersion ? ` ${normalizeVersion(info.browserVersion)}` : ""}` : "-"],
          ["Application", info.app ? `${info.app}${info.appVersion ? ` ${normalizeVersion(info.appVersion)}` : ""}` : "-"],
          ["OS", info.osLabel || "-"],
          ["Device", info.device || "-"],
          ["Engine", info.engine || "-"],
          ["Evidence", item.source || "loaded view"],
        ])}
      </article>
      <article class="detail-card">
        <h3>Attribution</h3>
        ${facts([
          ["Family", family || "-"],
          ["Known Actor", info.knownActor || agent.known_actor || "-"],
          ["Actor Type", agent.actor_type || info.actorType || "-"],
          ["Platform", info.platform || "-"],
          ["First Seen", shortTime(agent.first_seen || traffic.first_seen)],
          ["Last Seen", shortTime(agent.last_seen || traffic.last_seen)],
          ["Error Rate", formatPercent(ratio(errors, requests || relatedRequests.length))],
        ])}
      </article>
    </section>
    <article class="detail-card">
      <h3>Raw User Agent</h3>
      <pre>${escapeHTML(sample)}</pre>
    </article>
    <section class="detail-grid two">
      <article class="detail-card">
        <div class="detail-card-head"><h3>Related IPs</h3><span>${formatNumber(ipPage.total)} rows</span></div>
        <div class="list">${ipPage.rows.map((row) => `
          <div class="list-row">
            <div><strong>${ipLink(row.ip || row.label)}</strong><span>${formatNumber(row.requests)} events / ${formatNumber(row.errors || ((row.status_4xx || 0) + (row.status_5xx || 0)))} errors</span></div>
            <b>${shortTime(row.last_seen || row.last_seen_at)}</b>
          </div>
        `).join("") || empty("No related IPs in this range.")}</div>
        ${drawerPager("uaIPs", ipPage)}
      </article>
      <article class="detail-card">
        <div class="detail-card-head"><h3>Related Paths</h3><span>${formatNumber(pathPage.total)} rows</span></div>
        <div class="list">${pathPage.rows.map((row) => `
          <div class="list-row">
            <div><strong>${escapeHTML(row.path || row.label || "/")}</strong><span>${formatNumber(row.requests)} events / ${formatNumber(row.errors || ((row.status_4xx || 0) + (row.status_5xx || 0)))} errors</span></div>
            <b>${row.bytes_sent !== undefined ? formatBytes(row.bytes_sent) : shortTime(row.last_seen)}</b>
          </div>
        `).join("") || empty("No related paths in this range.")}</div>
        ${drawerPager("uaPaths", pathPage)}
      </article>
    </section>
    <article class="detail-card">
      <div class="detail-card-head"><h3>Related Requests</h3><span>${formatNumber(requestPage.total)} rows</span></div>
      ${userAgentRequestRows(requestPage.rows)}
      ${drawerPager("uaRequests", requestPage)}
    </article>
  `;
}

function incidentRows() {
  const alerts = state.data.alerts.map(alertRow);
  const errors = (state.data.traffic.recent_errors || []).slice(0, 4).map((event) => `
    <div class="list-row"><div><strong>${escapeHTML(event.status || "Error")} ${escapeHTML(event.path || "/")}</strong><span>${escapeHTML(event.site_id || "-")} / ${event.client_ip ? ipLink(event.client_ip) : "-"} / ${event.user_agent ? userAgentLink(event.user_agent, shortUserAgentSample(event.user_agent)) : "-"} / ${shortTime(event.ts)}</span></div><span class="severity ${Number(event.status) >= 500 ? "critical" : "high"}">${escapeHTML(event.status || "error")}</span></div>
  `);
  return alerts.concat(errors);
}

function recentIncidentsPaginatedPanel() {
  const rows = incidentRows();
  const page = paginate(rows, state.pages.overviewIncidents, 6);
  state.pages.overviewIncidents = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Recent Incidents</h2><p>Open alerts and error evidence.</p></div>
        <span class="pill">${formatNumber(rows.length)} incidents</span>
      </div>
      <div class="list">${page.rows.join("") || empty("No incidents found.")}</div>
      ${pager("overviewIncidents", page)}
    </article>
  `;
}

function siteRows(options = {}) {
  const analysis = options.estate ? state.data.estateAnalysis || state.data.analysis || {} : state.data.analysis || {};
  const siteStats = groupBy(analysis.sites || [], (item) => item.site_id);
  const configured = state.data.sites.length ? state.data.sites : (analysis.sites || []).map((item) => ({ id: item.site_id, name: item.site_id, envs: [item.env] }));
  const rows = configured.map((site) => {
    const stats = siteStats[site.id] || [];
    const requests = sum(stats, "requests");
    const errors = sum(stats, "status_4xx") + sum(stats, "status_5xx");
    const errorRate = requests ? errors / requests : 0;
    const maxP95 = Math.max(0, ...stats.map((item) => Number(item.p95_request_time_ms || 0)));
    const risk = Math.min(99, Math.round(errorRate * 900 + maxP95 / 90));
    const health = risk >= 65 ? "critical" : risk >= 25 ? "warning" : "healthy";
    return {
      id: site.id,
      name: site.name || site.id,
      envs: (site.envs || stats.map((item) => item.env)).join(", ") || "-",
      requests,
      errorRate,
      risk,
      health,
      tags: site.tags || [],
    };
  });
  return filtered(searchItems(rows, (site) => `${site.id} ${site.name} ${site.envs} ${(site.tags || []).join(" ")}`)).sort((a, b) => b.risk - a.risk || b.requests - a.requests);
}

function issuesFor(kind) {
  const rows = state.data.analysis.issues || [];
  const matchers = {
    errors: (item) => /error|5xx|4xx|fatal|exception/i.test(`${item.rule_key} ${item.title} ${item.summary}`),
    php: (item) => /php|fatal|wordpress|wp-/i.test(`${item.rule_key} ${item.title} ${item.summary} ${item.actor_value}`),
    mysql: (item) => /mysql|sql|database|query/i.test(`${item.rule_key} ${item.title} ${item.summary}`),
    security: (item) => /security|probe|injection|admin|tor|bot|abuse|login/i.test(`${item.rule_key} ${item.title} ${item.summary}`),
  };
  return filtered(searchItems(rows.filter(matchers[kind] || (() => true)), issueSearchText));
}

function issueSearchText(item) {
  return `${item.rule_key} ${item.title} ${item.summary} ${item.site_id} ${item.actor_value}`;
}

function isPHPPathRow(item) {
  return /php|wordpress|wp-|xmlrpc|admin-ajax|wp-json|wp-content|wp-admin/i.test(`${item.path || ""} ${item.site_id || ""}`);
}

function isPHPEventRow(item) {
  return /php|wordpress|wp-|xmlrpc|admin-ajax|wp-json|wp-content|wp-admin/i.test(item.path || "");
}

function userAgentsFromEvents(events) {
  const counts = new Map();
  events.forEach((event) => {
    const sample = event.user_agent || "Unknown";
    const info = parseUserAgent(sample);
    const row = counts.get(sample) || { family: info.family, sample, known_actor: info.knownActor || "", actor_type: info.actorType, requests: 0 };
    row.requests += 1;
    counts.set(sample, row);
  });
  return Array.from(counts.values()).sort((a, b) => b.requests - a.requests || a.family.localeCompare(b.family));
}

function userAgentFamily(sample) {
  return parseUserAgent(sample).family;
}

function parseUserAgent(agent) {
  const item = typeof agent === "string" ? { sample: agent } : (agent || {});
  const sample = String(item.sample || item.user_agent || item.family || "Unknown");
  const known = item.known_actor || "";
  const bot = detectBot(sample, known);
  const tool = detectTool(sample);
  const browser = item.browser_family ? { name: item.browser_family, version: item.browser_version || "" } : detectBrowser(sample);
  const os = item.os_family
    ? { name: item.os_family, version: item.os_version || "", label: `${item.os_family}${item.os_version ? ` ${item.os_version}` : ""}`, platform: item.os_family }
    : detectOS(sample);
  const engine = detectEngine(sample);
  const app = !bot && !tool && !browser.name ? detectApp(sample) : null;
  const isBot = Boolean(item.is_bot || bot || /crawler|bot|spider/i.test(item.actor_type || item.family || ""));
  const isTool = Boolean(item.is_tool || tool || /tool|script|scanner/i.test(item.actor_type || item.family || ""));
  const name = bot?.name || tool?.name || browser.name || app?.name || readableToken(item.family || sample);
  const version = bot?.version || tool?.version || browser.version || app?.version || "";
  const actorType = isBot ? "crawler" : isTool ? "tool" : item.actor_type || (browser.name ? "browser" : "unknown");
  const classification = bot ? "Crawler" : tool ? "Tool / script" : browser.name ? "Browser" : app ? "Application" : readableToken(actorType);
  const family = bot?.family || tool?.family || browser.name || app?.name || readableToken(item.family || actorType || sample);
  const label = [
    name,
    version ? normalizeVersion(version) : "",
    (browser.name || app) && os.label && os.label !== "Unknown OS" ? `on ${os.label}` : "",
  ].filter(Boolean).join(" ");
  return {
    sample,
    label: label || readableToken(sample),
    family,
    browser: browser.name || "",
    browserVersion: browser.version || "",
    app: app?.name || "",
    appVersion: app?.version || "",
    os: os.name,
    osVersion: os.version,
    osLabel: os.label,
    platform: os.platform,
    device: item.device_family || detectDevice(sample, os.name, isBot, isTool),
    engine,
    classification,
    actorType,
    isBot,
    isTool,
    knownActor: known || bot?.knownActor || "",
  };
}

function detectBrowser(sample) {
  const patterns = [
    [/EdgA?\/([\d.]+)/i, "Microsoft Edge"],
    [/OPR\/([\d.]+)/i, "Opera"],
    [/SamsungBrowser\/([\d.]+)/i, "Samsung Internet"],
    [/CriOS\/([\d.]+)/i, "Chrome iOS"],
    [/FxiOS\/([\d.]+)/i, "Firefox iOS"],
    [/Firefox\/([\d.]+)/i, "Firefox"],
    [/(?:Chrome|Chromium)\/([\d.]+)/i, "Chrome"],
    [/Version\/([\d.]+).*Safari\//i, "Safari"],
    [/MSIE\s([\d.]+)/i, "Internet Explorer"],
    [/Trident\/.*rv:([\d.]+)/i, "Internet Explorer"],
  ];
  for (const [regex, name] of patterns) {
    const match = sample.match(regex);
    if (match) return { name, version: match[1] || "" };
  }
  return { name: "", version: "" };
}

function detectTool(sample) {
  const patterns = [
    [/curl\/([\d.]+)/i, "curl", "curl"],
    [/Wget\/([\d.]+)/i, "Wget", "wget"],
    [/Go-http-client\/([\d.]+)/i, "Go HTTP client", "go-http-client"],
    [/python-requests\/([\d.]+)/i, "Python requests", "python"],
    [/Python-urllib\/([\d.]+)/i, "Python urllib", "python"],
    [/aiohttp\/([\d.]+)/i, "aiohttp", "python"],
    [/Scrapy\/([\d.]+)/i, "Scrapy", "scrapy"],
    [/okhttp\/([\d.]+)/i, "OkHttp", "okhttp"],
    [/PostmanRuntime\/([\d.]+)/i, "Postman Runtime", "postman"],
    [/axios\/([\d.]+)/i, "Axios", "axios"],
    [/node-fetch\/([\d.]+)/i, "node-fetch", "node-fetch"],
    [/Java\/([\d.]+)/i, "Java", "java"],
  ];
  for (const [regex, name, family] of patterns) {
    const match = sample.match(regex);
    if (match) return { name, version: match[1] || "", family };
  }
  return null;
}

function detectBot(sample, knownActor = "") {
  const patterns = [
    [/Googlebot\/?([\d.]*)/i, "Googlebot", "Google"],
    [/bingbot\/?([\d.]*)/i, "Bingbot", "Microsoft"],
    [/DuckDuckBot\/?([\d.]*)/i, "DuckDuckBot", "DuckDuckGo"],
    [/YandexBot\/?([\d.]*)/i, "YandexBot", "Yandex"],
    [/Baiduspider\/?([\d.]*)/i, "Baiduspider", "Baidu"],
    [/Applebot\/?([\d.]*)/i, "Applebot", "Apple"],
    [/GPTBot\/?([\d.]*)/i, "GPTBot", "OpenAI"],
    [/ChatGPT-User\/?([\d.]*)/i, "ChatGPT User", "OpenAI"],
    [/ClaudeBot\/?([\d.]*)/i, "ClaudeBot", "Anthropic"],
    [/AhrefsBot\/?([\d.]*)/i, "AhrefsBot", "Ahrefs"],
    [/SemrushBot\/?([\d.]*)/i, "SemrushBot", "Semrush"],
    [/facebookexternalhit\/?([\d.]*)/i, "Facebook crawler", "Meta"],
    [/LinkedInBot\/?([\d.]*)/i, "LinkedInBot", "LinkedIn"],
    [/Twitterbot\/?([\d.]*)/i, "Twitterbot", "X"],
    [/Slackbot-LinkExpanding\/?([\d.]*)/i, "Slackbot", "Slack"],
    [/VerityBot\/?([\d.]*)/i, "VerityBot", knownActor || ""],
    [/YisouSpider\/?([\d.]*)/i, "YisouSpider", knownActor || ""],
  ];
  for (const [regex, name, actor] of patterns) {
    const match = sample.match(regex);
    if (match) return { name, version: match[1] || "", family: name, knownActor: actor };
  }
  if (/bot|crawler|spider|slurp/i.test(sample)) {
    const token = readableToken(sample.split(/[ (;]/)[0] || "crawler");
    return { name: token, version: versionAfterSlash(sample), family: "Crawler", knownActor };
  }
  return null;
}

function detectApp(sample) {
  const match = sample.match(/^([A-Za-z0-9._-]+)\/([\d.]+).*CFNetwork\/([\d.]+).*Darwin\/([\d.]+)/i);
  if (!match) return null;
  return { name: readableToken(match[1]), version: match[2] };
}

function detectOS(sample) {
  let match = sample.match(/Windows NT ([\d.]+)/i);
  if (match) {
    const version = windowsVersion(match[1]);
    return { name: "Windows", version, label: `Windows ${version}`, platform: "Windows" };
  }
  match = sample.match(/Mac OS X ([\d_]+)/i);
  if (match) {
    const version = match[1].replaceAll("_", ".");
    return { name: "macOS", version, label: `macOS ${version}`, platform: "Mac" };
  }
  match = sample.match(/(?:iPhone|CPU) OS ([\d_]+)/i);
  if (match) {
    const version = match[1].replaceAll("_", ".");
    return { name: "iOS", version, label: `iOS ${version}`, platform: "iOS" };
  }
  match = sample.match(/Android ([\d.]+)/i);
  if (match) return { name: "Android", version: match[1], label: `Android ${match[1]}`, platform: "Android" };
  match = sample.match(/CrOS [^ ]+ ([\d.]+)/i);
  if (match) return { name: "Chrome OS", version: match[1], label: `Chrome OS ${match[1]}`, platform: "Chrome OS" };
  match = sample.match(/Darwin\/([\d.]+)/i);
  if (match) return { name: "Darwin", version: match[1], label: `Darwin ${match[1]}`, platform: "Apple" };
  if (/Linux/i.test(sample)) return { name: "Linux", version: "", label: "Linux", platform: "Linux" };
  return { name: "", version: "", label: "Unknown OS", platform: "" };
}

function detectDevice(sample, osName, isBot, isTool) {
  if (isBot) return "Bot";
  if (isTool) return "Service client";
  if (/iPad|Tablet/i.test(sample)) return "Tablet";
  if (/Mobile|iPhone|Android/i.test(sample) && !/Tablet/i.test(sample)) return "Mobile";
  if (/Windows|macOS|Linux|Chrome OS/i.test(osName)) return "Desktop";
  return "Unknown device";
}

function detectEngine(sample) {
  if (/AppleWebKit/i.test(sample) && /Chrome|Chromium|Edg|OPR|SamsungBrowser/i.test(sample)) return "Blink";
  if (/AppleWebKit/i.test(sample) && /Safari/i.test(sample)) return "WebKit";
  if (/Gecko\//i.test(sample) && /Firefox|FxiOS/i.test(sample)) return "Gecko";
  if (/Trident/i.test(sample)) return "Trident";
  if (/CFNetwork/i.test(sample)) return "CFNetwork";
  return "";
}

function windowsVersion(value) {
  const versions = { "10.0": "10/11", "6.3": "8.1", "6.2": "8", "6.1": "7", "6.0": "Vista", "5.1": "XP" };
  return versions[value] || value;
}

function normalizeVersion(value) {
  return String(value || "").split(".").filter(Boolean).slice(0, 3).join(".");
}

function versionAfterSlash(value) {
  return (String(value || "").match(/\/([\d.]+)/) || [])[1] || "";
}

function readableToken(value) {
  return String(value || "Unknown")
    .replace(/^com\.apple\./i, "Apple ")
    .replace(/[._-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
    .trim() || "Unknown";
}

function shortUserAgentSample(value) {
  const sample = String(value || "");
  if (!sample || sample === "Unknown") return "No raw sample";
  return sample.length > 150 ? `${sample.slice(0, 147)}...` : sample;
}

function isMySQLProbeRow(item) {
  return /sql|mysql|database|query|select_from|union|information_schema/i.test(`${item.category || ""} ${item.rule_key || ""} ${item.match_reason || ""} ${item.sample_query || ""} ${item.path || ""}`);
}

function isMySQLPathRow(item) {
  return /mysql|sql|database|query|select|union|information_schema|db-/i.test(`${item.path || ""} ${item.site_id || ""}`);
}

function mysqlProbeSearchText(item) {
  return `${item.category} ${item.rule_key} ${item.site_id} ${item.env} ${item.ip} ${item.method} ${item.path} ${item.sample_query} ${item.match_reason}`;
}

function mysqlProbeSourceIPs(probes) {
  const rows = new Map();
  probes.forEach((probe) => {
    const ip = probe.ip || "";
    if (!ip) return;
    const row = rows.get(ip) || { ip, requests: 0, status_4xx: 0, status_5xx: 0, risk_score: 0, sites: new Set() };
    row.requests += Number(probe.requests || 0);
    row.status_4xx += Number(probe.status_4xx || 0);
    row.status_5xx += Number(probe.status_5xx || 0);
    row.risk_score = Math.max(row.risk_score, Number(probe.risk_score || 0));
    if (probe.site_id) row.sites.add(probe.site_id);
    rows.set(ip, row);
  });
  return Array.from(rows.values()).map((row) => ({ ...row, sites: Array.from(row.sites) })).sort((a, b) => b.risk_score - a.risk_score || b.requests - a.requests);
}

function searchItems(items, text) {
  if (!state.search) return items;
  return items.filter((item) => text(item).toLowerCase().includes(state.search));
}

function filtered(items) {
  return items;
}

async function handleAction(button) {
  const action = button.dataset.action;
  if (action === "refresh") return refreshAll();
  if (action === "run-pipeline") {
    return runButton(button, "Pipeline complete", async () => {
      await fetchJSON("/api/v1/system/pipeline", { method: "POST", body: "{}" });
      await refreshAll();
    });
  }
  if (action === "run-backfill") {
    return runButton(button, "Backfill batch complete", async () => {
      await fetchJSON("/api/v1/system/backfill-dimensions", { method: "POST", body: JSON.stringify({ batch_size: 5000, max_batches: 1, rollups: true }) });
      await refreshAll();
    });
  }
  if (action === "run-archive-dry") {
    return runButton(button, "Archive check complete", async () => {
      const result = await fetchJSON("/api/v1/system/archive-logs", { method: "POST", body: JSON.stringify({ dry_run: true, max_groups: 25 }) });
      toast(`${formatNumber(result.groups_matched || 0)} archive groups ready`);
      await refreshAll();
    });
  }
  if (action === "run-archive") {
    if (!confirm("Create ready archive groups and remove archived hourly combined files?")) return;
    return runButton(button, "Archive complete", async () => {
      const result = await fetchJSON("/api/v1/system/archive-logs", { method: "POST", body: JSON.stringify({ max_groups: 25, remove_sources: true }) });
      await refreshAll();
      return `${formatNumber(result.archives_written || 0)} archives written / ${formatNumber(result.files_archived || 0)} files archived`;
    });
  }
  if (action === "import-archive") {
    const archiveID = button.dataset.archiveId;
    if (!archiveID) return;
    const archive = (state.data.archives || []).find((item) => item.id === archiveID) || {};
    const range = [shortTime(archive.range_start), shortTime(archive.range_end)].filter(Boolean).join(" to ") || "this archived range";
    const expiry = state.data.retention?.temporary_import_max_age || "the configured temporary import window";
    if (!confirm(`Temporarily import ${range} for investigation?\n\nImported events are marked as temporary and will expire after ${expiry}. Existing hot data is not replaced.`)) return;
    return runButton(button, "Archive import complete", async () => {
      const result = await fetchJSON("/api/v1/system/import-archive", { method: "POST", body: JSON.stringify({ archive_id: archiveID, reason: "manual UI import" }) });
      await refreshAll();
      return `${formatNumber(result.events_inserted || 0)} archived events imported / ${formatNumber(result.events_conflicted || 0)} already present`;
    });
  }
  if (action === "import-range-archives") {
    const coverage = state.data.archiveCoverage || {};
    const archives = coverage.archives || [];
    const archiveIDs = archives.map((item) => item.id).filter(Boolean);
    if (!archiveIDs.length) return;
    const range = [shortTime(coverage.import_window_start || coverage.since), shortTime(coverage.import_window_end || coverage.until)].filter(Boolean).join(" to ") || activeRangeLabel();
    const expiry = coverage.temporary_import_max_age || state.data.retention?.temporary_import_max_age || "the configured temporary import window";
    const size = formatBytes(coverage.selected_compressed_bytes || archives.reduce((sum, item) => sum + Number(item.compressed_bytes || 0), 0));
    if (!confirm(`Temporarily import archived logs for ${range}?\n\n${formatNumber(archiveIDs.length)} archive file(s), about ${size} compressed, will be loaded for investigation and expire after ${expiry}. Existing hot data is not replaced.`)) return;
    return runButton(button, "Archived range import complete", async () => {
      const result = await fetchJSON("/api/v1/system/import-archives", {
        method: "POST",
        body: JSON.stringify({ archive_ids: archiveIDs, reason: `UI old-range import for ${state.range}` }),
      });
      await refreshAll();
      return `${formatNumber(result.totals?.events_inserted || 0)} archived events imported / ${formatNumber(result.totals?.events_conflicted || 0)} already present`;
    });
  }
  if (action === "query-guide") {
    openModal("Query Guide", "Advanced Search", queryGuideHTML());
    return;
  }
  if (action === "modal-close") {
    closeModal();
    return;
  }
  if (action === "page") {
    const key = button.dataset.pageKey;
    const page = Number(button.dataset.page || 1);
    if (key && Number.isFinite(page)) {
      state.pages[key] = Math.max(1, page);
      render();
    }
    return;
  }
  if (action === "drawer-page") {
    const key = button.dataset.pageKey;
    const page = Number(button.dataset.page || 1);
    if (key && Number.isFinite(page)) {
      state.drawer.pages[key] = Math.max(1, page);
      renderCurrentDrawer();
    }
    return;
  }
  if (action === "evaluate-alerts") {
    return runButton(button, "Alert evaluation complete", async () => {
      await fetchJSON("/api/v1/alerts/evaluate", { method: "POST", body: JSON.stringify({ range: state.range, limit: 200 }) });
      await refreshAll();
    });
  }
  if (action === "send-notifications") {
    return runButton(button, "Notification run complete", async () => {
      const result = await fetchJSON("/api/v1/notifications/send", { method: "POST", body: "{}" });
      await refreshAll();
      return notificationResultMessage(result, "Notification run complete");
    });
  }
  if (action === "test-notifications") {
    return runButton(button, "Notification test complete", async () => {
      const result = await fetchJSON("/api/v1/notifications/test", { method: "POST", body: "{}" });
      await refreshAll();
      return notificationResultMessage(result, "Notification test complete");
    });
  }
  if (action === "enable-web-push") {
    return runButton(button, "Browser push enabled", async () => {
      await enableBrowserPush();
      await refreshAll();
    });
  }
  if (action === "disable-web-push") {
    return runButton(button, "Browser push disabled", async () => {
      await disableBrowserPush();
      await refreshAll();
    });
  }
  if (action === "refresh-ip-intel") {
    return runButton(button, "IP intelligence refreshed", async () => {
      await fetchJSON("/api/v1/system/refresh-ip-intel", { method: "POST", body: JSON.stringify({ range: state.range, limit: analysisHistoryLimit }) });
      await refreshAll();
    });
  }
  if (action === "generate-report") {
    return runButton(button, "Report generated", async () => {
      const report = await fetchJSON("/api/v1/reports/generate", { method: "POST", body: JSON.stringify({ range: state.range, site_id: state.siteID }) });
      state.localReports = [report, ...state.localReports].slice(0, 10);
      const recent = await safeFetch(`/api/v1/reports/recent?${buildFilterQuery({ limit: reportCatalogLimit })}`, { reports: [] });
      state.data.reports = recent.reports || [];
      render();
    });
  }
  if (action === "print-report") {
    printReport(state.drawer?.data);
    return;
  }
  if (action === "export-report") {
    exportReport(state.drawer?.data);
    return;
  }
}

async function enableBrowserPush() {
  const webPush = state.data.webPush || await fetchJSON("/api/v1/notifications/web-push/public-key");
  if (!webPush.enabled) throw new Error("Browser push is disabled in config.");
  if (!webPush.configured || !webPush.public_key) throw new Error("VAPID public/private keys are not configured.");
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) throw new Error("This browser does not support push notifications.");
  const permission = await Notification.requestPermission();
  if (permission !== "granted") throw new Error("Notification permission was not granted.");
  const registration = await navigator.serviceWorker.register("/sw.js");
  const existing = await registration.pushManager.getSubscription();
  if (existing) await existing.unsubscribe();
  const subscription = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(webPush.public_key),
  });
  await fetchJSON("/api/v1/notifications/web-push/subscribe", {
    method: "POST",
    body: JSON.stringify(subscription),
  });
}

async function disableBrowserPush() {
  if (!("serviceWorker" in navigator)) return;
  const registration = await navigator.serviceWorker.getRegistration("/sw.js") || await navigator.serviceWorker.getRegistration();
  if (!registration) return;
  const subscription = await registration.pushManager.getSubscription();
  if (!subscription) return;
  const endpoint = subscription.endpoint;
  await subscription.unsubscribe();
  await fetchJSON("/api/v1/notifications/web-push/subscribe", {
    method: "DELETE",
    body: JSON.stringify({ endpoint }),
  });
}

async function runButton(button, success, fn) {
  const original = button.innerHTML;
  button.disabled = true;
  button.innerHTML = `${iconHTML("fa-spinner fa-spin")}Working`;
  try {
    const message = await fn();
    toast(typeof message === "string" && message ? message : success);
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.innerHTML = original;
  }
}

function renderIPDetail(detail, summary = {}) {
  const traffic = detail.traffic || summary || {};
  const intel = detail.stored_intel || {};
  const geo = detail.geoip || {};
  const asn = detail.asn || {};
  const sites = drawerPage("ipSites", detail.sites || [], 5);
  const paths = drawerPage("ipPaths", detail.top_paths || [], 6);
  const urls = drawerPage("ipURLHits", detail.url_hits || [], 6);
  const agents = drawerPage("ipAgents", detail.top_user_agents || [], 6);
  const requests = drawerPage("ipRequests", detail.recent_requests || [], 8);
  return `
    ${miniMetrics([
      ["Total Requests", formatNumber(traffic.requests), "fa-arrow-trend-up"],
      ["Error Rate", formatPercent(ratio((traffic.status_4xx || 0) + (traffic.status_5xx || 0), traffic.requests)), "fa-fire"],
      ["Avg Response", formatMs(traffic.avg_request_time_ms), "fa-stopwatch"],
      ["Risk Score", intel.risk_score || summary.risk_score || "-", "fa-shield-halved"],
    ])}
    <section class="detail-grid two">
      <article class="detail-card">
        <h3>WHOIS / Reputation</h3>
        ${factsRich([
          ["IP Address", ipLink(detail.ip || summary.ip)],
          ["Known Actor", intel.known_actor || summary.known_actor || "-"],
          ["Actor Type", intel.actor_type || summary.actor_type || "-"],
          ["Reverse DNS", intel.reverse_dns || summary.reverse_dns || "-"],
          ["ASN", intel.asn || asn.asn || "-"],
          ["ASN Org", intel.asn_org || asn.name || "-"],
          ["Manual Action", intel.manual_action || "-"],
        ])}
      </article>
      <article class="detail-card">
        <h3>Geo / Network Intelligence</h3>
        ${facts([
          ["Country", geo.country_name || geo.country_code || intel.country_code || summary.country_code || "-"],
          ["City", geo.city_name || "-"],
          ["Time Zone", geo.time_zone || "-"],
          ["Network", intel.network || asn.prefix || "-"],
          ["Datacenter", yesNo(intel.is_datacenter)],
          ["Tor Exit", yesNo(intel.is_tor_exit)],
          ["GeoIP", geo.loaded ? "Loaded" : (geo.error || "Unavailable")],
        ])}
      </article>
    </section>
    <section class="detail-grid two">
      <article class="detail-card">
        <div class="detail-card-head"><h3>Host / Site Targeting</h3><span>${formatNumber(sites.total)} rows</span></div>
        ${simpleRows(sites.rows, (item) => compactRow(`${item.site_id || "-"}/${item.env || "-"}`, `${formatNumber(item.requests)} requests / ${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))} errors`, shortTime(item.last_seen)))}
        ${drawerPager("ipSites", sites)}
      </article>
      <article class="detail-card">
        <div class="detail-card-head"><h3>Top Paths</h3><span>${formatNumber(paths.total)} rows</span></div>
        ${simpleRows(paths.rows, (item) => compactRow(item.path || "/", `${formatNumber(item.requests)} requests / ${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))} errors`, formatBytes(item.bytes_sent)))}
        ${drawerPager("ipPaths", paths)}
      </article>
    </section>
    <section class="detail-grid two">
      <article class="detail-card">
        <div class="detail-card-head"><h3>URL Hits</h3><span>${formatNumber(urls.total)} rows</span></div>
        ${simpleRows(urls.rows, (item) => compactRow(`${item.method || "GET"} ${item.path || "/"}`, `${formatNumber(item.requests)} requests / p95 ${formatMs(item.p95_request_time_ms)}`, formatBytes(item.bytes_sent)))}
        ${drawerPager("ipURLHits", urls)}
      </article>
      <article class="detail-card">
        <div class="detail-card-head"><h3>User Agents</h3><span>${formatNumber(agents.total)} rows</span></div>
        ${simpleRows(agents.rows, (item) => `
          <div class="list-row">
            <div>${userAgentListLabel(item)}</div>
            <b>${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))} err</b>
          </div>
        `)}
        ${drawerPager("ipAgents", agents)}
      </article>
    </section>
    <article class="detail-card">
      <div class="detail-card-head"><h3>Recent Activity</h3><span>${formatNumber(requests.total)} rows</span></div>
      ${requestRows(requests.rows)}
      ${drawerPager("ipRequests", requests)}
    </article>
  `;
}

function renderRequestDetail(item) {
  const status = Number(item.status || 0);
  const risk = clamp(Math.round((status >= 500 ? 55 : status >= 400 ? 30 : 10) + Number(item.bytes_sent || 0) / 2048), 1, 100);
  return `
    <article class="trace-hero">
      <span class="method ${String(item.method || "GET").toLowerCase()}">${escapeHTML(item.method || "GET")}</span>
      <strong>${escapeHTML(item.path || "/")}</strong>
      <span class="severity ${status >= 500 ? "critical" : status >= 400 ? "high" : "low"}">${status || "-"}</span>
      <span>${formatMs(item.request_time_ms || 0)}</span>
      <span>Risk ${risk}/100</span>
    </article>
    <section class="detail-grid two">
      <article class="detail-card">
        <h3>Request Context</h3>
        ${factsRich([
          ["Time", shortTime(item.ts)],
          ["Project", item.site_id || "-"],
          ["Environment", item.env || "-"],
          ["Source IP", ipLink(item.client_ip)],
          ["Host", item.host || item.site_id || "-"],
          ["Bytes Sent", formatBytes(item.bytes_sent)],
          ["Container", item.container_id || "-"],
        ])}
      </article>
      <article class="detail-card">
        <h3>Risk Summary</h3>
        ${factsRich([
          ["Status class", escapeHTML(status >= 500 ? "Server error" : status >= 400 ? "Client error" : "Success")],
          ["Query string", escapeHTML(item.query || "-")],
          ["Referer", escapeHTML(item.referer || "-")],
          ["User Agent", item.user_agent ? userAgentLink(item.user_agent, item.user_agent) : "-"],
        ])}
      </article>
    </section>
    <article class="detail-card">
      <h3>Request Timeline</h3>
      <div class="trace-bars">
        ${traceBar("Access log match", 100, "cyan")}
        ${traceBar(status >= 500 ? "Server error response" : "Application response", status >= 500 ? 74 : 42, status >= 500 ? "red" : "green")}
        ${traceBar("IP attribution", item.client_ip ? 36 : 12, "purple")}
        ${traceBar("Related security checks", status >= 400 ? 58 : 20, "amber")}
      </div>
    </article>
    <article class="detail-card">
      <h3>Actions</h3>
      <div class="toolbar inline-toolbar">
        ${item.client_ip ? `<button class="button small" type="button" data-detail="ip" data-value="${escapeAttr(item.client_ip)}">${iconHTML("fa-location-crosshairs")}Open IP</button>` : ""}
        <button class="button small" type="button" data-route="logs">${iconHTML("fa-rectangle-list")}Live Logs</button>
        <button class="button small" type="button" data-route="security">${iconHTML("fa-shield-halved")}Security</button>
      </div>
    </article>
  `;
}

function renderReportDetail(item) {
  const summary = item.summary || {};
  const charts = item.charts || [];
  const drilldowns = item.drilldowns || [];
  return `
    <article class="detail-card report-actions-card">
      <div>
        <h3>${escapeHTML(reportTitle(item))}</h3>
        <p>${escapeHTML([formatReportType(reportKind(item)), item.range, item.model || "deterministic", shortTime(item.created_at || item.generated_at)].filter(Boolean).join(" / "))}</p>
      </div>
      <div class="toolbar inline-toolbar">
        <button class="button small" type="button" data-action="print-report">${iconHTML("fa-print")}Print</button>
        <button class="button small" type="button" data-action="export-report">${iconHTML("fa-download")}Export Markdown</button>
      </div>
    </article>
    ${miniMetrics([
      ["Requests", formatNumber(summary.requests), "fa-arrow-trend-up"],
      ["Unique IPs", formatNumber(summary.unique_ips), "fa-network-wired"],
      ["5xx Rate", formatPercent(summary.status_5xx_rate), "fa-bolt"],
      ["Open Alerts", formatNumber(summary.open_alerts), "fa-bell"],
    ])}
    <article class="detail-card">
      <h3>Executive Summary</h3>
      <div class="markdown-body">${renderMarkdown(reportSummaryText(item))}</div>
    </article>
    <article class="detail-card">
      <h3>Traffic & Risk Summary</h3>
      ${factsRich([
        ["Range", escapeHTML(summary.range || item.range || "-")],
        ["Generated", escapeHTML(shortTime(summary.generated_at || item.generated_at || item.created_at))],
        ["4xx", escapeHTML(`${formatNumber(summary.status_4xx)} (${formatPercent(summary.status_4xx_rate)})`)],
        ["5xx", escapeHTML(`${formatNumber(summary.status_5xx)} (${formatPercent(summary.status_5xx_rate)})`)],
        ["Issues", escapeHTML(formatNumber(summary.issue_count))],
        ["Top Site", escapeHTML(summary.top_site || "-")],
        ["Top Path", escapeHTML(summary.top_path || "-")],
        ["Top Source IP", summary.top_source_ip ? ipLink(summary.top_source_ip) : "-"],
      ])}
    </article>
    <section class="detail-grid two report-detail-grid">
      <article class="detail-card">
        <div class="detail-card-head"><h3>Charts</h3><span>${formatNumber(charts.length)} charts</span></div>
        <div class="report-chart-stack">${charts.length ? charts.map((chart, index) => reportChartCard(chart, index)).join("") : empty("No chart data stored with this report.")}</div>
      </article>
      <article class="detail-card">
        <div class="detail-card-head"><h3>Drilldowns</h3><span>${formatNumber(drilldowns.length)} sections</span></div>
        <div class="report-drilldown-stack">${drilldowns.length ? drilldowns.map((drill, index) => reportDrilldownCard(drill, index)).join("") : empty("No drilldowns stored with this report.")}</div>
      </article>
    </section>
  `;
}

function reportChartCard(chart, index = 0) {
  const points = chart.data || [];
  const pageKey = `reportChart${index}Points`;
  const page = drawerPage(pageKey, points, 6);
  const values = points.map((point) => Number(point.value || 0));
  const total = values.reduce((acc, value) => acc + value, 0);
  const peak = points.reduce((best, point) => Number(point.value || 0) > Number(best.value || 0) ? point : best, points[0] || {});
  return `
    <section class="report-subcard">
      <div class="report-subcard-head">
        <strong>${escapeHTML(chart.title || chart.key || "Chart")}</strong>
        <span>${escapeHTML(chart.kind || "chart")} / ${escapeHTML(chart.unit || "count")}</span>
      </div>
      ${factsRich([
        ["Points", escapeHTML(formatNumber(points.length))],
        ["Total", escapeHTML(formatNumber(total))],
        ["Peak", peak.label ? `${linkifyIPs(peak.label)} / ${escapeHTML(formatNumber(peak.value))}` : "-"],
      ])}
      <div class="list compact-list">${page.rows.map((point) => `
        <div class="list-row">
          <div><strong>${linkifyIPs(point.label || shortTime(point.timestamp) || "-")}</strong><span>${linkifyIPs(point.meta || chart.unit || "")}</span></div>
          <b>${formatNumber(point.value)}${point.secondary !== undefined ? ` / ${formatNumber(point.secondary)}` : ""}</b>
        </div>
      `).join("") || empty("No chart points.")}</div>
      ${drawerPager(pageKey, page)}
    </section>
  `;
}

function reportDrilldownCard(drill, index = 0) {
  const rows = drill.items || [];
  const pageKey = `reportDrilldown${index}Rows`;
  const page = drawerPage(pageKey, rows, 8);
  return `
    <section class="report-subcard">
      <div class="report-subcard-head">
        <strong>${escapeHTML(drill.title || drill.key || "Drilldown")}</strong>
        <span>${formatNumber(rows.length)} rows</span>
      </div>
      <div class="list compact-list">${page.rows.map((row) => `
        <div class="list-row">
          <div><strong>${reportDrilldownTitleHTML(row)}</strong><span>${reportDrilldownMetaHTML(row)}</span></div>
          <b>${escapeHTML(reportDrilldownValue(row))}</b>
        </div>
      `).join("") || empty("No drilldown rows.")}</div>
      ${drawerPager(pageKey, page)}
    </section>
  `;
}

function reportDrilldownTitle(row) {
  return row.title || row.label || row.path || row.ip || row.site_id || row.key || row.kind || row.rule_key || "-";
}

function reportDrilldownTitleHTML(row) {
  if (row.kind === "user_agent" && (row.meta || row.user_agent || row.label)) {
    return userAgentLink({ family: row.label, sample: row.meta || row.user_agent || row.label }, row.label || row.meta || "User Agent");
  }
  return linkifyIPs(reportDrilldownTitle(row));
}

function reportDrilldownMeta(row) {
  return row.summary || row.meta || [row.site_id, row.env, row.method, row.status, row.match_reason, row.category].filter(Boolean).join(" / ");
}

function reportDrilldownMetaHTML(row) {
  if (row.kind === "user_agent" && (row.meta || row.user_agent)) {
    return escapeHTML(userAgentMetaLine({ family: row.label, sample: row.meta || row.user_agent, actor_type: row.category, known_actor: row.known_actor }));
  }
  return linkifyIPs(reportDrilldownMeta(row));
}

function reportDrilldownValue(row) {
  return row.severity || row.requests || row.value || row.count || row.status_5xx || row.status_4xx || "";
}

function renderSiteDetail(item, scoped = {}) {
  const scopedAnalysis = scoped.analysis || state.data.estateAnalysis || state.data.analysis || {};
  const scopedTraffic = scoped.traffic || state.data.estateTraffic || state.data.traffic || {};
  const matching = (scopedAnalysis.sites || []).filter((row) => !row.site_id || row.site_id === item.id);
  const sitePathRows = (scopedTraffic.top_paths || scopedAnalysis.slow_paths || []).filter((row) => !row.site_id || row.site_id === item.id);
  const siteIPRows = (scopedTraffic.top_ips || scopedAnalysis.source_ips || []).filter((row) => !row.site_id || row.site_id === item.id);
  const siteEvents = (scopedTraffic.recent_errors || []).filter((row) => !row.site_id || row.site_id === item.id);
  const siteAlerts = (state.data.alerts || []).filter((row) => row.site_id === item.id);
  const siteIncidents = siteAlerts.length ? siteAlerts : siteEvents;
  const sitePaths = drawerPage("sitePaths", sitePathRows, 6);
  const siteIPs = drawerPage("siteIPs", siteIPRows, 6);
  const siteIncidentPage = drawerPage("siteIncidents", siteIncidents, 6);
  const total4xx = sum(matching, "status_4xx");
  const total5xx = sum(matching, "status_5xx");
  const totalBytes = sum(matching, "bytes_sent");
  const maxP95 = Math.max(0, ...matching.map((row) => Number(row.p95_request_time_ms || 0)));
  const envCount = matching.length || String(item.envs || "").split(",").filter(Boolean).length;
  return `
    ${miniMetrics([
      ["Requests", formatNumber(item.requests), "fa-arrow-trend-up"],
      ["Error Rate", formatPercent(item.errorRate), "fa-triangle-exclamation"],
      ["Risk", item.risk, "fa-shield-halved"],
      ["Health", item.health || "-", "fa-heart-pulse"],
    ])}
    <section class="detail-grid two">
      <article class="detail-card">
        <h3>Project Configuration</h3>
        ${facts([["ID", item.id], ["Name", item.name], ["Environments", item.envs], ["Tags", (item.tags || []).join(", ") || "-"]])}
      </article>
      <article class="detail-card">
        <h3>Traffic Summary</h3>
        ${facts([
          ["4xx", formatNumber(total4xx)],
          ["5xx", formatNumber(total5xx)],
          ["P95 Response", formatMs(maxP95)],
          ["Bytes Sent", formatBytes(totalBytes)],
          ["Environments", formatNumber(envCount)],
        ])}
      </article>
    </section>
    <article class="detail-card">
      <h3>Environment Breakdown</h3>
      ${simpleRows(matching, (row) => compactRow(`${row.site_id}/${row.env}`, `${formatNumber(row.requests)} requests / ${formatPercent(ratio((row.status_4xx || 0) + (row.status_5xx || 0), row.requests))} errors`, formatMs(row.p95_request_time_ms)))}
    </article>
    <section class="detail-grid two">
      <article class="detail-card">
        <h3>Top Paths</h3>
        ${simpleRows(sitePaths.rows, (row) => compactRow(row.path || "/", `${formatNumber(row.requests)} requests / ${formatNumber((row.status_4xx || 0) + (row.status_5xx || 0))} errors`, formatBytes(row.bytes_sent)))}
        ${drawerPager("sitePaths", sitePaths)}
      </article>
      <article class="detail-card">
        <h3>Source IPs</h3>
        ${simpleRows(siteIPs.rows, (row) => `
          <div class="list-row">
            <div><strong>${row.ip ? ipLink(row.ip) : "-"}</strong><span>${formatNumber(row.requests)} requests / ${formatNumber((row.status_4xx || 0) + (row.status_5xx || 0))} errors</span></div>
            <b>${escapeHTML(row.country_code || row.actor_type || "")}</b>
          </div>
        `)}
        ${drawerPager("siteIPs", siteIPs)}
      </article>
    </section>
    <section class="detail-grid two">
      <article class="detail-card">
        <h3>Recent Incidents</h3>
        ${siteAlerts.length ? simpleRows(siteIncidentPage.rows, (row) => alertRow(row)) : requestRows(siteIncidentPage.rows)}
        ${drawerPager("siteIncidents", siteIncidentPage)}
      </article>
      <article class="detail-card">
        <h3>Actions</h3>
        <div class="toolbar inline-toolbar">
          <button class="button small" type="button" data-route="logs">${iconHTML("fa-rectangle-list")}Live Logs</button>
          <button class="button small" type="button" data-route="traffic">${iconHTML("fa-chart-line")}Traffic</button>
          <button class="button small" type="button" data-route="reports">${iconHTML("fa-file-lines")}Reports</button>
        </div>
      </article>
    </section>
  `;
}

function renderSecuritySignalDetail(item) {
  const signal = item.signal || item;
  const relatedIPs = (item.related_ips || []).length ? item.related_ips : securityRelatedIPs(signal);
  const relatedRequests = (item.related_requests || []).length ? item.related_requests : securityRelatedRequests(signal);
  const ipPage = drawerPage("securitySignalIPs", relatedIPs, 6);
  const requestPage = drawerPage("securitySignalRequests", relatedRequests, 6);
  return `
    ${miniMetrics([
      ["Requests", formatNumber(signal.requests), "fa-arrow-trend-up"],
      ["Risk", formatNumber(signal.risk_score), "fa-shield-halved"],
      ["4xx", formatNumber(signal.status_4xx), "fa-triangle-exclamation"],
      ["5xx", formatNumber(signal.status_5xx), "fa-bolt"],
    ])}
    <section class="detail-grid two">
      <article class="detail-card">
        <h3>Signal Context</h3>
        ${factsRich([
          ["Type", escapeHTML(signal.title || signal.kind || "Security signal")],
          ["Category", escapeHTML(signal.category || signal.rule_key || signal.kind || "-")],
          ["Project", escapeHTML(signal.site_id || "-")],
          ["Environment", escapeHTML(signal.env || "-")],
          ["Source IP", signal.ip ? ipLink(signal.ip) : "-"],
          ["Path", escapeHTML(signal.path || "-")],
          ["Evidence", escapeHTML(item.source || "loaded view")],
        ])}
      </article>
      <article class="detail-card">
        <h3>Evidence</h3>
        ${facts([
          ["Method", signal.method || "-"],
          ["Match Reason", signal.match_reason || signal.category || "-"],
          ["Sample Query", signal.sample_query || "-"],
          ["First Seen", shortTime(signal.first_seen)],
          ["Last Seen", shortTime(signal.last_seen)],
          ["Total IP Hits", formatNumber(signal.total_ip_hits || signal.requests || 0)],
        ])}
      </article>
    </section>
    <article class="detail-card">
      <div class="detail-card-head"><h3>Related IPs</h3><span>${formatNumber(ipPage.total)} rows</span></div>
      <div class="list">${ipPage.rows.map((row) => `
        <div class="list-row">
          <div><strong>${ipLink(row.ip)}</strong><span>${formatNumber(row.requests)} requests / ${formatNumber((row.status_4xx || 0) + (row.status_5xx || 0))} errors / ${escapeHTML(row.meta || "")}</span></div>
          <span class="severity ${Number(row.risk_score || 0) >= 70 ? "critical" : "high"}">${formatNumber(row.risk_score || 0)}</span>
        </div>
      `).join("") || empty("No related IPs found.")}</div>
      ${drawerPager("securitySignalIPs", ipPage)}
    </article>
    <article class="detail-card">
      <div class="detail-card-head"><h3>Related Requests</h3><span>${formatNumber(requestPage.total)} rows</span></div>
      ${securityRequestRows(requestPage.rows)}
      ${drawerPager("securitySignalRequests", requestPage)}
    </article>
  `;
}

function miniMetrics(items) {
  return `<section class="mini-metric-grid">${items.map(([label, value, icon]) => `
    <div class="mini-metric"><span>${iconHTML(icon)}${escapeHTML(label)}</span><strong>${escapeHTML(String(value ?? "-"))}</strong></div>
  `).join("")}</section>`;
}

function simpleRows(rows, render) {
  if (!rows.length) return empty("No rows available.");
  return `<div class="list">${rows.map(render).join("")}</div>`;
}

function drawerPage(key, rows, pageSize = 6) {
  return paginate(rows, state.drawer.pages[key] || 1, pageSize);
}

function drawerPager(key, page) {
  if (page.totalPages <= 1) {
    return page.total ? `<div class="pager drawer-pager"><span>Showing ${formatNumber(page.total)} rows</span></div>` : "";
  }
  const pages = pagerPages(page.page, page.totalPages);
  return `
    <div class="pager drawer-pager">
      <span>Showing ${formatNumber(page.start)}-${formatNumber(page.end)} of ${formatNumber(page.total)}</span>
      <div class="pager-buttons">
        <button class="icon-button" type="button" data-action="drawer-page" data-page-kind="previous" data-page-key="${escapeAttr(key)}" data-page="${page.page - 1}" ${page.page <= 1 ? "disabled" : ""} title="Previous page">${iconHTML("fa-chevron-left")}</button>
        ${pages.map((item) => item === "..." ? `<span class="pager-gap">...</span>` : `<button class="button small ${item === page.page ? "primary" : ""}" type="button" data-action="drawer-page" data-page-kind="number" data-page-key="${escapeAttr(key)}" data-page="${item}">${item}</button>`).join("")}
        <button class="icon-button" type="button" data-action="drawer-page" data-page-kind="next" data-page-key="${escapeAttr(key)}" data-page="${page.page + 1}" ${page.page >= page.totalPages ? "disabled" : ""} title="Next page">${iconHTML("fa-chevron-right")}</button>
      </div>
    </div>
  `;
}

function requestRows(rows) {
  if (!rows.length) return empty("No recent requests.");
  const hasSource = rows.some((row) => row.client_ip || row.ip);
  return `
    <div class="table-wrap compact-table"><table>
      <thead><tr><th>Time</th>${hasSource ? "<th>Source</th>" : ""}<th>Request</th><th>Status</th><th>Bytes</th></tr></thead>
      <tbody>${rows.map((row) => `
        <tr>
          <td>${shortTime(row.ts)}</td>
          ${hasSource ? `<td>${ipLink(row.client_ip || row.ip)}</td>` : ""}
          <td>${escapeHTML(row.method || "GET")} ${escapeHTML(row.path || "/")}</td>
          <td><span class="severity ${Number(row.status) >= 500 ? "critical" : Number(row.status) >= 400 ? "high" : "low"}">${escapeHTML(row.status || "-")}</span></td>
          <td>${formatBytes(row.bytes_sent)}</td>
        </tr>
      `).join("")}</tbody>
    </table></div>
  `;
}

function securityRequestRows(rows) {
  if (!rows.length) return empty("No related requests.");
  return `
    <div class="table-wrap compact-table"><table>
      <thead><tr><th>Time</th><th>Source</th><th>Request</th><th>Status</th></tr></thead>
      <tbody>${rows.map((row) => `
        <tr>
          <td>${shortTime(row.ts)}</td>
          <td>${ipLink(row.client_ip)}</td>
          <td>${escapeHTML(row.method || "GET")} ${escapeHTML(row.path || "/")}<br><span class="subtle">${escapeHTML(row.site_id || "-")} / ${row.user_agent ? userAgentLink(row.user_agent, row.user_agent) : ""}</span></td>
          <td><span class="severity ${Number(row.status) >= 500 ? "critical" : Number(row.status) >= 400 ? "high" : "low"}">${escapeHTML(row.status || "-")}</span></td>
        </tr>
      `).join("")}</tbody>
    </table></div>
  `;
}

function userAgentRequestRows(rows) {
  if (!rows.length) return empty("No related requests.");
  return `
    <div class="table-wrap compact-table"><table>
      <thead><tr><th>Time</th><th>Source</th><th>Request</th><th>Status</th></tr></thead>
      <tbody>${rows.map((row, index) => {
        const requestKey = cacheDetail("request", row, `ua:${row.ts || ""}:${row.client_ip || ""}:${row.path || ""}:${index}`);
        return `
        <tr>
          <td>${shortTime(row.ts)}</td>
          <td>${ipLink(row.client_ip)}</td>
          <td>${escapeHTML(row.method || "GET")} ${escapeHTML(row.path || "/")}<br><span class="subtle">${escapeHTML(row.site_id || "-")} / ${escapeHTML(row.env || "-")}</span></td>
          <td><button class="button small" type="button" data-detail="request" data-value="${escapeAttr(requestKey)}">${escapeHTML(row.status || "-")}</button></td>
        </tr>
      `}).join("")}</tbody>
    </table></div>
  `;
}

function traceBar(label, value, color) {
  const width = clamp(Number(value || 0), 4, 100);
  return `<div class="trace-bar"><span>${escapeHTML(label)}</span><i><b style="width:${width}%; background: var(--${color})"></b></i><em>${width}%</em></div>`;
}

function deterministicReportSummary(item) {
  const summary = item.summary || {};
  return `Report ${item.id || ""}\nRange: ${item.range || "-"}\nRequests: ${formatNumber(summary.requests)}\nUnique IPs: ${formatNumber(summary.unique_ips)}\nOpen alerts: ${formatNumber(summary.open_alerts)}`;
}

function renderMarkdown(value) {
  const lines = String(value || "").replace(/\r\n/g, "\n").split("\n");
  const html = [];
  let list = "";
  let inCode = false;
  let code = [];
  const closeList = () => {
    if (!list) return;
    html.push(`</${list}>`);
    list = "";
  };
  const openList = (tag) => {
    if (list === tag) return;
    closeList();
    list = tag;
    html.push(`<${tag}>`);
  };
  const closeCode = () => {
    html.push(`<pre><code>${escapeHTML(code.join("\n"))}</code></pre>`);
    code = [];
    inCode = false;
  };
  for (const line of lines) {
    const trimmed = line.trim();
    if (/^```/.test(trimmed)) {
      if (inCode) closeCode();
      else {
        closeList();
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      code.push(line);
      continue;
    }
    if (!trimmed) {
      closeList();
      continue;
    }
    const heading = trimmed.match(/^(#{1,4})\s+(.+)$/);
    if (heading) {
      closeList();
      const level = heading[1].length;
      html.push(`<h${level}>${renderInlineMarkdown(heading[2])}</h${level}>`);
      continue;
    }
    const unordered = trimmed.match(/^[-*]\s+(.+)$/);
    if (unordered) {
      openList("ul");
      html.push(`<li>${renderInlineMarkdown(unordered[1])}</li>`);
      continue;
    }
    const ordered = trimmed.match(/^\d+\.\s+(.+)$/);
    if (ordered) {
      openList("ol");
      html.push(`<li>${renderInlineMarkdown(ordered[1])}</li>`);
      continue;
    }
    closeList();
    html.push(`<p>${renderInlineMarkdown(trimmed)}</p>`);
  }
  if (inCode) closeCode();
  closeList();
  return html.join("") || "<p>No summary text available.</p>";
}

function renderInlineMarkdown(value) {
  const code = [];
  let text = escapeHTML(value).replace(/`([^`]+)`/g, (_, snippet) => {
    const token = `@@CODE${code.length}@@`;
    code.push(`<code>${snippet}</code>`);
    return token;
  });
  text = text
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/__([^_]+)__/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>")
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, `<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>`);
  text = linkifyIPsInHTML(text);
  code.forEach((snippet, index) => {
    text = text.replace(`@@CODE${index}@@`, snippet);
  });
  return text;
}

function exportReport(item) {
  if (!item) return toast("No report selected.", true);
  const filename = `${slugify(item.title || `${reportKind(item)}-${item.range || "report"}`)}.md`;
  downloadText(filename, reportToMarkdown(item), "text/markdown");
}

function printReport(item) {
  if (!item) return toast("No report selected.", true);
  const popup = window.open("", "_blank");
  if (!popup) {
    toast("Print window was blocked.", true);
    return;
  }
  popup.document.write(`
    <!doctype html>
    <html>
      <head>
        <title>${escapeHTML(item.title || "OriginPulse Report")}</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 32px; color: #172033; line-height: 1.5; }
          h1, h2, h3 { color: #0f172a; }
          table { border-collapse: collapse; width: 100%; margin: 16px 0; }
          th, td { border: 1px solid #d8dee9; padding: 8px; text-align: left; }
          pre { white-space: pre-wrap; background: #f5f7fb; padding: 12px; }
          .muted { color: #64748b; }
        </style>
      </head>
      <body>
        ${renderPrintableReport(item)}
      </body>
    </html>
  `);
  popup.document.close();
  popup.focus();
  popup.print();
}

function renderPrintableReport(item) {
  const summary = item.summary || {};
  return `
    <h1>${escapeHTML(reportTitle(item))}</h1>
    <p class="muted">${escapeHTML([formatReportType(reportKind(item)), item.range, item.model || "deterministic", shortTime(item.created_at || item.generated_at)].filter(Boolean).join(" / "))}</p>
    <h2>Executive Summary</h2>
    ${renderMarkdown(reportSummaryText(item))}
    <h2>Metrics</h2>
    <table><tbody>
      ${[
        ["Requests", formatNumber(summary.requests)],
        ["Unique IPs", formatNumber(summary.unique_ips)],
        ["4xx", `${formatNumber(summary.status_4xx)} (${formatPercent(summary.status_4xx_rate)})`],
        ["5xx", `${formatNumber(summary.status_5xx)} (${formatPercent(summary.status_5xx_rate)})`],
        ["Open Alerts", formatNumber(summary.open_alerts)],
        ["Top Site", summary.top_site || "-"],
        ["Top Path", summary.top_path || "-"],
        ["Top Source IP", summary.top_source_ip || "-"],
      ].map(([label, value]) => `<tr><th>${escapeHTML(label)}</th><td>${escapeHTML(value)}</td></tr>`).join("")}
    </tbody></table>
    <h2>Charts</h2>
    ${(item.charts || []).map((chart) => `<h3>${escapeHTML(chart.title || chart.key || "Chart")}</h3><p>${escapeHTML(chart.kind || "chart")} / ${escapeHTML(chart.unit || "count")} / ${formatNumber((chart.data || []).length)} points</p>`).join("") || "<p>No chart data stored with this report.</p>"}
    <h2>Drilldowns</h2>
    ${(item.drilldowns || []).map((drill) => `<h3>${escapeHTML(drill.title || drill.key || "Drilldown")}</h3><ul>${(drill.items || []).slice(0, 20).map((row) => `<li><strong>${escapeHTML(reportDrilldownTitle(row))}</strong> ${escapeHTML(reportDrilldownMeta(row))} ${escapeHTML(reportDrilldownValue(row))}</li>`).join("")}</ul>`).join("") || "<p>No drilldowns stored with this report.</p>"}
  `;
}

function reportToMarkdown(item) {
  const summary = item.summary || {};
  const lines = [
    `# ${reportTitle(item)}`,
    "",
    [formatReportType(reportKind(item)), item.range, item.model || "deterministic", shortTime(item.created_at || item.generated_at)].filter(Boolean).join(" / "),
    "",
    "## Executive Summary",
    "",
    reportSummaryText(item),
    "",
    "## Metrics",
    "",
    `- Requests: ${formatNumber(summary.requests)}`,
    `- Unique IPs: ${formatNumber(summary.unique_ips)}`,
    `- 4xx: ${formatNumber(summary.status_4xx)} (${formatPercent(summary.status_4xx_rate)})`,
    `- 5xx: ${formatNumber(summary.status_5xx)} (${formatPercent(summary.status_5xx_rate)})`,
    `- Open Alerts: ${formatNumber(summary.open_alerts)}`,
    `- Top Site: ${summary.top_site || "-"}`,
    `- Top Path: ${summary.top_path || "-"}`,
    `- Top Source IP: ${summary.top_source_ip || "-"}`,
    "",
    "## Charts",
    "",
    ...(item.charts || []).flatMap((chart) => [`### ${chart.title || chart.key || "Chart"}`, `${chart.kind || "chart"} / ${chart.unit || "count"} / ${(chart.data || []).length} points`, ""]),
    "## Drilldowns",
    "",
    ...(item.drilldowns || []).flatMap((drill) => [`### ${drill.title || drill.key || "Drilldown"}`, ...(drill.items || []).slice(0, 20).map((row) => `- ${reportDrilldownTitle(row)}: ${[reportDrilldownMeta(row), reportDrilldownValue(row)].filter(Boolean).join(" / ")}`), ""]),
  ];
  return lines.join("\n");
}

function downloadText(filename, content, type = "text/plain") {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function slugify(value) {
  return String(value || "report").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "report";
}

async function openDrawer(kind, rawIndex, value) {
  const index = Number(rawIndex || 0);
  let title = "Details";
  let body = "";
  qs("#drawer").classList.toggle("wide", ["ip", "request", "report", "security-signal", "user-agent", "alert", "alert-rule"].includes(kind));
  qs("#drawerKicker").textContent = kind || "Details";
  qs("#drawerTitle").textContent = "Loading";
  qs("#drawerBody").innerHTML = `<div class="empty">${iconHTML("fa-spinner fa-spin")} Loading details...</div>`;
  qs("#drawer").classList.remove("hidden");

  if (kind === "ip") {
    const items = state.data.analysis.source_ips || state.data.traffic.top_ips || [];
    const item = items.find((row) => row.ip === value) || items[index] || {};
    const ip = value || item.ip || "";
    title = ip || "Source IP";
    try {
      const detail = ip ? await fetchJSON(`/api/v1/investigate/ip/${encodeURIComponent(ip)}?${buildFilterQuery({ limit: drawerHistoryLimit })}`) : item;
      state.drawer = { kind, title, data: detail, summary: item, pages: {} };
      body = renderIPDetail(detail, item);
    } catch (error) {
      state.drawer = { kind, title, data: item, summary: item, pages: {} };
      body = renderIPDetail(item, item) + `<p class="form-error">${escapeHTML(error.message)}</p>`;
    }
  } else if (kind === "site") {
    const rows = siteRows({ estate: true });
    const item = rows.find((row) => row.id === value) || rows[index] || {};
    title = item.name || "Site";
    const siteFilter = buildFilterQuery({ site_id: item.id, limit: analysisHistoryLimit }, { includeSite: false });
    const siteTrafficFilter = buildFilterQuery({ site_id: item.id, limit: analysisHistoryLimit }, { includeSite: false });
    const [siteAnalysis, siteTraffic] = await Promise.all([
      safeFetch(`/api/v1/analysis/access-log?${siteFilter}`, {}),
      safeFetch(`/api/v1/investigate/traffic?${siteTrafficFilter}`, {}),
    ]);
    const detail = { item, analysis: siteAnalysis, traffic: siteTraffic };
    state.drawer = { kind, title, data: detail, summary: null, pages: {} };
    body = renderSiteDetail(item, detail);
  } else if (kind === "request") {
    const item = state.detailCache[value] || (state.data.traffic.recent_errors || [])[index] || {};
    title = `${item.method || "GET"} ${item.path || "/"}`;
    state.drawer = { kind, title, data: item, summary: null, pages: {} };
    body = renderRequestDetail(item);
  } else if (kind === "security-signal") {
    const item = state.detailCache[value] || securitySignalRows()[index] || {};
    title = item.title || item.kind || "Security Signal";
    const params = new URLSearchParams(buildFilterQuery({
      limit: drawerHistoryLimit,
      kind: item.kind || "",
      category: item.category || "",
      rule_key: item.rule_key || "",
      env: item.env || "",
      ip: item.ip || "",
      method: item.method || "",
      path: item.path || "",
    }));
    try {
      const detail = await fetchJSON(`/api/v1/investigate/security-signal?${params}`);
      const merged = { ...item, ...detail, signal: { ...item, ...(detail.signal || {}) } };
      state.drawer = { kind, title, data: merged, summary: item, pages: {} };
      body = renderSecuritySignalDetail(merged);
    } catch (error) {
      state.drawer = { kind, title, data: item, summary: null, pages: {} };
      body = renderSecuritySignalDetail(item) + `<p class="form-error">${escapeHTML(error.message)}</p>`;
    }
  } else if (kind === "alert") {
    const cached = state.detailCache[value] || (state.data.alerts || [])[index] || {};
    title = cached.title || cached.rule_key || "Alert";
    let item = cached;
    if (cached.id) {
      try {
        const detail = await fetchJSON(`/api/v1/alerts/${encodeURIComponent(cached.id)}?limit=${alertHistoryLimit}`);
        item = { ...(detail.alert || cached), requests: detail.requests || [] };
        state.detailCache[value] = item;
      } catch (error) {
        body = `<p class="form-error">${escapeHTML(error.message)}</p>`;
      }
    }
    title = item.title || item.rule_key || "Alert";
    state.drawer = { kind, title, data: item, summary: cached, pages: {} };
    body += renderAlertDetail(item);
  } else if (kind === "alert-rule") {
    const item = state.detailCache[value] || alertRuleRows()[index] || {};
    title = item.title || item.rule_key || "Alert Rule";
    state.drawer = { kind, title, data: item, summary: null, pages: {} };
    body = renderAlertRuleDetail(item);
  } else if (kind === "user-agent") {
    const item = state.detailCache[value] || findUserAgentByValue(value) || {};
    const sample = item.sample || item.user_agent || item.family || "User Agent";
    title = parseUserAgent({ ...item, sample }).label || item.family || userAgentFamily(sample) || "User Agent";
    const params = new URLSearchParams(buildFilterQuery({ limit: drawerHistoryLimit }));
    if (item.id) params.set("id", item.id);
    if (sample && sample !== "User Agent") params.set("sample", sample);
    try {
      const detail = await fetchJSON(`/api/v1/investigate/user-agent?${params}`);
      const merged = { ...item, ...detail, user_agent: { ...item, ...(detail.user_agent || {}) } };
      state.drawer = { kind, title, data: merged, summary: item, pages: {} };
      body = renderUserAgentDetail(merged);
    } catch (error) {
      state.drawer = { kind, title, data: item, summary: null, pages: {} };
      body = renderUserAgentDetail(item) + `<p class="form-error">${escapeHTML(error.message)}</p>`;
    }
  } else if (kind === "report") {
    const cached = state.detailCache[value] || allReports()[index] || {};
    title = reportTitle(cached);
    let item = cached;
    if (cached.id) {
      try {
        item = await fetchJSON(`/api/v1/reports/${encodeURIComponent(cached.id)}`);
        state.detailCache[value] = item;
      } catch (error) {
        body = `<p class="form-error">${escapeHTML(error.message)}</p>`;
      }
    }
    title = reportTitle(item);
    state.drawer = { kind, title, data: item, summary: cached, pages: {} };
    body += renderReportDetail(item);
  }
  qs("#drawerKicker").textContent = kind || "Details";
  qs("#drawerTitle").textContent = title;
  qs("#drawerBody").innerHTML = body || empty("No details available.");
}

function closeDrawer() {
  qs("#drawer").classList.add("hidden");
  state.drawer = { kind: null, title: "", data: null, summary: null, pages: {} };
}

function openModal(title, kicker, body) {
  const backdrop = qs("#modalBackdrop");
  qs("#modalKicker").textContent = kicker || "Guide";
  qs("#modalTitle").textContent = title || "Guide";
  qs("#modalBody").innerHTML = body || "";
  backdrop.classList.remove("hidden");
  backdrop.setAttribute("aria-hidden", "false");
}

function closeModal() {
  const backdrop = qs("#modalBackdrop");
  if (backdrop) {
    backdrop.classList.add("hidden");
    backdrop.setAttribute("aria-hidden", "true");
  }
}

function queryGuideHTML() {
  return `
    <div class="guide-grid">
      <section>
        <h3>How Matching Works</h3>
        <p>The search box filters the loaded access-log evidence for the selected range and project. It matches status, project, environment, source IP, HTTP method, path, and user-agent text.</p>
      </section>
      <section>
        <h3>Useful Queries</h3>
        <div class="guide-examples">
          <code>500</code>
          <code>wp-login</code>
          <code>GET /xmlrpc.php</code>
          <code>167.103.5.57</code>
          <code>firefox</code>
          <code>example live</code>
        </div>
      </section>
      <section>
        <h3>Field Hints</h3>
        ${facts([
          ["Status", "Search 404, 403, 500, or any status code."],
          ["Path", "Use exact fragments like /wp-login.php or admin-ajax."],
          ["IP", "Paste a source IP to isolate its matching events."],
          ["Agent", "Use browser, bot, crawler, or tool names from user-agent strings."],
        ])}
      </section>
      <section>
        <h3>Scope</h3>
        <p>Range and project filters still apply. Clear the project selector to search across all projects.</p>
      </section>
    </div>
  `;
}

function renderCurrentDrawer() {
  if (!state.drawer.kind || !state.drawer.data) return;
  qs("#drawerKicker").textContent = state.drawer.kind;
  qs("#drawerTitle").textContent = state.drawer.title || "Details";
  qs("#drawerBody").innerHTML = renderDrawerBody(state.drawer.kind, state.drawer.data, state.drawer.summary);
}

function renderDrawerBody(kind, data, summary) {
  if (kind === "ip") return renderIPDetail(data, summary || {});
  if (kind === "site") return renderSiteDetail(data.item || data, data);
  if (kind === "request") return renderRequestDetail(data);
  if (kind === "security-signal") return renderSecuritySignalDetail(data);
  if (kind === "alert") return renderAlertDetail(data);
  if (kind === "alert-rule") return renderAlertRuleDetail(data);
  if (kind === "user-agent") return renderUserAgentDetail(data);
  if (kind === "report") return renderReportDetail(data);
  return empty("No details available.");
}

function showRoute(route, push) {
  state.route = routeById[route] ? route : "overview";
  updateURL(push);
  render();
  void ensureRouteData();
}

function updateURL(push) {
  const route = routeById[state.route] || routeById.overview;
  const params = new URLSearchParams();
  if (state.range !== "24h") params.set("range", state.range);
  if (state.siteID) params.set("site_id", state.siteID);
  const url = `${route.path}${params.toString() ? `?${params}` : ""}`;
  history[push ? "pushState" : "replaceState"]({}, "", url);
}

function buildFilterQuery(extra = {}, options = {}) {
  const params = new URLSearchParams();
  params.set("range", state.range);
  if (state.siteID && options.includeSite !== false) params.set("site_id", state.siteID);
  Object.entries(extra).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    params.set(key, value);
  });
  return params.toString();
}

function showApp() {
  qs("#loginView").classList.add("hidden");
  qs("#appShell").classList.remove("hidden");
}

function showLogin() {
  qs("#appShell").classList.add("hidden");
  qs("#loginView").classList.remove("hidden");
}

async function login(event) {
  event.preventDefault();
  qs("#loginError").textContent = "";
  try {
    const session = await fetchJSON("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ email: qs("#emailInput").value, password: qs("#passwordInput").value }),
    });
    state.currentUser = session.user || null;
    showApp();
    await refreshAll();
  } catch (error) {
    qs("#loginError").textContent = error.message;
  }
}

async function logout() {
  await fetchJSON("/api/v1/auth/logout", { method: "POST", body: "{}" }).catch(() => null);
  state.currentUser = null;
  showLogin();
}

function drawCharts() {
  qsa(".sparkline").forEach((canvas) => drawSpark(canvas, canvas.dataset.spark.split(",").map(Number), cssColor(canvas.dataset.color || "cyan")));
  if (qs("#trafficLine")) {
    const rows = state.data.traffic.timeline || [];
    drawTimeline(qs("#trafficLine"), rows);
    installTimelineHover(qs("#trafficLine"), rows);
  }
  if (qs("#statusBars")) {
    const rows = state.data.traffic.status_breakdown || state.data.analysis.status_breakdown || [];
    drawStatusBars(qs("#statusBars"), rows);
    installStatusHover(qs("#statusBars"), rows);
  }
}

function drawSpark(canvas, values, color) {
  const ctx = setupCanvas(canvas);
  const { width, height } = canvas.getBoundingClientRect();
  drawLine(ctx, values, width, height, color, 2);
}

function drawTimeline(canvas, rows) {
  const ctx = setupCanvas(canvas);
  const { width, height } = canvas.getBoundingClientRect();
  drawFrame(ctx, width, height);
  const values = rows.length ? rows.map((row) => row.requests || 0) : sparkValues(24, 120, 900);
  drawLine(ctx, values, width, height, cssColor("cyan"), 2.5);
  const errors = rows.map((row) => (row.status_4xx || 0) + (row.status_5xx || 0));
  if (errors.some(Boolean)) drawLine(ctx, errors, width, height, cssColor("red"), 2);
}

function drawStatusBars(canvas, rows) {
  const ctx = setupCanvas(canvas);
  const { width, height } = canvas.getBoundingClientRect();
  drawFrame(ctx, width, height);
  const buckets = rows.length ? rows : [
    { status: 200, requests: state.data.analysis?.totals?.requests || 0 },
    { status: 404, requests: state.data.analysis?.totals?.status_4xx || 0 },
    { status: 500, requests: state.data.analysis?.totals?.status_5xx || 0 },
  ];
  const max = Math.max(1, ...buckets.map((row) => row.requests || 0));
  const gap = 10;
  const barWidth = Math.max(16, (width - gap * (buckets.length + 1)) / Math.max(1, buckets.length));
  buckets.forEach((row, index) => {
    const h = ((row.requests || 0) / max) * (height - 44);
    const x = gap + index * (barWidth + gap);
    const y = height - h - 24;
    ctx.fillStyle = statusColor(row.status);
    ctx.fillRect(x, y, barWidth, h);
    ctx.fillStyle = "#91a3b8";
    ctx.font = "11px sans-serif";
    ctx.fillText(String(row.status || "n/a"), x, height - 8);
  });
}

function installTimelineHover(canvas, rows) {
  const values = rows.length ? rows.map((row) => row.requests || 0) : [];
  canvas.dataset.hoverReady = "timeline";
  canvas.onmousemove = (event) => {
    if (!values.length) return hideChartTooltip();
    const rect = canvas.getBoundingClientRect();
    const ratioX = clamp((event.clientX - rect.left) / Math.max(1, rect.width), 0, 1);
    const index = clamp(Math.round(ratioX * (rows.length - 1)), 0, rows.length - 1);
    const row = rows[index] || {};
    showChartTooltip(event, `
      <strong>${shortTime(row.bucket_ts)}</strong>
      <span><i style="background: var(--cyan)"></i>Requests ${formatNumber(row.requests)}</span>
      <span><i style="background: var(--amber)"></i>4xx ${formatNumber(row.status_4xx)}</span>
      <span><i style="background: var(--red)"></i>5xx ${formatNumber(row.status_5xx)}</span>
    `);
  };
  canvas.onmouseleave = hideChartTooltip;
}

function installStatusHover(canvas, rows) {
  const buckets = rows.length ? rows : [
    { status: 200, requests: state.data.analysis?.totals?.requests || 0 },
    { status: 404, requests: state.data.analysis?.totals?.status_4xx || 0 },
    { status: 500, requests: state.data.analysis?.totals?.status_5xx || 0 },
  ];
  canvas.dataset.hoverReady = "status";
  canvas.onmousemove = (event) => {
    if (!buckets.length) return hideChartTooltip();
    const rect = canvas.getBoundingClientRect();
    const gap = 10;
    const barWidth = Math.max(16, (rect.width - gap * (buckets.length + 1)) / Math.max(1, buckets.length));
    const x = event.clientX - rect.left;
    const index = Math.floor((x - gap) / (barWidth + gap));
    if (index < 0 || index >= buckets.length) return hideChartTooltip();
    const barStart = gap + index * (barWidth + gap);
    if (x < barStart || x > barStart + barWidth) return hideChartTooltip();
    const row = buckets[index] || {};
    showChartTooltip(event, `
      <strong>Status ${escapeHTML(row.status || "n/a")}</strong>
      <span><i style="background: ${statusColor(row.status)}"></i>${formatNumber(row.requests)} requests</span>
      <span>${formatPercent(ratio(row.requests, state.data.analysis?.totals?.requests))} of traffic</span>
    `);
  };
  canvas.onmouseleave = hideChartTooltip;
}

function showChartTooltip(event, html) {
  let tooltip = qs("#chartTooltip");
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.id = "chartTooltip";
    tooltip.className = "chart-tooltip";
    document.body.appendChild(tooltip);
  }
  tooltip.innerHTML = html;
  tooltip.classList.remove("hidden");
  const x = Math.min(window.innerWidth - 220, event.clientX + 14);
  const y = Math.min(window.innerHeight - 130, event.clientY + 14);
  tooltip.style.transform = `translate(${Math.max(8, x)}px, ${Math.max(8, y)}px)`;
}

function hideChartTooltip() {
  const tooltip = qs("#chartTooltip");
  if (tooltip) tooltip.classList.add("hidden");
}

function setupCanvas(canvas) {
  const ratio = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = Math.max(1, Math.floor(rect.width * ratio));
  canvas.height = Math.max(1, Math.floor(rect.height * ratio));
  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, rect.width, rect.height);
  return ctx;
}

function drawFrame(ctx, width, height) {
  ctx.strokeStyle = "rgba(43, 71, 100, 0.55)";
  ctx.lineWidth = 1;
  for (let i = 1; i < 4; i++) {
    const y = (height / 4) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }
}

function drawLine(ctx, values, width, height, color, lineWidth) {
  const max = Math.max(1, ...values);
  ctx.beginPath();
  values.forEach((value, index) => {
    const x = values.length <= 1 ? 0 : (index / (values.length - 1)) * (width - 2) + 1;
    const y = height - 4 - (value / max) * (height - 8);
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = color;
  ctx.lineWidth = lineWidth;
  ctx.lineCap = "round";
  ctx.stroke();
}

function sparkValues(count = 18, min = 10, max = 80) {
  return Array.from({ length: count }, (_, index) => Math.round(min + Math.abs(Math.sin(index * 1.7 + count) * max) + (index % 5) * 4));
}

function cssColor(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(`--${name}`).trim() || name;
}

function statusColor(status) {
  const value = Number(status);
  if (value >= 500) return cssColor("red");
  if (value >= 400) return cssColor("amber");
  if (value >= 300) return cssColor("purple");
  return cssColor("green");
}

function collectorHealth() {
  const stats = state.data.collectorHealth?.raw_files?.stats || {};
  const recent = state.data.collectorHealth?.raw_files?.recent || [];
  return {
    state: state.data.overview.database_configured ? "Healthy" : "Local",
    uptime: state.data.overview.collection_interval || "-",
    recent,
    stats,
  };
}

function requestsPerMinute() {
  return state.data.overview?.analytics?.requests_per_minute || 0;
}

function openProblemCount() {
  return state.data.alerts.length || (state.data.analysis?.totals?.status_5xx || 0);
}

function activeRangeLabel() {
  return qs("#rangeSelect")?.selectedOptions?.[0]?.textContent || state.range;
}

function reportKind(report) {
  return report.report_type || report.range || "daily";
}

function reportTitle(report) {
  return report.title || `${formatReportType(reportKind(report))} Report`;
}

function reportTypes(reports) {
  return unique(reports.map(reportKind)).sort((a, b) => a.localeCompare(b));
}

function formatReportType(value) {
  return String(value || "report")
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function allReports() {
  const seen = new Set();
  return [...state.localReports, ...(state.data.reports || [])].filter((report) => {
    const key = report.id || `${report.report_type}:${report.range_start}:${report.created_at}:${report.output}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function reportSearchText(item) {
  const summary = typeof item.summary === "string" ? item.summary : JSON.stringify(item.summary || {});
  return `${item.title || ""} ${summary} ${item.output || ""} ${item.report_type || ""}`;
}

function readinessBanner() {
  const overview = state.data.overview || {};
  const analytics = overview.analytics || {};
  const coverage = state.data.archiveCoverage || {};
  const fetchErrors = state.fetchErrors || [];
  const hasRequests = Number(analytics.requests || state.data.analysis?.totals?.requests || 0) > 0;
  const messages = [];
  const actions = [`<button class="button small" type="button" data-action="refresh">${iconHTML("fa-rotate-right")}Refresh</button>`];
  if (fetchErrors.length) {
    const first = fetchErrors[0];
    messages.push(`${formatNumber(fetchErrors.length)} dashboard request(s) failed while loading ${activeRangeLabel()}. First failure: ${first.message}.`);
  } else if (!overview.database_configured) {
    messages.push("DATABASE_URL is not set, so indexed analytics, persisted reports, users, alerts, and browser-push subscriptions are unavailable.");
  } else if (coverage.requires_archive_import) {
    const oldWindow = [shortTime(coverage.import_window_start), shortTime(coverage.import_window_end)].filter(Boolean).join(" to ");
    if (coverage.already_imported) {
      messages.push(`The old part of ${activeRangeLabel()} is temporarily imported from archives (${oldWindow}). It will expire after ${coverage.temporary_import_max_age || "the configured temporary window"}.`);
    } else if (coverage.import_recommended) {
      messages.push(`${activeRangeLabel()} reaches beyond the hot ${coverage.hot_event_max_age || "event"} window. ${formatNumber(coverage.selected_archive_count || 0)} archive file(s) cover ${formatPercent(coverage.archive_coverage_ratio || 0)} of the old range${oldWindow ? ` (${oldWindow})` : ""}.`);
      actions.push(`<button class="button small primary" type="button" data-action="import-range-archives">${iconHTML("fa-file-import")}Import Archived Range</button>`);
    } else {
      messages.push(`${activeRangeLabel()} reaches beyond the hot ${coverage.hot_event_max_age || "event"} window, but no ready archives currently cover the old portion of this range.`);
    }
  } else if (!hasRequests) {
    messages.push(`No indexed requests in ${activeRangeLabel()}. Run pipeline/backfill, or choose a range that overlaps indexed hot data.`);
  }
  if (!messages.length) return "";
  return `
    <article class="panel readiness-banner">
      <div class="panel-head">
        <div><h2>${iconHTML("fa-database")} Data Readiness</h2><p>${escapeHTML(messages.join(" "))}</p></div>
        <div class="toolbar">
          ${actions.join("")}
        </div>
      </div>
    </article>
  `;
}

function normalizeSeverity(value) {
  const severity = String(value || "low").toLowerCase();
  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "medium" || severity === "warning") return "medium";
  return "low";
}

function facts(items) {
  return `<dl class="facts">${items.map(([label, value]) => `<div><dt>${escapeHTML(label)}</dt><dd>${escapeHTML(value ?? "-")}</dd></div>`).join("")}</dl>`;
}

function factsRich(items) {
  return `<dl class="facts">${items.map(([label, value]) => `<div><dt>${escapeHTML(label)}</dt><dd>${value || "-"}</dd></div>`).join("")}</dl>`;
}

function empty(message) {
  return `<div class="empty">${escapeHTML(message)}</div>`;
}

function toast(message, error = false) {
  const el = qs("#toast");
  el.textContent = message;
  el.classList.toggle("error", error);
  el.classList.remove("hidden");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.add("hidden"), 3200);
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function formatCompact(value) {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(Number(value || 0));
}

function formatPercent(value) {
  const number = Number(value || 0) * 100;
  return `${number.toFixed(number > 0 && number < 1 ? 2 : 1)}%`;
}

function formatBytes(value) {
  const number = Number(value || 0);
  if (!number) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(number) / Math.log(1024)), units.length - 1);
  return `${(number / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
}

function formatMs(value) {
  const number = Number(value || 0);
  return number ? `${Math.round(number)}ms` : "0ms";
}

function shortTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function yesNo(value) {
  return value ? "Yes" : "No";
}

function formatChannel(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function iconHTML(name) {
  const classes = String(name || "fa-circle")
    .split(/\s+/)
    .filter(Boolean);
  const hasStyle = classes.some((klass) => /^fa-(solid|regular|light|thin|duotone|brands|sharp|classic|fass|fasr|fasl|fast|fasds|fasdr|fasdl|fasdt)$/.test(klass));
  if (!hasStyle) {
    classes.unshift("fa-solid");
  }
  return `<i class="${escapeAttr(classes.join(" "))}" aria-hidden="true"></i>`;
}

function sum(rows, key) {
  return rows.reduce((total, item) => total + Number(item[key] || 0), 0);
}

function ratio(part, whole) {
  const denom = Number(whole || 0);
  if (!denom) return 0;
  return Number(part || 0) / denom;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function unique(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function cacheDetail(kind, value, fallbackKey) {
  const key = `${kind}:${fallbackKey || Math.random().toString(36).slice(2)}`;
  state.detailCache[key] = value;
  return key;
}

function groupBy(rows, keyFn) {
  return rows.reduce((groups, item) => {
    const key = keyFn(item) || "";
    groups[key] = groups[key] || [];
    groups[key].push(item);
    return groups;
  }, {});
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttr(value) {
  return escapeHTML(value);
}

function urlBase64ToUint8Array(value) {
  const padding = "=".repeat((4 - value.length % 4) % 4);
  const base64 = (value + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  return Uint8Array.from([...raw].map((char) => char.charCodeAt(0)));
}

boot();
