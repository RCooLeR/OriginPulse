const qs = (selector, root = document) => root.querySelector(selector);
const qsa = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const routes = [
  { id: "overview", path: "/", title: "Overview", subtitle: "Real-time operations across your OriginPulse estate.", icon: "fa-table-cells-large" },
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
  { id: "pulse", path: "/pulse-logs", title: "Pulse Logs", subtitle: "Collector jobs, indexed segments, raw files, and delivery history.", icon: "fa-chart-line" },
  { id: "settings", path: "/settings", title: "Settings", subtitle: "User, notification, collection, and system status.", icon: "fa-gear" },
];

const routeById = Object.fromEntries(routes.map((route) => [route.id, route]));
const pathToRoute = Object.fromEntries(routes.map((route) => [route.path, route.id]));
const reportCatalogPageSize = 8;
const notificationPageSize = 8;
const segmentPageSize = 10;
const rawFilePageSize = 10;
const archivePageSize = 8;
const archiveImportPageSize = 8;
const jobPageSize = 10;
const jobStepPageSize = 12;
const pulseHistoryLimit = 500;
const alertHistoryLimit = 500;
const alertRequestPageSize = 6;
const userAgentDetailPageSize = 6;
const securitySignalDetailPageSize = 6;
const ipDetailPageSize = 6;
const drawerHistoryLimit = 500;
const analysisHistoryLimit = 500;
const dashboardAutoRefreshMs = 60 * 1000;
const PHP_LOG_TYPES = ["php-error", "php-slow"];
const MYSQL_LOG_TYPES = ["mysql", "mysql-slow"];

const state = {
  route: pathToRoute[location.pathname] || "overview",
  range: new URLSearchParams(location.search).get("range") || "24h",
  siteID: new URLSearchParams(location.search).get("site_id") || "",
  search: "",
  reportType: "all",
  rawFileStatus: "all",
  pipeline: {
    maxSegments: 100,
    indexWorkers: 2,
  },
  currentUser: null,
  loading: false,
  refreshing: false,
  autoRefreshTimer: null,
  securityAnalysisLoading: false,
  securityAnalysisKey: "",
  estateDataLoading: false,
  estateDataKey: "",
  localReports: [],
  detailCache: {},
  pages: {
    trafficPaths: 1,
    trafficIPs: 1,
    trafficQueries: 1,
    searchTopPaths: 1,
    searchMatchedEvents: 1,
    logRecentEvidence: 1,
    logTopPaths: 1,
    logSourceIPs: 1,
    logUserAgents: 1,
    pulseArchives: 1,
    pulseArchiveImports: 1,
    pulseCooldowns: 1,
    pulseJobSteps: 1,
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
    reportCatalog: { total: 0, limit: reportCatalogPageSize, offset: 0, report_types: [] },
    segmentCatalog: { total: 0, limit: segmentPageSize, offset: 0 },
    jobs: [],
    jobCatalog: { total: 0, limit: jobPageSize, offset: 0 },
    jobSteps: [],
    jobStepCatalog: { total: 0, limit: jobStepPageSize, offset: 0 },
    credentials: {},
    geoip: {},
    collectorHealth: {},
    rawFileCatalog: { total: 0, limit: rawFilePageSize, offset: 0 },
    retention: {},
    storage: {},
    fastReadAudit: {},
    archives: [],
    archiveCatalog: { total: 0, limit: archivePageSize, offset: 0 },
    archiveImports: [],
    archiveImportCatalog: { total: 0, limit: archiveImportPageSize, offset: 0 },
    notifications: {},
    pulseNotifications: {},
    webPush: {},
    users: [],
    segments: [],
  },
  ipTrust: {},
  fetchErrors: [],
  pendingRequests: 0,
  refreshQueued: false,
  advancedSearch: {
    key: "",
    events: [],
    total: 0,
    loading: false,
    error: "",
  },
};

class AuthError extends Error {}

async function fetchJSON(path, options = {}) {
  const { timeoutMs = 0, ...fetchOptions } = options;
  const controller = timeoutMs ? new AbortController() : null;
  const timeout = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  const method = String(fetchOptions.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...(fetchOptions.headers || {}) };
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers["X-OriginPulse-Request"] = "same-origin";
  }
  beginRequest();
  try {
    const response = await fetch(path, {
      headers,
      ...fetchOptions,
      ...(controller ? { signal: controller.signal } : {}),
    });
    if (response.status === 401) throw new AuthError();
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      throw new Error(detail?.error?.message || `${response.status} ${response.statusText}`);
    }
    return response.json();
  } finally {
    if (timeout) clearTimeout(timeout);
    endRequest();
  }
}

function beginRequest() {
  state.pendingRequests += 1;
  updateRequestActivity();
}

function endRequest() {
  state.pendingRequests = Math.max(0, state.pendingRequests - 1);
  updateRequestActivity();
}

function updateRequestActivity() {
  const activity = qs("#requestActivity");
  if (!activity) return;
  const count = state.pendingRequests;
  activity.classList.toggle("hidden", count === 0);
  activity.setAttribute("aria-busy", count > 0 ? "true" : "false");
  activity.querySelector("span").textContent = count > 1 ? `Loading ${count}` : "Loading";
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
    render();
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
  document.addEventListener("input", (event) => {
    if (event.target.id !== "advancedSearchInput") return;
    state.search = event.target.value.trim().toLowerCase();
    const headerSearch = qs("#searchInput");
    if (headerSearch && headerSearch.value !== event.target.value) headerSearch.value = event.target.value;
  });
  document.addEventListener("submit", (event) => {
    if (event.target.id !== "advancedSearchForm") return;
    event.preventDefault();
    const input = qs("#advancedSearchInput", event.target);
    state.search = (input?.value || "").trim().toLowerCase();
    const headerSearch = qs("#searchInput");
    if (headerSearch) headerSearch.value = input?.value || "";
    resetPagination();
    void runAdvancedSearch();
  });
  document.addEventListener("change", async (event) => {
    const reportType = event.target.closest("[data-report-type-filter]");
    if (reportType) {
      state.reportType = reportType.value || "all";
      await loadReportCatalogPage(1);
      return;
    }
    const rawFileStatus = event.target.closest("[data-raw-file-status-filter]");
    if (rawFileStatus) {
      state.rawFileStatus = rawFileStatus.value || "all";
      await loadRawFilePage(1);
      return;
    }
    const pipelineField = event.target.closest("[data-pipeline-field]");
    if (pipelineField) {
      updatePipelineOption(pipelineField.dataset.pipelineField, pipelineField.value);
    }
  });
  qs("#refreshButton").addEventListener("click", () => refreshAll());
  qs("#collectButton").addEventListener("click", () => runButton(qs("#collectButton"), "Collection queued", async () => {
    await fetchJSON("/api/v1/system/collect", { method: "POST" });
  }));
  qs("#pipelineButton").addEventListener("click", () => runButton(qs("#pipelineButton"), "Pipeline complete", async () => {
    const result = await runPipelineRequest();
    await refreshAll();
    return pipelineResultMessage(result);
  }));
  qs("#logoutButton").addEventListener("click", logout);
  qs("#loginForm").addEventListener("submit", login);
  qs("#drawerClose").addEventListener("click", closeDrawer);
  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeModal();
  });
  window.addEventListener("resize", drawCharts);
}

async function refreshAll(options = {}) {
  const background = Boolean(options.background);
  if (state.refreshing) {
    state.refreshQueued = true;
    return;
  }
  state.refreshing = true;
  state.loading = !background;
  state.fetchErrors = [];
  state.estateDataKey = "";
  state.securityAnalysisKey = "";
  if (!background) {
    document.body.classList.add("busy");
    render();
  }
  try {
    const filter = buildFilterQuery();
    const analysisFilter = buildFilterQuery({ limit: analysisHistoryLimit });
    const trafficFilter = buildFilterQuery({
      limit: analysisHistoryLimit,
      include_query_params: state.route === "traffic" ? "1" : "",
    });
    const wantsPulseData = state.route === "pulse";
    const heavyReadTimeoutMs = activeRangeMs() >= 90 * 24 * 60 * 60 * 1000 ? 120000 : 30000;
    const estateKey = buildFilterQuery({ limit: analysisHistoryLimit }, { includeSite: false });
    const analysisRequest = safeFetch(`/api/v1/analysis/access-log?${analysisFilter}`, {}, heavyReadTimeoutMs);
    const [overview, analysis, traffic, sites, alerts, reports, jobs, jobSteps, credentials, geoip, collectorHealth, retention, storage, fastReadAudit, archives, archiveImports, archiveCoverage, notifications, webPush, users, segments] = await Promise.all([
      safeFetch(`/api/v1/dashboard/overview?${filter}`, {}),
      analysisRequest,
      safeFetch(`/api/v1/investigate/traffic?${trafficFilter}`, {}, heavyReadTimeoutMs),
      safeFetch("/api/v1/sites", { sites: [] }),
      safeFetch(`/api/v1/alerts?limit=${alertHistoryLimit}`, { alerts: [] }),
      safeFetch(`/api/v1/reports/recent?${reportCatalogQuery(1)}`, { reports: [], total: 0, limit: reportCatalogPageSize, offset: 0, report_types: [] }),
      safeFetch(`/api/v1/system/jobs?${jobHistoryQuery(1)}`, { jobs: [], total: 0, limit: jobPageSize, offset: 0 }),
      safeFetch(`/api/v1/system/job-steps?${jobStepHistoryQuery(1)}`, { steps: [], total: 0, limit: jobStepPageSize, offset: 0 }),
      safeFetch("/api/v1/system/credentials", {}),
      safeFetch("/api/v1/system/geoip", {}),
      safeFetch(`/api/v1/system/collector-health?${rawFileHistoryQuery(1)}`, {}),
      safeFetch("/api/v1/system/retention", {}),
      wantsPulseData ? safeFetch("/api/v1/system/storage", {}) : Promise.resolve(state.data.storage || {}),
      wantsPulseData ? safeFetch(`/api/v1/system/fast-read-audit?${filter}`, {}) : Promise.resolve(state.data.fastReadAudit || {}),
      safeFetch(`/api/v1/system/archives?${archiveHistoryQuery(1)}`, { archives: [], total: 0, limit: archivePageSize, offset: 0 }),
      safeFetch(`/api/v1/system/archive-imports?${archiveImportHistoryQuery(1)}`, { imports: [], total: 0, limit: archiveImportPageSize, offset: 0 }),
      wantsPulseData ? safeFetch(`/api/v1/system/archive-coverage?${filter}`, { archives: [], active_temporary_imports: [] }) : Promise.resolve(state.data.archiveCoverage || { archives: [], active_temporary_imports: [] }),
      safeFetch(`/api/v1/notifications?${notificationHistoryQuery(1)}`, {}),
      safeFetch("/api/v1/notifications/web-push/public-key", {}),
      safeFetch("/api/v1/users", { users: [] }),
      safeFetch(`/api/v1/system/segments?${segmentHistoryQuery(1)}`, { segments: [], total: 0, limit: segmentPageSize, offset: 0 }),
    ]);
    state.data = {
      overview,
      analysis,
      traffic,
      estateAnalysis: state.siteID ? {} : analysis,
      estateTraffic: state.siteID ? {} : traffic,
      sites: sites.sites || [],
      alerts: alerts.alerts || [],
      reports: reports.reports || [],
      reportCatalog: reportCatalogMeta(reports),
      jobs: jobs.jobs || [],
      jobCatalog: jobCatalogMeta(jobs),
      jobSteps: jobSteps.steps || [],
      jobStepCatalog: jobStepCatalogMeta(jobSteps),
      credentials,
      geoip,
      collectorHealth,
      rawFileCatalog: rawFileCatalogMeta(collectorHealth.raw_files || {}),
      retention,
      storage,
      fastReadAudit,
      archives: archives.archives || [],
      archiveCatalog: archiveCatalogMeta(archives),
      archiveImports: archiveImports.imports || [],
      archiveImportCatalog: archiveImportCatalogMeta(archiveImports),
      archiveCoverage,
      notifications,
      pulseNotifications: notifications,
      webPush,
      users: users.users || [],
      segments: segments.segments || [],
      segmentCatalog: segmentCatalogMeta(segments),
    };
    if (!state.siteID) state.estateDataKey = estateKey;
    render();
    void ensureRouteData();
  } catch (error) {
    if (error instanceof AuthError) {
      showLogin();
      return;
    }
    toast(error.message, true);
  } finally {
    state.refreshing = false;
    state.loading = false;
    document.body.classList.remove("busy");
    if (state.refreshQueued) {
      state.refreshQueued = false;
      void refreshAll({ background });
    } else {
      render();
    }
  }
}

function startAutoRefresh() {
  stopAutoRefresh();
  state.autoRefreshTimer = window.setInterval(() => {
    if (!state.currentUser || document.visibilityState === "hidden") return;
    void refreshAll({ background: true });
  }, dashboardAutoRefreshMs);
}

function stopAutoRefresh() {
  if (!state.autoRefreshTimer) return;
  window.clearInterval(state.autoRefreshTimer);
  state.autoRefreshTimer = null;
}

async function ensureRouteData() {
  if (state.route === "sites") {
    await refreshEstateData();
  }
  if (state.route === "security" || state.route === "mysql") {
    await refreshSecurityAnalysis(state.route);
  }
}

async function refreshEstateData() {
  const key = buildFilterQuery({ limit: analysisHistoryLimit }, { includeSite: false });
  if (state.estateDataKey === key || state.estateDataLoading) return;
  state.estateDataLoading = true;
  render();
  try {
    const [analysis, traffic] = await Promise.all([
      fetchJSON(`/api/v1/analysis/access-log?${key}`, { timeoutMs: 120000 }),
      fetchJSON(`/api/v1/investigate/traffic?${key}`, { timeoutMs: 120000 }),
    ]);
    if (key === buildFilterQuery({ limit: analysisHistoryLimit }, { includeSite: false })) {
      state.data.estateAnalysis = analysis || {};
      state.data.estateTraffic = traffic || {};
      state.estateDataKey = key;
    }
  } catch (error) {
    if (error instanceof AuthError) {
      showLogin();
      return;
    }
    state.fetchErrors.push({ path: "sites estate analysis", message: error.message || "Request failed" });
    toast(`Sites estate analysis failed: ${error.message}`, true);
  } finally {
    state.estateDataLoading = false;
    render();
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
  state.detailCache = {};
  collectIPTrust();
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
  qs("#content").innerHTML = readinessBanner() + (state.loading ? loadingPanel() : (renderers[state.route] || renderOverview)());
  requestAnimationFrame(drawCharts);
}

function loadingPanel() {
  return `
    <article class="panel loading-panel">
      <div class="empty">${iconHTML("fa-spinner fa-spin")} Loading ${escapeHTML(activeRangeLabel())} data...</div>
    </article>
  `;
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
  qs("#collectorLastDownload").textContent = health.lastDownload;
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
      <button class="button outline" type="button" data-action="evaluate-alerts">${iconHTML("fa-chart-line")}Evaluate Alerts</button>
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
  const estateTotals = (state.data.estateAnalysis?.totals?.requests ? state.data.estateAnalysis : state.data.analysis)?.totals || {};
  const estateStatus = state.estateDataLoading ? `${iconHTML("fa-spinner fa-spin")} Loading estate data` : "Table View";
  return `
    ${metricGrid([
      metric("Total Projects", state.data.sites.length || state.data.overview.sites_enabled, "fa-diagram-project", "cyan"),
      metric("Healthy Sites", rows.filter((site) => site.health === "healthy").length, "fa-circle-check", "green"),
      metric("Warning Sites", rows.filter((site) => site.health === "warning").length, "fa-triangle-exclamation", "amber"),
      metric("Critical Sites", rows.filter((site) => site.health === "critical").length, "fa-circle-exclamation", "red"),
      metric("Requests", estateTotals.requests, "fa-arrow-trend-up", "purple"),
      metric("Alerts", state.data.alerts.length, "fa-bell", "red"),
    ])}
    <article class="panel">
      <div class="panel-head">
        <div><h2>Projects / Sites</h2><p>Operational health and traffic across configured projects.</p></div>
        <span class="pill">${estateStatus}</span>
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
  const searchIP = extractIPSearchValue(state.search);
  const advancedKey = advancedSearchKey(searchIP);
  const usingAdvancedEvents = searchIP && state.advancedSearch.key === advancedKey;
  const sourceEvents = usingAdvancedEvents ? state.advancedSearch.events : (state.data.traffic.recent_errors || []);
  const events = usingAdvancedEvents ? sourceEvents : filtered(searchItems(sourceEvents, (item) => `${item.status} ${item.site_id} ${item.env} ${item.client_ip} ${item.method} ${item.path} ${item.user_agent}`));
  const statuses = state.data.traffic.status_breakdown || state.data.analysis.status_breakdown || [];
  const hosts = groupCount(events, (item) => item.site_id || "unknown");
  const paths = groupCount(events, (item) => item.path || "/");
  const searchStatus = advancedSearchStatus(searchIP, usingAdvancedEvents);
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
          <form id="advancedSearchForm" class="query-form">
            <label class="sr-only" for="advancedSearchInput">Search query</label>
            <div class="query-string">
              <input id="advancedSearchInput" type="search" value="${escapeAttr(state.search)}" placeholder="status:>=400 OR severity:error OR path:/wp-*" autocomplete="off" spellcheck="false">
              <button class="icon-button" type="button" data-action="query-guide" aria-label="Query guide" title="Query guide">${iconHTML("fa-circle-info")}</button>
            </div>
          </form>
          <div class="toolbar">
            <span class="pill">${escapeHTML(activeRangeLabel())}</span>
            <span class="pill">${state.siteID ? escapeHTML(state.siteID) : "All Projects"}</span>
            <button class="button small" type="submit" form="advancedSearchForm">${iconHTML("fa-magnifying-glass")}Search</button>
          </div>
          ${searchStatus}
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

async function runAdvancedSearch() {
  const ip = extractIPSearchValue(state.search);
  if (!ip) {
    state.advancedSearch = { key: "", events: [], total: 0, loading: false, error: "" };
    render();
    return;
  }
  const key = advancedSearchKey(ip);
  state.advancedSearch = { key, events: [], total: 0, loading: true, error: "" };
  render();
  try {
    const detail = await fetchJSON(`/api/v1/investigate/ip/${encodeURIComponent(ip)}?${advancedIPSearchParams()}`);
    if (state.advancedSearch.key !== key) return;
    const events = (detail.recent_requests || []).map((event) => ({
      ...event,
      client_ip: ip,
      known_actor: detail.stored_intel?.known_actor || "",
      actor_type: detail.stored_intel?.actor_type || "",
      verified_actor: Boolean(detail.stored_intel?.verified_actor),
      provider_verified: Boolean(detail.stored_intel?.provider_verified),
      provider_name: detail.stored_intel?.provider_name || "",
      provider_range: detail.stored_intel?.provider_range || "",
      provider_source_url: detail.stored_intel?.provider_source_url || "",
    }));
    state.advancedSearch = {
      key,
      events,
      total: Number(detail.requests_total || events.length),
      loading: false,
      error: "",
    };
  } catch (error) {
    if (state.advancedSearch.key === key) {
      state.advancedSearch = { key, events: [], total: 0, loading: false, error: error.message || "Search failed" };
    }
  }
  render();
}

function advancedSearchStatus(ip, usingAdvancedEvents) {
  if (!ip) {
    return `<p class="subtle">Text search filters the currently loaded event sample. Use <code>ip:192.42.116.58</code> for a DB-backed IP lookup.</p>`;
  }
  if (state.advancedSearch.loading) {
    return `<p class="subtle">${iconHTML("fa-spinner fa-spin")} Searching full event history for ${escapeHTML(ip)}...</p>`;
  }
  if (state.advancedSearch.error) {
    return `<p class="form-error">${escapeHTML(state.advancedSearch.error)}</p>`;
  }
  if (usingAdvancedEvents) {
    return `<p class="subtle">Showing ${formatNumber(state.advancedSearch.events.length)} of ${formatNumber(state.advancedSearch.total)} DB matches for ${ipLink(ip)}.</p>`;
  }
  return `<p class="subtle">Press Search to load full DB matches for ${escapeHTML(ip)}.</p>`;
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
    ${queryParamsPanel()}
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
  const logTotals = logTotalsFor(PHP_LOG_TYPES);
  const logEvents = logEventsFor(PHP_LOG_TYPES);
  const logMessages = logMessagesFor(PHP_LOG_TYPES);
  const paths = filtered(searchItems((state.data.traffic.top_paths || state.data.analysis.slow_paths || []).filter(isPHPPathRow), (item) => `${item.path} ${item.site_id} ${item.requests}`));
  const accessEvents = filtered(searchItems((state.data.traffic.recent_errors || []).filter(isPHPEventRow), (item) => `${item.status} ${item.site_id} ${item.env} ${item.client_ip} ${item.method} ${item.path} ${item.user_agent}`));
  return `
    ${metricGrid([
      metric("PHP Findings", issues.length, "fa-brands fa-php", "purple"),
      metric("PHP Log Events", sum(logTotals, "events"), "fa-rectangle-list", "amber"),
      metric("Severe Logs", severeLogTotal(logTotals), "fa-triangle-exclamation", "red"),
      metric("Access Matches", accessEvents.length, "fa-route", "cyan"),
    ])}
    <section class="layout-2">
      ${issueFindingsPanel("php", issues)}
      ${runtimeLogMessagesPanel("PHP Runtime Messages", "Repeated PHP error and slow-log messages.", logMessages, "phpLogMessages")}
    </section>
    <section class="layout-2">
      ${runtimeLogEventsPanel("Recent PHP Log Evidence", "Latest PHP error and slow-log rows from imported files.", logEvents, "phpLogEvents")}
      ${issueTopPathsPanel("php", paths)}
    </section>
  `;
}

function renderMySQL() {
  const issues = issuesFor("mysql");
  const logTotals = logTotalsFor(MYSQL_LOG_TYPES);
  const logEvents = logEventsFor(MYSQL_LOG_TYPES);
  const logMessages = logMessagesFor(MYSQL_LOG_TYPES);
  const probes = filtered(searchItems((state.data.analysis.injection_probes || []).filter(isMySQLProbeRow), mysqlProbeSearchText));
  const slowPaths = filtered(searchItems((state.data.analysis.slow_paths || []).filter(isMySQLPathRow), (item) => `${item.site_id} ${item.path}`));
  const sourceIPs = mysqlProbeSourceIPs(probes);
  const loading = state.securityAnalysisLoading ? securityLoadingPanel("SQL probe analysis is still running for this range.") : "";
  return `
    ${metricGrid([
      metric("MySQL Findings", issues.length, "fa-database", "purple"),
      metric("MySQL Log Events", sum(logTotals, "events"), "fa-rectangle-list", "amber"),
      metric("Slow Log Rows", logTypeTotal(logTotals, "mysql-slow"), "fa-stopwatch", "cyan"),
      metric("SQL Probes", sum(probes, "requests"), "fa-syringe", "red"),
    ])}
    ${loading}
    <section class="layout-2">
      ${issueFindingsPanel("mysql", issues)}
      ${runtimeLogMessagesPanel("MySQL Runtime Messages", "Repeated MySQL error and slow-query messages.", logMessages, "mysqlLogMessages")}
    </section>
    <section class="layout-2">
      ${runtimeLogEventsPanel("Recent MySQL Log Evidence", "Latest MySQL error and slow-query rows from imported files.", logEvents, "mysqlLogEvents")}
      ${mysqlProbePanel(probes)}
    </section>
    <section class="layout-2">
      ${mysqlSlowPathsPanel(slowPaths)}
      ${mysqlSourceIPsPanel(sourceIPs)}
    </section>
  `;
}

function runtimeLogMessagesPanel(title, subtitle, rows, key) {
  const page = paginate(rows, state.pages[key], 7);
  state.pages[key] = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>${escapeHTML(title)}</h2><p>${escapeHTML(subtitle)}</p></div>
        <span class="pill">${formatNumber(rows.length)} messages</span>
      </div>
      <div class="list">${page.rows.map((item) => `
        <div class="list-row">
          <div>
            <strong>${escapeHTML(shortLogMessage(item.message))}</strong>
            <span>${escapeHTML([logTypeLabel(item.log_type), item.severity || "", item.sites || ""].filter(Boolean).join(" / "))} / ${shortTime(item.first_seen)} - ${shortTime(item.last_seen)}</span>
          </div>
          <b>${formatNumber(item.events)}</b>
        </div>
      `).join("") || empty("No runtime log messages in this range.")}</div>
      ${pager(key, page)}
    </article>
  `;
}

function runtimeLogEventsPanel(title, subtitle, rows, key) {
  const page = paginate(rows, state.pages[key], 7);
  state.pages[key] = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>${escapeHTML(title)}</h2><p>${escapeHTML(subtitle)}</p></div>
        <span class="pill">${formatNumber(rows.length)} rows</span>
      </div>
      <div class="list">${page.rows.map((item) => `
        <div class="list-row log-row">
          <div>
            <strong>${escapeHTML(shortLogMessage(item.message || item.raw))}</strong>
            <span>${escapeHTML(shortTime(item.ts))} / ${escapeHTML(item.site_id || "-")} / ${escapeHTML(item.env || "-")} / ${escapeHTML(item.container_id || "-")} / ${escapeHTML(logTypeLabel(item.log_type))}</span>
          </div>
          <span class="severity ${logSeverityClass(item.severity, item.log_type)}">${escapeHTML(item.severity || logSeverityLabel(item.log_type))}</span>
        </div>
      `).join("") || empty("No runtime log rows in this range.")}</div>
      ${pager(key, page)}
    </article>
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
      <div class="list">${page.rows.map((item, index) => {
        const key = cacheDetail("security-signal", item, `mysql:${item.category || ""}:${item.ip || ""}:${item.path || ""}:${index}`);
        const meta = [item.site_id, item.env, item.match_reason || item.category, item.sample_query || ""].filter(Boolean).join(" / ");
        return `
        <div class="list-row">
          <div><strong>${escapeHTML(`${item.method || "GET"} ${item.path || "/"}`)}</strong><span>${item.ip ? `${ipLink(item.ip)} / ` : ""}${escapeHTML(meta)}</span></div>
          <button class="button small" type="button" data-detail="security-signal" data-value="${escapeAttr(key)}">${formatNumber(item.requests)} req</button>
        </div>
      `;
      }).join("") || empty("No SQL injection probes found.")}</div>
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
      metric("P95", formatMs(state.data.analysis?.totals?.p95_request_time_ms), "fa-stopwatch", "purple"),
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
      metric("Verified Bots", sum(verified, "requests"), "fa-shield-halved", "green"),
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
  const catalog = state.data.reportCatalog || {};
  const all = filtered(searchItems(allReports(), reportSearchText));
  const types = (catalog.report_types || []).length ? catalog.report_types : reportTypes(all);
  if (state.reportType !== "all" && !types.includes(state.reportType)) state.reportType = "all";
  const reports = state.reportType === "all" ? all : all.filter((item) => reportKind(item) === state.reportType);
  const page = state.search
    ? paginate(reports, state.pages.reportCatalog, reportCatalogPageSize)
    : reportCatalogPage(reports, catalog);
  state.pages.reportCatalog = page.page;
  const selected = page.rows[0] || reports[0] || {};
  const totalReports = state.search ? reports.length : Number(catalog.total ?? all.length);
  const reportTypeCounts = catalog.report_type_counts || {};
  return `
    ${metricGrid([
      metric("Reports", totalReports, "fa-file-lines", "cyan"),
      metric("Daily", reportTypeCounts.daily ?? all.filter((r) => reportKind(r).includes("daily")).length, "fa-calendar-day", "green"),
      metric("Weekly", reportTypeCounts.weekly ?? all.filter((r) => reportKind(r).includes("weekly")).length, "fa-calendar-week", "purple"),
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
  const geoip = state.data.geoip || {};
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
      <article class="panel">
        <div class="panel-head"><div><h2>GeoIP</h2><p>MaxMind enrichment readiness.</p></div></div>
        <div class="panel-body">${facts([
          ["Enabled", yesNo(geoip.enabled)],
          ["Loaded", yesNo(geoip.loaded)],
          ["Runtime DB", geoip.database_exists ? formatBytes(geoip.database_bytes) : "Missing"],
          ["Bundled seed", yesNo(geoip.seed_exists)],
          ["MaxMind download", geoip.maxmind_credentials_configured && geoip.download_configured ? "Configured" : geoip.seed_exists ? "Seed fallback" : "Missing"],
          ["Updated", shortTime(geoip.database_modified_at)],
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
  const cooldowns = state.data.collectorHealth?.server_cooldowns || [];
  const deliveries = state.data.pulseNotifications?.recent || state.data.notifications?.recent || [];
  const archives = state.data.archives || [];
  const archiveImports = state.data.archiveImports || [];
  const storage = state.data.storage || {};
  const analytics = state.data.overview?.analytics || {};
  const scheduler = state.data.overview?.scheduler || {};
  const jobTotal = state.data.jobCatalog?.total ?? state.data.jobs.length;
  return `
    ${metricGrid([
      metric("Jobs", jobTotal, "fa-briefcase", "cyan"),
      metric("Runtime", appUptimeLabel(), "fa-clock", "green"),
      metric("Freshness", eventLagLabel(analytics.event_lag_seconds), "fa-hourglass-half", freshnessColor(analytics.event_lag_seconds)),
      metric("Cycle", cadenceCycleLabel(scheduler), "fa-gauge-high", cadenceColor(scheduler)),
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
          ${pipelineControls()}
          <button class="button small" type="button" data-action="run-pipeline">${iconHTML("fa-code-merge")}Run Pipeline</button>
          <button class="button small" type="button" data-action="run-backfill">${iconHTML("fa-database")}Backfill Batch</button>
          <button class="button small" type="button" data-action="run-archive-dry">${iconHTML("fa-box-archive")}Archive Check</button>
          <button class="button small" type="button" data-action="run-archive">${iconHTML("fa-file-zipper")}Archive</button>
          <button class="button small" type="button" data-action="clean-expired-imports">${iconHTML("fa-broom")}Clean Expired</button>
        </div>
      </div>
      ${cadencePressurePanel(scheduler)}
      <div class="ingestion-pipeline">
        ${pipelineStep("Downloaded", state.data.segments.length, "fa-cloud-arrow-down", "green")}
        ${pipelineStep("Combined", state.data.segments.filter((item) => item.status).length, "fa-code-merge", "cyan")}
        ${pipelineStep("Indexed", state.data.segments.filter((item) => item.status === "indexed").length, "fa-database", "purple")}
        ${pipelineStep("Stored", state.data.analysis?.totals?.requests || 0, "fa-chart-simple", "green")}
      </div>
    </article>
    <section class="layout-2">
      ${pulseJobsPanel()}
      ${pulseJobStepsPanel()}
    </section>
    ${serverCooldownsPanel(cooldowns)}
    <section class="layout-2">
      ${pulseSegmentsPanel()}
      ${pulseArchivesPanel(archives)}
    </section>
    <section class="layout-2">
      ${pulseArchiveImportsPanel(archiveImports)}
      ${pulseRawFilesPanel(rawFiles)}
    </section>
    <section class="layout-2">
      ${pulseDeliveriesPanel(deliveries)}
    </section>
  `;
}

function cadencePressurePanel(scheduler = {}) {
  const hasCycle = Number(scheduler.last_cycle_duration_ms || 0) > 0;
  if (!hasCycle && !Number(scheduler.collection_interval_ms || 0)) return "";
  return `
    <div class="panel-body layout-4 compact-grid">
      ${facts([
        ["Interval", formatDuration(scheduler.collection_interval_ms)],
        ["Last cycle", formatDuration(scheduler.last_cycle_duration_ms)],
        ["Cadence used", scheduler.last_cycle_utilization ? formatPercent(scheduler.last_cycle_utilization) : "-"],
        ["Latest pipeline", shortTime(scheduler.latest_pipeline_at)],
      ])}
      ${facts([
        ["Collection jobs", formatNumber(scheduler.collection_jobs)],
        ["Pipeline", formatDuration(scheduler.pipeline_duration_ms)],
        ["Post pipeline", formatDuration(scheduler.post_pipeline_duration_ms)],
        ["Cycle finished", shortTime(scheduler.last_cycle_finished_at)],
      ])}
      ${facts([
        ["Running since restart", formatNumber(scheduler.running_since_start)],
        ["Failed since restart", formatNumber(scheduler.failed_since_start)],
        ["Interrupted since restart", formatNumber(scheduler.interrupted_since_start)],
        ["Started", shortTime(scheduler.last_cycle_started_at)],
        ["Status", cadenceStatusLabel(scheduler)],
      ])}
    </div>
  `;
}

function cadenceCycleLabel(scheduler = {}) {
  const cycle = Number(scheduler.last_cycle_duration_ms || 0);
  const interval = Number(scheduler.collection_interval_ms || 0);
  if (!cycle && interval) return `- / ${formatDuration(interval)}`;
  if (!cycle) return "-";
  return interval ? `${formatDuration(cycle)} / ${formatDuration(interval)}` : formatDuration(cycle);
}

function cadenceStatusLabel(scheduler = {}) {
  const failed = Number(scheduler.failed_since_start || 0);
  if (failed > 0) return `${formatNumber(failed)} failed`;
  const running = Number(scheduler.running_since_start || 0);
  if (running > 0) return `${formatNumber(running)} running`;
  const interrupted = Number(scheduler.interrupted_since_start || 0);
  if (interrupted > 0) return `Healthy (${formatNumber(interrupted)} interrupted)`;
  const utilization = Number(scheduler.last_cycle_utilization || 0);
  if (utilization >= 0.9) return "Near interval";
  if (utilization >= 0.7) return "Watch";
  if (utilization > 0) return "Healthy";
  return "-";
}

function cadenceColor(scheduler = {}) {
  if (Number(scheduler.failed_since_start || 0) > 0) return "red";
  const utilization = Number(scheduler.last_cycle_utilization || 0);
  if (utilization >= 0.9) return "red";
  if (utilization >= 0.7) return "amber";
  return "green";
}

function serverCooldownsPanel(rows) {
  if (!rows.length) return "";
  const filteredRows = filtered(searchItems(rows || [], (item) => `${item.site_id || ""} ${item.env || ""} ${item.server_kind || ""} ${item.server_ip || ""} ${item.reason || ""}`));
  const page = paginate(filteredRows, state.pages.pulseCooldowns || 1, 8);
  state.pages.pulseCooldowns = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Pantheon Cooldowns</h2><p>Servers temporarily skipped after Pantheon resource-lock responses.</p></div>
        <span class="pill">${formatNumber(page.total)} active</span>
      </div>
      ${serverCooldownsTable(page.rows)}
      ${pager("pulseCooldowns", page)}
    </article>
  `;
}

function storageReadinessPanel(storage) {
  const readiness = storage.readiness || {};
  const storageBytes = storage.storage || {};
  const events = storage.events || {};
  const archives = storage.archives || {};
  const dimensions = storage.dimensions || {};
  const temporary = storage.temporary_imports || {};
  const fast = state.data.fastReadAudit || {};
  const fastStatus = fastReadiness();
  const fastReady = fastStatus.known && fastStatus.ready;
  const status = storageReadinessStatus(readiness, temporary, fastReady);
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Storage Readiness</h2><p>Hot events, rollups, archives, and retention posture.</p></div>
        <span class="pill" title="${escapeAttr(status.title)}">${escapeHTML(status.label)}</span>
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
          ["Active imports", formatNumber(temporary.active_imports)],
          ["Expired imports", formatNumber(temporary.expired_imports)],
          ["Temporary events", formatNumber(temporary.imported_events)],
          ["Temporary facts", formatNumber(temporary.imported_facts)],
        ])}
      </div>
      <div class="panel-body layout-4 compact-grid">
        ${facts([
          ["Fast reads", fastStatus.known ? (fastReady ? "Rollup backed" : "Raw fallback") : "Unavailable"],
          ["Latest event", shortTime(state.data.overview?.analytics?.latest_event_at)],
          ["Event lag", eventLagLabel(state.data.overview?.analytics?.event_lag_seconds)],
          ["Dimension rollups", yesNo(fast.dimension_rollups_ready)],
          ["Status rollups", yesNo(fast.status_rollups_ready)],
          ["Raw range aggregation", yesNo(fast.expected_raw_range_aggregations)],
        ])}
        ${facts([
          ["Full range events", formatNumber(fast.full_range_events)],
          ["Minute edge rows", formatNumber(fast.minute_edge_events)],
          ["Hour edge rows", formatNumber(fast.hour_edge_events)],
          ["Unbackfilled rows", formatNumber(fast.unbackfilled_full_hour_events)],
        ])}
        ${facts([
          ["Error fact rows", formatNumber(fast.recent_error_fact_rows)],
          ["Error raw gaps", formatNumber(fast.recent_error_raw_gap_rows)],
          ["Security facts", formatNumber(fast.security_probe_fact_rows)],
          ["Expected raw edge", formatNumber(fast.expected_raw_edge_rows)],
        ])}
        ${facts([
          ["Overview source", fast.overview_source || "-"],
          ["Analysis source", fast.access_analysis_source || "-"],
          ["Traffic source", fast.traffic_source || "-"],
          ["Recent errors", fast.recent_errors_source || "-"],
        ])}
      </div>
    </article>
  `;
}

function storageReadinessStatus(readiness = {}, temporary = {}, fastReady = false) {
  const blockers = [];
  if (!readiness.backfill_ready) blockers.push("rollup backfill pending");
  if (!readiness.hot_events_within_window) blockers.push("hot events exceed retention window");
  if (!readiness.archive_queue_empty) blockers.push("archive queue pending");
  if (!readiness.temporary_clean) {
    const expired = Number(temporary.expired_imports || 0);
    const active = Number(temporary.active_imports || 0);
    const facts = Number(temporary.imported_events || 0) + Number(temporary.imported_facts || 0);
    if (expired) blockers.push(`${formatNumber(expired)} expired temporary import${expired === 1 ? "" : "s"}`);
    else if (active) blockers.push(`${formatNumber(active)} active temporary import${active === 1 ? "" : "s"}`);
    else if (facts) blockers.push("temporary imported data present");
    else blockers.push("temporary import cleanup pending");
  }
  if (!fastReady) blockers.push("fast-read rollups incomplete");
  return blockers.length
    ? { label: "Needs work", title: blockers.join("; ") }
    : { label: "Ready", title: "Storage, retention, temporary imports, and fast reads are clean." };
}

function pulseArchivesPanel(rows) {
  const filteredRows = filtered(searchItems(rows || [], (item) => `${item.log_type || ""} ${item.granularity || ""} ${item.status || ""} ${item.path || ""}`));
  const page = state.search ? paginate(filteredRows, state.pages.pulseArchives, 8) : archivePage(rows || [], state.data.archiveCatalog);
  state.pages.pulseArchives = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Archives</h2><p>Daily and weekly packed combined logs available for rehydration.</p></div>
        <span class="pill">${formatNumber(page.total)} archives</span>
      </div>
      ${archivesTable(page.rows)}
      ${pager("pulseArchives", page)}
    </article>
  `;
}

function pulseArchiveImportsPanel(rows) {
  const filteredRows = filtered(searchItems(rows || [], (item) => `${item.status || ""} ${item.reason || ""} ${(item.archive_paths || []).join(" ")}`));
  const page = state.search ? paginate(filteredRows, state.pages.pulseArchiveImports, 8) : archiveImportPage(rows || [], state.data.archiveImportCatalog);
  state.pages.pulseArchiveImports = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Temporary Imports</h2><p>Archived data rehydrated for short investigations.</p></div>
        <span class="pill">${formatNumber(page.total)} imports</span>
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
  const webPushUnavailable = !webPush.enabled || !webPush.configured || !webPush.public_key;
  const webPushLabel = webPushStatusLabel(webPush);
  const page = notificationPage(recent, state.pages.notificationsRecent, status);
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
          ["Browser push", webPushLabel],
        ])}
        ${warnings.length ? `<div class="list compact-list">${warnings.map((warning) => `
          <div class="list-row">
            <div><strong>${iconHTML("fa-circle-info")} Attention</strong><span>${escapeHTML(warning)}</span></div>
          </div>
        `).join("")}</div>` : ""}
        <div class="toolbar inline-toolbar">
          <button class="button outline small" type="button" data-action="enable-web-push" ${webPushUnavailable ? "disabled" : ""} title="${escapeAttr(webPushHelp(webPush))}">${iconHTML("fa-bell")}Enable Browser Push</button>
          <button class="button outline small" type="button" data-action="disable-web-push" ${!Number(webPush.active_subscriptions || 0) ? "disabled" : ""} title="Remove this browser subscription if one exists.">${iconHTML("fa-bell-slash")}Disable Browser Push</button>
        </div>
      </div>
      <div class="list">${channels.map(channelRow).join("") || empty("No notification channels configured.")}</div>
      <div class="list">${page.rows.map(deliveryRow).join("") || empty("No recent deliveries.")}</div>
      ${pager("notificationsRecent", page)}
    </article>
  `;
}

function webPushStatusLabel(webPush = {}) {
  if (!webPush.enabled) return "Disabled";
  if (!webPush.configured) return "VAPID keys missing";
  if (!webPush.public_key) return "Public key missing";
  return `${formatNumber(webPush.active_subscriptions || 0)} active`;
}

function webPushHelp(webPush = {}) {
  if (!webPush.enabled) return "Browser push is disabled in notification config.";
  if (!webPush.configured) return "Set VAPID public/private keys before enabling browser push.";
  if (!webPush.public_key) return "The browser push public key is not available.";
  return "Enable push notifications for this browser.";
}

function pipelineStep(label, value, icon, color) {
  return `
    <div class="pipeline-step">
      <span style="color: var(--${color})">${iconHTML(icon)}</span>
      <div><strong>${escapeHTML(label)}</strong><small>${formatCompact(value)}</small></div>
    </div>
  `;
}

function pipelineControls() {
  return `
    <label class="number-control" title="Maximum pending combined segments to index in one run.">
      <span>Segments</span>
      <input type="number" min="1" max="5000" step="1" value="${escapeAttr(state.pipeline.maxSegments)}" data-pipeline-field="maxSegments" aria-label="Pipeline max segments">
    </label>
    <label class="number-control" title="Parallel index workers for independent pending segments.">
      <span>Workers</span>
      <input type="number" min="1" max="32" step="1" value="${escapeAttr(state.pipeline.indexWorkers)}" data-pipeline-field="indexWorkers" aria-label="Pipeline index workers">
    </label>
  `;
}

function updatePipelineOption(field, rawValue) {
  const value = Math.floor(Number(rawValue || 0));
  if (field === "maxSegments") state.pipeline.maxSegments = clamp(value || 100, 1, 5000);
  if (field === "indexWorkers") state.pipeline.indexWorkers = clamp(value || 2, 1, 32);
}

async function runPipelineRequest() {
  qsa("[data-pipeline-field]").forEach((field) => updatePipelineOption(field.dataset.pipelineField, field.value));
  const body = {
    max_segments: clamp(Math.floor(Number(state.pipeline.maxSegments || 100)), 1, 5000),
    index_workers: clamp(Math.floor(Number(state.pipeline.indexWorkers || 2)), 1, 32),
  };
  return fetchJSON("/api/v1/system/pipeline", { method: "POST", body: JSON.stringify(body) });
}

function pipelineResultMessage(result = {}) {
  const workers = state.pipeline.indexWorkers || 1;
  return `${formatNumber(result.indexed_segments || 0)} segments indexed with ${formatNumber(workers)} worker${Number(workers) === 1 ? "" : "s"}`;
}

function pulseJobsPanel() {
  const rows = filtered(searchItems(state.data.jobs || [], jobSearchText));
  const page = state.search ? paginate(rows, state.pages.pulseJobs, 10) : jobPage(rows, state.data.jobCatalog);
  state.pages.pulseJobs = page.page;
  const currentRuns = countSinceAppStart(state.data.jobs || []);
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Jobs</h2><p title="IP intelligence DNS/GeoIP misses are enrichment misses, not job failures. Hard failures are shown in the status column.">Recent background work and scheduler activity. ${currentRuns.label}</p></div>
        <span class="pill">${formatNumber(page.total)} jobs</span>
      </div>
      ${jobsTable(page.rows)}
      ${pager("pulseJobs", page)}
    </article>
  `;
}

function pulseJobStepsPanel() {
  const rows = filtered(searchItems(state.data.jobSteps || [], jobStepSearchText));
  const page = state.search ? paginate(rows, state.pages.pulseJobSteps, 12) : jobStepPage(rows, state.data.jobStepCatalog);
  state.pages.pulseJobSteps = page.page;
  const currentSteps = countSinceAppStart(state.data.jobSteps || []);
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Job Steps</h2><p>Measured phases inside collection, SFTP download, combine, index, and rollup work. ${currentSteps.label}</p></div>
        <span class="pill">${formatNumber(page.total)} steps</span>
      </div>
      ${slowPhasesSummary(state.data.jobStepCatalog.slow_phases || [])}
      ${jobStepsTable(page.rows)}
      ${pager("pulseJobSteps", page)}
    </article>
  `;
}

function slowPhasesSummary(rows) {
  if (!rows.length) return "";
  return `
    <div class="list compact-list slow-phases">
      <div class="list-row">
        <div><strong>Slowest Phases Since Restart</strong><span>Cumulative / maximum / average duration by measured step.</span></div>
        <b>${formatNumber(rows.length)} phases</b>
      </div>
      ${rows.map((item) => `
        <div class="list-row">
          <div><strong>${escapeHTML(formatJobType(item.name))}</strong><span>${escapeHTML(item.status || "-")} / ${formatNumber(item.count)} run${Number(item.count) === 1 ? "" : "s"} / latest ${shortTime(item.latest_at)}</span></div>
          <b title="Cumulative / maximum / average duration">${formatDuration(item.total_ms)} / ${formatDuration(item.max_ms)} / ${formatDuration(item.avg_ms)}</b>
        </div>
      `).join("")}
    </div>
  `;
}

function jobSearchText(item = {}) {
  return [
    item.type,
    item.status,
    item.message,
    item.last_error,
    item.triggered_by,
    item.started_at,
    item.finished_at,
    JSON.stringify(item.meta || {}),
  ].filter(Boolean).join(" ");
}

function jobStepSearchText(item = {}) {
  return [
    item.name,
    item.status,
    item.message,
    item.last_error,
    item.job_id,
    item.started_at,
    JSON.stringify(item.meta || {}),
  ].filter(Boolean).join(" ");
}

function pulseSegmentsPanel() {
  const rows = filtered(searchItems(state.data.segments || [], (item) => `${item.log_type || ""} ${item.status || ""} ${item.path || ""} ${item.bucket_ts || item.bucket_start || ""}`));
  const page = state.search ? paginate(rows, state.pages.pulseSegments, 10) : segmentPage(rows, state.data.segmentCatalog);
  state.pages.pulseSegments = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Indexed Segments</h2><p>Combined files registered for indexing.</p></div>
        <span class="pill">${formatNumber(page.total)} segments</span>
      </div>
      ${segmentsTable(page.rows)}
      ${pager("pulseSegments", page)}
    </article>
  `;
}

function pulseRawFilesPanel(rows) {
  const filteredRows = filtered(searchItems(rows || [], (item) => `${item.site_id || ""} ${item.env || ""} ${item.container_id || ""} ${item.log_type || ""} ${item.remote_path || ""} ${item.status || ""} ${item.error || ""}`));
  const page = state.search ? paginate(filteredRows, state.pages.pulseRawFiles, 10) : rawFilePage(rows || [], state.data.rawFileCatalog);
  state.pages.pulseRawFiles = page.page;
  const stats = state.data.collectorHealth?.raw_files?.stats || {};
  const failedRecent = Number(stats.failed_recent || 0);
  const failedStale = Number(stats.failed_stale || 0);
  const failureWindow = rawFileFailureWindowLabel(stats.failed_recent_window_seconds);
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Raw File Activity</h2><p>Recently discovered or downloaded source files.</p></div>
        <div class="toolbar">
          <span class="pill ${failedRecent ? "bad" : "good"}" title="${escapeAttr(`${formatNumber(failedStale)} older failed file(s) remain in the catalog`)}">${formatNumber(failedRecent)} failed ${escapeHTML(failureWindow)}</span>
          <select class="select compact-select" data-raw-file-status-filter aria-label="Raw file status">
            <option value="all" ${state.rawFileStatus === "all" ? "selected" : ""}>All statuses</option>
            ${["downloaded", "discovered", "failed"].map((status) => `<option value="${status}" ${state.rawFileStatus === status ? "selected" : ""}>${escapeHTML(formatRawFileStatus(status))} (${formatNumber(stats[status] || 0)})</option>`).join("")}
          </select>
          <span class="pill">${formatNumber(page.total)} files</span>
        </div>
      </div>
      ${rawFilesTable(page.rows)}
      ${pager("pulseRawFiles", page)}
    </article>
  `;
}

function formatRawFileStatus(status) {
  const value = String(status || "");
  return value ? value[0].toUpperCase() + value.slice(1) : "Unknown";
}

function rawFileFailureWindowLabel(seconds) {
  const value = Number(seconds || 0);
  if (!Number.isFinite(value) || value <= 0) return "recently";
  if (value % 3600 === 0) return `last ${formatNumber(value / 3600)}h`;
  if (value % 60 === 0) return `last ${formatNumber(value / 60)}m`;
  return `last ${formatNumber(value)}s`;
}

function pulseDeliveriesPanel(rows) {
  const filteredRows = filtered(searchItems(rows || [], (item) => `${item.title || ""} ${item.channel || ""} ${item.target || ""} ${item.status || ""} ${item.error || ""}`));
  const page = state.search ? paginate(filteredRows, state.pages.pulseDeliveries, 8) : notificationPage(rows || [], state.pages.pulseDeliveries, state.data.pulseNotifications || state.data.notifications);
  state.pages.pulseDeliveries = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div><h2>Notification Deliveries</h2><p>Recent email, webhook push, and browser push attempts.</p></div>
        <span class="pill">${formatNumber(page.total)} deliveries</span>
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
            <td>${ipLink(event.client_ip, event.client_ip, event)}</td>
            <td><span class="row-title"><strong>${requestLineHTML(event)}</strong><span>${event.user_agent ? userAgentLink(event.user_agent, event.user_agent) : ""}</span></span></td>
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
      <thead><tr><th>Job</th><th>Status</th><th>Details</th><th>Duration</th><th>Started</th></tr></thead>
      <tbody>${rows.map((job) => `
        <tr>
          <td><span class="row-title"><strong>${escapeHTML(formatJobType(job.type))}</strong><span>${jobScope(job)}</span></span></td>
          <td><span class="status ${jobStatusClass(job)}">${escapeHTML(jobStatusLabel(job))}</span></td>
          <td><span class="row-title"><strong>${escapeHTML(job.message || "-")}</strong><span class="job-meta">${jobMetaSummary(job)}</span></span></td>
          <td>${formatDuration(job.duration_ms)}</td>
          <td>${shortTime(job.started_at)}</td>
        </tr>
      `).join("")}</tbody>
    </table></div>
  `;
}

function jobStepsTable(rows) {
  if (!rows.length) return empty("No measured job steps yet.");
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>Step</th><th>Status</th><th>Scope</th><th>Duration</th><th>Started</th></tr></thead>
      <tbody>${rows.map((step) => `
        <tr>
          <td><span class="row-title"><strong>${escapeHTML(formatJobType(step.name))}</strong><span>${escapeHTML(step.message || step.last_error || step.job_id || "-")}</span></span></td>
          <td><span class="status ${jobStatusClass(step)}">${escapeHTML(jobStatusLabel(step))}</span></td>
          <td><span class="job-meta">${jobStepMetaSummary(step)}</span></td>
          <td>${formatDuration(step.duration_ms)}</td>
          <td>${shortTime(step.started_at)}</td>
        </tr>
      `).join("")}</tbody>
    </table></div>
  `;
}

function serverCooldownsTable(rows) {
  if (!rows.length) return empty("No active Pantheon cooldowns.");
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>Server</th><th>Site</th><th>Until</th><th>Remaining</th><th>Reason</th></tr></thead>
      <tbody>${rows.map((item) => `
        <tr>
          <td><span class="row-title"><strong>${item.server_ip ? ipLink(item.server_ip) : "-"}</strong><span>${escapeHTML(formatJobType(item.server_kind || "server"))}</span></span></td>
          <td>${escapeHTML(item.site_id || "-")}<br><span class="subtle">${escapeHTML(item.env || "")}</span></td>
          <td>${shortTime(item.cooldown_until)}</td>
          <td>${formatDuration(msUntil(item.cooldown_until))}</td>
          <td><span class="row-title"><strong>${escapeHTML(lockReasonLabel(item.reason))}</strong><span>${escapeHTML(shortToken(item.reason || ""))}</span></span></td>
        </tr>
      `).join("")}</tbody>
    </table></div>
  `;
}

function formatJobType(value) {
  return String(value || "job")
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function jobStepMetaSummary(step = {}) {
  const meta = step.meta || {};
  const keys = jobStepMetaKeys(step);
  const chips = keys
    .filter((key) => meta[key] !== undefined && meta[key] !== null && meta[key] !== "")
    .slice(0, 8)
    .map((key) => `<span title="${escapeAttr(String(meta[key]))}">${escapeHTML(formatJobType(key))} ${escapeHTML(formatJobStepValue(key, meta[key]))}</span>`);
  return chips.join("") || escapeHTML(step.job_id || "-");
}

function jobStepMetaKeys(step = {}) {
  const name = String(step.name || "").toLowerCase();
  const shared = ["site_id", "env", "server_kind", "server", "container_id"];
  if (name.includes("index segment")) {
    return ["log_type", "bucket_start", "bucket_end", "path", "events_inserted", "log_events_inserted", "error_events", "security_probes", "slow_request_events", "segment_id"];
  }
  if (name.includes("rebuild rollups")) {
    return ["from", "to", "rollups_repaired"];
  }
  if (name.includes("combine ")) {
    return ["log_type", "from", "to", "segments_created", "files_combined", "lines_combined", "invalid_lines", "path"];
  }
  if (name.includes("download file")) {
    return [...shared, "log_type", "remote_path", "remote_size", "bytes_written", "downloaded"];
  }
  if (name.includes("list remote files")) {
    return [...shared, "root", "files_seen", "files_downloaded", "files_skipped"];
  }
  if (name.includes("connect sftp")) {
    return [...shared, "address", "reason"];
  }
  if (name.includes("discover ")) {
    return ["site_id", "env", "host", "address_count", "addresses"];
  }
  return [...shared, "servers_locked", "servers_skipped", "server_failures", "log_type", "remote_path", "remote_size", "bytes_written", "files_seen", "files_downloaded", "files_skipped", "events_inserted", "log_events_inserted", "rollups_repaired"];
}

function formatJobStepValue(key, value) {
  if (key.includes("bytes") || key.includes("size")) return formatBytes(value);
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "number") return formatNumber(value);
  const text = String(value ?? "");
  if (text.length > 54) return `${text.slice(0, 51)}...`;
  return text;
}

function jobStatusLabel(item = {}) {
  if (isInterruptedJob(item)) return "interrupted";
  return String(item.status || "-");
}

function jobStatusClass(item = {}) {
  if (isInterruptedJob(item)) return "warn";
  const status = String(item.status || "").toLowerCase();
  if (status === "success") return "good";
  if (status === "failed") return "bad";
  if (status === "running") return "warn";
  return "";
}

function isInterruptedJob(item = {}) {
  if (String(item.status || "").toLowerCase() !== "failed") return false;
  return /(interrupted by application restart|context canceled)/i.test(`${item.last_error || ""} ${item.message || ""}`);
}

function jobScope(job = {}) {
  const meta = job.meta || {};
  const parts = [meta.site_id, meta.env, meta.range, meta.from && meta.to ? `${shortTime(meta.from)} to ${shortTime(meta.to)}` : ""].filter(Boolean);
  return escapeHTML(parts.join(" / ") || job.triggered_by || "scheduler");
}

function jobMetaSummary(job = {}) {
  const meta = job.meta || {};
  const byType = {
    collect_site_env: [
      ["Downloaded", meta.files_downloaded],
      ["Skipped", meta.files_skipped],
      ["Bytes", meta.bytes_downloaded, formatBytes],
      ["Servers locked", meta.servers_locked],
      ["Servers cooldown", meta.servers_skipped],
      ["Server failures", meta.server_failures],
    ],
    pipeline: [
      ["Segments", meta.indexed_segments],
      ["Access events", meta.events_inserted],
      ["Runtime logs", meta.log_events_inserted],
      ["Security probes", meta.security_probes],
      ["Errors", meta.error_events],
      ["Slow", meta.slow_request_events],
    ],
    evaluate_alerts: [
      ["Evaluated", meta.evaluated],
      ["Upserted", meta.upserted],
    ],
    send_notifications: [
      ["Evaluated", meta.evaluated],
      ["Sent", meta.sent],
      ["Skipped", meta.skipped],
      ["Failed", meta.failed],
    ],
    refresh_ip_intel: [
      ["Refreshed", meta.refreshed],
      ["DNS/GeoIP misses", meta.lookup_failed],
      ["Reverse DNS misses", meta.reverse_dns_failed],
      ["GeoIP misses", meta.geoip_failed],
      ["Hard failures", meta.failed],
    ],
    archive_logs: [
      ["Archives", meta.archives_written],
      ["Files", meta.files_archived],
      ["Compressed", meta.compressed_bytes, formatBytes],
    ],
    retention: [
      ["Access deleted", meta.access_events_deleted],
      ["Raw deleted", meta.raw_files_deleted],
      ["Segments deleted", meta.combined_segments_deleted],
    ],
    generate_llm_reports: [["Generated", meta.generated]],
  };
  const chips = (byType[job.type] || genericJobMeta(meta))
    .filter(([, value]) => value !== undefined && value !== null && value !== "")
    .map(([label, value, formatter]) => `<span>${escapeHTML(label)} ${escapeHTML(formatter ? formatter(value) : formatJobMetaValue(value))}</span>`);
  return chips.join("") || escapeHTML(job.last_error || "No counters reported");
}

function genericJobMeta(meta = {}) {
  return Object.entries(meta)
    .filter(([key, value]) => !["site_id", "env", "range", "from", "to", "min_severity"].includes(key) && typeof value !== "object")
    .slice(0, 4)
    .map(([key, value]) => [formatJobType(key), value]);
}

function formatJobMetaValue(value) {
  if (typeof value === "number") return formatNumber(value);
  const text = String(value ?? "");
  return /^-?\d+(\.\d+)?$/.test(text) ? formatNumber(text) : text;
}

function formatDuration(value) {
  const ms = Number(value || 0);
  if (!ms) return "-";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return `${minutes}m ${rest}s`;
}

function appStartedAt() {
  const value = new Date(state.data.overview?.started_at || 0).getTime();
  return Number.isFinite(value) && value > 0 ? value : 0;
}

function appUptimeLabel() {
  const seconds = Number(state.data.overview?.uptime_sec || 0);
  if (seconds > 0) return formatDuration(seconds * 1000);
  const startedAt = appStartedAt();
  return startedAt ? formatDuration(Date.now() - startedAt) : "-";
}

function eventLagLabel(seconds) {
  const value = Number(seconds || 0);
  if (!value) return "-";
  return formatDuration(value * 1000);
}

function freshnessColor(seconds) {
  const value = Number(seconds || 0);
  if (!value || value < 15 * 60) return "green";
  if (value < 60 * 60) return "amber";
  return "red";
}

function countSinceAppStart(rows) {
  const startedAt = appStartedAt();
  if (!startedAt) return { count: rows.length, label: "" };
  const count = rows.filter((item) => new Date(item.started_at || 0).getTime() >= startedAt).length;
  return {
    count,
    label: `${formatNumber(count)} shown since app restart at ${shortTime(state.data.overview?.started_at)}.`,
  };
}

function msUntil(value) {
  const ts = new Date(value || 0).getTime();
  if (!Number.isFinite(ts)) return 0;
  return Math.max(0, ts - Date.now());
}

function lockReasonLabel(value) {
  const reason = String(value || "").toLowerCase();
  if (reason.includes("requested resource is locked") || reason.includes("administratively prohibited")) {
    return "Pantheon resource lock";
  }
  return value ? "Collection cooldown" : "Cooldown";
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
  if (isIPActor(item.actor_type, item.actor_value)) return ipLink(firstIPAddress(item.actor_value));
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
        <strong>${ipLink(item.ip, item.ip, item)}</strong>
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
        <span>${escapeHTML(formatChannel(item.channel))} / ${escapeHTML(item.target || "-")} / ${shortTime(item.created_at)}${item.error ? ` / ${escapeHTML(item.error)}` : ""}</span>
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
          <td>${rawFileStatusCell(item)}</td>
          <td>${formatBytes(item.remote_size || item.local_size || 0)}</td>
          <td>${shortTime(item.last_seen_at || item.downloaded_at || item.remote_mtime)}</td>
        </tr>
      `).join("")}</tbody>
    </table></div>
  `;
}

function rawFileStatusCell(item = {}) {
  const stale = item.status === "failed" && !rawFileSeenRecently(item.last_seen_at);
  const status = `${escapeHTML(item.status || "-")}${stale ? ` <span class="subtle">(historical)</span>` : ""}`;
  const error = item.error ? `<br><span class="subtle">${escapeHTML(item.error)}</span>` : "";
  return `${status}${error}`;
}

function rawFileSeenRecently(value) {
  const ts = new Date(value || 0).getTime();
  if (!Number.isFinite(ts) || ts <= 0) return false;
  const windowSeconds = Number(state.data.collectorHealth?.raw_files?.stats?.failed_recent_window_seconds || 3600);
  return Date.now() - ts <= Math.max(60, windowSeconds) * 1000;
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

function queryParamsPanel() {
  const rows = filtered(searchItems(state.data.traffic.query_params || [], (item) => `${item.family} ${item.param} ${item.site_id} ${item.env} ${item.example_path} ${item.example_query} ${item.example_value}`));
  const page = paginate(rows, state.pages.trafficQueries, 10);
  state.pages.trafficQueries = page.page;
  return `
    <article class="panel">
      <div class="panel-head">
        <div>
          <h2>Query Parameters</h2>
          <p>Traffic grouped by query key so tracking parameters, cache variants, and error-heavy URLs are visible.</p>
        </div>
        <span class="pill">${formatNumber(rows.length)} params</span>
      </div>
      ${queryParamsTable(page.rows)}
      ${pager("trafficQueries", page)}
    </article>
  `;
}

function queryParamsTable(rows) {
  if (!rows.length) return empty("No query-parameter traffic found.");
  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Parameter</th>
            <th>Site</th>
            <th>Requests</th>
            <th>Values</th>
            <th>5xx</th>
            <th>Slow</th>
            <th>IPs</th>
            <th>Paths</th>
            <th>Avg</th>
            <th>Sample</th>
          </tr>
        </thead>
        <tbody>${rows.map((item) => {
          const family = queryFamilyMeta(item.family || item.param || "");
          const valueState = queryValueState(item);
          const samplePath = item.example_path || "/";
          const sampleQuery = item.example_query || "";
          const sampleTitle = [samplePath, sampleQuery].filter(Boolean).join("\n");
          return `
          <tr>
            <td><span class="row-title"><strong>${escapeHTML(item.param || "-")}</strong><span class="pill query-badge" title="${escapeAttr(family.title)}">${escapeHTML(family.label)}</span></span></td>
            <td>${escapeHTML(item.site_id || "-")}<br><span class="subtle">${escapeHTML(item.env || "")}</span></td>
            <td>${formatNumber(item.requests)}</td>
            <td>
              <span class="row-title">
                <strong>${formatNumber(item.distinct_values)}</strong>
                <span><span class="pill ${escapeAttr(valueState.className)}" title="${escapeAttr(valueState.title)}">${escapeHTML(valueState.label)}</span> ${escapeHTML(shortToken(item.example_value || ""))}</span>
              </span>
            </td>
            <td>${formatNumber(item.status_5xx)}</td>
            <td>${formatNumber(item.slow_requests)}</td>
            <td>${formatNumber(item.unique_ips)}</td>
            <td>${formatNumber(item.unique_paths)}</td>
            <td>${formatMs(item.avg_request_time_ms)}</td>
            <td><span class="row-title query-sample" title="${escapeAttr(sampleTitle)}"><strong>${escapeHTML(shortToken(samplePath, 72))}</strong><span>${queryBadgeHTML(sampleQuery)} ${escapeHTML(shortToken(sampleQuery, 96))}</span></span></td>
          </tr>`;
        }).join("")}</tbody>
      </table>
    </div>
  `;
}

function queryValueState(item = {}) {
  const requests = Number(item.requests || 0);
  const distinct = Number(item.distinct_values || 0);
  const example = String(item.example_value || "");
  const ratioValue = ratio(distinct, requests);
  if (!distinct) {
    return { label: "no value", className: "", title: "This parameter is usually present without a value." };
  }
  if (/PANTHEON_STRIPPED|TRACKING_STRIPPED/i.test(example)) {
    return { label: "stripped", className: "good", title: "The sampled value is stripped before logging, so high-cardinality tracking values are not visible here." };
  }
  if (/^srsltid$/i.test(String(item.param || item.family || ""))) {
    return { label: "raw ids", className: "warn", title: `${formatNumber(distinct)} distinct srsltid values are visible in logs. Add or verify edge stripping if this should be collapsed.` };
  }
  if (distinct >= 1000) {
    return { label: "many values", className: "warn", title: `${formatNumber(distinct)} distinct values are visible in logs.` };
  }
  if (requests >= 100 && ratioValue >= 0.5) {
    return { label: "mostly unique", className: "warn", title: `${formatPercent(ratioValue)} of requests have distinct values. This is usually a tracking ID or cache-busting parameter.` };
  }
  if (distinct === 1) {
    return { label: "single value", className: "", title: "All sampled requests use one value for this parameter." };
  }
  return { label: "reused", className: "", title: `${formatPercent(ratioValue)} of requests have distinct values.` };
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
            <td><span class="row-title"><strong>${ipLink(item.ip, item.ip, item)}</strong><span>${escapeHTML([item.known_actor || item.actor_type, item.reverse_dns].filter(Boolean).join(" / ") || "Unattributed source")}</span></span></td>
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

function ipLink(ip, label = ip, meta = null) {
  if (!ip) return "-";
  const status = ipTrustMeta(ip, meta);
  const statusClass = status.kind ? ` ${status.kind}-ip` : "";
  const title = status.label ? ` title="${escapeAttr(status.label)}"` : "";
  const badge = status.icon ? `<span class="ip-status-badge">${iconHTML(status.icon)}</span>` : "";
  return `<button class="link-button ip-link${statusClass}" type="button" data-detail="ip" data-value="${escapeAttr(ip)}"${title}>${escapeHTML(label || ip)}${badge}</button>`;
}

function collectIPTrust() {
  const trust = {};
  const visit = (value, depth = 0) => {
    if (!value || depth > 6) return;
    if (Array.isArray(value)) {
      value.forEach((item) => visit(item, depth + 1));
      return;
    }
    if (typeof value !== "object") return;
    const ip = value.ip || value.client_ip || value.source_ip || "";
    if (ip) {
      const status = ipStatusFromMeta(value);
      if (status.kind) trust[String(ip)] = status;
    }
    Object.values(value).forEach((item) => {
      if (item && typeof item === "object") visit(item, depth + 1);
    });
  };
  visit(state.data);
  visit(state.drawer?.data);
  visit(state.drawer?.summary);
  state.ipTrust = trust;
}

function ipTrustMeta(ip, meta = null) {
  if (meta) {
    const status = ipStatusFromMeta(meta);
    if (status.kind) return status;
  }
  return state.ipTrust[String(ip || "")] || { kind: "", label: "", icon: "" };
}

function ipStatusFromMeta(item = {}) {
  const intel = item.stored_intel || item.storedIntel || {};
  const action = String(item.manual_action || item.manualAction || intel.manual_action || intel.manualAction || "").toLowerCase();
  const actor = String(item.actor_type || item.actorType || intel.actor_type || intel.actorType || "").toLowerCase();
  const knownActor = item.known_actor || item.knownActor || intel.known_actor || intel.knownActor || "";
  if (action === "allowlisted" || action === "verified") return { kind: "trusted", label: trustedIPLabel(item), icon: "fa-circle-check" };
  if (isSuspiciousIPMeta(item)) return { kind: "suspicious", label: suspiciousIPLabel(item), icon: "fa-triangle-exclamation" };
  if (providerVerifiedIPMeta(item)) return { kind: "provider-verified", label: providerIPLabel(item), icon: "fa-shield-halved" };
  if (String(knownActor).toLowerCase() === "tor exit" || actor === "tor") return { kind: "suspicious", label: "Tor exit", icon: "fa-triangle-exclamation" };
  return { kind: "", label: "", icon: "" };
}

function providerVerifiedIPMeta(item = {}) {
  const intel = item.stored_intel || item.storedIntel || {};
  return Boolean(item.provider_verified || item.providerVerified || intel.provider_verified || intel.providerVerified);
}

function isSuspiciousIPMeta(item = {}) {
  const intel = item.stored_intel || item.storedIntel || {};
  const action = String(item.manual_action || item.manualAction || intel.manual_action || intel.manualAction || "").toLowerCase();
  const actor = String(item.actor_type || item.actorType || intel.actor_type || intel.actorType || "").toLowerCase();
  const knownActor = String(item.known_actor || item.knownActor || intel.known_actor || intel.knownActor || "").toLowerCase();
  const category = String(item.category || item.rule_key || item.ruleKey || item.match_reason || item.matchReason || item.kind || item.family || "").toLowerCase();
  const risk = Number(item.risk_score ?? item.riskScore ?? intel.risk_score ?? intel.riskScore ?? 0);
  const requests = Number(item.requests ?? item.Requests ?? item.traffic?.requests ?? 0);
  const status4xx = Number(item.status_4xx ?? item.status4xx ?? item.Status4xx ?? item.traffic?.status_4xx ?? 0);
  const status5xx = Number(item.status_5xx ?? item.status5xx ?? item.Status5xx ?? item.traffic?.status_5xx ?? 0);
  const provider = providerVerifiedIPMeta(item);
  const infra = provider || actor === "cloud" || actor === "datacenter" || actor === "edge" || actor === "hosting" || actor === "vps" || Boolean(item.is_datacenter || item.isDatacenter || intel.is_datacenter || intel.isDatacenter);
  if (action === "suspicious" || action === "watch") return true;
  if (actor === "tor" || knownActor === "tor exit" || item.is_tor_exit || item.isTorExit || intel.is_tor_exit || intel.isTorExit) return true;
  if (/(sql|xss|injection|traversal|secret_file|admin_tool|admin_path|admin_login|credential|scanner|probe)/.test(category)) return true;
  if (infra && requests >= 100 && (status4xx + status5xx) >= 50 && ((status4xx + status5xx) / requests) >= 0.80) return true;
  return risk >= 70;
}

function suspiciousIPLabel(item = {}) {
  const action = item.manual_action || item.manualAction || item.stored_intel?.manual_action || item.storedIntel?.manualAction || "";
  if (String(action).toLowerCase() === "suspicious") return "Manually marked suspicious";
  const category = item.category || item.rule_key || item.ruleKey || item.match_reason || item.matchReason || "";
  if (category) return `Suspicious signal: ${String(category).replaceAll("_", " ")}`;
  return "Suspicious source";
}

function providerIPLabel(item = {}) {
  const intel = item.stored_intel || item.storedIntel || {};
  const name = item.provider_name || item.providerName || intel.provider_name || intel.providerName || item.known_actor || item.knownActor || intel.known_actor || intel.knownActor || "Official provider";
  const range = item.provider_range || item.providerRange || intel.provider_range || intel.providerRange || "";
  return range ? `${name} official range ${range}` : `${name} official range`;
}

function trustedIPLabel(item = {}) {
  const intel = item.stored_intel || item.storedIntel || {};
  const action = String(item.manual_action || item.manualAction || intel.manual_action || intel.manualAction || "").toLowerCase();
  if (action === "allowlisted") return item.manual_label || item.manualLabel || intel.manual_label || intel.manualLabel || item.known_actor || item.knownActor || intel.known_actor || intel.knownActor || "Allowlisted IP";
  if (item.known_actor || item.knownActor || intel.known_actor || intel.knownActor) return `${item.known_actor || item.knownActor || intel.known_actor || intel.knownActor} verified`;
  if (item.verified_source || item.verifiedSource) return "Verified source";
  return "Trusted source";
}

function firstIPAddress(value) {
  const match = String(value || "").match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/);
  return match ? match[0] : "";
}

function userAgentLink(agent, label = "") {
  const item = typeof agent === "string" ? { family: userAgentFamily(agent), sample: agent } : (agent || {});
  const sample = item.sample || item.user_agent || item.family || "Unknown";
  const info = parseUserAgent(item);
  const status = userAgentStatusMeta(item, info);
  const statusClass = status.kind ? ` ${status.kind}-ua` : "";
  const title = status.label ? ` title="${escapeAttr(status.label)}"` : "";
  const badge = status.icon ? `<span class="ua-status-badge">${iconHTML(status.icon)}</span>` : "";
  const key = cacheDetail("user-agent", item, sample);
  return `<button class="link-button ua-link${statusClass}" type="button" data-detail="user-agent" data-value="${escapeAttr(key)}"${title}>${escapeHTML(label || info.label || item.family || sample || "Unknown")}${badge}</button>`;
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
  const risk = Number(item.risk_score || 0);
  return [
    info.classification,
    info.osLabel,
    info.device,
    info.engine,
    item.known_actor ? `Actor: ${item.known_actor}` : "",
    risk ? `Risk ${risk}/100` : "",
    errors ? `${formatNumber(errors)} errors` : "",
  ].filter(Boolean).join(" / ");
}

function userAgentStatusMeta(agent = {}, info = parseUserAgent(agent)) {
  const item = typeof agent === "string" ? { sample: agent } : (agent || {});
  if (isIgnoredUserAgent(item, info)) return { kind: "", label: "", icon: "" };
  if (isVerifiedUserAgent(item, info)) return { kind: "verified", label: "Verified bot/source", icon: "fa-circle-check" };
  if (isMaliciousUserAgent(item, info)) return { kind: "malicious", label: "Known malicious scanner/tool", icon: "fa-triangle-exclamation" };
  if (isOfficialNamedBot(item, info)) return { kind: "official", label: `${info.knownActor || item.known_actor || info.family || "Known bot"} user agent`, icon: "fa-shield-halved" };
  return { kind: "", label: "", icon: "" };
}

function isIgnoredUserAgent(item = {}, info = parseUserAgent(item)) {
  const text = `${item.sample || ""} ${item.user_agent || ""} ${item.family || ""} ${item.known_actor || ""} ${info.knownActor || ""} ${info.family || ""}`.toLowerCase();
  return text.includes("yandex");
}

function isVerifiedUserAgent(item = {}, info = parseUserAgent(item)) {
  return Boolean(item.verified_source || item.verifiedSource || Number(item.verified_requests || item.verifiedRequests || 0) > 0 || Number(item.verified_ips || item.verifiedIPs || 0) > 0);
}

function isMaliciousUserAgent(item = {}, info = parseUserAgent(item)) {
  const text = `${item.sample || ""} ${item.user_agent || ""} ${item.family || ""} ${item.actor_type || ""} ${item.known_actor || ""} ${info.family || ""} ${info.actorType || ""}`.toLowerCase();
  const risk = Number(item.risk_score || item.riskScore || 0);
  if (text.includes("malicious")) return true;
  if (/\b(sqlmap|nikto|nuclei|masscan|zgrab|zmap|wpscan|dirbuster|gobuster|ffuf|dirsearch|feroxbuster|acunetix|nessus|openvas|netsparker)\b/.test(text)) return true;
  return risk >= 90 && /(scanner|scan|exploit|vulnerability|tool|script)/.test(text);
}

function isOfficialNamedBot(item = {}, info = parseUserAgent(item)) {
  const actor = String(item.actor_type || info.actorType || "").toLowerCase();
  const known = String(item.known_actor || info.knownActor || "").trim();
  if (!known) return false;
  if (!["crawler", "fetcher", "monitor"].includes(actor) && !info.isBot) return false;
  return true;
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
    trafficQueries: 1,
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
    pulseJobSteps: 1,
    pulseCooldowns: 1,
    pulseSegments: 1,
    pulseRawFiles: 1,
    pulseArchives: 1,
    pulseArchiveImports: 1,
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
  const geoip = state.data.geoip || {};
  return `
    <article class="panel">
      <div class="panel-head"><div><h2>System Health</h2><p>Collector and storage readiness.</p></div></div>
      <div class="panel-body">${facts([
        ["Database", configured ? "Configured" : "Not configured"],
        ["GeoIP", geoip.enabled ? (geoip.loaded ? "Loaded" : geoip.seed_exists ? "Seed ready" : "Missing") : "Disabled"],
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
  const requestPage = alertRequestPage(item, requests);
  const sev = normalizeSeverity(item.severity);
  return `
    ${miniMetrics([
      ["Score", formatNumber(item.score || 0), "fa-gauge-high"],
      ["Requests", formatNumber(details.requests || item.request_total || requests.length), "fa-arrow-trend-up"],
      ["4xx", formatNumber(details.status_4xx), "fa-triangle-exclamation"],
      ["5xx", formatNumber(details.status_5xx), "fa-bolt"],
    ])}
    <section class="detail-grid two">
      <article class="detail-card">
        <h3>Alert Context</h3>
        ${factsRich([
          ["Title", item.title || item.rule_key || "Alert"],
          ["Severity", htmlSafe(`<span class="severity ${sev}">${escapeHTML(sev)}</span>`)],
          ["Status", item.status || "open"],
          ["Rule", item.rule_key || "-"],
          ["Project", item.site_id || "-"],
          ["Environment", item.env || "-"],
          ["Actor", htmlSafe(alertActorLink(item))],
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

function alertRequestPage(item, requests) {
  if (item && Object.prototype.hasOwnProperty.call(item, "request_total")) {
    return serverBackedPage(requests, Number(item.request_total || 0), Number(item.request_limit || alertRequestPageSize), Number(item.request_offset || 0));
  }
  return drawerPage("alertRequests", requests, alertRequestPageSize);
}

function serverBackedPage(rows, totalValue, limitValue, offsetValue) {
  const limit = Math.max(1, Number(limitValue || 1));
  const total = Math.max(0, Number(totalValue || 0));
  const offset = Math.max(0, Number(offsetValue || 0));
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const page = clamp(Math.floor(offset / limit) + 1, 1, totalPages);
  return {
    rows,
    page,
    pageSize: limit,
    total,
    totalPages,
    start: total ? offset + 1 : 0,
    end: Math.min(total, offset + rows.length),
  };
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
          ["Rule", item.rule_key || "-"],
          ["Title", item.title || item.rule_key || "Alert rule"],
          ["Severity", htmlSafe(`<span class="severity ${normalizeSeverity(item.severity)}">${escapeHTML(normalizeSeverity(item.severity))}</span>`)],
          ["Last Seen", shortTime(item.last_seen_at)],
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
  if (isIPActor(item.actor_type, item.actor_value)) return ipLink(firstIPAddress(item.actor_value));
  if (isUserAgentActor(item.actor_type) && item.actor_value) return userAgentLink(item.actor_value);
  return linkifyIPs([item.actor_type, item.actor_value].filter(Boolean).join(" / ") || "-");
}

function isUserAgentActor(actorType) {
  return /^(user_agent|user-agent|ua)$/i.test(String(actorType || ""));
}

function isIPActor(actorType, value) {
  return /^(ip|source_ip|source-ip|client_ip|client-ip)$/i.test(String(actorType || "")) && Boolean(firstIPAddress(value));
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
  const ipPage = userAgentSectionPage(item, "uaIPs", relatedIPs, "top_ips");
  const pathPage = userAgentSectionPage(item, "uaPaths", relatedPaths, "top_paths");
  const requestPage = userAgentSectionPage(item, "uaRequests", relatedRequests, "requests");
  const requests = Number(traffic.requests || agent.requests || item.requests || relatedRequests.length || 0);
  const errors = Number(traffic.status_4xx || agent.status_4xx || item.status_4xx || 0) + Number(traffic.status_5xx || agent.status_5xx || item.status_5xx || 0);
  return `
    ${miniMetrics([
      ["Requests", formatNumber(requests), "fa-arrow-trend-up"],
      ["Errors", formatNumber(errors || relatedRequests.filter((row) => Number(row.status || 0) >= 400).length), "fa-triangle-exclamation"],
      ["Related IPs", formatNumber(ipPage.total), "fa-network-wired"],
      ["Related Paths", formatNumber(pathPage.total), "fa-route"],
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
          ["Risk Score", agent.risk_score ? `${formatNumber(agent.risk_score)}/100` : "-"],
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

function userAgentSectionPage(item, key, rows, prefix) {
  const totalKey = `${prefix}_total`;
  const limitKey = `${prefix}_limit`;
  const offsetKey = `${prefix}_offset`;
  if (item && Object.prototype.hasOwnProperty.call(item, totalKey)) {
    return serverBackedPage(rows, Number(item[totalKey] || 0), Number(item[limitKey] || userAgentDetailPageSize), Number(item[offsetKey] || 0));
  }
  return drawerPage(key, rows, userAgentDetailPageSize);
}

function incidentRows() {
  const alerts = state.data.alerts.map(alertRow);
  const errors = (state.data.traffic.recent_errors || []).map((event) => `
    <div class="list-row"><div><strong>${escapeHTML(event.status || "Error")} ${requestLineHTML(event, false)}</strong><span>${escapeHTML(event.site_id || "-")} / ${event.client_ip ? ipLink(event.client_ip) : "-"} / ${event.user_agent ? userAgentLink(event.user_agent, shortUserAgentSample(event.user_agent)) : "-"} / ${shortTime(event.ts)}</span></div><span class="severity ${Number(event.status) >= 500 ? "critical" : "high"}">${escapeHTML(event.status || "error")}</span></div>
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

function logTotalsFor(types) {
  const allowed = new Set(types);
  return (state.data.analysis.log_event_totals || []).filter((item) => allowed.has(item.log_type));
}

function logEventsFor(types) {
  const allowed = new Set(types);
  return filtered(searchItems((state.data.analysis.log_events || []).filter((item) => allowed.has(item.log_type)), logEventSearchText));
}

function logMessagesFor(types) {
  const allowed = new Set(types);
  return filtered(searchItems((state.data.analysis.log_messages || []).filter((item) => allowed.has(item.log_type)), logMessageSearchText));
}

function logTypeTotal(totals, type) {
  return totals.filter((item) => item.log_type === type).reduce((count, item) => count + Number(item.events || 0), 0);
}

function severeLogTotal(totals) {
  return totals
    .filter((item) => isSevereLog(item.severity, item.log_type))
    .reduce((count, item) => count + Number(item.events || 0), 0);
}

function isSevereLog(severity, logType = "") {
  return /fatal|panic|emerg|alert|crit|critical|error/i.test(`${severity || ""} ${logType || ""}`);
}

function logSeverityClass(severity, logType = "") {
  if (isSevereLog(severity, logType)) return "critical";
  if (/warn/i.test(severity || "")) return "high";
  if (/slow/i.test(logType || "")) return "medium";
  return "low";
}

function logSeverityLabel(logType = "") {
  if (/error/i.test(logType)) return "error";
  if (/slow/i.test(logType)) return "slow";
  return "info";
}

function logTypeLabel(value) {
  const labels = {
    "nginx-error": "Nginx error",
    "php-error": "PHP error",
    "php-slow": "PHP slow",
    mysql: "MySQL error",
    "mysql-slow": "MySQL slow",
  };
  return labels[value] || readableToken(value || "log");
}

function shortLogMessage(value) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (!text) return "No message";
  return text.length > 180 ? `${text.slice(0, 177)}...` : text;
}

function logEventSearchText(item) {
  return `${item.ts || ""} ${item.site_id || ""} ${item.env || ""} ${item.container_id || ""} ${item.log_type || ""} ${item.severity || ""} ${item.message || ""} ${item.raw || ""}`;
}

function logMessageSearchText(item) {
  return `${item.log_type || ""} ${item.severity || ""} ${item.message || ""} ${item.sites || ""}`;
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
    [/msnbot\/?([\d.]*)/i, "MSNBot", "Microsoft"],
    [/DuckDuckBot\/?([\d.]*)/i, "DuckDuckBot", "DuckDuckGo"],
    [/DuckAssistBot\/?([\d.]*)/i, "DuckAssistBot", "DuckDuckGo"],
    [/YandexBot\/?([\d.]*)/i, "YandexBot", "Yandex"],
    [/Baiduspider\/?([\d.]*)/i, "Baiduspider", "Baidu"],
    [/Applebot\/?([\d.]*)/i, "Applebot", "Apple"],
    [/Yahoo!? Slurp\/?([\d.]*)/i, "Yahoo Slurp", "Yahoo"],
    [/Slurp\/?([\d.]*)/i, "Yahoo Slurp", "Yahoo"],
    [/Ask Jeeves\/Teoma\/?([\d.]*)/i, "Teoma", "Ask"],
    [/Teoma\/?([\d.]*)/i, "Teoma", "Ask"],
    [/Aolbot-News\/?([\d.]*)/i, "AOLbot News", "AOL"],
    [/Aolbot\/?([\d.]*)/i, "AOLbot", "AOL"],
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
  const query = parseSearchQuery(state.search);
  if (!query.groups.length) return items;
  return items.filter((item) => matchesSearchQuery(item, text(item), query));
}

function filtered(items) {
  return items;
}

function extractIPSearchValue(raw) {
  const query = parseSearchQuery(raw);
  for (const group of query.groups) {
    for (const term of group) {
      if (!term.field || !["ip", "client_ip", "client-ip", "source_ip", "source-ip"].includes(term.field)) continue;
      const value = String(term.value || "").trim();
      if (/^[0-9a-f:.]+$/i.test(value)) return value;
    }
  }
  return "";
}

function advancedSearchKey(ip) {
  return [ip || "", state.range || "", state.siteID || ""].join("|");
}

function advancedIPSearchParams() {
  return buildFilterQuery({
    limit: 100,
    sites_offset: 0,
    top_paths_offset: 0,
    url_hits_offset: 0,
    requests_offset: 0,
    user_agents_offset: 0,
  });
}

function parseSearchQuery(raw) {
  const groups = String(raw || "")
    .split(/\s+or\s+/i)
    .map((part) => tokenizeSearch(part).map(parseSearchToken).filter((token) => token.value))
    .filter((group) => group.length);
  return { groups };
}

function tokenizeSearch(value) {
  const tokens = [];
  const pattern = /"([^"]+)"|'([^']+)'|(\S+)/g;
  for (const match of String(value || "").matchAll(pattern)) {
    tokens.push(match[1] || match[2] || match[3] || "");
  }
  return tokens;
}

function parseSearchToken(token) {
  const match = String(token || "").match(/^([a-z_][a-z0-9_-]*):(.*)$/i);
  if (!match) return { value: token.toLowerCase() };
  return { field: match[1].toLowerCase(), value: match[2].toLowerCase() };
}

function matchesSearchQuery(item, textValue, query) {
  const text = String(textValue || "").toLowerCase();
  return query.groups.some((group) => group.every((term) => matchesSearchTerm(item, text, term)));
}

function matchesSearchTerm(item, text, term) {
  if (!term.field) return text.includes(term.value);
  const matched = matchesFieldSearch(item, term.field, term.value);
  return matched || text.includes(`${term.field}:${term.value}`);
}

function matchesFieldSearch(item, field, value) {
  if (field === "status") return matchesNumericSearch(item.status, value);
  if (field === "severity") return severityFromStatus(item.status, item.severity).includes(value);
  const candidates = fieldSearchValues(item, field).map((part) => String(part || "").toLowerCase()).filter(Boolean);
  if (!candidates.length) return false;
  return candidates.some((candidate) => matchesWildcardText(candidate, value));
}

function fieldSearchValues(item, field) {
  const aliases = {
    agent: ["user_agent", "sample", "family", "known_actor", "actor_type"],
    browser: ["user_agent", "sample", "family"],
    env: ["env", "environment"],
    host: ["site_id", "host"],
    ip: ["client_ip", "ip", "source_ip"],
    method: ["method"],
    path: ["path"],
    project: ["site_id", "project", "site"],
    site: ["site_id", "project", "site"],
    ua: ["user_agent", "sample", "family", "known_actor", "actor_type"],
  };
  return (aliases[field] || [field]).map((key) => item?.[key]);
}

function matchesNumericSearch(actual, expression) {
  const value = Number(actual);
  if (!Number.isFinite(value)) return false;
  const match = String(expression || "").match(/^(>=|<=|>|<|=)?(\d+)$/);
  if (!match) return String(actual || "").toLowerCase().includes(String(expression || "").toLowerCase());
  const expected = Number(match[2]);
  const op = match[1] || "=";
  if (op === ">=") return value >= expected;
  if (op === "<=") return value <= expected;
  if (op === ">") return value > expected;
  if (op === "<") return value < expected;
  return value === expected;
}

function severityFromStatus(status, severity = "") {
  const explicit = String(severity || "").toLowerCase();
  if (explicit) return explicit;
  const code = Number(status);
  if (code >= 500) return "critical error 5xx";
  if (code >= 400) return "high warning error 4xx";
  return "info ok";
}

function matchesWildcardText(candidate, pattern) {
  const value = String(pattern || "");
  if (!value.includes("*")) return candidate.includes(value);
  const escaped = value.split("*").map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*");
  return new RegExp(`^${escaped}$`, "i").test(candidate);
}

async function handleAction(button) {
  const action = button.dataset.action;
  if (action === "refresh") return refreshAll();
  if (action === "run-pipeline") {
    return runButton(button, "Pipeline complete", async () => {
      const result = await runPipelineRequest();
      await refreshAll();
      return pipelineResultMessage(result);
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
  if (action === "clean-expired-imports") {
    const expired = Number(state.data.storage?.temporary_imports?.expired_imports || state.data.retention?.temporary_imports_matched || 0);
    if (!expired) {
      toast("No expired temporary imports to clean");
      return;
    }
    if (!confirm(`Delete ${formatNumber(expired)} expired temporary import${expired === 1 ? "" : "s"} and rebuild affected rollups?`)) return;
    return runButton(button, "Expired imports cleaned", async () => {
      const result = await fetchJSON("/api/v1/system/retention", {
        method: "POST",
        body: JSON.stringify({ temporary_imports_only: true }),
      });
      await refreshAll();
      return `${formatNumber(result.temporary_imports_deleted || 0)} imports deleted / ${formatNumber(result.rollups_rebuilt || 0)} rollups rebuilt`;
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
      if (key === "reportCatalog" && !state.search) {
        await loadReportCatalogPage(page);
        return;
      }
      if ((key === "notificationsRecent" || key === "pulseDeliveries") && !state.search) {
        await loadNotificationPage(page, key);
        return;
      }
      if (key === "pulseSegments" && !state.search) {
        await loadSegmentPage(page);
        return;
      }
      if (key === "pulseRawFiles" && !state.search) {
        await loadRawFilePage(page);
        return;
      }
      if (key === "pulseArchives" && !state.search) {
        await loadArchivePage(page);
        return;
      }
      if (key === "pulseArchiveImports" && !state.search) {
        await loadArchiveImportPage(page);
        return;
      }
      if (key === "pulseJobs" && !state.search) {
        await loadJobPage(page);
        return;
      }
      if (key === "pulseJobSteps" && !state.search) {
        await loadJobStepPage(page);
        return;
      }
      state.pages[key] = Math.max(1, page);
      render();
    }
    return;
  }
  if (action === "drawer-page") {
    const key = button.dataset.pageKey;
    const page = Number(button.dataset.page || 1);
    if (key && Number.isFinite(page)) {
      if (key === "alertRequests" && state.drawer.kind === "alert" && state.drawer.data?.id) {
        await loadAlertRequestPage(page);
        return;
      }
      if (state.drawer.kind === "user-agent" && ["uaIPs", "uaPaths", "uaRequests"].includes(key) && state.drawer.data) {
        await loadUserAgentDetailPage(key, page);
        return;
      }
      if (state.drawer.kind === "security-signal" && ["securitySignalIPs", "securitySignalRequests"].includes(key) && state.drawer.data) {
        await loadSecuritySignalDetailPage(key, page);
        return;
      }
      if (state.drawer.kind === "ip" && ["ipSites", "ipPaths", "ipURLHits", "ipAgents", "ipRequests"].includes(key) && state.drawer.data?.ip) {
        await loadIPDetailPage(key, page);
        return;
      }
      state.drawer.pages[key] = Math.max(1, page);
      renderCurrentDrawer();
    }
    return;
  }
  if (action === "save-ip-intel") {
    return saveIPManualIntel(button);
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
      await loadReportCatalogPage(1);
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

async function saveIPManualIntel(button) {
  const ip = button.dataset.ip || state.drawer.data?.ip || "";
  if (!ip) return;
  const root = button.closest("[data-ip-intel-form]") || document;
  const action = root.querySelector("[data-ip-intel-action]")?.value || "";
  const label = root.querySelector("[data-ip-intel-label]")?.value || "";
  await runButton(button, "IP intelligence updated", async () => {
    const detail = await fetchJSON(`/api/v1/investigate/ip/${encodeURIComponent(ip)}/manual-intel?${ipDetailParams({ ip }, {})}`, {
      method: "PATCH",
      body: JSON.stringify({ manual_action: action, manual_label: label }),
    });
    state.drawer.data = detail;
    state.drawer.summary = { ...(state.drawer.summary || {}), ...(detail.traffic || {}), ip: detail.ip };
    collectIPTrust();
    renderCurrentDrawer();
  });
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
  const sites = ipSectionPage(detail, "ipSites", detail.sites || [], "sites");
  const paths = ipSectionPage(detail, "ipPaths", detail.top_paths || [], "top_paths");
  const urls = ipSectionPage(detail, "ipURLHits", detail.url_hits || [], "url_hits");
  const agents = ipSectionPage(detail, "ipAgents", detail.top_user_agents || [], "top_user_agents");
  const requests = ipSectionPage(detail, "ipRequests", detail.recent_requests || [], "requests");
  return `
    ${miniMetrics([
      ["Total Requests", formatNumber(traffic.requests), "fa-arrow-trend-up"],
      ["Error Rate", formatPercent(ratio((traffic.status_4xx || 0) + (traffic.status_5xx || 0), traffic.requests)), "fa-fire"],
      ["Avg Response", formatMs(traffic.avg_request_time_ms), "fa-stopwatch"],
      ["Risk Score", intel.risk_score || summary.risk_score || "-", "fa-shield-halved"],
    ])}
    ${ipManualIntelForm(detail, summary)}
    <section class="detail-grid two">
      <article class="detail-card">
        <h3>WHOIS / Reputation</h3>
        ${factsRich([
          ["IP Address", htmlSafe(ipLink(detail.ip || summary.ip, detail.ip || summary.ip, detail))],
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

function ipManualIntelForm(detail = {}, summary = {}) {
  const intel = detail.stored_intel || {};
  const action = intel.manual_action || summary.manual_action || "";
  const label = intel.manual_label || summary.manual_label || intel.known_actor || summary.known_actor || "";
  return `
    <article class="detail-card ip-intel-form" data-ip-intel-form>
      <div>
        <h3>Trust Label</h3>
        <p>Manual whitelist, corporate VPN, RAG egress, crawler validation, or review status.</p>
      </div>
      <label class="select-shell compact">
        <span>Status</span>
        <select data-ip-intel-action>
          ${ipManualActionOption("", "None", action)}
          ${ipManualActionOption("allowlisted", "Allowlisted", action)}
          ${ipManualActionOption("verified", "Verified", action)}
          ${ipManualActionOption("watch", "Watch", action)}
          ${ipManualActionOption("suspicious", "Suspicious", action)}
          ${ipManualActionOption("ignored", "Ignored", action)}
          ${ipManualActionOption("clear", "Clear", action)}
        </select>
      </label>
      <label>
        <span>Label</span>
        <input type="text" data-ip-intel-label value="${escapeAttr(label)}" placeholder="Corporate VPN, RAG egress, Pantheon internal">
      </label>
      <button class="button small primary" type="button" data-action="save-ip-intel" data-ip="${escapeAttr(detail.ip || summary.ip || "")}">${iconHTML("fa-floppy-disk")}Save</button>
    </article>
  `;
}

function ipManualActionOption(value, label, current) {
  return `<option value="${escapeAttr(value)}" ${String(value) === String(current || "") ? "selected" : ""}>${escapeHTML(label)}</option>`;
}

function ipSectionPage(item, key, rows, prefix) {
  const totalKey = `${prefix}_total`;
  const limitKey = `${prefix}_limit`;
  const offsetKey = `${prefix}_offset`;
  if (item && Object.prototype.hasOwnProperty.call(item, totalKey)) {
    return serverBackedPage(rows, Number(item[totalKey] || 0), Number(item[limitKey] || ipDetailPageSize), Number(item[offsetKey] || 0));
  }
  return drawerPage(key, rows, ipDetailPageSize);
}

function renderRequestDetail(item) {
  const status = Number(item.status || 0);
  const risk = clamp(Math.round((status >= 500 ? 55 : status >= 400 ? 30 : 10) + Number(item.bytes_sent || 0) / 2048), 1, 100);
  return `
    <article class="trace-hero">
      <span class="method ${String(item.method || "GET").toLowerCase()}">${escapeHTML(item.method || "GET")}</span>
      <strong>${requestLineHTML(item, false)}</strong>
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
          ["Source IP", htmlSafe(ipLink(item.client_ip))],
          ["Host", item.host || item.site_id || "-"],
          ["Bytes Sent", formatBytes(item.bytes_sent)],
          ["Container", item.container_id || "-"],
        ])}
      </article>
      <article class="detail-card">
        <h3>Risk Summary</h3>
        ${factsRich([
          ["Status class", status >= 500 ? "Server error" : status >= 400 ? "Client error" : "Success"],
          ["Query Family", queryFamilyLabel(item.query) || "-"],
          ["Query string", item.query || "-"],
          ["Referer", item.referer || "-"],
          ["User Agent", item.user_agent ? htmlSafe(userAgentLink(item.user_agent, item.user_agent)) : "-"],
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
        ["Range", summary.range || item.range || "-"],
        ["Generated", shortTime(summary.generated_at || item.generated_at || item.created_at)],
        ["4xx", `${formatNumber(summary.status_4xx)} (${formatPercent(summary.status_4xx_rate)})`],
        ["5xx", `${formatNumber(summary.status_5xx)} (${formatPercent(summary.status_5xx_rate)})`],
        ["Issues", formatNumber(summary.issue_count)],
        ["Top Site", summary.top_site || "-"],
        ["Top Path", summary.top_path || "-"],
        ["Top Source IP", summary.top_source_ip ? htmlSafe(ipLink(summary.top_source_ip)) : "-"],
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
  const points = sortedReportChartPoints(chart.data || []);
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
        ["Points", formatNumber(points.length)],
        ["Total", formatNumber(total)],
        ["Peak", peak.label ? htmlSafe(`${linkifyIPs(peak.label)} / ${escapeHTML(formatNumber(peak.value))}`) : "-"],
      ])}
      ${reportChartVisual(chart, points)}
      <div class="list compact-list">${page.rows.map((point) => `
        <div class="list-row">
          <div><strong>${reportPointLabelHTML(point)}</strong><span>${linkifyIPs(point.meta || chart.unit || "")}</span></div>
          <b>${formatNumber(point.value)}${point.secondary !== undefined ? ` / ${formatNumber(point.secondary)}` : ""}</b>
        </div>
      `).join("") || empty("No chart points.")}</div>
      ${drawerPager(pageKey, page)}
    </section>
  `;
}

function reportChartVisual(chart, points) {
  if (!points.length) return "";
  const visible = points.slice(0, 12);
  const max = Math.max(1, ...visible.map((point) => Number(point.value || 0)));
  const unit = chart.unit || "count";
  const hasSecondary = visible.some((point) => point.secondary !== undefined && Number(point.secondary || 0) > 0);
  return `
    <div class="report-chart-visual" aria-label="${escapeAttr(chart.title || chart.key || "Report chart")}">
      <div class="report-chart-legend">
        <span><i style="background: var(--cyan)"></i>${escapeHTML(unit)}</span>
        ${hasSecondary ? `<span><i style="background: var(--amber)"></i>secondary</span>` : ""}
      </div>
      <div class="report-bars">
        ${visible.map((point) => {
          const value = Number(point.value || 0);
          const secondary = Number(point.secondary || 0);
          const width = clamp((value / max) * 100, value > 0 ? 3 : 0, 100);
          const secondaryWidth = hasSecondary ? clamp((secondary / max) * 100, secondary > 0 ? 3 : 0, 100) : 0;
          const color = reportChartColor(point.color);
          const title = `${point.label || shortTime(point.timestamp) || "point"}: ${formatNumber(value)} ${unit}${point.secondary !== undefined ? ` / ${formatNumber(point.secondary)}` : ""}${point.meta ? ` / ${point.meta}` : ""}`;
          return `
            <div class="report-bar-row" title="${escapeAttr(title)}">
              <span>${reportPointLabelHTML(point)}</span>
              <div class="report-bar-track">
                <i style="width:${width}%; background:${escapeAttr(color)}"></i>
                ${hasSecondary ? `<em style="width:${secondaryWidth}%"></em>` : ""}
              </div>
              <b>${formatCompact(value)}</b>
            </div>
          `;
        }).join("")}
      </div>
    </div>
  `;
}

function sortedReportChartPoints(points) {
  const rows = Array.isArray(points) ? [...points] : [];
  const hasTimestamps = rows.some((point) => point?.timestamp && !Number.isNaN(new Date(point.timestamp).getTime()));
  if (!hasTimestamps) return rows;
  return rows.sort((a, b) => {
    const aTime = reportPointTime(a);
    const bTime = reportPointTime(b);
    return aTime - bTime;
  });
}

function reportPointTime(point) {
  const value = new Date(point?.timestamp || "").getTime();
  return Number.isNaN(value) ? Number.POSITIVE_INFINITY : value;
}

function reportChartColor(color) {
  const value = String(color || "").trim();
  if (/^#[0-9a-f]{3}(?:[0-9a-f]{3})?$/i.test(value)) return value;
  return "var(--cyan)";
}

function reportPointLabelHTML(point) {
  return linkifyIPs(point.label || shortTime(point.timestamp) || "-");
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
    const agent = { family: row.label, sample: row.meta || row.user_agent || row.label, actor_type: row.category, known_actor: row.known_actor };
    const info = parseUserAgent(agent);
    return userAgentLink(agent, info.label || row.label || row.meta || "User Agent");
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
  const ipPage = securitySignalSectionPage(item, "securitySignalIPs", relatedIPs, "related_ips");
  const requestPage = securitySignalSectionPage(item, "securitySignalRequests", relatedRequests, "related_requests");
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
          ["Type", signal.title || signal.kind || "Security signal"],
          ["Category", signal.category || signal.rule_key || signal.kind || "-"],
          ["Project", signal.site_id || "-"],
          ["Environment", signal.env || "-"],
          ["Source IP", signal.ip ? htmlSafe(ipLink(signal.ip)) : "-"],
          ["Path", signal.path || "-"],
          ["Evidence", item.source || "loaded view"],
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

function securitySignalSectionPage(item, key, rows, prefix) {
  const totalKey = `${prefix}_total`;
  const limitKey = `${prefix}_limit`;
  const offsetKey = `${prefix}_offset`;
  if (item && Object.prototype.hasOwnProperty.call(item, totalKey)) {
    return serverBackedPage(rows, Number(item[totalKey] || 0), Number(item[limitKey] || securitySignalDetailPageSize), Number(item[offsetKey] || 0));
  }
  return drawerPage(key, rows, securitySignalDetailPageSize);
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
          <td>${requestLineHTML(row)}</td>
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
          <td>${requestLineHTML(row)}<br><span class="subtle">${escapeHTML(row.site_id || "-")} / ${row.user_agent ? userAgentLink(row.user_agent, row.user_agent) : ""}</span></td>
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
          <td>${requestLineHTML(row)}<br><span class="subtle">${escapeHTML(row.site_id || "-")} / ${escapeHTML(row.env || "-")}</span></td>
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
  const lines = normalizeMarkdownLines(repairReportText(String(value || "")));
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
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
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
    const table = readMarkdownTable(lines, index);
    if (table) {
      closeList();
      html.push(table.html);
      index = table.nextIndex - 1;
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

function repairReportText(value) {
  return String(value || "")
    .replace(/\r\n/g, "\n")
    .replace(/рџљЁ|рџ“€|рџ›ЎпёЏ|рџ”¬|рџљЂ/g, "")
    .replace(/\$\\approx\$/g, "approximately")
    .replace(/\$\\le\$/g, "<=")
    .replace(/\$\\ge\$/g, ">=");
}

function normalizeMarkdownLines(value) {
  const raw = String(value || "").split("\n");
  const lines = [];
  for (let index = 0; index < raw.length; index += 1) {
    const line = raw[index];
    const trimmed = line.trim();
    if (!trimmed) {
      const previousIsTable = lines.length && isMarkdownTableLine(lines[lines.length - 1]);
      let nextIndex = index + 1;
      while (nextIndex < raw.length && !raw[nextIndex].trim()) nextIndex += 1;
      if (previousIsTable && nextIndex < raw.length && isMarkdownTableLine(raw[nextIndex])) continue;
      lines.push(line);
      continue;
    }
    if (isMarkdownTableLine(line) && lines.length && isMarkdownTableLine(lines[lines.length - 1]) && !lines[lines.length - 1].trim().endsWith("|")) {
      lines[lines.length - 1] = `${lines[lines.length - 1].trimEnd()} | ${trimmed.replace(/^\|\s*/, "")}`;
      continue;
    }
    lines.push(line);
  }
  return lines;
}

function isMarkdownTableLine(line) {
  const trimmed = String(line || "").trim();
  return trimmed.startsWith("|") && trimmed.includes("|", 1);
}

function isMarkdownTableSeparator(line) {
  return /^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(String(line || "").trim());
}

function markdownTableCells(line) {
  return String(line || "")
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((cell) => cell.trim());
}

function readMarkdownTable(lines, startIndex) {
  if (!isMarkdownTableLine(lines[startIndex]) || !isMarkdownTableSeparator(lines[startIndex + 1])) return null;
  const headers = markdownTableCells(lines[startIndex]);
  const rows = [];
  let index = startIndex + 2;
  while (index < lines.length && isMarkdownTableLine(lines[index]) && !isMarkdownTableSeparator(lines[index])) {
    const cells = markdownTableCells(lines[index]);
    while (cells.length < headers.length) cells.push("");
    rows.push(cells.slice(0, headers.length));
    index += 1;
  }
  if (!headers.length || !rows.length) return null;
  return {
    nextIndex: index,
    html: `<div class="table-wrap markdown-table-wrap"><table class="markdown-table"><thead><tr>${headers.map((header) => `<th>${renderInlineMarkdown(header)}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${renderInlineMarkdown(cell)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`,
  };
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
    ${(item.charts || []).map(printableChart).join("") || "<p>No chart data stored with this report.</p>"}
    <h2>Drilldowns</h2>
    ${(item.drilldowns || []).map(printableDrilldown).join("") || "<p>No drilldowns stored with this report.</p>"}
  `;
}

function printableChart(chart) {
  const rows = sortedReportChartPoints(chart.data || []);
  return `
    <h3>${escapeHTML(chart.title || chart.key || "Chart")}</h3>
    <p>${escapeHTML(chart.kind || "chart")} / ${escapeHTML(chart.unit || "count")} / ${formatNumber(rows.length)} points</p>
    ${rows.length ? `<table><thead><tr><th>Label</th><th>Value</th><th>Secondary</th><th>Meta</th></tr></thead><tbody>${rows.map((point) => `
      <tr>
        <td>${escapeHTML(point.label || shortTime(point.timestamp) || "-")}</td>
        <td>${escapeHTML(formatNumber(point.value))}</td>
        <td>${point.secondary !== undefined ? escapeHTML(formatNumber(point.secondary)) : "-"}</td>
        <td>${escapeHTML(point.meta || "")}</td>
      </tr>
    `).join("")}</tbody></table>` : "<p>No chart points.</p>"}
  `;
}

function printableDrilldown(drill) {
  const rows = drill.items || [];
  return `
    <h3>${escapeHTML(drill.title || drill.key || "Drilldown")}</h3>
    ${rows.length ? `<ul>${rows.map((row) => `<li><strong>${escapeHTML(reportDrilldownTitle(row))}</strong> ${escapeHTML(reportDrilldownMeta(row))} ${escapeHTML(reportDrilldownValue(row))}</li>`).join("")}</ul>` : "<p>No drilldown rows.</p>"}
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
    ...(item.charts || []).flatMap(markdownChart),
    "## Drilldowns",
    "",
    ...(item.drilldowns || []).flatMap(markdownDrilldown),
  ];
  return lines.join("\n");
}

function markdownChart(chart) {
  const rows = sortedReportChartPoints(chart.data || []);
  return [
    `### ${chart.title || chart.key || "Chart"}`,
    `${chart.kind || "chart"} / ${chart.unit || "count"} / ${rows.length} points`,
    "",
    ...rows.map((point) => `- ${point.label || shortTime(point.timestamp) || "-"}: ${formatNumber(point.value)}${point.secondary !== undefined ? ` / ${formatNumber(point.secondary)}` : ""}${point.meta ? ` / ${point.meta}` : ""}`),
    "",
  ];
}

function markdownDrilldown(drill) {
  const rows = drill.items || [];
  return [
    `### ${drill.title || drill.key || "Drilldown"}`,
    ...rows.map((row) => `- ${reportDrilldownTitle(row)}: ${[reportDrilldownMeta(row), reportDrilldownValue(row)].filter(Boolean).join(" / ")}`),
    "",
  ];
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
      const detail = ip ? await fetchJSON(`/api/v1/investigate/ip/${encodeURIComponent(ip)}?${ipDetailParams({ ip }, {})}`) : item;
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
    const params = securitySignalDetailParams(item, { related_ip_offset: 0, related_request_offset: 0 });
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
        const detail = await fetchJSON(`/api/v1/alerts/${encodeURIComponent(cached.id)}?limit=${alertRequestPageSize}&offset=0`);
        item = { ...(detail.alert || cached), requests: detail.requests || [] };
        item.request_total = detail.request_total ?? item.request_total ?? item.requests.length;
        item.request_limit = detail.request_limit ?? alertRequestPageSize;
        item.request_offset = detail.request_offset ?? 0;
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
    const params = userAgentDetailParams({ ...item, sample }, { top_ip_offset: 0, top_path_offset: 0, request_offset: 0 });
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

async function loadAlertRequestPage(page) {
  const item = state.drawer.data || {};
  if (!item.id) return;
  const limit = Math.max(1, Number(item.request_limit || alertRequestPageSize));
  const safePage = Math.max(1, Number(page || 1));
  const detail = await fetchJSON(`/api/v1/alerts/${encodeURIComponent(item.id)}?limit=${limit}&offset=${(safePage - 1) * limit}`);
  const merged = {
    ...item,
    ...(detail.alert || {}),
    requests: detail.requests || [],
    request_total: detail.request_total ?? 0,
    request_limit: detail.request_limit ?? limit,
    request_offset: detail.request_offset ?? (safePage - 1) * limit,
  };
  state.drawer.data = merged;
  state.detailCache[`alert:${item.id}`] = merged;
  renderCurrentDrawer();
}

function userAgentDetailParams(item, offsets = {}) {
  const agent = item.user_agent || item || {};
  const sample = agent.sample || agent.user_agent || item.sample || item.family || "";
  const params = new URLSearchParams(buildFilterQuery({
    limit: userAgentDetailPageSize,
    top_ip_offset: offsets.top_ip_offset ?? item.top_ips_offset ?? 0,
    top_path_offset: offsets.top_path_offset ?? item.top_paths_offset ?? 0,
    request_offset: offsets.request_offset ?? item.requests_offset ?? 0,
  }));
  if (agent.id || item.id) params.set("id", agent.id || item.id);
  if (sample && sample !== "User Agent") params.set("sample", sample);
  return params;
}

async function loadUserAgentDetailPage(key, page) {
  const item = state.drawer.data || {};
  const limit = Math.max(1, Number(item.top_ips_limit || item.top_paths_limit || item.requests_limit || userAgentDetailPageSize));
  const offset = (Math.max(1, Number(page || 1)) - 1) * limit;
  const offsets = {
    top_ip_offset: item.top_ips_offset || 0,
    top_path_offset: item.top_paths_offset || 0,
    request_offset: item.requests_offset || 0,
  };
  if (key === "uaIPs") offsets.top_ip_offset = offset;
  if (key === "uaPaths") offsets.top_path_offset = offset;
  if (key === "uaRequests") offsets.request_offset = offset;
  const detail = await fetchJSON(`/api/v1/investigate/user-agent?${userAgentDetailParams(item, offsets)}`);
  const merged = {
    ...item,
    ...detail,
    user_agent: { ...(item.user_agent || {}), ...(detail.user_agent || {}) },
  };
  state.drawer.data = merged;
  renderCurrentDrawer();
}

function securitySignalDetailParams(item, offsets = {}) {
  const signal = item.signal || item || {};
  return new URLSearchParams(buildFilterQuery({
    limit: securitySignalDetailPageSize,
    kind: signal.kind || item.kind || "",
    category: signal.category || item.category || "",
    rule_key: signal.rule_key || item.rule_key || "",
    site_id: signal.site_id || item.site_id || "",
    env: signal.env || item.env || "",
    ip: signal.ip || item.ip || "",
    method: signal.method || item.method || "",
    path: signal.path || item.path || "",
    related_ip_offset: offsets.related_ip_offset ?? item.related_ips_offset ?? 0,
    related_request_offset: offsets.related_request_offset ?? item.related_requests_offset ?? 0,
  }));
}

async function loadSecuritySignalDetailPage(key, page) {
  const item = state.drawer.data || {};
  const limit = Math.max(1, Number(item.related_ips_limit || item.related_requests_limit || securitySignalDetailPageSize));
  const offset = (Math.max(1, Number(page || 1)) - 1) * limit;
  const offsets = {
    related_ip_offset: item.related_ips_offset || 0,
    related_request_offset: item.related_requests_offset || 0,
  };
  if (key === "securitySignalIPs") offsets.related_ip_offset = offset;
  if (key === "securitySignalRequests") offsets.related_request_offset = offset;
  const detail = await fetchJSON(`/api/v1/investigate/security-signal?${securitySignalDetailParams(item, offsets)}`);
  const merged = {
    ...item,
    ...detail,
    signal: { ...(item.signal || item), ...(detail.signal || {}) },
  };
  state.drawer.data = merged;
  renderCurrentDrawer();
}

function ipDetailParams(item, offsets = {}) {
  return buildFilterQuery({
    limit: ipDetailPageSize,
    sites_offset: offsets.sites_offset ?? item.sites_offset ?? 0,
    top_paths_offset: offsets.top_paths_offset ?? item.top_paths_offset ?? 0,
    url_hits_offset: offsets.url_hits_offset ?? item.url_hits_offset ?? 0,
    requests_offset: offsets.requests_offset ?? item.requests_offset ?? 0,
    user_agents_offset: offsets.user_agents_offset ?? item.top_user_agents_offset ?? 0,
  });
}

async function loadIPDetailPage(key, page) {
  const item = state.drawer.data || {};
  const limit = Math.max(1, Number(item.sites_limit || item.top_paths_limit || item.url_hits_limit || item.requests_limit || item.top_user_agents_limit || ipDetailPageSize));
  const offset = (Math.max(1, Number(page || 1)) - 1) * limit;
  const offsets = {
    sites_offset: item.sites_offset || 0,
    top_paths_offset: item.top_paths_offset || 0,
    url_hits_offset: item.url_hits_offset || 0,
    requests_offset: item.requests_offset || 0,
    user_agents_offset: item.top_user_agents_offset || 0,
  };
  if (key === "ipSites") offsets.sites_offset = offset;
  if (key === "ipPaths") offsets.top_paths_offset = offset;
  if (key === "ipURLHits") offsets.url_hits_offset = offset;
  if (key === "ipRequests") offsets.requests_offset = offset;
  if (key === "ipAgents") offsets.user_agents_offset = offset;
  const detail = await fetchJSON(`/api/v1/investigate/ip/${encodeURIComponent(item.ip)}?${ipDetailParams(item, offsets)}`);
  state.drawer.data = { ...item, ...detail };
  renderCurrentDrawer();
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
        <p>The search box filters the loaded access-log evidence for the selected range and project. Plain words match visible event text. Field filters narrow specific values, and OR starts an alternate match group.</p>
      </section>
      <section>
        <h3>Useful Queries</h3>
        <div class="guide-examples">
          <code>status:>=500</code>
          <code>path:/wp-*</code>
          <code>method:POST path:/xmlrpc.php</code>
          <code>ip:167.103.5.57</code>
          <code>agent:firefox</code>
          <code>project:example env:live</code>
          <code>status:>=400 OR path:/wp-*</code>
        </div>
      </section>
      <section>
        <h3>Field Hints</h3>
        ${facts([
          ["Status", "Use status:404, status:>=400, status:<500."],
          ["Path", "Use path:/wp-login.php or wildcards like path:/wp-*."],
          ["IP", "Use ip: with a full source address."],
          ["Agent", "Use agent:, ua:, or browser: for user-agent text."],
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
  if (state.currentUser) startAutoRefresh();
}

function showLogin() {
  stopAutoRefresh();
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
  stopAutoRefresh();
  showLogin();
}

function drawCharts() {
  if (qs("#trafficLine")) {
    const rows = routeTimelineRows();
    drawTimeline(qs("#trafficLine"), rows);
    installTimelineHover(qs("#trafficLine"), rows);
  }
  if (qs("#statusBars")) {
    const rows = state.data.traffic.status_breakdown || state.data.analysis.status_breakdown || [];
    drawStatusBars(qs("#statusBars"), rows);
    installStatusHover(qs("#statusBars"), rows);
  }
}

function sortedTimelineRows(rows) {
  return [...rows].sort((a, b) => new Date(a.bucket_ts || 0) - new Date(b.bucket_ts || 0));
}

function routeTimelineRows() {
  if (state.route === "search") {
    const events = currentSearchEvents();
    if (events.length) return timelineRowsFromEvents(events);
  }
  return sortedTimelineRows(state.data.traffic.timeline || []);
}

function currentSearchEvents() {
  const searchIP = extractIPSearchValue(state.search);
  const advancedKey = advancedSearchKey(searchIP);
  const usingAdvancedEvents = searchIP && state.advancedSearch.key === advancedKey;
  const sourceEvents = usingAdvancedEvents ? state.advancedSearch.events : (state.data.traffic.recent_errors || []);
  if (usingAdvancedEvents) return sourceEvents;
  return filtered(searchItems(sourceEvents, (item) => `${item.status} ${item.site_id} ${item.env} ${item.client_ip} ${item.method} ${item.path} ${item.user_agent}`));
}

function timelineRowsFromEvents(events) {
  const rangeMs = activeRangeMs();
  const bucketMs = Math.max(60 * 1000, Math.ceil(rangeMs / 60 / (60 * 1000)) * 60 * 1000);
  const buckets = new Map();
  events.forEach((event) => {
    const ts = new Date(event.ts || event.timestamp || event.created_at || 0).getTime();
    if (!Number.isFinite(ts) || ts <= 0) return;
    const bucket = Math.floor(ts / bucketMs) * bucketMs;
    const row = buckets.get(bucket) || { bucket_ts: new Date(bucket).toISOString(), requests: 0, status_4xx: 0, status_5xx: 0 };
    row.requests += 1;
    const status = Number(event.status || 0);
    if (status >= 400 && status < 500) row.status_4xx += 1;
    if (status >= 500 && status < 600) row.status_5xx += 1;
    buckets.set(bucket, row);
  });
  return sortedTimelineRows(Array.from(buckets.values()));
}

function activeRangeMs() {
  const value = String(state.range || "24h").toLowerCase();
  const match = value.match(/^(\d+)(m|h|d)$/);
  if (!match) return 24 * 60 * 60 * 1000;
  const amount = Number(match[1]);
  if (match[2] === "m") return amount * 60 * 1000;
  if (match[2] === "h") return amount * 60 * 60 * 1000;
  return amount * 24 * 60 * 60 * 1000;
}

function drawTimeline(canvas, rows) {
  const ctx = setupCanvas(canvas);
  const { width, height } = canvas.getBoundingClientRect();
  const axisHeight = rows.length > 1 ? 18 : 0;
  const plotHeight = Math.max(40, height - axisHeight);
  drawFrame(ctx, width, plotHeight);
  if (!rows.length) {
    drawNoChartData(ctx, width, plotHeight);
    return;
  }
  const values = rows.map((row) => row.requests || 0);
  drawLine(ctx, values, width, plotHeight, cssColor("cyan"), 2.5);
  const errors = rows.map((row) => (row.status_4xx || 0) + (row.status_5xx || 0));
  if (errors.some(Boolean)) drawLine(ctx, errors, width, plotHeight, cssColor("red"), 2);
  drawTimelineAxis(ctx, rows, width, height);
}

function drawNoChartData(ctx, width, height) {
  ctx.fillStyle = "#91a3b8";
  ctx.font = "12px sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText("No data in selected range", width / 2, height / 2);
  ctx.textAlign = "start";
  ctx.textBaseline = "alphabetic";
}

function drawTimelineAxis(ctx, rows, width, height) {
  if (rows.length <= 1) return;
  const first = shortTime(rows[0].bucket_ts);
  const last = shortTime(rows[rows.length - 1].bucket_ts);
  ctx.fillStyle = "#91a3b8";
  ctx.font = "11px sans-serif";
  ctx.textBaseline = "alphabetic";
  ctx.fillText(first, 4, height - 4);
  const lastWidth = ctx.measureText(last).width;
  ctx.fillText(last, Math.max(4, width - lastWidth - 4), height - 4);
  ctx.strokeStyle = "rgba(145, 163, 184, 0.35)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(4, height - 16);
  ctx.lineTo(width - 4, height - 16);
  ctx.stroke();
}

function drawStatusBars(canvas, rows) {
  const ctx = setupCanvas(canvas);
  const { width, height } = canvas.getBoundingClientRect();
  drawFrame(ctx, width, height);
  const buckets = statusClassRows(rows);
  const max = Math.max(1, ...buckets.map((row) => row.requests || 0));
  const gap = 10;
  const barWidth = Math.max(16, (width - gap * (buckets.length + 1)) / Math.max(1, buckets.length));
  buckets.forEach((row, index) => {
    const h = ((row.requests || 0) / max) * (height - 44);
    const x = gap + index * (barWidth + gap);
    const y = height - h - 24;
    ctx.fillStyle = statusBucketColor(row.status);
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
  const buckets = statusClassRows(rows);
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
      <span><i style="background: ${statusBucketColor(row.status)}"></i>${formatNumber(row.requests)} requests</span>
      <span>${formatPercent(ratio(row.requests, state.data.analysis?.totals?.requests))} of traffic</span>
    `);
  };
  canvas.onmouseleave = hideChartTooltip;
}

function statusClassRows(rows) {
  const buckets = [
    { status: "2xx", requests: 0 },
    { status: "3xx", requests: 0 },
    { status: "4xx", requests: 0 },
    { status: "5xx", requests: 0 },
  ];
  const source = rows.length ? rows : [
    { status: 200, requests: state.data.analysis?.totals?.requests || 0 },
    { status: 400, requests: state.data.analysis?.totals?.status_4xx || 0 },
    { status: 500, requests: state.data.analysis?.totals?.status_5xx || 0 },
  ];
  source.forEach((row) => {
    const status = Number(row.status || 0);
    const index = status >= 500 ? 3 : status >= 400 ? 2 : status >= 300 ? 1 : status >= 200 ? 0 : -1;
    if (index >= 0) buckets[index].requests += Number(row.requests || 0);
  });
  return buckets;
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

function statusBucketColor(status) {
  const value = String(status || "");
  if (value.startsWith("5")) return cssColor("red");
  if (value.startsWith("4")) return cssColor("amber");
  if (value.startsWith("3")) return cssColor("purple");
  return cssColor("green");
}

function collectorHealth() {
  const stats = state.data.collectorHealth?.raw_files?.stats || {};
  const recent = state.data.collectorHealth?.raw_files?.recent || [];
  const lastDownloadAt = state.data.collectorHealth?.raw_files?.last_download_at;
  return {
    state: state.data.overview.database_configured ? "Healthy" : "Local",
    lastDownload: shortTime(lastDownloadAt),
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

function reportCatalogQuery(page = state.pages.reportCatalog || 1) {
  const safePage = Math.max(1, Number(page || 1));
  const extra = {
    limit: reportCatalogPageSize,
    offset: (safePage - 1) * reportCatalogPageSize,
  };
  if (state.reportType && state.reportType !== "all") extra.report_type = state.reportType;
  return buildFilterQuery(extra);
}

async function loadReportCatalogPage(page = state.pages.reportCatalog || 1) {
  const safePage = Math.max(1, Number(page || 1));
  const response = await safeFetch(`/api/v1/reports/recent?${reportCatalogQuery(safePage)}`, {
    reports: [],
    total: 0,
    limit: reportCatalogPageSize,
    offset: (safePage - 1) * reportCatalogPageSize,
    report_types: state.data.reportCatalog?.report_types || [],
  });
  state.data.reports = response.reports || [];
  state.data.reportCatalog = reportCatalogMeta(response);
  state.pages.reportCatalog = reportCatalogPage(state.data.reports, state.data.reportCatalog).page;
  render();
}

function notificationHistoryQuery(page = state.pages.notificationsRecent || 1) {
  const safePage = Math.max(1, Number(page || 1));
  return new URLSearchParams({
    limit: String(notificationPageSize),
    offset: String((safePage - 1) * notificationPageSize),
  }).toString();
}

async function loadNotificationPage(page = state.pages.notificationsRecent || 1, key = "notificationsRecent") {
  const safePage = Math.max(1, Number(page || 1));
  const response = await safeFetch(`/api/v1/notifications?${notificationHistoryQuery(safePage)}`, {
    recent: [],
    recent_total: 0,
    recent_limit: notificationPageSize,
    recent_offset: (safePage - 1) * notificationPageSize,
  });
  if (key === "pulseDeliveries") {
    state.data.pulseNotifications = response;
    state.pages.pulseDeliveries = notificationPage(response.recent || [], safePage, response).page;
  } else {
    state.data.notifications = response;
    state.pages.notificationsRecent = notificationPage(response.recent || [], safePage, response).page;
  }
  render();
}

function notificationPage(rows, page = 1, status = state.data.notifications || {}) {
  if (Object.prototype.hasOwnProperty.call(status, "recent_total")) {
    return serverBackedPage(rows, Number(status.recent_total || 0), Number(status.recent_limit || notificationPageSize), Number(status.recent_offset || 0));
  }
  return paginate(rows, page, notificationPageSize);
}

function segmentHistoryQuery(page = state.pages.pulseSegments || 1) {
  const safePage = Math.max(1, Number(page || 1));
  return new URLSearchParams({
    limit: String(segmentPageSize),
    offset: String((safePage - 1) * segmentPageSize),
  }).toString();
}

async function loadSegmentPage(page = state.pages.pulseSegments || 1) {
  const safePage = Math.max(1, Number(page || 1));
  const response = await safeFetch(`/api/v1/system/segments?${segmentHistoryQuery(safePage)}`, {
    segments: [],
    total: 0,
    limit: segmentPageSize,
    offset: (safePage - 1) * segmentPageSize,
  });
  state.data.segments = response.segments || [];
  state.data.segmentCatalog = segmentCatalogMeta(response);
  state.pages.pulseSegments = segmentPage(state.data.segments, state.data.segmentCatalog).page;
  render();
}

function segmentCatalogMeta(response = {}) {
  return {
    total: Number(response.total || 0),
    limit: Number(response.limit || segmentPageSize),
    offset: Number(response.offset || 0),
  };
}

function segmentPage(rows, catalog = {}) {
  return serverBackedPage(rows, Number(catalog.total ?? rows.length), Number(catalog.limit || segmentPageSize), Number(catalog.offset || 0));
}

function rawFileHistoryQuery(page = state.pages.pulseRawFiles || 1) {
  const safePage = Math.max(1, Number(page || 1));
  const params = {
    limit: String(rawFilePageSize),
    offset: String((safePage - 1) * rawFilePageSize),
  };
  if (state.rawFileStatus && state.rawFileStatus !== "all") params.status = state.rawFileStatus;
  return new URLSearchParams(params).toString();
}

async function loadRawFilePage(page = state.pages.pulseRawFiles || 1) {
  const safePage = Math.max(1, Number(page || 1));
  const response = await safeFetch(`/api/v1/system/collector-health?${rawFileHistoryQuery(safePage)}`, {
    raw_files: { recent: [], total: 0, limit: rawFilePageSize, offset: (safePage - 1) * rawFilePageSize },
  });
  state.data.collectorHealth = response;
  state.data.rawFileCatalog = rawFileCatalogMeta(response.raw_files || {});
  state.pages.pulseRawFiles = rawFilePage(response.raw_files?.recent || [], state.data.rawFileCatalog).page;
  render();
}

function rawFileCatalogMeta(rawFiles = {}) {
  return {
    total: Number(rawFiles.total || 0),
    limit: Number(rawFiles.limit || rawFilePageSize),
    offset: Number(rawFiles.offset || 0),
    status: rawFiles.status || "",
  };
}

function rawFilePage(rows, catalog = {}) {
  return serverBackedPage(rows, Number(catalog.total ?? rows.length), Number(catalog.limit || rawFilePageSize), Number(catalog.offset || 0));
}

function archiveHistoryQuery(page = state.pages.pulseArchives || 1) {
  const safePage = Math.max(1, Number(page || 1));
  return new URLSearchParams({
    limit: String(archivePageSize),
    offset: String((safePage - 1) * archivePageSize),
  }).toString();
}

async function loadArchivePage(page = state.pages.pulseArchives || 1) {
  const safePage = Math.max(1, Number(page || 1));
  const response = await safeFetch(`/api/v1/system/archives?${archiveHistoryQuery(safePage)}`, {
    archives: [],
    total: 0,
    limit: archivePageSize,
    offset: (safePage - 1) * archivePageSize,
  });
  state.data.archives = response.archives || [];
  state.data.archiveCatalog = archiveCatalogMeta(response);
  state.pages.pulseArchives = archivePage(state.data.archives, state.data.archiveCatalog).page;
  render();
}

function archiveCatalogMeta(response = {}) {
  return {
    total: Number(response.total || 0),
    limit: Number(response.limit || archivePageSize),
    offset: Number(response.offset || 0),
  };
}

function archivePage(rows, catalog = {}) {
  return serverBackedPage(rows, Number(catalog.total ?? rows.length), Number(catalog.limit || archivePageSize), Number(catalog.offset || 0));
}

function archiveImportHistoryQuery(page = state.pages.pulseArchiveImports || 1) {
  const safePage = Math.max(1, Number(page || 1));
  return new URLSearchParams({
    limit: String(archiveImportPageSize),
    offset: String((safePage - 1) * archiveImportPageSize),
  }).toString();
}

async function loadArchiveImportPage(page = state.pages.pulseArchiveImports || 1) {
  const safePage = Math.max(1, Number(page || 1));
  const response = await safeFetch(`/api/v1/system/archive-imports?${archiveImportHistoryQuery(safePage)}`, {
    imports: [],
    total: 0,
    limit: archiveImportPageSize,
    offset: (safePage - 1) * archiveImportPageSize,
  });
  state.data.archiveImports = response.imports || [];
  state.data.archiveImportCatalog = archiveImportCatalogMeta(response);
  state.pages.pulseArchiveImports = archiveImportPage(state.data.archiveImports, state.data.archiveImportCatalog).page;
  render();
}

function archiveImportCatalogMeta(response = {}) {
  return {
    total: Number(response.total || 0),
    limit: Number(response.limit || archiveImportPageSize),
    offset: Number(response.offset || 0),
  };
}

function archiveImportPage(rows, catalog = {}) {
  return serverBackedPage(rows, Number(catalog.total ?? rows.length), Number(catalog.limit || archiveImportPageSize), Number(catalog.offset || 0));
}

function jobHistoryQuery(page = state.pages.pulseJobs || 1) {
  const safePage = Math.max(1, Number(page || 1));
  return new URLSearchParams({
    limit: String(jobPageSize),
    offset: String((safePage - 1) * jobPageSize),
  }).toString();
}

function jobStepHistoryQuery(page = state.pages.pulseJobSteps || 1) {
  const safePage = Math.max(1, Number(page || 1));
  return new URLSearchParams({
    limit: String(jobStepPageSize),
    offset: String((safePage - 1) * jobStepPageSize),
  }).toString();
}

async function loadJobPage(page = state.pages.pulseJobs || 1) {
  const safePage = Math.max(1, Number(page || 1));
  const response = await safeFetch(`/api/v1/system/jobs?${jobHistoryQuery(safePage)}`, {
    jobs: [],
    total: 0,
    limit: jobPageSize,
    offset: (safePage - 1) * jobPageSize,
  });
  state.data.jobs = response.jobs || [];
  state.data.jobCatalog = jobCatalogMeta(response);
  state.pages.pulseJobs = jobPage(state.data.jobs, state.data.jobCatalog).page;
  render();
}

async function loadJobStepPage(page = state.pages.pulseJobSteps || 1) {
  const safePage = Math.max(1, Number(page || 1));
  const response = await safeFetch(`/api/v1/system/job-steps?${jobStepHistoryQuery(safePage)}`, {
    steps: [],
    total: 0,
    limit: jobStepPageSize,
    offset: (safePage - 1) * jobStepPageSize,
  });
  state.data.jobSteps = response.steps || [];
  state.data.jobStepCatalog = jobStepCatalogMeta(response);
  state.pages.pulseJobSteps = jobStepPage(state.data.jobSteps, state.data.jobStepCatalog).page;
  render();
}

function jobCatalogMeta(response = {}) {
  return {
    total: Number(response.total || 0),
    limit: Number(response.limit || jobPageSize),
    offset: Number(response.offset || 0),
  };
}

function jobPage(rows, catalog = {}) {
  return serverBackedPage(rows, Number(catalog.total ?? rows.length), Number(catalog.limit || jobPageSize), Number(catalog.offset || 0));
}

function jobStepCatalogMeta(response = {}) {
  return {
    total: Number(response.total || 0),
    limit: Number(response.limit || jobStepPageSize),
    offset: Number(response.offset || 0),
    slow_phases: response.slow_phases || [],
  };
}

function jobStepPage(rows, catalog = {}) {
  return serverBackedPage(rows, Number(catalog.total ?? rows.length), Number(catalog.limit || jobStepPageSize), Number(catalog.offset || 0));
}

function reportCatalogMeta(response = {}) {
  return {
    total: Number(response.total || 0),
    limit: Number(response.limit || reportCatalogPageSize),
    offset: Number(response.offset || 0),
    report_types: response.report_types || [],
    report_type_counts: response.report_type_counts || {},
  };
}

function reportCatalogPage(rows, catalog = {}) {
  const pageSize = Number(catalog.limit || reportCatalogPageSize);
  const total = Number(catalog.total ?? rows.length);
  const offset = Number(catalog.offset || 0);
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = clamp(Math.floor(offset / pageSize) + 1, 1, totalPages);
  const visibleRows = rows.slice(0, pageSize);
  return {
    rows: visibleRows,
    page,
    pageSize,
    total,
    totalPages,
    start: total ? offset + 1 : 0,
    end: Math.min(total, offset + visibleRows.length),
  };
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
  const overviewLoaded = overview.database_configured !== undefined || Boolean(overview.started_at);
  const analytics = overview.analytics || {};
  const coverage = state.data.archiveCoverage || {};
  const fast = fastReadiness();
  const fetchErrors = state.fetchErrors || [];
  const hasRequests = Number(analytics.requests || state.data.analysis?.totals?.requests || 0) > 0;
  const messages = [];
  const actions = [`<button class="button small" type="button" data-action="refresh">${iconHTML("fa-rotate-right")}Refresh</button>`];
  if (fetchErrors.length) {
    const first = fetchErrors[0];
    messages.push(`${formatNumber(fetchErrors.length)} dashboard request(s) failed while loading ${activeRangeLabel()}. First failure: ${first.message}.`);
  } else if (overviewLoaded && !overview.database_configured) {
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
  } else if (overviewLoaded && !hasRequests) {
    messages.push(`No indexed requests in ${activeRangeLabel()}. Run pipeline/backfill, or choose a range that overlaps indexed hot data.`);
  } else if (fast.known && !fast.ready) {
    messages.push(`${activeRangeLabel()} is visible, but some dashboard reads are using raw event fallbacks instead of rollups. ${fast.rawFallbackSources.length ? `Raw fallback: ${fast.rawFallbackSources.join(", ")}.` : ""}`);
    actions.push(`<button class="button small" type="button" data-route="pulse">${iconHTML("fa-chart-line")}Pulse Logs</button>`);
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

function fastReadiness() {
  const audit = state.data.fastReadAudit || {};
  const known = Boolean(audit.range || audit.since || audit.until);
  const rawFallbackSources = [];
  if (usesRawFallback(audit.overview_source)) rawFallbackSources.push("overview");
  if (usesRawFallback(audit.access_analysis_source)) rawFallbackSources.push("analysis");
  if (usesRawFallback(audit.traffic_source)) rawFallbackSources.push("traffic");
  if (Number(audit.recent_error_raw_gap_rows || audit.expected_raw_gap_rows || 0) > 0 || usesRawFallback(audit.recent_errors_source)) {
    rawFallbackSources.push("recent errors");
  }
  return {
    known,
    ready: known && audit.dimension_rollups_ready !== false && audit.status_rollups_ready !== false && !audit.expected_raw_range_aggregations && rawFallbackSources.length === 0,
    rawFallbackSources,
  };
}

function usesRawFallback(source) {
  return /raw/i.test(String(source || ""));
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

function htmlSafe(value) {
  return { __html: String(value ?? "") };
}

function factsRich(items) {
  return `<dl class="facts">${items.map(([label, value]) => {
    const html = value && typeof value === "object" && Object.prototype.hasOwnProperty.call(value, "__html")
      ? value.__html
      : escapeHTML(value ?? "-");
    return `<div><dt>${escapeHTML(label)}</dt><dd>${html || "-"}</dd></div>`;
  }).join("")}</dl>`;
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

function requestLineHTML(row, includeMethod = true) {
  const method = includeMethod ? `${escapeHTML(row.method || "GET")} ` : "";
  return `${method}${escapeHTML(row.path || "/")}${queryBadgeHTML(row.query)}`;
}

function queryBadgeHTML(query) {
  const family = queryFamily(query);
  if (!family) return "";
  return ` <span class="pill query-badge" title="${escapeAttr(family.title)}">${escapeHTML(family.label)}</span>`;
}

function queryFamilyLabel(query) {
  const family = queryFamily(query);
  return family ? escapeHTML(family.description || family.label) : "";
}

function queryFamilyMeta(value) {
  const family = String(value || "").toLowerCase();
  if (family === "srsltid") {
    return {
      label: "srsltid",
      description: "Google search result tracking parameter",
      title: "Google search result tracking parameter. Usually safe to ignore in cache keys.",
    };
  }
  if (family === "utm" || family.startsWith("utm_")) {
    return {
      label: "utm",
      description: "Marketing campaign tracking parameter",
      title: "Marketing campaign tracking parameter. Can create many cache variants.",
    };
  }
  if (family === "click-id" || ["gclid", "fbclid", "msclkid", "dclid", "gad_source", "gbraid", "wbraid", "gad_campaignid"].includes(family)) {
    return {
      label: "click-id",
      description: "Ad/social click tracking parameter",
      title: "Ad/social click tracking parameter. Can create many cache variants.",
    };
  }
  if (family === "campaign" || ["campaign", "cid", "x-campaign"].includes(family)) {
    return {
      label: "campaign",
      description: "Campaign tracking parameter",
      title: "Campaign tracking parameter. Can create many cache variants.",
    };
  }
  if (family === "wpv" || family.startsWith("wpv_")) {
    return {
      label: "wpv",
      description: "WordPress Views query parameter",
      title: "WordPress Views query parameter. Often changes filtered/paginated page variants.",
    };
  }
  return {
    label: family === "other" ? "query" : (family || "query"),
    description: "Query string present",
    title: "Request includes a query string.",
  };
}

function queryFamily(query) {
  const value = String(query || "").toLowerCase();
  if (!value) return null;
  if (/(^|&)srsltid=/.test(value)) {
    return queryFamilyMeta("srsltid");
  }
  if (/(^|&)utm_[^=]+=/.test(value)) {
    return queryFamilyMeta("utm");
  }
  if (/(^|&)(gclid|fbclid|msclkid|dclid|gad_source|gbraid|wbraid|gad_campaignid)=/.test(value)) {
    return queryFamilyMeta("click-id");
  }
  if (/(^|&)(campaign|cid|x-campaign)=/.test(value)) {
    return queryFamilyMeta("campaign");
  }
  if (/(^|&)wpv_/.test(value)) {
    return queryFamilyMeta("wpv");
  }
  return queryFamilyMeta("query");
}

function shortToken(value, max = 28) {
  const text = String(value || "");
  if (!text) return "-";
  return text.length > max ? `${text.slice(0, Math.max(0, max - 3))}...` : text;
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
  if (date.getFullYear() < 2000) return "-";
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
