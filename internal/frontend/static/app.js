const qs = (selector, root = document) => root.querySelector(selector);
const qsa = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const routes = {
  overview: { title: "Overview", path: "/" },
  sites: { title: "Sites", path: "/sites" },
  logs: { title: "Logs", path: "/logs" },
  signals: { title: "Signals", path: "/signals" },
  investigate: { title: "Investigate", path: "/investigate" },
  reports: { title: "Reports", path: "/reports" },
  system: { title: "System", path: "/system" },
  settings: { title: "Settings", path: "/settings" },
};

const routeAliases = {
  dashboard: "overview",
  analysis: "signals",
  alerts: "signals",
  users: "settings",
};

const pageSize = {
  issues: 6,
  sourceIPs: 12,
  userAgents: 12,
  adminProbes: 12,
  injectionProbes: 12,
  torSources: 12,
  sites: 12,
  alerts: 12,
  reports: 5,
  jobs: 12,
  segments: 12,
  users: 12,
  signals: 25,
  logEvidence: 18,
};

const state = {
  route: routeFromPath(location.pathname),
  range: "24h",
  siteID: "",
  from: "",
  to: "",
  analysisTab: "sourceIPs",
  logType: "nginx-access",
  signalFilter: "all",
  signalKey: "",
  siteTab: "overview",
  entity: null,
  entityDetails: {},
  entityDetailLoading: {},
  viewContext: {},
  reportTab: "daily",
  selectedReportIDs: {},
  currentUser: null,
  loading: false,
  pages: {},
  data: {
    overview: {},
    analysis: {},
    traffic: {},
    sites: [],
    jobs: [],
    credentials: {},
    collectorHealth: {},
    alerts: [],
    reports: [],
    retention: {},
    notifications: {},
    webPush: {},
    segments: [],
    users: [],
  },
};

class AuthError extends Error {
  constructor() {
    super("login required");
    this.name = "AuthError";
  }
}

async function fetchJSON(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (response.status === 401) {
    throw new AuthError();
  }
  if (!response.ok) {
    const detail = await response.json().catch(() => null);
    throw new Error(detail?.error?.message || `${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function boot() {
  syncContextFromURL();
  wireEvents();
  try {
    const session = await fetchJSON("/api/v1/auth/me");
    state.currentUser = session.user || null;
    showApp();
    showRoute(state.route, false);
    await refreshAll();
  } catch (error) {
    if (error instanceof AuthError) {
      showLogin();
      return;
    }
    showApp();
    toast(error.message, true);
  }
}

function wireEvents() {
  qsa("[data-route]").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      const route = link.dataset.route || "overview";
      state.viewContext = {};
      state.entity = null;
      state.signalKey = "";
      showRoute(route, true);
    });
  });

  window.addEventListener("popstate", () => {
    syncContextFromURL();
    showRoute(state.route, false);
    render();
  });
  window.addEventListener("resize", () => renderCharts());

  qs("#rangeSelect").addEventListener("change", async (event) => {
    state.range = event.target.value;
    if (state.range === "custom") {
      seedCustomWindow();
    } else {
      state.from = "";
      state.to = "";
      syncWindowInputs();
    }
    resetPages();
    updateURL(false);
    await refreshWithValidation();
  });
  qs("#siteSelect").addEventListener("change", async (event) => {
    state.siteID = event.target.value;
    resetPages();
    updateURL(false);
    await refreshWithValidation();
  });
  qs("#fromInput").addEventListener("change", (event) => {
    state.from = event.target.value;
    state.range = "custom";
    qs("#rangeSelect").value = "custom";
    syncWindowInputs();
  });
  qs("#toInput").addEventListener("change", (event) => {
    state.to = event.target.value;
    state.range = "custom";
    qs("#rangeSelect").value = "custom";
    syncWindowInputs();
  });
  qs("#applyWindowButton").addEventListener("click", async () => {
    resetPages();
    updateURL(false);
    await refreshWithValidation();
  });

  qs("#refreshButton").addEventListener("click", () => refreshWithValidation());
  qsa("[data-analysis-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      state.analysisTab = button.dataset.analysisTab || "sourceIPs";
      renderAnalysisTabs();
    });
  });
  qsa("[data-report-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      state.reportTab = button.dataset.reportTab || "daily";
      state.pages.reports = 0;
      renderReports();
      requestAnimationFrame(drawReportCharts);
    });
  });
  qsa("[data-site-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      state.siteTab = button.dataset.siteTab || "overview";
      renderSites();
      requestAnimationFrame(() => renderCharts());
    });
  });
  qsa("[data-log-type]").forEach((button) => {
    button.addEventListener("click", () => {
      state.logType = button.dataset.logType || "nginx-access";
      state.pages.logEvidence = 0;
      updateURL(false);
      renderLogs();
      requestAnimationFrame(() => renderCharts());
    });
  });
  qsa("[data-signal-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.signalFilter = button.dataset.signalFilter || "all";
      state.signalKey = "";
      state.pages.signals = 0;
      updateURL(false);
      renderSignals();
    });
  });
  qs("#collectButton").addEventListener("click", () => runAction(qs("#collectButton"), "Collect queued", async () => {
    await fetchJSON("/api/v1/system/collect", { method: "POST" });
  }));
  qs("#pipelineButton").addEventListener("click", () => runAction(qs("#pipelineButton"), "Pipeline complete", async () => {
    await fetchJSON("/api/v1/system/pipeline", { method: "POST", body: "{}" });
  }));
  qs("#evaluateAlertsButton").addEventListener("click", () => runAction(qs("#evaluateAlertsButton"), "Alert evaluation complete", async () => {
    await fetchJSON("/api/v1/alerts/evaluate", {
      method: "POST",
      body: JSON.stringify({ range: state.range, limit: 200 }),
    });
  }));
  qs("#refreshIntelButton").addEventListener("click", () => runAction(qs("#refreshIntelButton"), "IP intel refreshed", async () => {
    await fetchJSON("/api/v1/system/refresh-ip-intel", {
      method: "POST",
      body: JSON.stringify({ range: state.range, limit: 50 }),
    });
  }));
  qs("#refreshIntelButtonInvestigate").addEventListener("click", () => runAction(qs("#refreshIntelButtonInvestigate"), "IP intel refreshed", async () => {
    await fetchJSON("/api/v1/system/refresh-ip-intel", {
      method: "POST",
      body: JSON.stringify({ range: state.range, limit: 50 }),
    });
  }));
  qs("#retentionButton").addEventListener("click", () => runAction(qs("#retentionButton"), "Retention dry run complete", async () => {
    state.data.retention = await fetchJSON("/api/v1/system/retention");
    renderSystem();
  }, false));
  qs("#sendNotificationsButton").addEventListener("click", () => runAction(qs("#sendNotificationsButton"), "Notification run complete", async () => {
    await fetchJSON("/api/v1/notifications/send", { method: "POST", body: "{}" });
  }));
  qs("#testNotificationsButton").addEventListener("click", () => runAction(qs("#testNotificationsButton"), "Notification test complete", async () => {
    await fetchJSON("/api/v1/notifications/test", { method: "POST", body: "{}" });
  }));
  qs("#enableBrowserPushButton").addEventListener("click", () => runAction(qs("#enableBrowserPushButton"), "Browser push enabled", enableBrowserPush));
  qs("#disableBrowserPushButton").addEventListener("click", () => runAction(qs("#disableBrowserPushButton"), "Browser push disabled", disableBrowserPush));
  qs("#detailCloseButton").addEventListener("click", hideDetail);
  qs("#logoutButton").addEventListener("click", logout);
  qs("#loginForm").addEventListener("submit", login);
  qs("#userForm").addEventListener("submit", createUser);

  document.addEventListener("click", async (event) => {
    const routeButton = event.target.closest("[data-route-target]");
    if (routeButton) {
      state.viewContext = {};
      state.entity = null;
      state.signalKey = "";
      showRoute(routeButton.dataset.routeTarget || "overview", true);
      return;
    }

    const contextActionButton = event.target.closest("[data-context-action]");
    if (contextActionButton) {
      await handleWorkspaceContextAction(contextActionButton.dataset.contextAction || "");
      return;
    }

    const siteActionButton = event.target.closest("[data-site-action]");
    if (siteActionButton) {
      await handleSiteAction(siteActionButton.dataset.siteAction || "focus");
      return;
    }

    const pivotButton = event.target.closest("[data-pivot]");
    if (pivotButton) {
      await handlePivot(decodePivot(pivotButton.dataset.pivot || "{}"));
      return;
    }

    const manualIntelButton = event.target.closest("[data-ip-intel-action]");
    if (manualIntelButton) {
      await handleManualIntelAction(manualIntelButton);
      return;
    }

    const pageButton = event.target.closest("[data-page-key]");
    if (pageButton) {
      const key = pageButton.dataset.pageKey;
      const delta = Number(pageButton.dataset.pageDelta || 0);
      state.pages[key] = Math.max(0, (state.pages[key] || 0) + delta);
      render();
      return;
    }

    const deleteButton = event.target.closest("[data-user-delete]");
    if (deleteButton) {
      const id = deleteButton.dataset.userDelete;
      await runAction(deleteButton, "User deactivated", async () => {
        await fetchJSON(`/api/v1/users/${encodeURIComponent(id)}`, { method: "DELETE" });
      });
    }

    const reportButton = event.target.closest("[data-report-range]");
    if (reportButton) {
      const range = reportButton.dataset.reportRange;
      await runAction(reportButton, "Report generated", async () => {
        const report = await fetchJSON("/api/v1/reports/generate", {
          method: "POST",
          body: JSON.stringify({ range, site_id: state.siteID }),
        });
        state.data.reports = [report, ...(state.data.reports || [])];
        state.reportTab = reportTabForReport(report);
        state.selectedReportIDs[state.reportTab] = reportKey(report);
        state.pages.reports = 0;
        renderReports();
        requestAnimationFrame(drawReportCharts);
      }, false);
    }

    const reportSelectButton = event.target.closest("[data-report-select]");
    if (reportSelectButton) {
      state.selectedReportIDs[state.reportTab] = reportSelectButton.dataset.reportSelect || "";
      renderReports();
      requestAnimationFrame(drawReportCharts);
      return;
    }

    const reportIPButton = event.target.closest("[data-report-ip]");
    if (reportIPButton) {
      await showReportSourceIPDetail(reportIPButton.dataset.reportIp || "");
      return;
    }

    const reportDetailButton = event.target.closest("[data-report-detail-key]");
    if (reportDetailButton) {
      showReportDrilldownDetail(reportDetailButton.dataset.reportDetailKey || "", Number(reportDetailButton.dataset.reportDetailIndex || 0));
      return;
    }

    const detailButton = event.target.closest("[data-detail-kind]");
    if (detailButton) {
      await showDetail(detailButton.dataset.detailKind, Number(detailButton.dataset.detailIndex || 0));
    }
  });
}

async function refreshAll() {
  if (state.loading) return;
  state.loading = true;
  setBusy(true);
  try {
    const filterQuery = buildFilterQuery();
    const analysisQuery = buildFilterQuery({ limit: 100 });
    const trafficQuery = buildFilterQuery({ limit: 50 });
    const [
      overview,
      analysis,
      traffic,
      sites,
      jobs,
      credentials,
      collectorHealth,
      alerts,
      reports,
      retention,
      notifications,
      webPush,
      segments,
      users,
    ] = await Promise.all([
      fetchJSON(`/api/v1/dashboard/overview?${filterQuery}`),
      fetchJSON(`/api/v1/analysis/access-log?${analysisQuery}`),
      fetchJSON(`/api/v1/investigate/traffic?${trafficQuery}`),
      fetchJSON("/api/v1/sites"),
      fetchJSON("/api/v1/system/jobs"),
      fetchJSON("/api/v1/system/credentials"),
      fetchJSON("/api/v1/system/collector-health"),
      fetchJSON("/api/v1/alerts?limit=100"),
      fetchJSON(`/api/v1/reports/recent?${buildReportsQuery()}`),
      fetchJSON("/api/v1/system/retention"),
      fetchJSON("/api/v1/notifications?limit=25"),
      fetchJSON("/api/v1/notifications/web-push/public-key"),
      fetchJSON("/api/v1/system/segments?limit=100"),
      fetchJSON("/api/v1/users"),
    ]);

    state.data = {
      overview,
      analysis,
      traffic,
      sites: sites.sites || [],
      jobs: jobs.jobs || [],
      credentials,
      collectorHealth,
      alerts: alerts.alerts || [],
      reports: reports.reports || [],
      retention,
      notifications,
      webPush,
      segments: segments.segments || [],
      users: users.users || [],
    };
    render();
  } catch (error) {
    if (error instanceof AuthError) {
      showLogin();
      return;
    }
    toast(error.message, true);
  } finally {
    state.loading = false;
    setBusy(false);
  }
}

async function refreshWithValidation() {
  if (state.range === "custom") {
    seedCustomWindow();
    const validation = validateCustomWindow();
    if (validation) {
      toast(validation, true);
      return;
    }
  }
  await refreshAll();
}

function render() {
  renderUserBadge();
  renderFilters();
  renderWorkspaceContext();
  renderDashboard();
  renderLogs();
  renderSignals();
  renderInvestigate();
  renderSites();
  renderAlerts();
  renderReports();
  renderSystem();
  renderNotifications();
  renderUsers();
  renderCharts();
}

function renderFilters() {
  const sites = state.data.sites || [];
  const siteSelect = qs("#siteSelect");
  const knownSites = new Set(sites.map((site) => site.id));
  const options = [
    `<option value="">All sites</option>`,
    ...sites.map((site) => `<option value="${escapeHTML(site.id)}">${escapeHTML(site.name || site.id)}</option>`),
  ];
  if (state.siteID && !knownSites.has(state.siteID)) {
    options.push(`<option value="${escapeHTML(state.siteID)}">${escapeHTML(state.siteID)}</option>`);
  }
  siteSelect.innerHTML = options.join("");
  siteSelect.value = state.siteID;
  qs("#rangeSelect").value = state.range;
  syncWindowInputs();
  setText("#activeFilterSummary", activeFilterLabel());
}

function renderWorkspaceContext() {
  const bar = qs("#workspaceContextBar");
  if (!bar) return;
  const route = normalizeRoute(state.route);
  const activeContext = workspaceContextPairs(route);
  const hasDrilldownContext = workspaceHasDrilldownContext();
  setText("#workspaceContextTitle", `${routes[route].title} workspace`);
  setText("#workspaceContextSubtitle", workspaceContextSubtitle(route));
  qs("#workspaceContextChips").innerHTML = activeContext.map(contextChip).join("");
  qs("#workspaceContextActions").innerHTML = workspaceContextActions(route, hasDrilldownContext);
  bar.classList.toggle("has-drilldown", hasDrilldownContext);
}

function workspaceContextSubtitle(route = state.route) {
  const parts = [activeFilterLabel()];
  if (route === "logs") parts.push(formatLogType(state.logType));
  if (route === "signals" && state.signalFilter !== "all") parts.push(`${formatCategory(state.signalFilter)} signals`);
  if (state.signalKey) parts.push("signal detail");
  if (state.entity?.kind && state.entity.value) parts.push(`${formatCategory(state.entity.kind)} detail`);
  const context = state.viewContext || {};
  if (context.status_class === "errors") parts.push("errors only");
  return parts.filter(Boolean).join(" / ");
}

function workspaceContextPairs(route = state.route) {
  const pairs = [
    ["Route", routes[route]?.title || "Overview"],
    ["Scope", activeFilterLabel()],
  ];
  if (route === "logs") pairs.push(["Log type", formatLogType(state.logType)]);
  if (route === "signals") pairs.push(["Signal tab", formatCategory(state.signalFilter || "all")]);
  if (route === "reports") pairs.push(["Report tab", formatCategory(state.reportTab || "daily")]);
  if (state.signalKey) pairs.push(["Signal", shortLabel(state.signalKey, 42)]);
  if (state.entity?.kind && state.entity.value) pairs.push([formatCategory(state.entity.kind), state.entity.value]);
  const context = state.viewContext || {};
  if (context.ip && !(state.entity?.kind === "ip" && state.entity.value === context.ip)) pairs.push(["IP", context.ip]);
  if (context.path && !(state.entity?.kind === "path" && state.entity.value === context.path)) pairs.push(["Path", context.path]);
  if (context.known_actor && !(state.entity?.kind === "actor" && state.entity.value === context.known_actor)) pairs.push(["Actor", context.known_actor]);
  if (context.actor_type) pairs.push(["Actor type", formatCategory(context.actor_type)]);
  if (context.status_class === "errors") pairs.push(["Status", "Errors only"]);
  if (context.user_agent) pairs.push(["User agent", context.user_agent]);
  return pairs;
}

function contextChip([label, value]) {
  return `<span class="context-chip"><b>${escapeHTML(label)}</b>${escapeHTML(value || "-")}</span>`;
}

function workspaceHasDrilldownContext() {
  const context = state.viewContext || {};
  return Boolean(
    state.siteID
    || state.signalKey
    || state.entity?.value
    || Object.values(context).some(Boolean)
    || state.logType !== "nginx-access"
    || state.signalFilter !== "all"
  );
}

function workspaceContextActions(route = state.route, hasDrilldownContext = workspaceHasDrilldownContext()) {
  const actions = [];
  if (route !== "logs") {
    actions.push(`<button class="ghost mini" type="button" data-pivot='${encodePivot(currentLogPivot("workspace"))}'>Open logs</button>`);
  }
  if (route !== "signals") {
    actions.push(`<button class="ghost mini" type="button" data-context-action="open-signals">Signals</button>`);
  }
  if (route !== "reports") {
    actions.push(`<button class="ghost mini" type="button" data-pivot='${encodePivot(currentReportPivot("workspace"))}'>Reports</button>`);
  }
  actions.push(`<button class="ghost mini" type="button" data-context-action="copy-link">Copy link</button>`);
  if (hasDrilldownContext) {
    actions.push(`<button class="ghost mini" type="button" data-context-action="clear">Clear context</button>`);
  }
  return actions.join("");
}

function currentLogPivot(origin = state.route) {
  const pivot = {
    kind: "log_filter",
    log_type: state.logType || "nginx-access",
    origin,
    ...state.viewContext,
  };
  if (state.siteID || state.viewContext.site_id) pivot.site_id = state.viewContext.site_id || state.siteID;
  return pivot;
}

function currentReportPivot(origin = state.route) {
  return {
    kind: "report",
    report_tab: state.reportTab || "daily",
    site_id: state.viewContext.site_id || state.siteID || "",
    origin,
  };
}

async function handleWorkspaceContextAction(action) {
  if (action === "open-signals") {
    state.entity = null;
    state.signalKey = "";
    showRoute("signals", true);
    renderSignals();
    renderWorkspaceContext();
    return;
  }
  if (action === "clear") {
    state.siteID = "";
    state.viewContext = {};
    state.entity = null;
    state.signalKey = "";
    state.signalFilter = "all";
    state.logType = "nginx-access";
    resetContextPages();
    updateURL(false);
    await refreshWithValidation();
    return;
  }
  if (action === "copy-link") {
    updateURL(false);
    try {
      await navigator.clipboard.writeText(location.href);
      toast("Workspace link copied");
    } catch {
      toast("Copy failed; use the address bar link instead.", true);
    }
  }
}

function buildFilterQuery(extra = {}) {
  const params = new URLSearchParams();
  params.set("range", state.range || "24h");
  if (state.siteID) params.set("site_id", state.siteID);
  const from = localInputToISO(state.from);
  const to = localInputToISO(state.to);
  if (state.range === "custom" && from) params.set("from", from);
  if (state.range === "custom" && to) params.set("to", to);
  Object.entries(extra).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") params.set(key, value);
  });
  return params.toString();
}

function buildReportsQuery() {
  const params = new URLSearchParams();
  params.set("limit", "100");
  if (state.siteID) params.set("site_id", state.siteID);
  return params.toString();
}

function syncContextFromURL() {
  const params = new URLSearchParams(location.search);
  state.route = routeFromPath(location.pathname);
  state.range = params.get("range") || state.range || "24h";
  state.siteID = params.has("site_id") ? params.get("site_id") || "" : state.siteID || "";
  const pathParts = location.pathname.replace(/^\/+/, "").split("/");
  if (state.route === "sites" && pathParts[1]) {
    state.siteID = decodeURIComponent(pathParts[1]);
  }
  state.entity = null;
  state.signalKey = "";
  if (state.route === "investigate" && pathParts[1]) {
    const kind = pathParts[1];
    const value = pathParts[2] ? decodeURIComponent(pathParts.slice(2).join("/")) : params.get(kind === "path" ? "path" : "value") || "";
    if (value) state.entity = { kind, value };
  }
  if (state.route === "signals" && pathParts[1]) {
    state.signalKey = decodeURIComponent(pathParts.slice(1).join("/"));
  }
  state.from = params.get("from") ? dateToLocalInput(new Date(params.get("from"))) : "";
  state.to = params.get("to") ? dateToLocalInput(new Date(params.get("to"))) : "";
  if (state.range !== "custom") {
    state.from = "";
    state.to = "";
  }
  state.logType = params.get("log_type") || state.logType || "nginx-access";
  state.signalFilter = params.get("signal_filter") || state.signalFilter || "all";
  state.viewContext = {};
  ["ip", "path", "known_actor", "actor_type", "status_class", "site_id", "user_agent"].forEach((key) => {
    const value = params.get(key);
    if (value) state.viewContext[key] = value;
  });
  if (state.entity?.kind === "ip") state.viewContext.ip = state.entity.value;
  if (state.entity?.kind === "path") state.viewContext.path = state.entity.value;
  if (state.entity?.kind === "actor") state.viewContext.known_actor = state.entity.value;
  if (state.entity?.kind === "user-agent") state.viewContext.user_agent = state.entity.value;
}

function updateURL(push) {
  const route = normalizeRoute(state.route);
  const query = viewQuery().toString();
  const url = `${routePath(route)}${query ? `?${query}` : ""}`;
  const method = push ? "pushState" : "replaceState";
  history[method]({}, "", url);
}

function routePath(route) {
  if (route === "sites" && state.siteID) {
    return `/sites/${encodeURIComponent(state.siteID)}`;
  }
  if (route === "investigate" && state.entity?.kind && state.entity?.value) {
    if (state.entity.kind === "path") return "/investigate/path";
    return `/investigate/${encodeURIComponent(state.entity.kind)}/${encodeURIComponent(state.entity.value)}`;
  }
  if (route === "signals" && state.signalKey) {
    return `/signals/${encodeURIComponent(state.signalKey)}`;
  }
  return routes[route].path;
}

function viewQuery(extra = {}) {
  const params = new URLSearchParams();
  if (state.range && state.range !== "24h") params.set("range", state.range);
  const from = localInputToISO(state.from);
  const to = localInputToISO(state.to);
  if (state.range === "custom" && from) params.set("from", from);
  if (state.range === "custom" && to) params.set("to", to);
  if (state.route === "sites") return params;
  if (state.route === "investigate" && state.entity?.kind === "path" && state.entity.value) params.set("path", state.entity.value);
  if (state.siteID) params.set("site_id", state.siteID);
  if (state.route === "logs" && state.logType && state.logType !== "nginx-access") params.set("log_type", state.logType);
  if (state.route === "signals" && state.signalFilter && state.signalFilter !== "all") params.set("signal_filter", state.signalFilter);
  Object.entries({ ...state.viewContext, ...extra }).forEach(([key, value]) => {
    if (state.route === "investigate" && state.entity?.kind === "ip" && key === "ip") return;
    if (state.route === "investigate" && state.entity?.kind === "actor" && key === "known_actor") return;
    if (state.route === "investigate" && state.entity?.kind === "user-agent" && key === "user_agent") return;
    if (value !== undefined && value !== null && value !== "") params.set(key, value);
  });
  return params;
}

function seedCustomWindow() {
  if (state.from && state.to) return;
  const currentUntil = state.to ? new Date(state.to) : new Date();
  const currentSince = state.from ? new Date(state.from) : new Date(currentUntil.getTime() - 24 * 60 * 60 * 1000);
  state.from = dateToLocalInput(currentSince);
  state.to = dateToLocalInput(currentUntil);
  syncWindowInputs();
}

function syncWindowInputs() {
  const custom = state.range === "custom";
  const fromInput = qs("#fromInput");
  const toInput = qs("#toInput");
  fromInput.disabled = !custom;
  toInput.disabled = !custom;
  fromInput.value = state.from;
  toInput.value = state.to;
}

function validateCustomWindow() {
  if (!state.from || !state.to) return "Custom windows need both from and to.";
  const from = new Date(state.from);
  const to = new Date(state.to);
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) return "Custom window dates are invalid.";
  if (to <= from) return "Custom window end must be after start.";
  return "";
}

function activeFilterLabel() {
  const site = (state.data.sites || []).find((item) => item.id === state.siteID);
  const siteLabel = site ? site.name || site.id : state.siteID || "All sites";
  if (state.range === "custom" && state.from && state.to) {
    return `${siteLabel} / ${shortDateTime(state.from)} to ${shortDateTime(state.to)}`;
  }
  return `${siteLabel} / ${state.range || "24h"}`;
}

function renderDashboard() {
  const analysis = state.data.analysis || {};
  const totals = analysis.totals || {};
  const traffic = state.data.traffic || {};
  const signals = buildSignalItems();
  const critical = signals.filter((item) => item.severity === "critical").length;
  const high = signals.filter((item) => item.severity === "high").length;
  const medium = signals.filter((item) => item.severity === "medium").length;
  const overall = critical ? "Critical" : high ? "Elevated" : medium ? "Watch" : "Normal";
  const topSignal = signals[0];
  const latestEvent = latestObservedTime();
  const securityPressure = (analysis.admin_probes || []).reduce((sum, item) => sum + Number(item.requests || 0), 0)
    + (analysis.injection_probes || []).reduce((sum, item) => sum + Number(item.requests || 0), 0)
    + (analysis.tor_sources || []).reduce((sum, item) => sum + Number(item.requests || 0), 0);

  setText("#situationState", overall);
  setText("#situationScope", activeFilterLabel());
  setText("#situationFreshness", latestEvent ? shortDateTime(latestEvent) : "-");
  setText("#situationFreshnessMeta", latestEvent ? "latest indexed event" : "no indexed events in scope");
  setText("#situationSignals", `${critical}/${high}/${medium}`);
  setText("#situationSignalsMeta", `${formatNumber(signals.length)} ranked signals`);
  setText("#situationTraffic", formatNumber(totals.requests || 0));
  setText("#situationTrafficMeta", `${formatNumber(totals.unique_ips || 0)} IPs / ${formatNumber(totals.unique_user_agents || 0)} user agents`);
  setText("#situationReliability", `${formatPercent(totals.status_5xx_rate || 0)} 5xx`);
  setText("#situationReliabilityMeta", `${formatPercent(totals.slow_requests_rate || 0)} slow / ${formatPercent(totals.status_4xx_rate || 0)} 4xx`);
  setText("#situationSecurity", formatNumber(securityPressure));
  setText("#situationSecurityMeta", topSignal ? topSignal.title : "no active security signal");
  setText("#timelineRange", analysis.range || state.range);
  setText("#statusTotal", formatNumber(totals.requests || 0));
  setText("#agentClassCount", `${aggregateAgentClasses(analysis.user_agents || []).length} classes`);

  renderPrioritySignals(signals);
  renderSiteRiskOverview(aggregateSiteRows());
  renderRecentErrors(traffic.recent_errors || []);
}

function renderPrioritySignals(items) {
  const container = qs("#prioritySignalsList");
  if (!container) return;
  const groups = prioritySignalGroups(items);
  container.innerHTML = groups.map(prioritySignalGroup).join("") || `<div class="empty">No active signals in this scope.</div>`;
}

function prioritySignalGroups(signals = []) {
  const groupDefs = [
    { key: "critical", label: "Critical now", match: (item) => item.severity === "critical" },
    { key: "security", label: "Security probes", match: (item) => item.group === "security" && item.severity !== "critical" },
    { key: "reliability", label: "Reliability", match: (item) => item.group === "reliability" && item.severity !== "critical" },
    { key: "traffic", label: "Traffic shape", match: (item) => item.group === "traffic" && item.severity !== "critical" },
    { key: "pipeline", label: "Data pipeline", match: (item) => item.group === "pipeline" && item.severity !== "critical" },
  ];
  return groupDefs.map((group) => {
    const rows = signals.filter(group.match);
    const top = rows[0] || null;
    return { ...group, rows, top };
  }).filter((group) => group.rows.length || group.key === "critical" || group.key === "security" || group.key === "reliability");
}

function prioritySignalGroup(group) {
  const shown = group.rows.slice(0, 3);
  const topRisk = group.top ? group.top.risk || severityRank(group.top.severity) * 20 || 0 : 0;
  return `
    <section class="priority-signal-group ${group.rows.length ? "" : "muted"}">
      <div class="priority-signal-head">
        <div>
          <h3>${escapeHTML(group.label)}</h3>
          <span>${group.rows.length ? escapeHTML(prioritySignalGroupSummary(group.rows)) : "No active signals"}</span>
        </div>
        <div class="signal-numbers">
          <span>${formatNumber(group.rows.length)} signals</span>
          <b>${formatNumber(topRisk)}</b>
        </div>
      </div>
      <div class="priority-signal-list">
        ${shown.map(prioritySignalRow).join("") || `<div class="empty">No ${escapeHTML(group.label.toLowerCase())} in this scope.</div>`}
      </div>
    </section>
  `;
}

function prioritySignalGroupSummary(rows) {
  const requests = rows.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  const errors = rows.reduce((sum, item) => sum + Number(item.errors || 0), 0);
  const sites = new Set(rows.map((item) => item.siteID).filter(Boolean));
  const parts = [
    requests ? `${formatNumber(requests)} requests` : "",
    errors ? `${formatNumber(errors)} errors` : "",
    sites.size ? `${formatNumber(sites.size)} sites` : "all selected sites",
  ];
  return parts.filter(Boolean).join(" / ");
}

function prioritySignalRow(item) {
  const entity = item.ip || item.path || item.actor || item.siteID || "";
  return `
    <div class="priority-signal-row">
      <span class="severity severity-${escapeHTML(item.severity || "low")}">${escapeHTML(item.severity || "low")}</span>
      <div>
        <strong>${escapeHTML(item.title || "Signal")}</strong>
        <span>${escapeHTML([entity, item.lastSeen ? formatTime(item.lastSeen) : ""].filter(Boolean).join(" / ") || item.summary || "No extra context")}</span>
        <div class="signal-actions">${signalActionButtons(item, "overview", "mini")}</div>
      </div>
      <div class="signal-score">
        <span>risk</span>
        <b>${escapeHTML(item.risk || severityRank(item.severity) * 20 || 0)}</b>
      </div>
    </div>
  `;
}

function renderSiteRiskOverview(sites) {
  const topContainer = qs("#topProblemSite");
  const listContainer = qs("#siteRiskList");
  if (!topContainer || !listContainer) return;
  if (!sites.length) {
    topContainer.innerHTML = `<div class="empty">No site telemetry is available in this scope.</div>`;
    listContainer.innerHTML = "";
    return;
  }

  const top = sites[0];
  const topIP = siteTopSourceIPs(top.id)[0];
  const topPath = siteTopPaths(top.id)[0];
  const reason = siteRiskReason(top, topIP, topPath);
  topContainer.innerHTML = `
    <div class="problem-site-main">
      <div>
        <span class="severity severity-${escapeHTML(top.severity || "low")}">${escapeHTML(top.status || "healthy")}</span>
        <h3>${escapeHTML(top.name || top.id)}</h3>
        <p>${escapeHTML(reason)}</p>
      </div>
      <div class="problem-site-actions">
        <button class="primary small" type="button" data-pivot='${encodePivot({ kind: "site", value: top.id, origin: "overview" })}'>Open site</button>
        <button class="ghost small" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: top.id, status_class: top.status5xx || top.status4xx ? "errors" : "", origin: "overview" })}'>Open logs</button>
        <button class="ghost small" type="button" data-pivot='${encodePivot({ kind: "report", report_tab: "daily", site_id: top.id, origin: "overview" })}'>Reports</button>
      </div>
    </div>
    <div class="field-grid problem-site-facts">
      ${[
        ["Requests", formatNumber(top.requests || 0)],
        ["5xx", `${formatPercent(top.status5xxRate || 0)} / ${formatNumber(top.status5xx || 0)}`],
        ["4xx", `${formatPercent(top.status4xxRate || 0)} / ${formatNumber(top.status4xx || 0)}`],
        ["Signals", `${formatNumber(top.signalCount || 0)} total / ${formatNumber(top.securitySignals || 0)} security`],
        ["Top IP", topIP?.ip || "-"],
        ["Top path", topPath?.path || "-"],
      ].map(statTile).join("")}
    </div>
  `;
  listContainer.innerHTML = sites.slice(0, 10).map(siteRiskRow).join("");
}

function siteRiskReason(site, topIP, topPath) {
  const parts = [];
  if (site.status5xxRate >= 0.01 || site.status5xx) parts.push(`${formatPercent(site.status5xxRate || 0)} 5xx`);
  if (site.securitySignals) parts.push(`${formatNumber(site.securitySignals)} security signals`);
  if (site.signalCount && !site.securitySignals) parts.push(`${formatNumber(site.signalCount)} active signals`);
  if (topPath?.path) parts.push(`top path ${topPath.path}`);
  if (topIP?.ip) parts.push(`top IP ${topIP.ip}`);
  return parts.length ? parts.join(" / ") : "Lowest-risk site in the current filtered scope.";
}

function siteRiskRow(site) {
  const topIP = siteTopSourceIPs(site.id)[0];
  const topPath = siteTopPaths(site.id)[0];
  const meta = [
    `${formatNumber(site.requests || 0)} requests`,
    `${formatPercent(site.status5xxRate || 0)} 5xx`,
    `${formatNumber(site.signalCount || 0)} signals`,
    topPath?.path ? `path ${topPath.path}` : "",
    topIP?.ip ? `IP ${topIP.ip}` : "",
  ].filter(Boolean).join(" - ");
  return `
    <div class="signal-row site-risk-row">
      <div>
        <strong>${escapeHTML(site.name || site.id)}</strong>
        <span>${escapeHTML(meta)}</span>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: site.id, origin: "overview" })}'>Open site</button>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: site.id, status_class: site.status5xx || site.status4xx ? "errors" : "", origin: "overview" })}'>Logs</button>
        ${topPath?.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: topPath.path, site_id: site.id, origin: "overview" })}'>Top path</button>` : ""}
      </div>
      <div class="signal-numbers">
        <span>${escapeHTML(site.status || "healthy")}</span>
        <b>${formatNumber(site.statusRank || 0)}</b>
      </div>
    </div>
  `;
}

function buildSignalItems() {
  const analysis = state.data.analysis || {};
  const traffic = state.data.traffic || {};
  const out = [];

  (analysis.issues || []).forEach((item, index) => {
    out.push({
      key: `issue:${index}:${item.rule_key || item.title || ""}`,
      group: issueGroup(item),
      severity: item.severity || severityForScore(item.score || 0),
      title: item.title || item.rule_key || "Detected issue",
      summary: item.summary || "",
      siteID: item.site_id || "",
      actor: item.actor_value || item.actor_type || "",
      requests: Number(item.requests || item.events || 0),
      errors: 0,
      risk: Number(item.score || 0),
      lastSeen: item.last_seen || item.last_seen_at || "",
      sourceKind: "issue",
      sourceIndex: index,
      details: item.evidence || item.details || null,
    });
  });

  (analysis.injection_probes || []).forEach((item, index) => {
    const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    out.push({
      key: `injection:${index}:${item.ip || ""}:${item.path || ""}`,
      group: "security",
      severity: severityForScore(item.risk_score || 70),
      title: `${formatCategory(item.category || "Injection probe")} against ${item.path || "/"}`,
      summary: `${formatCategory(item.match_reason || "probe")} from ${item.ip || "unknown IP"}`,
      siteID: item.site_id || "",
      env: item.env || "",
      ip: item.ip || "",
      path: item.path || "",
      requests: Number(item.requests || 0),
      errors,
      risk: Number(item.risk_score || 0),
      lastSeen: item.last_seen || "",
      sourceKind: "injectionProbe",
      sourceIndex: index,
      details: item.evidence || null,
    });
  });

  (analysis.admin_probes || []).forEach((item, index) => {
    const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    out.push({
      key: `admin:${index}:${item.ip || ""}:${item.path || ""}`,
      group: "security",
      severity: severityForScore(item.risk_score || 65),
      title: `${formatCategory(item.category || "Admin probe")} on ${item.path || "/"}`,
      summary: `${formatNumber(item.total_ip_hits || item.requests || 0)} total IP hits from ${item.ip || "unknown IP"}`,
      siteID: item.site_id || "",
      env: item.env || "",
      ip: item.ip || "",
      path: item.path || "",
      requests: Number(item.requests || 0),
      errors,
      risk: Number(item.risk_score || 0),
      lastSeen: item.last_seen || "",
      sourceKind: "adminProbe",
      sourceIndex: index,
      details: item.evidence || null,
    });
  });

  (analysis.tor_sources || []).forEach((item, index) => {
    const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    out.push({
      key: `tor:${index}:${item.ip || ""}`,
      group: "security",
      severity: item.admin_requests ? "high" : "medium",
      title: `Tor exit traffic from ${item.ip || "unknown IP"}`,
      summary: `${formatNumber(item.admin_requests || 0)} admin requests / ${formatNumber(errors)} errors`,
      siteID: item.site_id || "",
      env: item.env || "",
      ip: item.ip || "",
      requests: Number(item.requests || 0),
      errors,
      risk: Number(item.risk_score || 80),
      lastSeen: item.last_seen || "",
      sourceKind: "torSource",
      sourceIndex: index,
    });
  });

  (analysis.slow_paths || []).forEach((item, index) => {
    out.push({
      key: `slow:${index}:${item.site_id || ""}:${item.path || ""}`,
      group: "reliability",
      severity: Number(item.p95_request_time_ms || 0) >= 5000 ? "high" : "medium",
      title: `Slow path p95 on ${item.path || "/"}`,
      summary: `${formatMs(item.p95_request_time_ms || 0)} p95 / avg ${formatMs(item.avg_request_time_ms || 0)}`,
      siteID: item.site_id || "",
      path: item.path || "",
      requests: Number(item.requests || 0),
      errors: Number(item.status_4xx || 0) + Number(item.status_5xx || 0),
      risk: Math.min(90, Math.round(Number(item.p95_request_time_ms || 0) / 100)),
      lastSeen: item.last_seen || "",
      sourceKind: "slowPath",
      sourceIndex: index,
    });
  });

  (traffic.recent_errors || []).slice(0, 20).forEach((item, index) => {
    out.push({
      key: `recent-error:${index}:${item.client_ip || ""}:${item.path || ""}:${item.ts || ""}`,
      group: "reliability",
      severity: Number(item.status || 0) >= 500 ? "high" : "medium",
      title: `${item.status || "-"} on ${item.path || "/"}`,
      summary: `${item.method || "GET"} from ${item.client_ip || "unknown IP"}`,
      siteID: item.site_id || "",
      ip: item.client_ip || "",
      path: item.path || "",
      requests: 1,
      errors: 1,
      risk: Number(item.status || 0) >= 500 ? 70 : 45,
      lastSeen: item.ts || "",
      sourceKind: "recentError",
      sourceIndex: index,
    });
  });

  (state.data.jobs || []).filter((job) => job.status === "failed").slice(0, 8).forEach((job, index) => {
    out.push({
      key: `job:${index}:${job.id || job.type || ""}`,
      group: "pipeline",
      severity: "high",
      title: `Pipeline job failed: ${job.type || "job"}`,
      summary: job.message || job.last_error || "Background job needs attention",
      requests: 0,
      errors: 0,
      risk: 75,
      lastSeen: job.started_at || job.updated_at || job.created_at || "",
      sourceKind: "job",
      sourceIndex: index,
    });
  });

  return out.sort((a, b) => {
    const severityDelta = severityRank(b.severity) - severityRank(a.severity);
    if (severityDelta) return severityDelta;
    if ((b.risk || 0) !== (a.risk || 0)) return (b.risk || 0) - (a.risk || 0);
    return new Date(b.lastSeen || 0) - new Date(a.lastSeen || 0);
  });
}

function signalRow(item) {
  const actions = signalActionButtons(item, state.route, "mini");
  const meta = [
    formatCategory(item.group || "signal"),
    item.siteID ? `${item.siteID}${item.env ? `/${item.env}` : ""}` : "",
    item.ip || item.actor || "",
    item.requests ? `${formatNumber(item.requests)} requests` : "",
    item.errors ? `${formatNumber(item.errors)} errors` : "",
    item.lastSeen ? formatTime(item.lastSeen) : "",
  ].filter(Boolean).join(" - ");
  return `
    <div class="signal-card">
      <div class="signal-card-main">
        <span class="severity severity-${escapeHTML(item.severity || "low")}">${escapeHTML(item.severity || "low")}</span>
        <div>
          <strong>${escapeHTML(item.title || "Signal")}</strong>
          <span>${escapeHTML(item.summary || meta || "No extra context")}</span>
          <small>${escapeHTML(meta)}</small>
          <div class="signal-actions">${actions}</div>
        </div>
      </div>
      <div class="signal-score">
        <span>risk</span>
        <b>${escapeHTML(item.risk || severityRank(item.severity) * 20 || 0)}</b>
      </div>
    </div>
  `;
}

function signalActionButtons(item, origin = state.route, size = "mini") {
  const klass = `ghost ${size} inline-action`;
  const actions = [
    `<button class="${klass}" type="button" data-pivot='${encodePivot({ kind: "signal", key: item.key, origin })}'>Open signal</button>`,
    item.ip ? `<button class="${klass}" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: item.siteID, origin })}'>Open IP</button>` : "",
    item.path ? `<button class="${klass}" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path, site_id: item.siteID, origin })}'>Open path</button>` : "",
    item.sourceKind === "job"
      ? `<button class="${klass}" type="button" data-route-target="system">System</button>`
      : `<button class="${klass}" type="button" data-pivot='${encodePivot(signalLogPivot(item, origin))}'>Open logs</button>`,
    `<button class="${klass}" type="button" data-pivot='${encodePivot(signalReportContextPivot(item, origin))}'>Reports</button>`,
  ];
  return actions.filter(Boolean).join("");
}

function signalReportContextPivot(item, origin = state.route) {
  const pivot = {
    kind: "report",
    report_tab: "daily",
    site_id: item.siteID || state.siteID || state.viewContext.site_id || "",
    origin,
  };
  if (state.range && state.range !== "24h") pivot.range = state.range;
  if (state.range === "custom") {
    const from = localInputToISO(state.from);
    const to = localInputToISO(state.to);
    if (from) pivot.from = from;
    if (to) pivot.to = to;
  }
  return pivot;
}

function latestObservedTime() {
  const candidates = [
    ...(state.data.traffic?.recent_errors || []).map((item) => item.ts),
    ...(state.data.analysis?.source_ips || []).map((item) => item.last_seen),
    ...(state.data.analysis?.admin_probes || []).map((item) => item.last_seen),
    ...(state.data.analysis?.injection_probes || []).map((item) => item.last_seen),
    ...(state.data.analysis?.slow_paths || []).map((item) => item.last_seen),
  ].filter(Boolean).map((value) => new Date(value)).filter((date) => !Number.isNaN(date.getTime()));
  if (!candidates.length) return "";
  return new Date(Math.max(...candidates.map((date) => date.getTime()))).toISOString();
}

function issueGroup(item) {
  const key = String(item.rule_key || item.title || "").toLowerCase();
  if (key.includes("probe") || key.includes("crawler") || key.includes("tor") || key.includes("user_agent")) return "security";
  if (key.includes("slow") || key.includes("5xx") || key.includes("error")) return "reliability";
  return "traffic";
}

function severityForScore(score) {
  const value = Number(score || 0);
  if (value >= 90) return "critical";
  if (value >= 70) return "high";
  if (value >= 40) return "medium";
  return "low";
}

function severityRank(severity) {
  return { low: 1, medium: 2, high: 3, critical: 4 }[severity] || 0;
}

function renderAnalysis() {
  renderAnalysisTabs();
  renderSourceIPs();
  renderUserAgents();
  renderAdminProbes();
  renderInjectionProbes();
  renderTorSources();
  renderTopPaths(state.data.traffic?.top_paths || []);
  renderSlowPaths(state.data.analysis?.slow_paths || []);
}

function renderLogs() {
  qsa("[data-log-type]").forEach((button) => {
    const active = button.dataset.logType === state.logType;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  const supported = state.logType === "nginx-access";
  setText("#logsTitle", supported ? "Access logs" : `${formatLogType(state.logType)} logs`);
  qs("#logsContext").innerHTML = logContextChips().join("");
  setText("#logsEvidenceEyebrow", "Evidence");
  setText("#logsEvidenceTitle", "Recent matching rows");

  if (!supported) {
    renderUnsupportedLogExplorer();
    return;
  }

  const analysis = state.data.analysis || {};
  const totals = analysis.totals || {};
  const evidence = filteredLogEvidence();
  const topPaths = filteredTopPaths();
  const timeline = logTimelineRows(evidence);
  const pageItems = paginate("logEvidence", evidence);

  qs("#logsFieldStats").innerHTML = accessLogStats(totals, evidence, topPaths).map(statTile).join("");
  setText("#logsTimelineSummary", `${formatNumber(timeline.length)} buckets`);
  renderPager("#logsPager", "logEvidence", evidence);
  setText("#logsEvidenceCount", `${formatNumber(pageItems.length)} of ${formatNumber(evidence.length)} rows`);
  qs("#logsEvidenceTable").innerHTML = pageItems.map(logEvidenceTableRow).join("") || emptyRow(7, "No matching access-log evidence in this scope.");
  qs("#logsFacetsList").innerHTML = logFacetSections(evidence, topPaths).join("");
  setText("#logsFacetSummary", `${formatNumber(logFacetCount(evidence, topPaths))} values`);
  setText("#logsTopPathCount", `${formatNumber(topPaths.length)} paths`);
  qs("#logsTopPathsList").innerHTML = topPaths.slice(0, 12).map(topPathLogRow).join("") || `<div class="empty">No paths match this scope.</div>`;
}

function renderUnsupportedLogExplorer() {
  const segments = unsupportedLogSegments();
  const segmentTimeline = logSegmentTimelineRows(segments);
  const indexed = segments.filter((item) => item.indexed || item.status === "indexed").length;
  const pending = Math.max(0, segments.length - indexed);
  const lines = segments.reduce((sum, item) => sum + Number(item.line_count || 0), 0);
  const latest = segments[0];
  const correlatedEvidence = filteredLogEvidence();
  const correlatedPaths = filteredTopPaths();
  const pageItems = paginate("logEvidence", segments);
  qs("#logsFieldStats").innerHTML = [
    ["Log type", formatLogType(state.logType)],
    ["Explorer mode", "Segment evidence"],
    ["Combined segments", formatNumber(segments.length)],
    ["Indexed segments", formatNumber(indexed)],
    ["Pending parser", formatNumber(pending)],
    ["Lines combined", formatNumber(lines)],
    ["Latest segment", formatTime(latest?.bucket_start || latest?.min_ts)],
    ["Correlated access rows", formatNumber(correlatedEvidence.length)],
  ].map(statTile).join("");
  setText("#logsTimelineSummary", segmentTimeline.length ? `${formatNumber(segmentTimeline.length)} segment buckets` : "no segments");
  setText("#logsEvidenceEyebrow", "Segment evidence");
  setText("#logsEvidenceTitle", `${formatLogType(state.logType)} combined segments`);
  renderPager("#logsPager", "logEvidence", segments);
  setText("#logsEvidenceCount", segments.length ? `${formatNumber(pageItems.length)} of ${formatNumber(segments.length)} segments` : "no segments");
  qs("#logsEvidenceTable").innerHTML = pageItems.map(logSegmentTableRow).join("") || emptyRow(7, `${formatLogType(state.logType)} has no combined segments in the recent segment window.`);
  qs("#logsFacetsList").innerHTML = `
    <section class="facet-section">
      <h3>Ingestion state</h3>
      <div class="facet-row">
        <span>Combined segments</span>
        <strong>${formatNumber(segments.length)}</strong>
      </div>
      <div class="facet-row">
        <span>Indexed</span>
        <strong>${formatNumber(indexed)}</strong>
      </div>
      <div class="facet-row">
        <span>Parser pending</span>
        <strong>${formatNumber(pending)}</strong>
      </div>
      <div class="facet-row">
        <span>Lines combined</span>
        <strong>${formatNumber(lines)}</strong>
      </div>
    </section>
    <section class="facet-section">
      <h3>Expected fields</h3>
      ${unsupportedLogFieldFacets(state.logType)}
    </section>
    <section class="facet-section">
      <h3>Access correlation</h3>
      ${unsupportedLogCorrelationFacet(correlatedEvidence)}
    </section>
    <section class="facet-section">
      <h3>Current context</h3>
      ${logContextFacetRows()}
    </section>
  `;
  setText("#logsFacetSummary", `${formatNumber(segments.length)} segments`);
  setText("#logsTopPathCount", correlatedPaths.length ? `${formatNumber(correlatedPaths.length)} correlated paths` : "no correlated paths");
  qs("#logsTopPathsList").innerHTML = correlatedPaths.slice(0, 12).map(correlatedPathRow).join("") || `<div class="empty">No access-log path context matches this ${escapeHTML(formatLogType(state.logType))} scope yet.</div>`;
}

function unsupportedLogSegments(logType = state.logType) {
  return (state.data.segments || [])
    .filter((item) => item.log_type === logType)
    .sort((a, b) => new Date(b.bucket_start || b.min_ts || 0) - new Date(a.bucket_start || a.min_ts || 0));
}

function logSegmentTimelineRows(segments = unsupportedLogSegments()) {
  const buckets = new Map();
  segments.forEach((segment) => {
    const key = segment.bucket_start || segment.min_ts || segment.bucket_end;
    if (!key) return;
    const date = new Date(key);
    if (Number.isNaN(date.getTime())) return;
    const bucket = date.toISOString();
    const existing = buckets.get(bucket) || { bucket_ts: bucket, requests: 0, secondary: 0, status_4xx: 0, status_5xx: 0 };
    existing.requests += Number(segment.line_count || 0);
    if (!(segment.indexed || segment.status === "indexed")) {
      existing.secondary += 1;
    }
    buckets.set(bucket, existing);
  });
  return Array.from(buckets.values()).sort((a, b) => new Date(a.bucket_ts) - new Date(b.bucket_ts));
}

function unsupportedLogCorrelationFacet(evidence) {
  const pivot = {
    kind: "log_filter",
    log_type: "nginx-access",
    origin: "logs",
    ...state.viewContext,
  };
  if (state.siteID || state.viewContext.site_id) pivot.site_id = state.viewContext.site_id || state.siteID;
  return `
    <div class="facet-row">
      <div>
        <span>Matching access rows</span>
        <small>${escapeHTML(logContextLabel())}</small>
        <div class="signal-actions">
          <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(pivot)}'>Open access rows</button>
        </div>
      </div>
      <strong>${formatNumber(evidence.length)}</strong>
    </div>
  `;
}

function logSegmentTableRow(segment) {
  const status = segment.indexed || segment.status === "indexed" ? "indexed" : segment.status || "combined";
  const start = segment.min_ts || segment.bucket_start;
  const end = segment.max_ts || segment.bucket_end;
  const accessPivot = {
    kind: "log_filter",
    log_type: "nginx-access",
    origin: "logs",
    ...state.viewContext,
  };
  if (state.siteID || state.viewContext.site_id) accessPivot.site_id = state.viewContext.site_id || state.siteID;
  return `
    <tr>
      <td><strong>${formatTime(segment.bucket_start || start)}</strong><br><span>${formatTime(segment.bucket_end || end)}</span></td>
      <td><span class="status-${escapeHTML(status)}">${escapeHTML(status)}</span><br><span>${escapeHTML(formatLogType(segment.log_type))}</span></td>
      <td>${escapeHTML(state.siteID || state.viewContext.site_id || "all sites")}<br><span>combined scope</span></td>
      <td><strong>${formatNumber(segment.line_count || 0)} lines</strong><br><span>${escapeHTML(shortHash(segment.sha256 || segment.id || ""))}</span></td>
      <td class="clip">${escapeHTML(segment.path || "-")}</td>
      <td>${escapeHTML([start ? `min ${formatTime(start)}` : "", end ? `max ${formatTime(end)}` : ""].filter(Boolean).join(" / ") || "parser pending")}</td>
      <td class="row-actions">
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(accessPivot)}'>Access rows</button>
        <button class="ghost mini inline-action" type="button" data-route-target="system">System</button>
      </td>
    </tr>
  `;
}

function shortHash(value) {
  value = String(value || "");
  if (!value) return "-";
  if (value.length <= 12) return value;
  return `${value.slice(0, 12)}...`;
}

function unsupportedLogFieldFacets(logType) {
  const fields = {
    "nginx-error": ["severity", "message fingerprint", "site/env/container", "correlated path", "request id"],
    "php-error": ["severity", "message fingerprint", "file/function", "site/env/container", "correlated path"],
    "php-slow": ["script", "duration", "stack fingerprint", "site/env/container", "correlated path"],
    "mysql-slow": ["query fingerprint", "duration", "rows examined", "site/env/container"],
  }[logType] || ["severity", "message", "site/env", "timestamp"];
  return fields.map((field) => `
    <div class="facet-row">
      <span>${escapeHTML(field)}</span>
      <strong>planned</strong>
    </div>
  `).join("");
}

function logContextFacetRows() {
  return logContextPairs().map(([label, value]) => `
    <div class="facet-row">
      <span>${escapeHTML(label)}</span>
      <strong>${escapeHTML(value)}</strong>
    </div>
  `).join("") || `<div class="empty">No context filters are active.</div>`;
}

function accessLogStats(totals, evidence, topPaths) {
  const topIP = countFacet(evidence, (item) => item.ip, (item) => item.requests)[0];
  const topKind = countFacet(evidence, (item) => item.kind, (item) => item.requests)[0];
  const topPath = topPaths[0];
  const errors = evidence.reduce((sum, item) => sum + Number(item.errors || 0), 0);
  return [
    ["Log type", "Access"],
    ["Requests", formatNumber(totals.requests || 0)],
    ["Sites", formatNumber((state.data.analysis?.sites || []).length)],
    ["Source IPs", formatNumber(totals.unique_ips || 0)],
    ["User agents", formatNumber(totals.unique_user_agents || 0)],
    ["4xx / 5xx", `${formatPercent(totals.status_4xx_rate || 0)} / ${formatPercent(totals.status_5xx_rate || 0)}`],
    ["Evidence errors", formatNumber(errors)],
    ["Top evidence", topKind?.label || "-"],
    ["Noisy IP", topIP?.label || "-"],
    ["Top path", topPath?.path || "-"],
  ];
}

function logContextChips() {
  return logContextPairs().map(contextChip);
}

function logContextPairs() {
  const context = state.viewContext || {};
  const pairs = [
    ["Scope", activeFilterLabel()],
    ["Log type", formatLogType(state.logType)],
  ];
  if (context.ip) pairs.push(["IP", context.ip]);
  if (context.path) pairs.push(["Path", context.path]);
  if (context.known_actor) pairs.push(["Actor", context.known_actor]);
  if (context.actor_type) pairs.push(["Actor type", formatCategory(context.actor_type)]);
  if (context.status_class === "errors") pairs.push(["Status", "Errors only"]);
  if (context.user_agent) pairs.push(["User agent", context.user_agent]);
  return pairs;
}

function logTimelineRows(evidence = filteredLogEvidence(), allowCorrelated = false) {
  if (state.logType !== "nginx-access" && !allowCorrelated) return [];
  const context = state.viewContext || {};
  const contextKeys = Object.keys(context).filter((key) => context[key] && !(key === "site_id" && state.siteID === context[key]));
  if (!contextKeys.length) return state.data.traffic?.timeline || [];
  const bucketMs = logTimelineBucketMs();
  const buckets = new Map();
  evidence.forEach((item) => {
    const date = new Date(item.ts || item.last_seen || 0);
    if (Number.isNaN(date.getTime())) return;
    const bucket = new Date(Math.floor(date.getTime() / bucketMs) * bucketMs).toISOString();
    const existing = buckets.get(bucket) || { bucket_ts: bucket, requests: 0, status_4xx: 0, status_5xx: 0 };
    existing.requests += Number(item.requests || 1);
    const errors = Number(item.errors || 0);
    if (Number(item.status || 0) >= 500) existing.status_5xx += Math.max(1, errors);
    else existing.status_4xx += errors;
    buckets.set(bucket, existing);
  });
  return Array.from(buckets.values()).sort((a, b) => new Date(a.bucket_ts) - new Date(b.bucket_ts));
}

function logTimelineBucketMs() {
  if (state.range === "1h") return 5 * 60 * 1000;
  if (state.range === "6h") return 15 * 60 * 1000;
  if (state.range === "24h") return 60 * 60 * 1000;
  if (state.range === "7d") return 6 * 60 * 60 * 1000;
  return 24 * 60 * 60 * 1000;
}

function logFacetSections(evidence, topPaths) {
  return [
    facetSectionMarkup("Source IPs", countFacet(evidence, (item) => item.ip, (item) => item.requests).slice(0, 6), "ip"),
    facetSectionMarkup("Paths", topPaths.slice(0, 6).map((item) => ({
      label: item.path || "/",
      value: Number(item.requests || 0),
      errors: Number(item.status_4xx || 0) + Number(item.status_5xx || 0),
      site_id: item.site_id || "",
    })), "path"),
    facetSectionMarkup("Sites", countFacet(evidence, (item) => item.site_id, (item) => item.requests).slice(0, 6), "site"),
    facetSectionMarkup("Evidence types", countFacet(evidence, (item) => item.kind, (item) => item.requests).slice(0, 6), "kind"),
    facetSectionMarkup("Status", statusFacets(evidence), "status"),
  ];
}

function logFacetCount(evidence, topPaths) {
  return countFacet(evidence, (item) => item.ip).length
    + topPaths.length
    + countFacet(evidence, (item) => item.site_id).length
    + countFacet(evidence, (item) => item.kind).length
    + statusFacets(evidence).length;
}

function countFacet(rows, keyFn, valueFn = (item) => item.requests) {
  const map = new Map();
  rows.forEach((item) => {
    const label = String(keyFn(item) || "").trim();
    if (!label) return;
    const existing = map.get(label) || { label, value: 0, errors: 0, site_id: item.site_id || "" };
    existing.value += Number(valueFn(item) || 0) || 1;
    existing.errors += Number(item.errors || 0) + Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    if (!existing.site_id && item.site_id) existing.site_id = item.site_id;
    map.set(label, existing);
  });
  return Array.from(map.values()).sort((a, b) => b.value - a.value);
}

function statusFacets(evidence) {
  const errors = evidence.reduce((sum, item) => sum + Number(item.errors || 0), 0);
  const requests = evidence.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  return [
    { label: "Errors only", value: errors, errors },
    { label: "Non-error evidence", value: Math.max(0, requests - errors), errors: 0 },
  ].filter((item) => item.value > 0);
}

function facetSectionMarkup(title, items, type) {
  return `
    <section class="facet-section">
      <h3>${escapeHTML(title)}</h3>
      ${items.map((item) => facetRowMarkup(item, type)).join("") || `<div class="empty">No ${escapeHTML(title.toLowerCase())} in this scope.</div>`}
    </section>
  `;
}

function facetRowMarkup(item, type) {
  const siteID = item.site_id || state.viewContext.site_id || state.siteID || "";
  const label = item.label || "-";
  const refine = {
    ip: { kind: "log_filter", ip: label, site_id: siteID, origin: "logs" },
    path: { kind: "log_filter", path: label, site_id: siteID, status_class: item.errors ? "errors" : "", origin: "logs" },
    site: { kind: "log_filter", site_id: label, origin: "logs" },
    status: label === "Errors only" ? { kind: "log_filter", site_id: siteID, status_class: "errors", origin: "logs" } : null,
  }[type];
  const secondary = [
    type === "ip" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: label, site_id: siteID, origin: "logs" })}'>Open IP</button>` : "",
    type === "path" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: label, site_id: siteID, origin: "logs" })}'>Open path</button>` : "",
    type === "site" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: label, origin: "logs" })}'>Open site</button>` : "",
  ].filter(Boolean).join("");
  return `
    <div class="facet-row">
      <div>
        <span>${escapeHTML(label)}</span>
        ${item.errors ? `<small>${formatNumber(item.errors)} errors</small>` : ""}
        <div class="signal-actions">
          ${type === "path"
            ? correlatedLogActions({ path: label, siteID, statusClass: item.errors ? "errors" : "", origin: "logs" })
            : refine ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(refine)}'>Refine</button>` : ""}
          ${secondary}
        </div>
      </div>
      <strong>${formatNumber(item.value || 0)}</strong>
    </div>
  `;
}

function topPathLogRow(item) {
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  const siteID = item.site_id || state.viewContext.site_id || state.siteID || "";
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.path || "/")}</strong>
        <span>${escapeHTML(item.site_id || "all sites")} - ${formatStatusBuckets(item)}</span>
        <div class="signal-actions">
          <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path || "/", site_id: siteID, origin: "logs" })}'>Open path</button>
          ${correlatedLogActions({ path: item.path || "/", siteID, statusClass: errors ? "errors" : "", origin: "logs" })}
        </div>
      </div>
      <div class="signal-numbers">
        <span>${formatBytes(item.bytes_sent || 0)}</span>
        <b>${formatNumber(item.requests || 0)}</b>
      </div>
    </div>
  `;
}

function correlatedPathRow(item) {
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  const siteID = item.site_id || state.viewContext.site_id || state.siteID || "";
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.path || "/")}</strong>
        <span>${escapeHTML([siteID || "all sites", `${formatNumber(item.requests || 0)} access requests`, errors ? `${formatNumber(errors)} errors` : ""].filter(Boolean).join(" - "))}</span>
        <div class="signal-actions">
          <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path || "/", site_id: siteID, origin: "logs" })}'>Open path</button>
          ${correlatedLogActions({ path: item.path || "/", siteID, statusClass: errors ? "errors" : "", origin: "logs" })}
        </div>
      </div>
      <div class="signal-numbers"><span>correlated</span><b>${formatNumber(item.requests || 0)}</b></div>
    </div>
  `;
}

function correlatedLogActions({ path = "", siteID = "", ip = "", statusClass = "", origin = "correlation", includeAccess = true } = {}) {
  const types = [
    includeAccess ? ["nginx-access", "Access rows"] : null,
    ["nginx-error", "Nginx errors"],
    ["php-error", "PHP errors"],
    ["php-slow", "PHP slow"],
  ].filter(Boolean);
  return types.map(([logType, label]) => {
    const pivot = {
      kind: "log_filter",
      path,
      ip,
      site_id: siteID,
      status_class: statusClass,
      log_type: logType,
      origin,
    };
    return `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(pivot)}'>${escapeHTML(label)}</button>`;
  }).join("");
}

function correlatedLogPanel(options = {}) {
  return `
    <div class="correlated-log-panel">
      <p>${escapeHTML("Open the same site, path, IP, and time window across access and error-oriented log types.")}</p>
      <div class="signal-actions">
        ${correlatedLogActions(options)}
      </div>
    </div>
  `;
}

function formatLogType(type) {
  return {
    "nginx-access": "Access",
    "nginx-error": "Nginx error",
    "php-error": "PHP error",
    "php-slow": "PHP slow",
    "mysql-slow": "MySQL slow",
  }[type] || formatCategory(type || "log");
}

function logContextLabel() {
  const context = state.viewContext || {};
  const parts = [activeFilterLabel()];
  if (context.ip) parts.push(`IP ${context.ip}`);
  if (context.path) parts.push(context.path);
  if (context.known_actor) parts.push(context.known_actor);
  if (context.actor_type) parts.push(formatCategory(context.actor_type));
  if (context.status_class === "errors") parts.push("Errors only");
  return parts.join(" / ");
}

function filteredLogEvidence() {
  const traffic = state.data.traffic || {};
  const analysis = state.data.analysis || {};
  const rows = [];
  (traffic.recent_errors || []).forEach((item) => {
    rows.push({
      kind: "Recent error",
      ts: item.ts,
      site_id: item.site_id || "",
      env: item.env || "",
      ip: item.client_ip || "",
      method: item.method || "GET",
      path: item.path || "/",
      query: item.query || "",
      status: item.status || "",
      requests: 1,
      errors: Number(item.status || 0) >= 400 ? 1 : 0,
      user_agent: item.user_agent || "",
    });
  });
  (analysis.admin_probes || []).forEach((item) => rows.push(analysisEvidenceRow("Admin probe", item)));
  (analysis.injection_probes || []).forEach((item) => rows.push(analysisEvidenceRow("Injection probe", item)));
  (analysis.tor_sources || []).forEach((item) => rows.push({
    kind: "Tor source",
    ts: item.last_seen,
    site_id: item.site_id || "",
    env: item.env || "",
    ip: item.ip || "",
    path: "/",
    status: "",
    requests: Number(item.requests || 0),
    errors: Number(item.status_4xx || 0) + Number(item.status_5xx || 0),
    known_actor: item.known_actor || "Tor exit",
    actor_type: item.actor_type || "tor",
  }));
  (analysis.slow_paths || []).forEach((item) => rows.push({
    kind: "Slow path",
    ts: item.last_seen,
    site_id: item.site_id || "",
    env: item.env || "",
    path: item.path || "/",
    status: "",
    requests: Number(item.requests || 0),
    errors: Number(item.status_4xx || 0) + Number(item.status_5xx || 0),
    p95_request_time_ms: item.p95_request_time_ms || 0,
  }));
  return rows
    .filter(logMatchesContext)
    .sort((a, b) => new Date(b.ts || 0) - new Date(a.ts || 0));
}

function analysisEvidenceRow(kind, item) {
  return {
    kind,
    ts: item.last_seen,
    site_id: item.site_id || "",
    env: item.env || "",
    ip: item.ip || "",
    method: item.method || "GET",
    path: item.path || "/",
    query: item.sample_query || item.query || "",
    status: item.status || "",
    requests: Number(item.requests || 0),
    errors: Number(item.status_4xx || 0) + Number(item.status_5xx || 0),
    category: item.category || "",
    match_reason: item.match_reason || "",
    risk_score: item.risk_score || 0,
  };
}

function filteredTopPaths() {
  const rows = [
    ...(state.data.traffic?.top_paths || []),
    ...(state.data.analysis?.slow_paths || []).map((item) => ({
      ...item,
      status_4xx: item.status_4xx || 0,
      status_5xx: item.status_5xx || 0,
    })),
  ];
  const seen = new Map();
  rows.forEach((item) => {
    if (!logMatchesContext({ ...item, errors: Number(item.status_4xx || 0) + Number(item.status_5xx || 0) })) return;
    const key = `${item.site_id || ""}|${item.path || "/"}`;
    const existing = seen.get(key) || { site_id: item.site_id || "", path: item.path || "/", requests: 0, bytes_sent: 0, status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0 };
    existing.requests += Number(item.requests || 0);
    existing.bytes_sent += Number(item.bytes_sent || 0);
    existing.status_2xx += Number(item.status_2xx || 0);
    existing.status_3xx += Number(item.status_3xx || 0);
    existing.status_4xx += Number(item.status_4xx || 0);
    existing.status_5xx += Number(item.status_5xx || 0);
    seen.set(key, existing);
  });
  return Array.from(seen.values()).sort((a, b) => b.requests - a.requests);
}

function logMatchesContext(item) {
  const context = state.viewContext || {};
  if (context.site_id && item.site_id !== context.site_id) return false;
  if (context.ip && item.ip !== context.ip) return false;
  if (context.path && !pathMatches(item.path, context.path)) return false;
  if (context.status_class === "errors") {
    const status = Number(item.status || 0);
    const errors = Number(item.errors || 0) + Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    if (status < 400 && errors <= 0) return false;
  }
  if (context.known_actor || context.actor_type) {
    const ips = contextActorIPs(context);
    if (item.ip && ips.size && !ips.has(item.ip)) return false;
    if (!item.ip && ips.size) return false;
  }
  if (context.user_agent && !String(item.user_agent || "").includes(context.user_agent)) return false;
  return true;
}

function pathMatches(value, expected) {
  const path = String(value || "");
  const target = String(expected || "");
  if (!target) return true;
  return path === target || path.startsWith(target) || target.startsWith(path);
}

function logEvidenceRow(item) {
  const title = [item.kind, item.method, item.path || "/"].filter(Boolean).join(" ");
  const meta = [
    item.ip,
    item.site_id ? `${item.site_id}${item.env ? `/${item.env}` : ""}` : "",
    item.query ? `?${item.query}` : "",
    item.category ? formatCategory(item.category) : "",
    item.match_reason ? formatCategory(item.match_reason) : "",
    item.p95_request_time_ms ? `p95 ${formatMs(item.p95_request_time_ms)}` : "",
    formatTime(item.ts),
  ].filter(Boolean).join(" - ");
  const actions = [
    item.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: item.site_id, origin: "logs" })}'>Open IP</button>` : "",
    item.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path, site_id: item.site_id, origin: "logs" })}'>Open path</button>` : "",
    item.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", path: item.path, ip: item.ip, site_id: item.site_id, status_class: item.errors ? "errors" : "", origin: "logs" })}'>Refine</button>` : "",
  ].filter(Boolean).join("");
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(title)}</strong>
        <span>${escapeHTML(meta)}</span>
        ${actions}
      </div>
      <div class="signal-numbers">
        ${item.status ? `<span>${escapeHTML(item.status)}</span>` : item.errors ? `<span>${formatNumber(item.errors)} errors</span>` : ""}
        <b>${formatNumber(item.requests || 0)}</b>
      </div>
    </div>
  `;
}

function logEvidenceTableRow(item) {
  const site = item.site_id ? `${item.site_id}${item.env ? ` / ${item.env}` : ""}` : "-";
  const source = [
    item.ip || "",
    item.user_agent ? shortLabel(item.user_agent, 58) : "",
  ].filter(Boolean).join(" / ") || "-";
  const signal = logSignalMeta(item);
  const siteID = item.site_id || state.viewContext.site_id || state.siteID || "";
  const errors = Number(item.errors || 0);
  const actions = [
    item.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: siteID, origin: "logs" })}'>Open IP</button>` : "",
    item.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path, site_id: siteID, origin: "logs" })}'>Open path</button>` : "",
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", path: item.path || "", ip: item.ip || "", site_id: siteID, status_class: errors ? "errors" : "", origin: "logs" })}'>Refine</button>`,
  ].filter(Boolean).join("");
  return `
    <tr>
      <td>${formatTime(item.ts)}</td>
      <td><strong>${escapeHTML(item.kind || "Evidence")}</strong><br><span>${escapeHTML(logEvidenceStatus(item))}</span></td>
      <td>${escapeHTML(site)}</td>
      <td>${escapeHTML(source)}</td>
      <td><strong>${escapeHTML(formatURLTarget(item))}</strong></td>
      <td>${escapeHTML(signal)}</td>
      <td class="row-actions">${actions}</td>
    </tr>
  `;
}

function logEvidenceStatus(item) {
  if (item.status) return String(item.status);
  if (item.errors) return `${formatNumber(item.errors)} errors`;
  if (item.p95_request_time_ms) return `p95 ${formatMs(item.p95_request_time_ms)}`;
  return `${formatNumber(item.requests || 0)} requests`;
}

function logSignalMeta(item) {
  return [
    item.known_actor || "",
    item.actor_type ? formatCategory(item.actor_type) : "",
    item.category ? formatCategory(item.category) : "",
    item.match_reason ? formatCategory(item.match_reason) : "",
    item.risk_score ? `risk ${item.risk_score}` : "",
  ].filter(Boolean).join(" / ") || "-";
}

function statTile([label, value]) {
  return `
    <article class="stat-tile">
      <span>${escapeHTML(label)}</span>
      <strong>${escapeHTML(value)}</strong>
    </article>
  `;
}

function renderSignals() {
  qsa("[data-signal-filter]").forEach((button) => {
    const active = button.dataset.signalFilter === state.signalFilter;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  const allSignals = buildSignalItems();
  renderSignalDetail(allSignals);
  const signals = state.signalFilter === "all" ? allSignals : allSignals.filter((item) => item.group === state.signalFilter);
  renderPager("#signalsPager", "signals", signals);
  const pageItems = paginate("signals", signals);
  qs("#signalsList").innerHTML = pageItems.map(signalRow).join("") || `<div class="empty">No ${escapeHTML(state.signalFilter)} signals in this scope.</div>`;
  setText("#signalsSummary", `${formatNumber(pageItems.length)} of ${formatNumber(signals.length)} shown`);
  const groups = ["security", "reliability", "traffic", "pipeline"].map((group) => {
    const count = allSignals.filter((item) => item.group === group).length;
    return [formatCategory(group), formatNumber(count)];
  });
  qs("#signalsGroupStats").innerHTML = groups.map(statTile).join("");
}

function renderSignalDetail(signals = buildSignalItems()) {
  const panel = qs("#signalDetailPanel");
  if (!panel) return;
  if (!state.signalKey) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  const signal = findSignalByKey(state.signalKey, signals);
  if (!signal) {
    setText("#signalDetailEyebrow", "Signal investigation");
    setText("#signalDetailTitle", "Signal not found");
    qs("#signalDetailActions").innerHTML = `<button class="ghost small" type="button" data-route-target="signals">Back to signals</button>`;
    qs("#signalDetailBody").innerHTML = `<div class="empty">This signal is no longer present in the current site and time window.</div>`;
    return;
  }
  setText("#signalDetailEyebrow", `${formatCategory(signal.group || "Signal")} signal`);
  setText("#signalDetailTitle", signal.title || "Signal investigation");
  qs("#signalDetailActions").innerHTML = signalDetailActions(signal);
  qs("#signalDetailBody").innerHTML = signalDetailBody(signal, signals);
}

function findSignalByKey(key, signals = buildSignalItems()) {
  const direct = (signals || []).find((item) => item.key === key);
  if (direct) return direct;
  const hint = parseReportSignalKey(key);
  if (!hint) return null;
  return findSignalByHint(hint, signals);
}

function findSignalByHint(hint, signals = buildSignalItems()) {
  return (signals || []).find((signal) => {
    if (hint.sourceKind && signal.sourceKind !== hint.sourceKind) return false;
    if (hint.siteID && signal.siteID && signal.siteID !== hint.siteID) return false;
    if (hint.ip && signal.ip !== hint.ip) return false;
    if (hint.path && !pathMatches(signal.path, hint.path)) return false;
    if (hint.title && signal.title !== hint.title) return false;
    if (hint.actor && signal.actor && signal.actor !== hint.actor) return false;
    return true;
  }) || null;
}

function parseReportSignalKey(key) {
  if (!String(key || "").startsWith("report:")) return null;
  const value = String(key).slice("report:".length);
  try {
    if (value.startsWith("%7B") || value.startsWith("{")) {
      return JSON.parse(decodeURIComponent(value));
    }
    const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    return JSON.parse(decodeURIComponent(atob(padded)));
  } catch {
    return null;
  }
}

function signalDetailActions(signal) {
  const actions = [
    signal.sourceKind === "job"
      ? `<button class="ghost small" type="button" data-route-target="system">Open system</button>`
      : `<button class="ghost small" type="button" data-pivot='${encodePivot(signalLogPivot(signal))}'>Open matching logs</button>`,
    signal.ip ? `<button class="ghost small" type="button" data-pivot='${encodePivot({ kind: "ip", value: signal.ip, site_id: signal.siteID || "", origin: "signal_detail" })}'>Open source IP</button>` : "",
    signal.path ? `<button class="ghost small" type="button" data-pivot='${encodePivot({ kind: "path", value: signal.path, site_id: signal.siteID || "", origin: "signal_detail" })}'>Open affected path</button>` : "",
    signal.siteID ? `<button class="ghost small" type="button" data-pivot='${encodePivot({ kind: "site", value: signal.siteID, origin: "signal_detail" })}'>Open site</button>` : "",
    `<button class="ghost small" type="button" data-pivot='${encodePivot(signalReportContextPivot(signal, "signal_detail"))}'>Open report context</button>`,
    `<button class="ghost small" type="button" data-route-target="signals">Ranked list</button>`,
  ];
  return actions.filter(Boolean).join("");
}

function signalDetailBody(signal, signals = buildSignalItems()) {
  const evidence = signalEvidence(signal).slice(0, 12);
  const related = relatedSignals(signal, signals).slice(0, 6);
  const paths = signalPaths(signal, evidence).slice(0, 8);
  const sites = signalSites(signal, evidence).slice(0, 8);
  const details = signal.details ? JSON.stringify(signal.details, null, 2) : "";
  return `
    <div class="field-grid signal-facts">${signalFacts(signal).map(statTile).join("")}</div>
    <section class="signal-detail-grid">
      ${entitySection("What happened", signalNarrative(signal), "")}
      ${entitySection("Matching evidence", evidence.map(logEvidenceRow).join(""), "No matching evidence rows in this scope.")}
      ${signal.path ? entitySection("Correlated logs", correlatedLogPanel({
        path: signal.path,
        siteID: signal.siteID || "",
        ip: signal.ip || "",
        statusClass: signal.errors ? "errors" : "",
        origin: "signal_detail",
      }), "") : ""}
      ${entitySection("Related entities", signalEntities(signal), "No entity pivots available.")}
      ${entitySection("Related signals", related.map(signalRow).join(""), "No related signals in this scope.")}
      ${entitySection("Affected sites", sites.map(signalSiteRow).join(""), "No site distribution available.")}
      ${entitySection("Affected paths", paths.map(signalPathRow).join(""), "No path distribution available.")}
      ${details ? entitySection("Raw signal details", `<pre class="signal-raw">${escapeHTML(details)}</pre>`, "") : ""}
    </section>
  `;
}

function signalFacts(signal) {
  return [
    ["Severity", formatCategory(signal.severity || "-")],
    ["Risk", signal.risk || severityRank(signal.severity) * 20 || "-"],
    ["Group", formatCategory(signal.group || "-")],
    ["Requests", formatNumber(signal.requests || 0)],
    ["Errors", formatNumber(signal.errors || 0)],
    ["Site", signal.siteID || "All sites"],
    ["Source IP", signal.ip || "-"],
    ["Path", signal.path || "-"],
    ["Last seen", formatTime(signal.lastSeen)],
    ["Source", formatCategory(signal.sourceKind || "signal")],
  ];
}

function signalNarrative(signal) {
  const recommendation = signalRecommendation(signal);
  return `
    <div class="signal-narrative">
      <p>${escapeHTML(signal.summary || "The signal was produced from current access-log analysis.")}</p>
      <dl class="facts compact-facts">
        <div><dt>Recommended action</dt><dd>${escapeHTML(recommendation)}</dd></div>
        <div><dt>Blast radius</dt><dd>${escapeHTML(signalBlastRadius(signal))}</dd></div>
        <div><dt>Confidence</dt><dd>${escapeHTML(signalConfidence(signal))}</dd></div>
      </dl>
    </div>
  `;
}

function signalRecommendation(signal) {
  if (signal.sourceKind === "injectionProbe") return "Review matching requests, inspect the source IP, and confirm whether the affected path needs blocking or application hardening.";
  if (signal.sourceKind === "adminProbe") return "Check source IP reputation, confirm the targeted admin path is expected, and review repeated hits across sites.";
  if (signal.sourceKind === "torSource") return "Inspect the Tor source, compare admin-path pressure, and decide whether rate limiting or temporary blocking is appropriate.";
  if (signal.sourceKind === "slowPath") return "Open matching logs, inspect status and timing, then compare this path against site reliability signals.";
  if (signal.sourceKind === "recentError") return "Open matching logs and inspect the source, path, and status trend before escalating.";
  if (signal.sourceKind === "job") return "Open system status and inspect the failed background job before trusting freshness-sensitive charts.";
  return "Open supporting logs and related entities, then decide whether this signal is expected noise or needs response.";
}

function signalBlastRadius(signal) {
  const parts = [
    signal.siteID ? `site ${signal.siteID}` : "all selected sites",
    signal.path ? `path ${signal.path}` : "",
    signal.ip ? `source ${signal.ip}` : "",
  ].filter(Boolean);
  return parts.join(" / ");
}

function signalConfidence(signal) {
  if ((signal.risk || 0) >= 80 || signal.severity === "critical") return "High";
  if ((signal.risk || 0) >= 50 || signal.severity === "high") return "Medium";
  return "Watch";
}

function signalEvidence(signal) {
  const targetKind = signalEvidenceKind(signal);
  const rows = filteredLogEvidence();
  const matched = rows.filter((row) => {
    const siteMatches = !signal.siteID || !row.site_id || row.site_id === signal.siteID;
    const ipMatches = Boolean(signal.ip && row.ip === signal.ip);
    const pathMatchesSignal = Boolean(signal.path && pathMatches(row.path, signal.path));
    const kindMatches = Boolean(targetKind && row.kind === targetKind);
    if (signal.sourceKind === "job") return false;
    if (signal.ip && signal.path) return siteMatches && (ipMatches || pathMatchesSignal || kindMatches);
    if (signal.ip) return siteMatches && (ipMatches || kindMatches);
    if (signal.path) return siteMatches && (pathMatchesSignal || kindMatches);
    return siteMatches && kindMatches;
  });
  return matched.length ? matched : rows.filter((row) => {
    if (signal.siteID && row.site_id !== signal.siteID) return false;
    if (signal.group === "reliability") return Number(row.errors || 0) > 0;
    return false;
  });
}

function signalEvidenceKind(signal) {
  return {
    injectionProbe: "Injection probe",
    adminProbe: "Admin probe",
    torSource: "Tor source",
    slowPath: "Slow path",
    recentError: "Recent error",
  }[signal.sourceKind] || "";
}

function relatedSignals(signal, signals = buildSignalItems()) {
  return (signals || []).filter((item) => {
    if (item.key === signal.key) return false;
    if (signal.ip && item.ip === signal.ip) return true;
    if (signal.path && item.path && pathMatches(item.path, signal.path)) return true;
    if (signal.siteID && item.siteID === signal.siteID && item.group === signal.group) return true;
    return false;
  });
}

function signalEntities(signal) {
  const rows = [
    signal.ip ? signalEntityRow("Source IP", signal.ip, { kind: "ip", value: signal.ip, site_id: signal.siteID || "", origin: "signal_detail" }) : "",
    signal.path ? signalEntityRow("Path", signal.path, { kind: "path", value: signal.path, site_id: signal.siteID || "", origin: "signal_detail" }) : "",
    signal.actor ? signalEntityRow("Actor", signal.actor, { kind: "actor", value: signal.actor, site_id: signal.siteID || "", origin: "signal_detail" }) : "",
    signal.siteID ? signalEntityRow("Site", signal.siteID, { kind: "site", value: signal.siteID, origin: "signal_detail" }) : "",
  ];
  return rows.filter(Boolean).join("");
}

function signalEntityRow(label, value, pivot) {
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(label)}</strong>
        <span>${escapeHTML(value || "-")}</span>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(pivot)}'>Open</button>
      </div>
      <div class="signal-numbers"><span>entity</span><b>${escapeHTML(formatCategory(pivot.kind || "-"))}</b></div>
    </div>
  `;
}

function signalPaths(signal, evidence = signalEvidence(signal)) {
  const paths = new Map();
  filteredTopPaths().forEach((item) => {
    if (signal.siteID && item.site_id && item.site_id !== signal.siteID) return;
    if (signal.path && !pathMatches(item.path, signal.path)) return;
    const key = `${item.site_id || ""}|${item.path || "/"}`;
    paths.set(key, { ...item });
  });
  evidence.forEach((item) => {
    const key = `${item.site_id || ""}|${item.path || "/"}`;
    const existing = paths.get(key) || { site_id: item.site_id || "", path: item.path || "/", requests: 0, status_4xx: 0, status_5xx: 0, bytes_sent: 0 };
    existing.requests += Number(item.requests || 0);
    existing.status_4xx += Number(item.status_4xx || 0) + (Number(item.status || 0) >= 400 && Number(item.status || 0) < 500 ? 1 : 0);
    existing.status_5xx += Number(item.status_5xx || 0) + (Number(item.status || 0) >= 500 ? 1 : 0);
    existing.bytes_sent += Number(item.bytes_sent || 0);
    paths.set(key, existing);
  });
  return Array.from(paths.values()).sort((a, b) => Number(b.requests || 0) - Number(a.requests || 0));
}

function signalSites(signal, evidence = signalEvidence(signal)) {
  const sites = new Map();
  evidence.forEach((item) => {
    const siteID = item.site_id || signal.siteID || "unknown";
    const existing = sites.get(siteID) || { site_id: siteID, env: item.env || "", requests: 0, errors: 0, last_seen: "" };
    existing.requests += Number(item.requests || 0);
    existing.errors += Number(item.errors || 0);
    if (!existing.last_seen || new Date(item.ts || 0) > new Date(existing.last_seen || 0)) existing.last_seen = item.ts || "";
    sites.set(siteID, existing);
  });
  if (!sites.size && signal.siteID) {
    sites.set(signal.siteID, { site_id: signal.siteID, env: signal.env || "", requests: signal.requests || 0, errors: signal.errors || 0, last_seen: signal.lastSeen || "" });
  }
  return Array.from(sites.values()).sort((a, b) => Number(b.requests || 0) - Number(a.requests || 0));
}

function signalSiteRow(item) {
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.site_id || "-")}</strong>
        <span>${escapeHTML([item.env, formatTime(item.last_seen)].filter(Boolean).join(" - ") || "current scope")}</span>
        <div class="signal-actions">
          ${item.site_id && item.site_id !== "unknown" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: item.site_id, origin: "signal_detail" })}'>Open site</button>` : ""}
          ${item.site_id && item.site_id !== "unknown" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: item.site_id, status_class: item.errors ? "errors" : "", origin: "signal_detail" })}'>Open logs</button>` : ""}
        </div>
      </div>
      <div class="signal-numbers"><span>${formatNumber(item.errors || 0)} errors</span><b>${formatNumber(item.requests || 0)}</b></div>
    </div>
  `;
}

function signalPathRow(item) {
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.path || "/")}</strong>
        <span>${escapeHTML(item.site_id || "all sites")} - ${formatStatusBuckets(item)}</span>
        <div class="signal-actions">
          <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path || "/", site_id: item.site_id || "", origin: "signal_detail" })}'>Open path</button>
          ${correlatedLogActions({ path: item.path || "/", siteID: item.site_id || "", statusClass: errors ? "errors" : "", origin: "signal_detail" })}
        </div>
      </div>
      <div class="signal-numbers"><span>${formatBytes(item.bytes_sent || 0)}</span><b>${formatNumber(item.requests || 0)}</b></div>
    </div>
  `;
}

function signalLogPivot(signal, origin = "signal_detail") {
  const pivot = {
    kind: "log_filter",
    site_id: signal.siteID || "",
    origin,
  };
  if (signal.ip) pivot.ip = signal.ip;
  if (signal.path) pivot.path = signal.path;
  if (signal.errors) pivot.status_class = "errors";
  if (signal.actor) pivot.known_actor = signal.actor;
  return pivot;
}

function signalContext(signal) {
  const context = {};
  if (signal.siteID) context.site_id = signal.siteID;
  if (signal.ip) context.ip = signal.ip;
  if (signal.path) context.path = signal.path;
  if (signal.errors) context.status_class = "errors";
  if (signal.actor) context.known_actor = signal.actor;
  return context;
}

function renderInvestigate() {
  renderEntityPage();
  renderSourceIPs();
  renderUserAgents();
  renderActors();
}

function renderEntityPage() {
  const panel = qs("#entityPagePanel");
  if (!panel) return;
  const entity = state.entity;
  if (!entity?.kind || !entity?.value) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  ensureEntityDetailLoaded(entity);
  setText("#entityPageEyebrow", `${formatCategory(entity.kind)} investigation`);
  setText("#entityPageTitle", entity.value);
  qs("#entityPageActions").innerHTML = entityActions(entity);
  qs("#entityPageBody").innerHTML = entityBody(entity);
}

function ensureEntityDetailLoaded(entity) {
  if (entity.kind !== "ip") return;
  const key = entityKey(entity);
  if (state.entityDetails[key] || state.entityDetailLoading[key]) return;
  state.entityDetailLoading[key] = true;
  fetchJSON(`/api/v1/investigate/ip/${encodeURIComponent(entity.value)}?${buildFilterQuery({ limit: 30, site_id: state.viewContext.site_id || state.siteID || "" })}`)
    .then((detail) => {
      state.entityDetails[key] = detail;
      renderEntityPage();
    })
    .catch((error) => {
      state.entityDetails[key] = { lookup_errors: [error.message] };
      renderEntityPage();
    })
    .finally(() => {
      state.entityDetailLoading[key] = false;
    });
}

function entityKey(entity) {
  return `${entity.kind}:${entity.value}:${state.siteID || state.viewContext.site_id || ""}:${state.range}:${state.from}:${state.to}`;
}

function entityActions(entity) {
  const siteID = state.viewContext.site_id || state.siteID || "";
  const logPivot = entityLogPivot(entity, siteID);
  const detail = state.entityDetails[entityKey(entity)] || {};
  return `
    <button class="ghost small" type="button" data-pivot='${encodePivot(logPivot)}'>Open matching logs</button>
    ${entity.kind === "ip" ? `<button class="ghost small" type="button" data-pivot='${encodePivot({ kind: "ip", value: entity.value, site_id: siteID, origin: "entity" })}'>Refresh IP lookup</button>` : ""}
    ${entity.kind === "ip" ? ipManualButtons(entity.value, detail.stored_intel || {}, siteID, "small") : ""}
    <button class="ghost small" type="button" data-route-target="investigate">All entities</button>
  `;
}

function entityLogPivot(entity, siteID = "") {
  if (entity.kind === "ip") return { kind: "log_filter", ip: entity.value, site_id: siteID, origin: "entity" };
  if (entity.kind === "path") return { kind: "log_filter", path: entity.value, site_id: siteID, origin: "entity" };
  if (entity.kind === "actor") return { kind: "log_filter", known_actor: entity.value, actor_type: state.viewContext.actor_type || "", site_id: siteID, origin: "entity" };
  if (entity.kind === "user-agent") return { kind: "log_filter", user_agent: entity.value, site_id: siteID, origin: "entity" };
  return { kind: "log_filter", site_id: siteID, origin: "entity" };
}

function ipManualButtons(ip, item = {}, siteID = "", size = "mini") {
  if (!ip) return "";
  const action = String(item.manual_action || "").toLowerCase();
  const alreadyVerified = Boolean(item.verified_source || item.verified_actor || item.forward_confirmed);
  const buttonClass = `ghost ${size} inline-action`;
  const buttons = [];
  if (action !== "verified" && !alreadyVerified) {
    buttons.push(manualActionButton(ip, "verified", "Mark verified", siteID, buttonClass));
  }
  if (action !== "suspicious") {
    buttons.push(manualActionButton(ip, "suspicious", "Mark suspicious", siteID, buttonClass));
  }
  if (action && action !== "clear") {
    buttons.push(manualActionButton(ip, "clear", "Clear label", siteID, buttonClass));
  }
  return `<span class="manual-actions">${buttons.join("")}</span>`;
}

function manualActionButton(ip, action, label, siteID, className) {
  return `<button class="${className}" type="button" data-ip-intel-ip="${escapeHTML(ip)}" data-ip-intel-action="${escapeHTML(action)}" data-ip-intel-label="${escapeHTML(manualActionDefaultLabel(action))}" data-ip-intel-site="${escapeHTML(siteID || "")}">${escapeHTML(label)}</button>`;
}

function manualActionDefaultLabel(action) {
  switch (action) {
  case "verified":
    return "Operator verified source";
  case "suspicious":
    return "Operator marked suspicious";
  case "watch":
    return "Operator watch";
  case "ignored":
    return "Operator ignored";
  default:
    return "";
  }
}

function formatManualAction(action) {
  action = String(action || "").trim();
  return action ? formatCategory(action) : "-";
}

function entityBody(entity) {
  const detail = state.entityDetails[entityKey(entity)] || {};
  const facts = entityFacts(entity, detail);
  const signals = entitySignals(entity).slice(0, 8);
  const evidence = entityEvidence(entity).slice(0, 12);
  const paths = entityPaths(entity, detail).slice(0, 10);
  const sites = entitySites(entity, detail).slice(0, 10);
  const agents = entityUserAgents(entity, detail).slice(0, 10);
  const timeline = entityTimelineRows(entity, { detail, signals, evidence, paths, sites, agents }).slice(0, 18);
  return `
    <div class="field-grid entity-facts">${facts.map(statTile).join("")}</div>
    <section class="entity-detail-grid">
      ${entitySection("Investigation timeline", entityTimeline(timeline), "No timeline events in this scope.", "entity-section-wide")}
      ${entitySection("Related signals", signals.map(signalRow).join(""), "No related signals in this scope.")}
      ${entitySection("Recent evidence", evidence.map(logEvidenceRow).join(""), "No recent evidence in this scope.")}
      ${entity.kind === "path" ? entitySection("Correlated logs", correlatedLogPanel({
        path: entity.value,
        siteID: state.siteID || state.viewContext.site_id || "",
        statusClass: state.viewContext.status_class || "",
        origin: "entity",
      }), "") : ""}
      ${entity.kind === "actor" ? entitySection("Source IP verification", actorVerificationPanel(entity), "No source IPs are tied to this actor in the current scope.") : ""}
      ${entitySection("Sites touched", sites.map(entitySiteRow).join(""), "No site distribution available.")}
      ${entitySection("Paths", paths.map(entityPathRow).join(""), "No path distribution available.")}
      ${entitySection("User agents", agents.map(entityUserAgentRow).join(""), "No user-agent distribution available.")}
      ${entity.lookup_errors?.length || detail.lookup_errors?.length ? entitySection("Lookup notes", `<div class="empty">${escapeHTML((entity.lookup_errors || detail.lookup_errors || []).join("\\n"))}</div>`, "") : ""}
    </section>
  `;
}

function entityFacts(entity, detail = {}) {
  if (entity.kind === "ip") {
    const local = (state.data.analysis?.source_ips || []).find((item) => item.ip === entity.value) || {};
    const traffic = detail.traffic || {};
    const stored = detail.stored_intel || {};
    const errors = Number(traffic.status_4xx || local.status_4xx || 0) + Number(traffic.status_5xx || local.status_5xx || 0);
    return [
      ["Requests", formatNumber(traffic.requests || local.requests || 0)],
      ["Errors", formatNumber(errors)],
      ["Error rate", formatPercent(ratio(errors, traffic.requests || local.requests || 0))],
      ["Known actor", stored.known_actor || local.known_actor || "-"],
      ["Manual action", formatManualAction(stored.manual_action || local.manual_action)],
      ["Manual label", stored.manual_label || local.manual_label || "-"],
      ["ASN", (detail.asn?.asn || stored.asn) ? `AS${detail.asn?.asn || stored.asn}` : "-"],
      ["Last seen", formatTime(traffic.last_seen || local.last_seen)],
    ];
  }
  if (entity.kind === "path") {
    const rows = entityEvidence(entity);
    const totalRequests = entityPaths(entity).reduce((sum, item) => sum + Number(item.requests || 0), 0);
    const errors = rows.reduce((sum, item) => sum + Number(item.errors || 0), 0);
    const sites = new Set(rows.map((item) => item.site_id).filter(Boolean));
    const ips = new Set(rows.map((item) => item.ip).filter(Boolean));
    return [
      ["Requests", formatNumber(totalRequests || rows.length)],
      ["Errors", formatNumber(errors)],
      ["Source IPs", formatNumber(ips.size)],
      ["Sites", formatNumber(sites.size)],
      ["Current site", state.siteID || state.viewContext.site_id || "All sites"],
      ["Window", activeFilterLabel()],
    ];
  }
  if (entity.kind === "actor") {
    const actor = aggregateActors().find((item) => item.label === entity.value) || {};
    const ips = contextActorIPs({ known_actor: entity.value, actor_type: state.viewContext.actor_type || actor.type });
    return [
      ["Type", formatCategory(actor.type || state.viewContext.actor_type || "-")],
      ["Verification", actorVerificationState(actor)],
      ["Requests", formatNumber(actor.requests || 0)],
      ["Errors", formatNumber(actor.errors || 0)],
      ["Source IPs", formatNumber(actor.ips || ips.size)],
      ["Verified IPs", formatNumber(actor.verifiedIPs || 0)],
      ["Needs review", formatNumber(actor.reviewIPs || actor.unverifiedIPs || 0)],
      ["Risk", actor.risk || "-"],
      ["Last seen", formatTime(actor.lastSeen)],
    ];
  }
  return [
    ["Value", entity.value],
    ["Window", activeFilterLabel()],
  ];
}

function entitySignals(entity) {
  return buildSignalItems().filter((item) => {
    if (entity.kind === "ip") return item.ip === entity.value;
    if (entity.kind === "path") return item.path && pathMatches(item.path, entity.value);
    if (entity.kind === "actor") return item.actor === entity.value || item.summary?.includes(entity.value) || item.title?.includes(entity.value);
    return false;
  });
}

function entityEvidence(entity) {
  const rows = filteredLogEvidence();
  if (entity.kind === "ip") return rows.filter((item) => item.ip === entity.value);
  if (entity.kind === "path") return rows.filter((item) => pathMatches(item.path, entity.value));
  if (entity.kind === "actor") {
    const ips = contextActorIPs({ known_actor: entity.value, actor_type: state.viewContext.actor_type || "" });
    return rows.filter((item) => item.known_actor === entity.value || (item.ip && ips.has(item.ip)));
  }
  if (entity.kind === "user-agent") return rows.filter((item) => String(item.user_agent || "").includes(entity.value));
  return rows;
}

function entityPaths(entity, detail = {}) {
  if (entity.kind === "ip" && detail.top_paths) return detail.top_paths;
  if (entity.kind === "path") return filteredTopPaths().filter((item) => pathMatches(item.path, entity.value));
  const paths = new Map();
  entityEvidence(entity).forEach((item) => {
    const key = item.path || "/";
    const existing = paths.get(key) || { path: key, requests: 0, status_4xx: 0, status_5xx: 0, bytes_sent: 0 };
    existing.requests += Number(item.requests || 1);
    existing.status_4xx += Number(item.status_4xx || (Number(item.status || 0) >= 400 && Number(item.status || 0) < 500 ? 1 : 0));
    existing.status_5xx += Number(item.status_5xx || (Number(item.status || 0) >= 500 ? 1 : 0));
    existing.bytes_sent += Number(item.bytes_sent || 0);
    paths.set(key, existing);
  });
  return Array.from(paths.values()).sort((a, b) => b.requests - a.requests);
}

function entitySites(entity, detail = {}) {
  if (entity.kind === "ip" && detail.sites) return detail.sites;
  const sites = new Map();
  entityEvidence(entity).forEach((item) => {
    const key = item.site_id || "unknown";
    const existing = sites.get(key) || { site_id: key, env: item.env || "", requests: 0, status_4xx: 0, status_5xx: 0, last_seen: "" };
    existing.requests += Number(item.requests || 1);
    existing.status_4xx += Number(item.status_4xx || (Number(item.status || 0) >= 400 && Number(item.status || 0) < 500 ? 1 : 0));
    existing.status_5xx += Number(item.status_5xx || (Number(item.status || 0) >= 500 ? 1 : 0));
    if (new Date(item.ts || 0) > new Date(existing.last_seen || 0)) existing.last_seen = item.ts;
    sites.set(key, existing);
  });
  return Array.from(sites.values()).sort((a, b) => b.requests - a.requests);
}

function entityUserAgents(entity, detail = {}) {
  if (entity.kind === "ip" && detail.top_user_agents) return detail.top_user_agents;
  const agents = new Map();
  entityEvidence(entity).forEach((item) => {
    const key = item.user_agent || "(empty)";
    const existing = agents.get(key) || { sample: key, requests: 0, status_4xx: 0, status_5xx: 0 };
    existing.requests += Number(item.requests || 1);
    existing.status_4xx += Number(item.status_4xx || (Number(item.status || 0) >= 400 && Number(item.status || 0) < 500 ? 1 : 0));
    existing.status_5xx += Number(item.status_5xx || (Number(item.status || 0) >= 500 ? 1 : 0));
    agents.set(key, existing);
  });
  return Array.from(agents.values()).sort((a, b) => b.requests - a.requests);
}

function entityTimelineRows(entity, context = {}) {
  const detail = context.detail || {};
  const events = [];
  const seen = new Set();
  const addEvent = (event) => {
    const time = event.time || "";
    if (!time) return;
    const parsed = new Date(time);
    if (Number.isNaN(parsed.getTime())) return;
    const key = [event.kind, parsed.toISOString(), event.title, event.meta].join("|");
    if (seen.has(key)) return;
    seen.add(key);
    events.push({ ...event, time: parsed.toISOString() });
  };

  (context.signals || entitySignals(entity)).forEach((signal) => {
    addEvent({
      kind: "Signal",
      time: signal.lastSeen,
      title: signal.title || "Signal",
      meta: [
        formatCategory(signal.group || "signal"),
        signal.siteID || "",
        signal.ip ? `IP ${signal.ip}` : "",
        signal.path || "",
        signal.requests ? `${formatNumber(signal.requests)} requests` : "",
        signal.errors ? `${formatNumber(signal.errors)} errors` : "",
      ].filter(Boolean).join(" / "),
      valueLabel: "risk",
      value: signal.risk || severityRank(signal.severity) * 20 || 0,
      actions: signalActionButtons(signal, "entity_timeline", "mini"),
    });
  });

  (context.evidence || entityEvidence(entity)).forEach((item) => {
    const errors = Number(item.errors || 0) + Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    addEvent({
      kind: item.kind || "Evidence",
      time: item.ts || item.last_seen,
      title: [item.method, item.path || "/"].filter(Boolean).join(" "),
      meta: [
        item.site_id ? `${item.site_id}${item.env ? `/${item.env}` : ""}` : "",
        item.ip ? `IP ${item.ip}` : "",
        item.status ? `status ${item.status}` : "",
        errors ? `${formatNumber(errors)} errors` : "",
        item.query ? `?${item.query}` : "",
      ].filter(Boolean).join(" / "),
      valueLabel: item.status ? "status" : "requests",
      value: item.status || formatNumber(item.requests || 1),
      actions: entityEvidenceTimelineActions(item),
    });
  });

  (detail.recent_requests || []).forEach((request) => {
    addEvent({
      kind: "Request",
      time: request.ts,
      title: formatURLTarget(request),
      meta: [
        request.site_id ? `${request.site_id}${request.env ? `/${request.env}` : ""}` : "",
        request.user_agent || "",
        request.referer ? `ref ${request.referer}` : "",
      ].filter(Boolean).join(" / "),
      valueLabel: "status",
      value: request.status || "-",
      actions: entityRequestTimelineActions(request, entity),
    });
  });

  (detail.url_hits || []).forEach((hit) => {
    const errors = Number(hit.status_4xx || 0) + Number(hit.status_5xx || 0);
    addEvent({
      kind: "URL hit",
      time: hit.last_seen || hit.first_seen,
      title: formatURLTarget(hit),
      meta: [
        hit.site_id ? `${hit.site_id}${hit.env ? `/${hit.env}` : ""}` : "",
        formatStatusBuckets(hit),
        hit.p95_request_time_ms ? `p95 ${formatMs(hit.p95_request_time_ms)}` : "",
        errors ? `${formatNumber(errors)} errors` : "",
      ].filter(Boolean).join(" / "),
      valueLabel: "requests",
      value: formatNumber(hit.requests || 0),
      actions: correlatedLogActions({
        path: hit.path || "/",
        siteID: hit.site_id || state.siteID || state.viewContext.site_id || "",
        ip: entity.kind === "ip" ? entity.value : "",
        statusClass: errors ? "errors" : "",
        origin: "entity_timeline",
      }),
    });
  });

  (context.sites || entitySites(entity, detail)).forEach((site) => {
    const errors = Number(site.status_4xx || 0) + Number(site.status_5xx || 0);
    addEvent({
      kind: "Site",
      time: site.last_seen,
      title: `${site.site_id || "unknown"}${site.env ? ` / ${site.env}` : ""}`,
      meta: [
        `${formatNumber(site.requests || 0)} requests`,
        errors ? `${formatNumber(errors)} errors` : "",
      ].filter(Boolean).join(" / "),
      valueLabel: "errors",
      value: formatNumber(errors),
      actions: [
        site.site_id ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: site.site_id, origin: "entity_timeline" })}'>Open site</button>` : "",
        site.site_id ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ ...entityLogPivot(entity, site.site_id), origin: "entity_timeline" })}'>Open logs</button>` : "",
      ].filter(Boolean).join(""),
    });
  });

  return events.sort((a, b) => new Date(b.time) - new Date(a.time));
}

function entityTimeline(events) {
  if (!events.length) return "";
  return `<div class="entity-timeline">${events.map(entityTimelineRow).join("")}</div>`;
}

function entityTimelineRow(event) {
  return `
    <div class="entity-timeline-row">
      <time>${formatTime(event.time)}</time>
      <div>
        <span>${escapeHTML(event.kind || "Event")}</span>
        <strong>${escapeHTML(event.title || "Timeline event")}</strong>
        <small>${escapeHTML(event.meta || "")}</small>
        <div class="signal-actions">${event.actions || ""}</div>
      </div>
      <div class="signal-numbers">
        <span>${escapeHTML(event.valueLabel || "")}</span>
        <b>${escapeHTML(event.value ?? "")}</b>
      </div>
    </div>
  `;
}

function entityEvidenceTimelineActions(item) {
  const siteID = item.site_id || state.siteID || state.viewContext.site_id || "";
  const statusClass = Number(item.errors || 0) || Number(item.status || 0) >= 400 ? "errors" : "";
  return [
    item.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: siteID, origin: "entity_timeline" })}'>Open IP</button>` : "",
    item.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path, site_id: siteID, origin: "entity_timeline" })}'>Open path</button>` : "",
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", path: item.path || "", ip: item.ip || "", site_id: siteID, status_class: statusClass, origin: "entity_timeline" })}'>Open logs</button>`,
  ].filter(Boolean).join("");
}

function entityRequestTimelineActions(request, entity) {
  const siteID = request.site_id || state.siteID || state.viewContext.site_id || "";
  const statusClass = Number(request.status || 0) >= 400 ? "errors" : "";
  return [
    request.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: request.path, site_id: siteID, origin: "entity_timeline" })}'>Open path</button>` : "",
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", path: request.path || "", ip: entity.kind === "ip" ? entity.value : "", site_id: siteID, status_class: statusClass, origin: "entity_timeline" })}'>Open logs</button>`,
  ].filter(Boolean).join("");
}

function entitySection(title, html, emptyMessage, className = "") {
  if (!html && !emptyMessage) return "";
  const classes = ["entity-section", className].filter(Boolean).join(" ");
  return `
    <article class="${escapeHTML(classes)}">
      <div class="panel-head"><h2>${escapeHTML(title)}</h2></div>
      <div class="signal-list">${html || `<div class="empty">${escapeHTML(emptyMessage)}</div>`}</div>
    </article>
  `;
}

function entitySiteRow(item) {
  const siteID = item.site_id || "-";
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(siteID)}</strong>
        <span>${escapeHTML([item.env, `${formatNumber(errors)} errors`, item.last_seen ? `last ${formatTime(item.last_seen)}` : ""].filter(Boolean).join(" - "))}</span>
        ${item.site_id ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: item.site_id, origin: "entity" })}'>Open site</button>` : ""}
        ${item.site_id ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ ...entityLogPivot(state.entity, item.site_id), origin: "entity" })}'>Open logs</button>` : ""}
      </div>
      <div class="signal-numbers"><span>requests</span><b>${formatNumber(item.requests || 0)}</b></div>
    </div>
  `;
}

function entityPathRow(item) {
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.path || "/")}</strong>
        <span>${escapeHTML(`${formatNumber(errors)} errors - ${formatBytes(item.bytes_sent || 0)}`)}</span>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path || "/", site_id: state.siteID || state.viewContext.site_id || "", origin: "entity" })}'>Open path</button>
        ${correlatedLogActions({ path: item.path || "/", siteID: state.siteID || state.viewContext.site_id || "", statusClass: errors ? "errors" : "", origin: "entity" })}
      </div>
      <div class="signal-numbers"><span>requests</span><b>${formatNumber(item.requests || 0)}</b></div>
    </div>
  `;
}

function entityUserAgentRow(item) {
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.family || "User agent")}</strong>
        <span>${escapeHTML(item.sample || "(empty)")}</span>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", user_agent: item.sample || "", site_id: state.siteID || state.viewContext.site_id || "", status_class: errors ? "errors" : "", origin: "entity" })}'>Open logs</button>
      </div>
      <div class="signal-numbers"><span>${formatNumber(errors)} errors</span><b>${formatNumber(item.requests || 0)}</b></div>
    </div>
  `;
}

function renderActors() {
  const actors = aggregateActors();
  const reviewCount = actors.reduce((sum, actor) => sum + Number(actor.reviewIPs || 0), 0);
  setText("#actorSummary", `${formatNumber(actors.length)} actors / ${formatNumber(reviewCount)} to review`);
  qs("#actorsList").innerHTML = actors.map(actorRow).join("") || `<div class="empty">No known actors have been classified in this scope.</div>`;
}

function actorRow(actor) {
  const verification = actorVerificationState(actor);
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(actor.label)}</strong>
        <span>${escapeHTML([
          formatCategory(actor.type),
          `${formatNumber(actor.ips)} IPs`,
          `${formatNumber(actor.verifiedIPs || 0)} verified`,
          `${formatNumber(actor.reviewIPs || actor.unverifiedIPs || 0)} review`,
          `${formatNumber(actor.requests)} requests`,
        ].join(" - "))}</span>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: actor.label, actor_type: actor.type, origin: "investigate" })}'>Open actor</button>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", known_actor: actor.label, actor_type: actor.type, origin: "investigate" })}'>Open logs</button>
      </div>
      <div class="signal-numbers">
        <span>${escapeHTML(verification)}</span>
        <b>${escapeHTML(actor.risk)}</b>
      </div>
    </div>
  `;
}

function aggregateActors() {
  const groups = new Map();
  (state.data.analysis?.source_ips || []).forEach((item) => {
    const label = item.known_actor || actorLabelFromType(item.actor_type);
    if (!label) return;
    const key = `${item.actor_type || "service"}|${label}`;
    const existing = groups.get(key) || {
      label,
      type: item.actor_type || "service",
      requests: 0,
      errors: 0,
      risk: 0,
      ips: new Set(),
      ipCount: 0,
      verifiedIPs: 0,
      unverifiedIPs: 0,
      reviewIPs: 0,
      lastSeen: "",
    };
    existing.requests += Number(item.requests || 0);
    existing.errors += Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    existing.risk = Math.max(existing.risk, Number(item.risk_score || 0));
    if (item.ip) existing.ips.add(item.ip);
    if (item.verified_source) existing.verifiedIPs += 1;
    else existing.unverifiedIPs += 1;
    if (actorSourceNeedsReview(item)) existing.reviewIPs += 1;
    if (new Date(item.last_seen || 0) > new Date(existing.lastSeen || 0)) existing.lastSeen = item.last_seen;
    groups.set(key, existing);
  });
  (state.data.analysis?.user_agents || []).forEach((item) => {
    if (!item.actor_type || item.actor_type === "browser" || item.actor_type === "unknown") return;
    const label = item.family || formatCategory(item.actor_type);
    const key = `${item.actor_type}|${label}`;
    const existing = groups.get(key) || {
      label,
      type: item.actor_type,
      requests: 0,
      errors: 0,
      risk: 0,
      ips: new Set(),
      ipCount: 0,
      verifiedIPs: 0,
      unverifiedIPs: 0,
      reviewIPs: 0,
      lastSeen: "",
    };
    existing.requests += Number(item.requests || 0);
    existing.errors += Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    existing.risk = Math.max(existing.risk, Number(item.risk_score || 0));
    existing.ipCount = Math.max(existing.ipCount, Number(item.unique_ips || 0));
    if (new Date(item.last_seen || 0) > new Date(existing.lastSeen || 0)) existing.lastSeen = item.last_seen;
    groups.set(key, existing);
  });
  return Array.from(groups.values())
    .map((item) => ({ ...item, ips: Math.max(item.ips.size, item.ipCount || 0) }))
    .sort((a, b) => (b.risk - a.risk) || (b.requests - a.requests))
    .slice(0, 14);
}

function actorLabelFromType(type) {
  const normalized = String(type || "").toLowerCase();
  if (!normalized || normalized === "unknown" || normalized === "browser") return "";
  return formatCategory(normalized);
}

function actorVerificationState(actor = {}) {
  const verified = Number(actor.verifiedIPs || 0);
  const unverified = Number(actor.unverifiedIPs || 0);
  const review = Number(actor.reviewIPs || 0);
  if (review > 0) return "needs review";
  if (verified > 0 && unverified > 0) return "mixed";
  if (verified > 0) return "verified";
  if (unverified > 0) return "unverified";
  return actor.ipCount ? "ua-only" : "no IP proof";
}

function actorSourceNeedsReview(item = {}) {
  const manualAction = String(item.manual_action || "").toLowerCase();
  if (manualAction === "verified" || manualAction === "ignored") return false;
  if (manualAction === "suspicious" || manualAction === "watch") return true;
  if (item.verified_source) return false;
  const type = String(item.actor_type || "").toLowerCase();
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  const risk = Number(item.risk_score || 0);
  return Boolean(item.known_actor || ["crawler", "service", "monitor", "scanner", "tool", "tor", "datacenter"].includes(type) || risk >= 50 || errors > 0);
}

function actorSourceRows(label, type = "") {
  const normalizedLabel = String(label || "").toLowerCase();
  const normalizedType = String(type || "").toLowerCase();
  return (state.data.analysis?.source_ips || [])
    .filter((item) => {
      const actor = String(item.known_actor || "").toLowerCase();
      const actorType = String(item.actor_type || "").toLowerCase();
      const typeLabel = actorLabelFromType(actorType).toLowerCase();
      if (normalizedLabel && actor !== normalizedLabel && typeLabel !== normalizedLabel) return false;
      if (normalizedType && actorType !== normalizedType) return false;
      return true;
    })
    .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0) || Number(b.requests || 0) - Number(a.requests || 0));
}

function actorVerificationPanel(entity) {
  const actor = aggregateActors().find((item) => item.label === entity.value) || {};
  const rows = actorSourceRows(entity.value, state.viewContext.actor_type || actor.type);
  if (!rows.length) return "";
  const verified = rows.filter((item) => item.verified_source).length;
  const review = rows.filter(actorSourceNeedsReview).length;
  const summary = `
    <div class="verification-summary">
      ${statTile(["Verification", actorVerificationState({ ...actor, verifiedIPs: verified, unverifiedIPs: rows.length - verified, reviewIPs: review })])}
      ${statTile(["Verified IPs", formatNumber(verified)])}
      ${statTile(["Needs review", formatNumber(review)])}
      ${statTile(["Total actor IPs", formatNumber(rows.length)])}
    </div>
  `;
  return `${summary}${rows.slice(0, 16).map(actorSourceRow).join("")}`;
}

function actorSourceRow(item) {
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  const status = actorSourceStatus(item);
  const siteID = item.site_id || state.siteID || state.viewContext.site_id || "";
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.ip || "-")}</strong>
        <span>${escapeHTML([
          status,
          item.reverse_dns || "",
          item.known_actor || actorLabelFromType(item.actor_type),
          siteID || "",
          `${formatNumber(item.requests || 0)} requests`,
          errors ? `${formatNumber(errors)} errors` : "",
          item.manual_label || "",
        ].filter(Boolean).join(" - "))}</span>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: siteID, origin: "actor" })}'>Open IP</button>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ip: item.ip, known_actor: item.known_actor || "", actor_type: item.actor_type || "", site_id: siteID, status_class: errors ? "errors" : "", origin: "actor" })}'>Open logs</button>
        ${ipManualButtons(item.ip, item, siteID, "mini")}
      </div>
      <div class="signal-numbers"><span>${escapeHTML(status)}</span><b>${escapeHTML(item.risk_score || 0)}</b></div>
    </div>
  `;
}

function actorSourceStatus(item = {}) {
  const manualAction = String(item.manual_action || "").toLowerCase();
  if (manualAction) return manualAction;
  if (item.verified_source) return "verified";
  return actorSourceNeedsReview(item) ? "review" : "unverified";
}

function contextActorIPs(context = state.viewContext || {}) {
  const label = String(context.known_actor || "").toLowerCase();
  const type = String(context.actor_type || "").toLowerCase();
  const ips = new Set();
  (state.data.analysis?.source_ips || []).forEach((item) => {
    const actor = String(item.known_actor || "").toLowerCase();
    const actorType = String(item.actor_type || "").toLowerCase();
    const typeLabel = actorLabelFromType(actorType).toLowerCase();
    if (label && actor !== label && typeLabel !== label) return;
    if (type && actorType !== type) return;
    if (item.ip) ips.add(item.ip);
  });
  return ips;
}

function renderAnalysisTabs() {
  qsa("[data-analysis-tab]").forEach((button) => {
    const active = button.dataset.analysisTab === state.analysisTab;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  qsa("[data-analysis-panel]").forEach((panel) => {
    panel.classList.toggle("hidden", panel.dataset.analysisPanel !== state.analysisTab);
    panel.classList.toggle("active", panel.dataset.analysisPanel === state.analysisTab);
  });
}

function renderIssuesTable() {
  const issues = state.data.analysis?.issues || [];
  renderPager("#issuesPager", "issues", issues);
  const rows = paginateWithIndex("issues", issues).map(({ item: issue, index }) => `
    <tr>
      <td><span class="severity severity-${escapeHTML(issue.severity || "low")}">${escapeHTML(issue.severity || "low")}</span></td>
      <td><strong>${escapeHTML(issue.title || issue.rule_key)}</strong><br><span>${escapeHTML(issue.summary || "")}</span><br><button class="ghost mini inline-action" type="button" data-detail-kind="issue" data-detail-index="${index}">Details</button></td>
      <td>${escapeHTML(issue.actor_value || issue.site_id || "-")}</td>
      <td>${formatNumber(issue.requests || 0)}</td>
      <td>${formatTime(issue.last_seen)}</td>
    </tr>
  `);
  qs("#issuesTable").innerHTML = rows.join("") || emptyRow(5, "No issues detected.");
}

function renderSourceIPs() {
  const items = state.data.analysis?.source_ips || [];
  renderPager("#sourceIPPagers", "sourceIPs", items);
  const rows = paginateWithIndex("sourceIPs", items).map(({ item, index }) => {
    const actor = [item.actor_type, item.known_actor].filter(Boolean).join(" / ") || "-";
    const source = item.manual_action ? `manual ${formatManualAction(item.manual_action).toLowerCase()}` : item.verified_source ? "verified" : item.reverse_dns ? "reverse DNS" : "unverified";
    const actions = [
      `<button class="ghost mini inline-action" type="button" data-detail-kind="sourceIP" data-detail-index="${index}">Details</button>`,
      `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: item.site_id, origin: "investigate" })}'>Open IP</button>`,
      `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ip: item.ip, site_id: item.site_id, origin: "investigate" })}'>Logs</button>`,
      ipManualButtons(item.ip, item, item.site_id || state.siteID, "mini"),
    ].join("");
    return `
      <tr>
        <td><strong>${escapeHTML(item.ip)}</strong><br><span>${escapeHTML(item.reverse_dns || "")}</span></td>
        <td>${formatNumber(item.requests || 0)}</td>
        <td>${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))}</td>
        <td>${escapeHTML(actor)}</td>
        <td>${escapeHTML(source)}</td>
        <td>${item.risk_score === undefined ? "-" : escapeHTML(item.risk_score)}</td>
        <td class="row-actions">${actions}</td>
      </tr>
    `;
  });
  qs("#sourceIPsTable").innerHTML = rows.join("") || emptyRow(7, "No source IPs found.");
}

function renderUserAgents() {
  const items = state.data.analysis?.user_agents || [];
  renderPager("#userAgentPager", "userAgents", items);
  const rows = paginateWithIndex("userAgents", items).map(({ item, index }) => `
    <tr>
      <td><strong>${escapeHTML(item.family || "unknown")}</strong><br><span>${escapeHTML(item.actor_type || "")}</span><br><button class="ghost mini inline-action" type="button" data-detail-kind="userAgent" data-detail-index="${index}">Details</button></td>
      <td class="clip">${escapeHTML(item.sample || "(empty)")}</td>
      <td>${formatNumber(item.requests || 0)}</td>
      <td>${formatNumber(item.unique_ips || 0)}</td>
      <td>${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))}</td>
      <td>${escapeHTML(item.risk_score || 0)}</td>
    </tr>
  `);
  qs("#userAgentsTable").innerHTML = rows.join("") || emptyRow(6, "No user agents found.");
}

function renderAdminProbes() {
  const items = state.data.analysis?.admin_probes || [];
  renderPager("#adminProbePager", "adminProbes", items);
  setText("#adminProbeSummary", `${items.length} probes`);
  const rows = paginateWithIndex("adminProbes", items).map(({ item, index }) => {
    const target = `${item.method || "GET"} ${item.path || "/"}`;
    const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    return `
      <tr>
        <td><strong>${escapeHTML(formatCategory(item.category || "admin"))}</strong><br><span>${escapeHTML(item.site_id || "-")} / ${escapeHTML(item.env || "-")}</span></td>
        <td><strong>${escapeHTML(item.ip || "-")}</strong><br><button class="ghost mini inline-action" type="button" data-detail-kind="adminProbe" data-detail-index="${index}">Details</button></td>
        <td class="clip">${escapeHTML(target)}${item.sample_query ? `<br><span>${escapeHTML(item.sample_query)}</span>` : ""}</td>
        <td>${formatNumber(item.requests || 0)}</td>
        <td>${formatNumber(item.total_ip_hits || item.requests || 0)}</td>
        <td>${formatNumber(errors)}</td>
        <td>${formatTime(item.last_seen)}</td>
      </tr>
    `;
  });
  qs("#adminProbesTable").innerHTML = rows.join("") || emptyRow(7, "No admin probes found.");
}

function renderInjectionProbes() {
  const items = state.data.analysis?.injection_probes || [];
  renderPager("#injectionProbePager", "injectionProbes", items);
  setText("#injectionProbeSummary", `${items.length} probes`);
  const rows = paginateWithIndex("injectionProbes", items).map(({ item, index }) => {
    const target = `${item.method || "GET"} ${item.path || "/"}`;
    const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    return `
      <tr>
        <td><strong>${escapeHTML(formatCategory(item.category || "probe"))}</strong><br><span>${escapeHTML(item.match_reason ? `${formatCategory(item.match_reason)} - risk ${item.risk_score || 0}` : `risk ${item.risk_score || 0}`)}</span></td>
        <td><strong>${escapeHTML(item.ip || "-")}</strong><br><button class="ghost mini inline-action" type="button" data-detail-kind="injectionProbe" data-detail-index="${index}">Details</button></td>
        <td class="clip">${escapeHTML(target)}${item.sample_query ? `<br><span>${escapeHTML(item.sample_query)}</span>` : ""}</td>
        <td>${formatNumber(item.requests || 0)}</td>
        <td>${formatNumber(item.total_ip_hits || item.requests || 0)}</td>
        <td>${formatNumber(errors)}</td>
        <td>${formatTime(item.last_seen)}</td>
      </tr>
    `;
  });
  qs("#injectionProbesTable").innerHTML = rows.join("") || emptyRow(7, "No injection probes found.");
}

function renderTorSources() {
  const items = state.data.analysis?.tor_sources || [];
  renderPager("#torSourcePager", "torSources", items);
  setText("#torSourceSummary", `${items.length} sources`);
  const rows = paginateWithIndex("torSources", items).map(({ item, index }) => {
    const actor = [item.actor_type, item.known_actor].filter(Boolean).join(" / ") || "tor";
    const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    return `
      <tr>
        <td><strong>${escapeHTML(item.ip || "-")}</strong><br><span>${escapeHTML(item.reverse_dns || "")}</span><br><button class="ghost mini inline-action" type="button" data-detail-kind="torSource" data-detail-index="${index}">Details</button></td>
        <td>${escapeHTML(item.site_id || "-")}<br><span>${escapeHTML(item.env || "-")}</span></td>
        <td>${formatNumber(item.requests || 0)}</td>
        <td>${formatNumber(item.admin_requests || 0)}</td>
        <td>${formatNumber(errors)}</td>
        <td>${escapeHTML(actor)}<br><span>risk ${escapeHTML(item.risk_score || 0)}</span></td>
      </tr>
    `;
  });
  qs("#torSourcesTable").innerHTML = rows.join("") || emptyRow(6, "No Tor exit traffic found.");
}

function renderTopPaths(items) {
  setText("#topPathSummary", `${items.length} paths`);
  qs("#topPathsList").innerHTML = items.slice(0, 12).map((item) => `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.path || "/")}</strong>
        <span>${formatNumber(item.status_4xx || 0)} 4xx - ${formatNumber(item.status_5xx || 0)} 5xx</span>
      </div>
      <div class="signal-numbers">
        <span>${formatBytes(item.bytes_sent || 0)}</span>
        <b>${formatNumber(item.requests || 0)}</b>
      </div>
    </div>
  `).join("") || `<div class="empty">No paths found.</div>`;
}

function renderSlowPaths(items) {
  setText("#slowPathSummary", `${items.length} paths`);
  qs("#slowPathsList").innerHTML = items.slice(0, 12).map((item) => `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.path || "/")}</strong>
        <span>${escapeHTML(item.site_id || "")} - p95 ${formatMs(item.p95_request_time_ms || 0)}</span>
      </div>
      <div class="signal-numbers">
        <span>avg ${formatMs(item.avg_request_time_ms || 0)}</span>
        <b>${formatNumber(item.requests || 0)}</b>
      </div>
    </div>
  `).join("") || `<div class="empty">No slow paths found.</div>`;
}

function renderRecentErrors(items) {
  qs("#recentErrorsList").innerHTML = items.slice(0, 10).map((item) => {
    const path = `${item.method || "GET"} ${item.path || "/"}`;
    const meta = [item.client_ip, item.site_id, formatTime(item.ts)].filter(Boolean).join(" - ");
    const actions = [
      item.client_ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.client_ip, site_id: item.site_id, origin: "recent_errors" })}'>Open IP</button>` : "",
      `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", path: item.path || "/", ip: item.client_ip || "", site_id: item.site_id || "", status_class: "errors", origin: "recent_errors" })}'>Open logs</button>`,
    ].filter(Boolean).join("");
    return `
      <div class="signal-row">
        <div>
          <strong>${escapeHTML(path)}</strong>
          <span>${escapeHTML(meta)}</span>
          ${actions}
        </div>
        <div class="signal-numbers">
          <b class="${Number(item.status) >= 500 ? "status-failed" : "status-skipped"}">${escapeHTML(item.status || "-")}</b>
        </div>
      </div>
    `;
  }).join("") || `<div class="empty">No recent 4xx or 5xx responses.</div>`;
}

function renderSites() {
  const sites = aggregateSiteRows();
  renderPager("#sitesPager", "sites", sites);
  const selectedID = currentSiteIDForView(sites);
  const rows = paginate("sites", sites).map((site) => `
    <tr>
      <td><strong>${escapeHTML(site.name || site.id)}</strong><br><span>${escapeHTML(site.id)}${site.envs?.length ? ` / ${escapeHTML(site.envs.join(", "))}` : ""}</span></td>
      <td><span class="severity severity-${escapeHTML(site.severity)}">${escapeHTML(site.status)}</span><br><span>${escapeHTML(site.lastSeen ? `last ${shortDateTime(site.lastSeen)}` : "no indexed events")}</span></td>
      <td>${formatNumber(site.requests || 0)}</td>
      <td>${formatPercent(site.status5xxRate || 0)}<br><span>${formatNumber(site.status5xx || 0)} responses</span></td>
      <td>${formatNumber(site.signalCount || 0)}<br><span>${formatNumber(site.securitySignals || 0)} security</span></td>
      <td class="row-actions">
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: site.id, origin: "sites" })}'>Open</button>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: site.id, origin: "sites" })}'>Logs</button>
      </td>
    </tr>
  `);
  qs("#sitesTable").innerHTML = rows.join("") || emptyRow(6, "No enabled sites configured.");
  renderSiteDetail(sites.find((site) => site.id === selectedID) || sites[0] || null);
}

function aggregateSiteRows() {
  const configs = new Map((state.data.sites || []).map((site) => [site.id, { ...site }]));
  const metrics = new Map();
  (state.data.analysis?.sites || []).forEach((item) => {
    const id = item.site_id || "";
    if (!id) return;
    const existing = metrics.get(id) || {
      id,
      requests: 0,
      uniqueIPs: 0,
      status4xx: 0,
      status5xx: 0,
      p95: 0,
      firstSeen: "",
      lastSeen: "",
      envs: new Set(),
    };
    existing.requests += Number(item.requests || 0);
    existing.uniqueIPs += Number(item.unique_ips || 0);
    existing.status4xx += Number(item.status_4xx || 0);
    existing.status5xx += Number(item.status_5xx || 0);
    existing.p95 = Math.max(existing.p95, Number(item.p95_request_time_ms || 0));
    if (item.env) existing.envs.add(item.env);
    if (!existing.firstSeen || new Date(item.first_seen || 0) < new Date(existing.firstSeen || 0)) existing.firstSeen = item.first_seen;
    if (!existing.lastSeen || new Date(item.last_seen || 0) > new Date(existing.lastSeen || 0)) existing.lastSeen = item.last_seen;
    metrics.set(id, existing);
  });

  const ids = new Set([...configs.keys(), ...metrics.keys()]);
  return Array.from(ids).map((id) => {
    const config = configs.get(id) || { id, name: id, envs: [], tags: [] };
    const metric = metrics.get(id) || {};
    const signals = siteSignalItems(id);
    const securitySignals = signals.filter((item) => item.group === "security").length;
    const status5xxRate = ratio(metric.status5xx || 0, metric.requests || 0);
    const status4xxRate = ratio(metric.status4xx || 0, metric.requests || 0);
    const status = siteStatus({ ...metric, signalCount: signals.length, securitySignals, status5xxRate });
    return {
      ...config,
      id,
      envs: Array.from(new Set([...(config.envs || []), ...Array.from(metric.envs || [])])),
      requests: metric.requests || 0,
      uniqueIPs: metric.uniqueIPs || 0,
      status4xx: metric.status4xx || 0,
      status5xx: metric.status5xx || 0,
      status4xxRate,
      status5xxRate,
      p95: metric.p95 || 0,
      firstSeen: metric.firstSeen || "",
      lastSeen: metric.lastSeen || "",
      signalCount: signals.length,
      securitySignals,
      status: status.label,
      severity: status.severity,
      statusRank: status.rank,
    };
  }).sort((a, b) => {
    if (state.siteID && a.id === state.siteID) return -1;
    if (state.siteID && b.id === state.siteID) return 1;
    return (b.statusRank - a.statusRank) || (b.signalCount - a.signalCount) || (b.requests - a.requests) || String(a.name || a.id).localeCompare(String(b.name || b.id));
  });
}

function siteStatus(site) {
  if (!site.requests && !site.lastSeen) return { label: "stale", severity: "medium", rank: 2 };
  if ((site.status5xxRate || 0) >= 0.05 || (site.signalCount || 0) >= 10) return { label: "degraded", severity: "critical", rank: 5 };
  if ((site.status5xxRate || 0) >= 0.01 || (site.securitySignals || 0) >= 3) return { label: "elevated", severity: "high", rank: 4 };
  if ((site.signalCount || 0) > 0 || (site.status4xxRate || 0) >= 0.1) return { label: "watch", severity: "medium", rank: 3 };
  return { label: "healthy", severity: "low", rank: 1 };
}

function currentSiteIDForView(sites) {
  if (state.siteID) return state.siteID;
  return sites[0]?.id || "";
}

function renderSiteDetail(site) {
  if (!site) {
    setText("#siteDetailName", "No sites configured");
    setText("#siteDetailMeta", "Add sites to start building a workspace.");
    setText("#siteTabSummary", "-");
    qs("#siteRiskStrip").innerHTML = "";
    qs("#siteTabBody").innerHTML = `<div class="empty">No enabled sites configured.</div>`;
    return;
  }
  const focused = state.siteID === site.id;
  const signals = siteSignalItems(site.id);
  const topIP = siteTopSourceIPs(site.id)[0];
  const topPath = siteTopPaths(site.id)[0];
  setText("#siteDetailName", site.name || site.id);
  setText("#siteDetailMeta", `${site.id} / ${site.pantheon_site_id || "no Pantheon UUID"} / ${activeFilterLabel()}${focused ? "" : " / preview"}`);
  const status = qs("#siteDetailStatus");
  status.textContent = site.status || "healthy";
  status.className = `severity severity-${site.severity || "low"}`;
  qs("#siteRiskStrip").innerHTML = [
    ["Requests", formatNumber(site.requests || 0)],
    ["4xx / 5xx", `${formatPercent(site.status4xxRate || 0)} / ${formatPercent(site.status5xxRate || 0)}`],
    ["Slow p95", formatMs(site.p95 || 0)],
    ["Active signals", formatNumber(signals.length)],
    ["Top source IP", topIP?.ip || "-"],
    ["Top path", topPath?.path || "-"],
  ].map(statTile).join("");
  qs("#siteFocusButton").textContent = focused ? "Focused" : "Focus site";
  qs("#siteFocusButton").disabled = focused;
  qsa("[data-site-tab]").forEach((button) => {
    const active = button.dataset.siteTab === state.siteTab;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  renderSiteTab(site);
}

function renderSiteTab(site) {
  const id = site.id;
  const signals = siteSignalItems(id);
  const recentErrors = siteRecentErrors(id);
  const title = formatCategory(state.siteTab || "overview");
  setText("#siteTabTitle", `${title} / ${site.name || site.id}`);
  const body = qs("#siteTabBody");
  if (state.siteTab === "security") {
    const probes = [
      ...siteScopedRows(state.data.analysis?.injection_probes || [], id).map((item) => ({ ...item, kind: "Injection probe" })),
      ...siteScopedRows(state.data.analysis?.admin_probes || [], id).map((item) => ({ ...item, kind: "Admin probe" })),
      ...siteScopedRows(state.data.analysis?.tor_sources || [], id).map((item) => ({ ...item, kind: "Tor source" })),
    ].sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
    setText("#siteTabSummary", `${formatNumber(Math.min(30, probes.length))} of ${formatNumber(probes.length)} shown`);
    body.innerHTML = siteRowsMarkup(probes.slice(0, 30), siteSecurityRow, "No security probes for this site in scope.");
    return;
  }
  if (state.siteTab === "reliability") {
    const rows = [
      ...recentErrors.map((item) => ({ ...item, kind: "Recent error" })),
      ...siteScopedRows(state.data.analysis?.slow_paths || [], id).map((item) => ({ ...item, kind: "Slow path" })),
    ];
    setText("#siteTabSummary", `${formatNumber(Math.min(30, rows.length))} of ${formatNumber(rows.length)} shown`);
    body.innerHTML = siteRowsMarkup(rows.slice(0, 30), siteReliabilityRow, "No reliability findings for this site in scope.");
    return;
  }
  if (state.siteTab === "actors") {
    const rows = [
      ...siteTopSourceIPs(id).map((item) => ({ ...item, kind: "Source IP" })),
      ...siteTopUserAgents(id).map((item) => ({ ...item, kind: "User agent" })),
    ];
    setText("#siteTabSummary", `${formatNumber(Math.min(30, rows.length))} of ${formatNumber(rows.length)} shown`);
    body.innerHTML = siteRowsMarkup(rows.slice(0, 30), siteActorRow, "No actor data for this site in scope.");
    return;
  }
  if (state.siteTab === "paths") {
    const rows = siteTopPaths(id);
    setText("#siteTabSummary", `${formatNumber(Math.min(30, rows.length))} of ${formatNumber(rows.length)} shown`);
    body.innerHTML = siteRowsMarkup(rows.slice(0, 30), sitePathRow, "No path data for this site in scope.");
    return;
  }
  if (state.siteTab === "logs") {
    const rows = siteLogEvidence(id).slice(0, 30);
    setText("#siteTabSummary", `${formatNumber(rows.length)} evidence rows`);
    body.innerHTML = siteRowsMarkup(rows, logEvidenceRow, "No matching log evidence for this site in scope.");
    return;
  }
  if (state.siteTab === "reports") {
    const rows = siteReports(id);
    setText("#siteTabSummary", `${formatNumber(Math.min(30, rows.length))} of ${formatNumber(rows.length)} shown`);
    body.innerHTML = siteRowsMarkup(rows.slice(0, 30), siteReportRow, "No generated reports are scoped to this site yet.");
    return;
  }
  setText("#siteTabSummary", `${formatNumber(signals.length)} signals / ${formatNumber(recentErrors.length)} errors`);
  body.innerHTML = `
    <section class="site-tab-grid">
      <div class="site-subsection">
        <h3>Priority signals</h3>
        <div class="signal-stack">${signals.slice(0, 8).map(signalRow).join("") || `<div class="empty">No active signals for this site.</div>`}</div>
      </div>
      <div class="site-subsection">
        <h3>Recent errors</h3>
        <div class="signal-list">${recentErrors.slice(0, 10).map(siteRecentErrorRow).join("") || `<div class="empty">No recent errors for this site.</div>`}</div>
      </div>
    </section>
  `;
}

function siteRowsMarkup(rows, renderer, emptyMessage) {
  return `<div class="signal-list">${rows.map(renderer).join("") || `<div class="empty">${escapeHTML(emptyMessage)}</div>`}</div>`;
}

function siteScopedRows(rows, siteID) {
  return (rows || []).filter((item) => item.site_id === siteID || (state.siteID === siteID && !item.site_id));
}

function siteSignalItems(siteID) {
  return buildSignalItems().filter((item) => item.siteID === siteID || (state.siteID === siteID && !item.siteID));
}

function siteRecentErrors(siteID) {
  return siteScopedRows(state.data.traffic?.recent_errors || [], siteID).sort((a, b) => new Date(b.ts || 0) - new Date(a.ts || 0));
}

function siteTopSourceIPs(siteID) {
  return siteScopedRows(state.data.analysis?.source_ips || [], siteID)
    .sort((a, b) => Number(b.requests || 0) - Number(a.requests || 0));
}

function siteTopUserAgents(siteID) {
  return siteScopedRows(state.data.analysis?.user_agents || [], siteID)
    .sort((a, b) => Number(b.requests || 0) - Number(a.requests || 0));
}

function siteTopPaths(siteID) {
  const trafficPaths = siteScopedRows(state.data.traffic?.top_paths || [], siteID);
  const slowPaths = siteScopedRows(state.data.analysis?.slow_paths || [], siteID);
  const byPath = new Map();
  [...trafficPaths, ...slowPaths].forEach((item) => {
    const key = item.path || "/";
    const existing = byPath.get(key) || { ...item, path: key, requests: 0, status_4xx: 0, status_5xx: 0, bytes_sent: 0, p95_request_time_ms: 0 };
    existing.requests += Number(item.requests || 0);
    existing.status_4xx += Number(item.status_4xx || 0);
    existing.status_5xx += Number(item.status_5xx || 0);
    existing.bytes_sent += Number(item.bytes_sent || 0);
    existing.p95_request_time_ms = Math.max(existing.p95_request_time_ms || 0, Number(item.p95_request_time_ms || 0));
    byPath.set(key, existing);
  });
  return Array.from(byPath.values()).sort((a, b) => (b.status_5xx - a.status_5xx) || (b.requests - a.requests));
}

function siteLogEvidence(siteID) {
  return filteredLogEvidence().filter((item) => item.site_id === siteID || (state.siteID === siteID && !item.site_id));
}

function siteReports(siteID) {
  return (state.data.reports || []).filter((report) => report.site_id === siteID);
}

function siteSecurityRow(item) {
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  const path = item.path || "/";
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.kind || formatCategory(item.category || "Security"))}: ${escapeHTML(path)}</strong>
        <span>${escapeHTML([item.ip, formatCategory(item.match_reason || item.category || ""), `${formatNumber(item.requests || 0)} requests`, `${formatNumber(errors)} errors`].filter(Boolean).join(" - "))}</span>
        ${item.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: item.site_id, origin: "site" })}'>Open IP</button>` : ""}
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: path, site_id: item.site_id || "", origin: "site" })}'>Open path</button>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", path, ip: item.ip || "", site_id: item.site_id || "", status_class: errors ? "errors" : "", origin: "site" })}'>Open logs</button>
      </div>
      <div class="signal-numbers"><span>risk</span><b>${escapeHTML(item.risk_score || 0)}</b></div>
    </div>
  `;
}

function siteReliabilityRow(item) {
  if (item.kind === "Recent error") return siteRecentErrorRow(item);
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.path || "/")}</strong>
        <span>${escapeHTML(`p95 ${formatMs(item.p95_request_time_ms || 0)} - avg ${formatMs(item.avg_request_time_ms || 0)} - ${formatNumber(item.status_5xx || 0)} 5xx`)}</span>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path || "/", site_id: item.site_id || "", origin: "site" })}'>Open path</button>
        ${correlatedLogActions({ path: item.path || "/", siteID: item.site_id || "", statusClass: Number(item.status_5xx || 0) ? "errors" : "", origin: "site" })}
      </div>
      <div class="signal-numbers"><span>requests</span><b>${formatNumber(item.requests || 0)}</b></div>
    </div>
  `;
}

function siteRecentErrorRow(item) {
  return logEvidenceRow({
    kind: "Recent error",
    ts: item.ts,
    site_id: item.site_id,
    env: item.env,
    ip: item.client_ip,
    method: item.method,
    path: item.path,
    query: item.query,
    status: item.status,
    requests: 1,
    errors: 1,
    user_agent: item.user_agent,
  });
}

function siteActorRow(item) {
  const isIP = item.kind === "Source IP";
  const label = isIP ? item.ip : item.family || item.known_actor || "User agent";
  const verification = isIP ? actorSourceStatus(item) : "user-agent";
  const meta = isIP
    ? [verification, item.reverse_dns, item.known_actor, item.actor_type, item.manual_label, `${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))} errors`].filter(Boolean).join(" - ")
    : [item.actor_type, `${formatNumber(item.unique_ips || 0)} IPs`, `${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))} errors`].filter(Boolean).join(" - ");
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(label)}</strong>
        <span>${escapeHTML(meta)}</span>
        ${isIP ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: state.siteID, origin: "site" })}'>Open IP</button>` : ""}
        ${isIP && (item.known_actor || item.actor_type) ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: item.known_actor || actorLabelFromType(item.actor_type), actor_type: item.actor_type || "", site_id: state.siteID, origin: "site" })}'>Open actor</button>` : ""}
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ip: isIP ? item.ip : "", user_agent: isIP ? "" : item.sample || "", site_id: state.siteID, origin: "site" })}'>Open logs</button>
        ${isIP ? ipManualButtons(item.ip, item, state.siteID || item.site_id || "", "mini") : ""}
      </div>
      <div class="signal-numbers"><span>${escapeHTML(verification)}</span><b>${formatNumber(item.requests || 0)}</b></div>
    </div>
  `;
}

function sitePathRow(item) {
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.path || "/")}</strong>
        <span>${escapeHTML(`${formatNumber(errors)} errors - ${formatBytes(item.bytes_sent || 0)} - p95 ${formatMs(item.p95_request_time_ms || 0)}`)}</span>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path || "/", site_id: state.siteID || item.site_id || "", origin: "site" })}'>Open path</button>
        ${correlatedLogActions({ path: item.path || "/", siteID: state.siteID || item.site_id || "", statusClass: errors ? "errors" : "", origin: "site" })}
      </div>
      <div class="signal-numbers"><span>requests</span><b>${formatNumber(item.requests || 0)}</b></div>
    </div>
  `;
}

function siteReportRow(report) {
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(reportListLabel(report))}</strong>
        <span>${escapeHTML(reportWindowLabel(report))}</span>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), origin: "site" }))}'>Open report</button>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", origin: "site" }))}'>Open logs</button>
      </div>
      <div class="signal-numbers"><span>${escapeHTML(report.model || "local")}</span><b>${formatNumber(report.summary?.requests || 0)}</b></div>
    </div>
  `;
}

async function handleSiteAction(action) {
  const site = aggregateSiteRows().find((item) => item.id === currentSiteIDForView(aggregateSiteRows()));
  if (!site) return;
  if (action === "logs") {
    await handlePivot({ kind: "log_filter", site_id: site.id, origin: "site" });
    return;
  }
  if (action === "signals") {
    state.siteID = site.id;
    state.viewContext = {};
    state.signalKey = "";
    showRoute("signals", true);
    await refreshWithValidation();
    return;
  }
  if (action === "reports") {
    state.siteID = site.id;
    state.viewContext = {};
    state.signalKey = "";
    showRoute("reports", true);
    await refreshWithValidation();
    return;
  }
  await handlePivot({ kind: "site", value: site.id, origin: "site" });
}

function renderAlerts() {
  const alerts = state.data.alerts || [];
  renderPager("#alertsPager", "alerts", alerts);
  const rows = paginateWithIndex("alerts", alerts).map(({ item: alert, index }) => `
    <tr>
      <td><span class="severity severity-${escapeHTML(alert.severity || "low")}">${escapeHTML(alert.severity || "low")}</span></td>
      <td><strong>${escapeHTML(alert.title || alert.rule_key)}</strong><br><span>${escapeHTML(alert.summary || "")}</span><br><button class="ghost mini inline-action" type="button" data-detail-kind="alert" data-detail-index="${index}">Details</button></td>
      <td>${escapeHTML(alert.actor_value || "-")}</td>
      <td>${escapeHTML(alert.score || 0)}</td>
      <td>${formatTime(alert.last_seen_at)}</td>
    </tr>
  `);
  qs("#alertsTable").innerHTML = rows.join("") || emptyRow(5, "No alerts are open.");
}

function renderReports() {
  const reports = state.data.reports || [];
  renderReportTabs(reports);
  const selected = reportsForCurrentTab(reports);
  const report = selectedReportFromList(selected);
  const countLabel = `${formatNumber(selected.length)} ${selected.length === 1 ? "report" : "reports"}`;
  const reportsPager = qs("#reportsPager");
  if (reportsPager) reportsPager.innerHTML = `<span class="pill">${escapeHTML(countLabel)}</span>`;
  setText("#reportPeriodTitle", `${formatCategory(state.reportTab)} reports`);

  qs("#reportsBody").innerHTML = `
    <section class="report-browser">
      <aside class="panel report-list-panel">
        <div class="panel-head">
          <h2>${escapeHTML(reportListTitle(state.reportTab))}</h2>
          <span class="pill">${escapeHTML(countLabel)}</span>
        </div>
        <div class="report-date-list">
          ${selected.map((item) => reportListRow(item, report && reportKey(item) === reportKey(report))).join("") || `<div class="empty">No ${escapeHTML(state.reportTab)} reports yet.</div>`}
        </div>
      </aside>
      <section class="report-detail-stack">
        ${report ? reportDetailMarkup(report) : `
          <article class="panel">
            <div class="empty">No ${escapeHTML(state.reportTab)} reports have been generated yet.</div>
          </article>
        `}
      </section>
    </section>
  `;
}

function reportDetailMarkup(report) {
  const summary = report.summary || {};
  return `
    <section class="metrics report-metrics" aria-label="Report metrics">
      ${reportMetric("Requests", formatNumber(summary.requests || 0))}
      ${reportMetric("5xx rate", formatPercent(summary.status_5xx_rate || 0))}
      ${reportMetric("4xx rate", formatPercent(summary.status_4xx_rate || 0))}
      ${reportMetric("Issues", formatNumber(summary.issue_count || 0))}
      ${reportMetric("Security probes", formatNumber((summary.admin_probe_requests || 0) + (summary.injection_probe_requests || 0)))}
      ${reportMetric("Tor requests", formatNumber(summary.tor_requests || 0))}
      ${reportMetric("Unique IPs", formatNumber(summary.unique_ips || 0))}
      ${reportMetric("Slow rate", formatPercent(summary.slow_requests_rate || 0))}
    </section>

    <section class="report-layout">
      <article class="panel report-summary-panel">
        <div class="panel-head">
          <h2>LLM summary</h2>
          <div class="panel-tools">
            <span class="pill">${escapeHTML(report.model || "local")}</span>
            <span class="pill">${escapeHTML(report.site_id || "All sites")}</span>
            <span class="pill">${formatTime(report.created_at)}</span>
          </div>
        </div>
        <div class="report-copy markdown-body">${renderMarkdown(report.output || "No LLM summary stored.")}</div>
      </article>

      <article class="panel">
        <div class="panel-head">
          <h2>Report facts</h2>
        </div>
        <dl class="facts">
          ${facts([
            ["Window", `${formatTime(report.range_start)} to ${formatTime(report.range_end)}`],
            ["Top site", summary.top_site || "-"],
            ["Top path", summary.top_path || "-"],
            ["Top source IP", summary.top_source_ip || "-"],
            ["Top user agent", summary.top_user_agent || "-"],
            ["Open alerts", formatNumber(summary.open_alerts || 0)],
          ])}
        </dl>
        <div class="report-actions">
          ${summary.top_site ? `<button class="ghost small" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "site", value: summary.top_site, site_id: summary.top_site, origin: "report" }))}'>Open top site</button>` : ""}
          ${summary.top_source_ip ? `<button class="ghost small" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "ip", value: summary.top_source_ip, site_id: report.site_id || "", origin: "report" }))}'>Open top IP</button>` : ""}
          ${summary.top_path ? `<button class="ghost small" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "log_filter", path: summary.top_path, site_id: report.site_id || "", status_class: "errors", origin: "report" }))}'>Open top path logs</button>` : ""}
          <button class="ghost small" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", origin: "report" }))}'>Open report logs</button>
        </div>
      </article>
    </section>

    <section class="report-chart-grid">
      ${reportChartsMarkup(report)}
    </section>

    <section class="report-drilldown-grid">
      ${reportDrilldownsMarkup(report)}
    </section>
  `;
}

function renderReportTabs(reports) {
  qsa("[data-report-tab]").forEach((button) => {
    const tab = button.dataset.reportTab || "daily";
    const count = reportsForTab(reports, tab).length;
    const active = tab === state.reportTab;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
    button.textContent = `${reportPeriodLabel(tab)} (${count})`;
  });
}

function reportsForCurrentTab(reports) {
  return reportsForTab(reports, state.reportTab);
}

function selectedReportFromList(reports) {
  if (!reports.length) return null;
  const selectedKey = state.selectedReportIDs[state.reportTab];
  const selected = reports.find((report) => reportKey(report) === selectedKey) || reports[0];
  state.selectedReportIDs[state.reportTab] = reportKey(selected);
  return selected;
}

function reportsForTab(reports, tab) {
  return [...(reports || [])]
    .filter((report) => reportTabForReport(report) === tab)
    .sort((a, b) => new Date(b.created_at || b.range_end || 0) - new Date(a.created_at || a.range_end || 0));
}

function reportTabForReport(report) {
  const type = String(report?.report_type || "").toLowerCase();
  if (["daily", "weekly", "monthly", "quarterly", "annual"].includes(type)) return type;
  switch (report?.range) {
    case "24h":
      return "daily";
    case "7d":
      return "weekly";
    case "30d":
      return "monthly";
    case "90d":
      return "quarterly";
    case "365d":
      return "annual";
    default:
      if (type.includes("week")) return "weekly";
      if (type.includes("month")) return "monthly";
      if (type.includes("quarter")) return "quarterly";
      if (type.includes("annual") || type.includes("year")) return "annual";
      return "daily";
  }
}

function reportPeriodLabel(tab) {
  return {
    daily: "Daily",
    weekly: "Weekly",
    monthly: "Monthly",
    quarterly: "Quarterly",
    annual: "Annual",
  }[tab] || "Reports";
}

function reportListTitle(tab) {
  return {
    daily: "Days",
    weekly: "Weeks",
    monthly: "Months",
    quarterly: "Quarters",
    annual: "Years",
  }[tab] || "Reports";
}

function reportKey(report) {
  if (!report) return "";
  return String(report.id || [
    reportTabForReport(report),
    report.range || "",
    report.site_id || "",
    report.range_start || "",
    report.range_end || "",
    report.created_at || "",
  ].join("|"));
}

function reportPivot(report, extra = {}) {
  return {
    ...extra,
    range: "custom",
    from: report?.range_start || "",
    to: report?.range_end || "",
    site_id: extra.site_id || report?.site_id || "",
    log_type: "nginx-access",
    origin: extra.origin || "report",
  };
}

function reportListRow(report, active) {
  const summary = report.summary || {};
  const errors = (Number(summary.status_5xx_rate || 0) + Number(summary.status_4xx_rate || 0));
  const meta = [
    report.site_id || "All sites",
    `${formatNumber(summary.requests || 0)} requests`,
    `${formatPercent(summary.status_5xx_rate || 0)} 5xx`,
    summary.issue_count ? `${formatNumber(summary.issue_count)} issues` : "",
  ].filter(Boolean).join(" - ");
  return `
    <button class="report-list-row ${active ? "active" : ""}" type="button" data-report-select="${escapeHTML(reportKey(report))}" aria-pressed="${active ? "true" : "false"}">
      <span class="report-list-title">${escapeHTML(reportListLabel(report))}</span>
      <span class="report-list-window">${escapeHTML(reportWindowLabel(report))}</span>
      <span class="report-list-meta">${escapeHTML(meta)}</span>
      <span class="report-list-foot">${escapeHTML(report.model || "local")} - generated ${formatTime(report.created_at)}${errors ? ` - ${formatPercent(errors)} error rate` : ""}</span>
    </button>
  `;
}

function reportListLabel(report) {
  const date = reportPeriodDate(report);
  if (!date) return reportPeriodLabel(reportTabForReport(report));
  const tab = reportTabForReport(report);
  if (tab === "daily") {
    return date.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric", year: "numeric" });
  }
  if (tab === "weekly") {
    return `Week ending ${date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}`;
  }
  if (tab === "monthly") {
    return date.toLocaleDateString(undefined, { month: "long", year: "numeric" });
  }
  if (tab === "quarterly") {
    return `Q${Math.floor(date.getMonth() / 3) + 1} ${date.getFullYear()}`;
  }
  if (tab === "annual") {
    return String(date.getFullYear());
  }
  return reportPeriodLabel(tab);
}

function reportWindowLabel(report) {
  if (!report?.range_start || !report?.range_end) return report.range || "";
  return `${shortDateTime(report.range_start)} to ${shortDateTime(report.range_end)}`;
}

function reportPeriodDate(report) {
  const value = report?.range_end || report?.created_at || report?.range_start;
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function reportMetric(label, value) {
  return `
    <article>
      <span>${escapeHTML(label)}</span>
      <strong>${escapeHTML(value)}</strong>
    </article>
  `;
}

function reportChartsMarkup(report) {
  const charts = report.charts || [];
  if (!charts.length) {
    return `
      <article class="panel report-empty-panel">
        <div class="empty">No chart data stored for this report.</div>
      </article>
    `;
  }
  return charts.map((chart) => reportChartPanel(report, chart)).join("");
}

function reportChartPanel(report, chart) {
  const actions = reportChartActions(report, chart);
  return `
    <article class="panel report-chart-panel">
      <div class="panel-head">
        <div>
          <h2>${escapeHTML(chart.title || chart.key || "Chart")}</h2>
        </div>
        <div class="panel-tools">
          <span class="pill">${escapeHTML(chart.unit || chart.kind || "")}</span>
          ${actions}
        </div>
      </div>
      <div class="chart-box small-chart">
        <canvas id="${escapeHTML(reportChartID(chart.key))}"></canvas>
      </div>
    </article>
  `;
}

function reportChartActions(report, chart) {
  const key = chart.key || "";
  const summary = report.summary || {};
  const buttons = [];
  const add = (label, pivot) => {
    if (!pivot) return;
    buttons.push(`<button class="ghost mini" type="button" data-pivot='${encodePivot(pivot)}'>${escapeHTML(label)}</button>`);
  };

  if (key === "traffic_timeline") {
    add("Open logs", reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", origin: "report_chart" }));
  } else if (key === "status_mix") {
    add("Open errors", reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", status_class: "errors", origin: "report_chart" }));
  } else if (key === "site_traffic") {
    if (summary.top_site) add("Open top site", reportPivot(report, { kind: "site", value: summary.top_site, site_id: summary.top_site, origin: "report_chart" }));
    add("Open logs", reportPivot(report, { kind: "log_filter", site_id: summary.top_site || report.site_id || "", origin: "report_chart" }));
  } else if (key === "source_ips") {
    const topIP = reportDrilldownItemFor(report, "source_ips", (item) => item.ip === summary.top_source_ip) || reportFirstDrilldownItem(report, "source_ips");
    if (topIP?.ip) add("Open top IP", reportPivot(report, { kind: "ip", value: topIP.ip, site_id: topIP.site_id || report.site_id || "", origin: "report_chart" }));
    if (topIP?.ip) add("Open IP logs", reportPivot(report, { kind: "log_filter", ip: topIP.ip, site_id: topIP.site_id || report.site_id || "", origin: "report_chart" }));
  } else if (key === "user_agent_classes") {
    if (summary.top_user_agent) add("Open UA logs", reportPivot(report, { kind: "log_filter", user_agent: summary.top_user_agent, site_id: report.site_id || "", origin: "report_chart" }));
  } else if (key === "security_signals") {
    add("Open signal", firstReportSignalPivot(report, ["injection_probes", "admin_probes", "tor_sources", "issues"]));
    add("Open security logs", reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", status_class: "errors", origin: "report_chart" }));
  } else if (key === "slow_paths") {
    add("Open slow signal", firstReportSignalPivot(report, ["slow_paths"]));
    if (summary.top_path) add("Open path logs", reportPivot(report, { kind: "log_filter", path: summary.top_path, site_id: report.site_id || "", status_class: "errors", origin: "report_chart" }));
  } else {
    add("Open logs", reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", origin: "report_chart" }));
  }

  return buttons.slice(0, 3).join("");
}

function firstReportSignalPivot(report, keys) {
  for (const key of keys) {
    const item = reportFirstDrilldownItem(report, key);
    if (!item) continue;
    const signalKey = reportSignalKey(key, item);
    if (!signalKey) continue;
    const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    return reportSignalPivot(report, key, item, signalKey, item.site_id || report.site_id || "", errors);
  }
  return null;
}

function reportFirstDrilldownItem(report, key) {
  const drilldown = (report?.drilldowns || []).find((item) => item.key === key);
  return drilldown?.items?.[0] || null;
}

function reportDrilldownItemFor(report, key, predicate) {
  const drilldown = (report?.drilldowns || []).find((item) => item.key === key);
  return (drilldown?.items || []).find(predicate) || null;
}

function reportDrilldownsMarkup(report) {
  const panels = [
    reportDrilldownPanel(report, "source_ips", 10),
    reportDrilldownPanel(report, "issues", 8),
    reportDrilldownPanel(report, "admin_probes", 8),
    reportDrilldownPanel(report, "injection_probes", 8),
    reportDrilldownPanel(report, "tor_sources", 8),
    reportDrilldownPanel(report, "top_paths", 8),
    reportDrilldownPanel(report, "slow_paths", 8),
    reportDrilldownPanel(report, "recent_errors", 8),
  ].filter(Boolean).join("");
  if (panels) return panels;
  return `
    <article class="panel report-empty-panel">
      <div class="empty">No drilldown data stored for this report.</div>
    </article>
  `;
}

function reportDrilldownPanel(report, key, limit) {
  const drilldown = (report.drilldowns || []).find((item) => item.key === key);
  if (!drilldown) return "";
  const items = (drilldown.items || []).slice(0, limit);
  return `
    <article class="panel report-drilldown">
      <div class="panel-head">
        <h2>${escapeHTML(drilldown.title || formatCategory(key))}</h2>
        <span class="pill">${formatNumber(drilldown.items?.length || 0)} rows</span>
      </div>
      <div class="signal-list">
        ${items.map((item, index) => reportDrilldownRow(report, key, item, index)).join("") || `<div class="empty">No rows for this report.</div>`}
      </div>
    </article>
  `;
}

function reportDrilldownRow(report, key, item, index) {
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  const value = reportDrilldownValue(item);
  const meta = reportDrilldownMeta(item, errors);
  const siteID = item.site_id || report.site_id || "";
  const signalKey = reportSignalKey(key, item);
  const detailButtons = `
    ${signalKey ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportSignalPivot(report, key, item, signalKey, siteID, errors))}'>Open signal</button>` : ""}
    ${siteID ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "site", value: siteID, site_id: siteID, origin: "report" }))}'>Open site</button>` : ""}
    ${item.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "ip", value: item.ip, site_id: siteID, origin: "report" }))}'>Open IP</button>` : ""}
    ${item.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "path", value: item.path, site_id: siteID, origin: "report" }))}'>Open path</button>` : ""}
    ${item.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "log_filter", path: item.path, ip: item.ip || "", site_id: siteID, status_class: errors || item.status >= 400 ? "errors" : "", origin: "report" }))}'>Open logs</button>` : ""}
    <button class="ghost mini inline-action" type="button" data-report-detail-key="${escapeHTML(key)}" data-report-detail-index="${index}">Details</button>
  `;
  return `
    <div class="signal-row report-drilldown-row">
      <div>
        <strong>${escapeHTML(item.label || item.ip || item.path || "-")}</strong>
        <span>${escapeHTML(meta)}</span>
        ${detailButtons}
      </div>
      <div class="signal-numbers">
        ${errors ? `<span>${formatNumber(errors)} errors</span>` : ""}
        <b>${escapeHTML(value)}</b>
      </div>
    </div>
  `;
}

function reportSignalKey(key, item) {
  const sourceKind = reportSignalSourceKind(key, item);
  if (!sourceKind) return "";
  const hint = {
    sourceKind,
    siteID: item.site_id || "",
    ip: item.ip || "",
    path: item.path || "",
    title: sourceKind === "issue" ? item.label || "" : "",
    actor: item.actor_value || item.known_actor || "",
    status: item.status || 0,
    category: item.category || "",
  };
  return `report:${encodeReportSignalHint(hint)}`;
}

function encodeReportSignalHint(hint) {
  return btoa(encodeURIComponent(JSON.stringify(hint)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function reportSignalSourceKind(key, item) {
  const kind = String(item.kind || key || "");
  return {
    issue: "issue",
    issues: "issue",
    admin_probe: "adminProbe",
    admin_probes: "adminProbe",
    injection_probe: "injectionProbe",
    injection_probes: "injectionProbe",
    tor_source: "torSource",
    tor_sources: "torSource",
    slow_path: "slowPath",
    slow_paths: "slowPath",
    recent_error: "recentError",
    recent_errors: "recentError",
  }[kind] || "";
}

function reportSignalPivot(report, key, item, signalKey, siteID, errors) {
  return reportPivot(report, {
    kind: "signal",
    key: signalKey,
    site_id: siteID,
    ip: item.ip || "",
    path: item.path || "",
    known_actor: item.actor_value || item.known_actor || "",
    status_class: errors || Number(item.status || 0) >= 400 ? "errors" : "",
    origin: "report",
    report_tab: reportTabForReport(report),
  });
}

function reportDrilldownValue(item) {
  if (item.status) return String(item.status);
  if (item.p95_request_time_ms) return formatMs(item.p95_request_time_ms);
  if (item.score) return String(item.score);
  if (item.risk_score) return `risk ${item.risk_score}`;
  return formatNumber(item.requests || item.events || 0);
}

function reportDrilldownMeta(item, errors) {
  const parts = [];
  if (item.site_id) parts.push(item.env ? `${item.site_id}/${item.env}` : item.site_id);
  if (item.category) parts.push(formatCategory(item.category));
  if (item.match_reason) parts.push(formatCategory(item.match_reason));
  if (item.meta) parts.push(item.meta);
  if (item.known_actor) parts.push(item.known_actor);
  if (item.requests) parts.push(`${formatNumber(item.requests)} requests`);
  if (item.total_ip_hits) parts.push(`${formatNumber(item.total_ip_hits)} IP hits`);
  if (errors) parts.push(`${formatNumber(errors)} errors`);
  const when = item.last_seen || item.timestamp;
  if (when) parts.push(formatTime(when));
  return parts.filter(Boolean).join(" - ");
}

function renderSystem() {
  const credentials = state.data.credentials || {};
  const summary = credentials.summary || {};
  const collector = state.data.collectorHealth || {};
  const rawStats = collector.raw_files?.stats || {};
  const retention = state.data.retention || {};
  const overview = state.data.overview || {};

  setText("#credentialState", summary.ssh_key_configured ? "ready" : "missing SSH");
  qs("#credentialFacts").innerHTML = facts([
    ["Database", overview.database_configured ? "On" : "Off"],
    ["Collection", `${overview.collection_enabled ? "On" : "Off"} / ${overview.collection_interval || "-"}`],
    ["Downloaded raw files", formatNumber(rawStats.downloaded || 0)],
    ["Pending raw files", formatNumber(rawStats.discovered || 0)],
    ["SSH key", summary.ssh_key_configured ? "Configured" : "Missing"],
    ["Machine token", summary.machine_token_configured ? "Configured" : "Optional"],
  ]);

  qs("#retentionFacts").innerHTML = facts([
    ["Enabled", retention.enabled ? "Yes" : "No"],
    ["Max age", retention.max_age || overview.retention_max_age || "-"],
    ["Cutoff", formatTime(retention.cutoff)],
    ["Raw files matched", formatNumber(retention.raw_files_matched || 0)],
    ["Segments matched", formatNumber(retention.combined_segments_matched || 0)],
    ["Events matched", formatNumber(retention.access_events_matched || 0)],
  ]);

  renderJobs();
  renderSegments();
}

function renderNotifications() {
  const notifications = state.data.notifications || {};
  const webPush = state.data.webPush || {};
  const channels = notifications.channels || [];
  const recent = notifications.recent || [];
  const browserPushAvailable = Boolean(webPush.enabled && webPush.configured && webPush.public_key);
  setText("#browserPushState", browserPushAvailable ? `${formatNumber(webPush.active_subscriptions || 0)} browser subscriptions` : "Browser push unavailable");
  qs("#enableBrowserPushButton").disabled = !browserPushAvailable || !browserPushSupported();
  qs("#disableBrowserPushButton").disabled = !browserPushSupported();
  qs("#notificationFacts").innerHTML = facts([
    ["Enabled", notifications.enabled ? "Yes" : "No"],
    ["Minimum severity", notifications.min_severity || "-"],
    ["Browser push", webPush.configured ? `${formatNumber(webPush.active_subscriptions || 0)} active subscriptions` : "Not configured"],
    ...channels.map((channel) => [
      channel.name,
      `${channel.enabled ? "enabled" : "disabled"} / ${channel.configured ? "configured" : "not configured"}${channel.targets?.length ? ` / ${channel.targets.join(", ")}` : ""}`,
    ]),
  ]);
  qs("#notificationsTable").innerHTML = recent.map((item) => `
    <tr>
      <td>${escapeHTML(item.channel || "-")}</td>
      <td>${escapeHTML(item.target || "-")}</td>
      <td><span class="status-${escapeHTML(item.status || "pending")}">${escapeHTML(item.status || "pending")}</span></td>
      <td><strong>${escapeHTML(item.title || "-")}</strong><br><span>${escapeHTML(item.error || item.severity || "")}</span></td>
      <td>${formatTime(item.created_at)}</td>
    </tr>
  `).join("") || emptyRow(5, "No notification deliveries yet.");
}

function renderJobs() {
  const jobs = state.data.jobs || [];
  renderPager("#jobsPager", "jobs", jobs);
  const rows = paginate("jobs", jobs).map((job) => `
    <tr>
      <td><strong>${escapeHTML(job.type || "-")}</strong></td>
      <td><span class="status-${escapeHTML(job.status || "pending")}">${escapeHTML(job.status || "pending")}</span></td>
      <td>${escapeHTML(job.message || job.last_error || "")}</td>
      <td>${formatTime(job.started_at || job.created_at)}</td>
    </tr>
  `);
  qs("#jobsTable").innerHTML = rows.join("") || emptyRow(4, "No jobs have run yet.");
}

function renderSegments() {
  const segments = state.data.segments || [];
  renderPager("#segmentsPager", "segments", segments);
  const rows = paginate("segments", segments).map((segment) => `
    <tr>
      <td><strong>${formatTime(segment.bucket_start)}</strong><br><span>${formatTime(segment.bucket_end)}</span></td>
      <td><span class="status-${escapeHTML(segment.status || "pending")}">${escapeHTML(segment.status || "pending")}</span></td>
      <td>${formatNumber(segment.line_count || segment.lines_combined || 0)}</td>
      <td>${formatTime(segment.indexed_at)}</td>
    </tr>
  `);
  qs("#segmentsTable").innerHTML = rows.join("") || emptyRow(4, "No combined segments found.");
}

function renderUsers() {
  const users = state.data.users || [];
  renderPager("#usersPager", "users", users);
  const rows = paginate("users", users).map((user) => {
    const disabled = state.currentUser?.id === user.id || !user.is_active ? "disabled" : "";
    return `
      <tr>
        <td><strong>${escapeHTML(user.display_name || user.email)}</strong><br><span>${escapeHTML(user.email)}</span></td>
        <td>${escapeHTML(user.role || "user")}</td>
        <td>${user.is_active ? "active" : "inactive"}</td>
        <td>${formatTime(user.last_login_at)}</td>
        <td class="row-actions"><button class="ghost small" type="button" data-user-delete="${escapeHTML(user.id)}" ${disabled}>Deactivate</button></td>
      </tr>
    `;
  });
  qs("#usersTable").innerHTML = rows.join("") || emptyRow(5, "No users found.");
}

function renderCharts() {
  drawTimeline(qs("#timelineChart"), state.data.traffic?.timeline || []);
  const logTimeline = state.logType === "nginx-access" ? logTimelineRows(filteredLogEvidence()) : logSegmentTimelineRows();
  drawTimeline(qs("#logsTimelineChart"), logTimeline, state.logType === "nginx-access" ? ["requests", "errors"] : ["lines", "pending"]);
  drawStatus(qs("#statusChart"), state.data.analysis?.status_breakdown || []);
  drawSites(qs("#siteChart"), state.data.analysis?.sites || []);
  drawSourceIPs(qs("#sourceChart"), state.data.analysis?.source_ips || []);
  drawAgentClasses(qs("#agentChart"), state.data.analysis?.user_agents || []);
  drawReportCharts();
}

function drawTimeline(canvas, timeline, labels = ["requests", "errors"]) {
  const chart = setupCanvas(canvas);
  if (!chart) return;
  const { ctx, width, height } = chart;
  const rows = [...timeline].sort((a, b) => new Date(a.bucket_ts) - new Date(b.bucket_ts)).slice(-90);
  drawFrame(ctx, width, height);
  if (!rows.length) {
    drawEmptyChart(ctx, width, height);
    return;
  }
  const maxValue = Math.max(1, ...rows.map((item) => item.value || item.requests || 0));
  const maxSecondary = Math.max(1, ...rows.map((item) => item.secondary ?? ((item.status_4xx || 0) + (item.status_5xx || 0))));
  drawLine(ctx, rows.map((item) => item.requests || 0), maxValue, width, height, "#2364aa", 2);
  drawLine(ctx, rows.map((item) => item.secondary ?? ((item.status_4xx || 0) + (item.status_5xx || 0))), maxSecondary, width, height, "#b93232", 2);
  drawLegend(ctx, [[labels[0] || "requests", "#2364aa"], [labels[1] || "errors", "#b93232"]], width);
}

function drawStatus(canvas, rows) {
  const chart = setupCanvas(canvas);
  if (!chart) return;
  const { ctx, width, height } = chart;
  const groups = [
    { label: "2xx", value: sumStatus(rows, 200, 299), color: "#178a5f" },
    { label: "3xx", value: sumStatus(rows, 300, 399), color: "#2364aa" },
    { label: "4xx", value: sumStatus(rows, 400, 499), color: "#a96216" },
    { label: "5xx", value: sumStatus(rows, 500, 599), color: "#b93232" },
  ];
  const total = groups.reduce((sum, item) => sum + item.value, 0);
  drawFrame(ctx, width, height);
  if (!total) {
    drawEmptyChart(ctx, width, height);
    return;
  }
  const barWidth = Math.max(24, (width - 72) / groups.length);
  groups.forEach((item, index) => {
    const barHeight = Math.max(2, (height - 58) * (item.value / total));
    const x = 34 + index * barWidth;
    const y = height - 34 - barHeight;
    ctx.fillStyle = item.color;
    ctx.fillRect(x, y, barWidth - 12, barHeight);
    ctx.fillStyle = "#64707d";
    ctx.font = "12px sans-serif";
    ctx.fillText(item.label, x, height - 14);
  });
}

function drawSites(canvas, sites) {
  const rows = sites.slice(0, 8).map((item) => ({
    label: item.site_id || "site",
    value: item.requests || 0,
    color: item.status_5xx_rate >= 0.02 ? "#b93232" : "#178a5f",
  }));
  drawBars(canvas, rows);
}

function drawSourceIPs(canvas, items) {
  const rows = items.slice(0, 8).map((item) => ({
    label: item.ip || "unknown",
    value: item.requests || 0,
    color: item.verified_source ? "#178a5f" : item.status_5xx > 0 ? "#b93232" : "#2364aa",
  }));
  drawBars(canvas, rows);
}

function drawAgentClasses(canvas, agents) {
  drawBars(canvas, aggregateAgentClasses(agents), {
    colors: {
      browser: "#178a5f",
      crawler: "#2364aa",
      tool: "#a96216",
      monitor: "#0f766e",
      missing: "#b93232",
      unknown: "#64707d",
    },
  });
}

function drawReportCharts() {
  const report = currentReport();
  (report?.charts || []).forEach((chart) => {
    const canvas = document.getElementById(reportChartID(chart.key));
    if (!canvas) return;
    if (chart.kind === "line") {
      drawReportLine(canvas, chart);
      return;
    }
    drawBars(canvas, (chart.data || []).map((item) => ({
      label: item.label || "",
      value: item.value || 0,
      color: item.color || "#2364aa",
    })));
  });
}

function drawReportLine(canvas, chart) {
  const frame = setupCanvas(canvas);
  if (!frame) return;
  const { ctx, width, height } = frame;
  const rows = [...(chart.data || [])].sort((a, b) => new Date(a.timestamp || 0) - new Date(b.timestamp || 0));
  drawFrame(ctx, width, height);
  if (!rows.length) {
    drawEmptyChart(ctx, width, height);
    return;
  }
  const primary = rows.map((item) => Number(item.value || 0));
  const secondary = rows.map((item) => Number(item.secondary || 0));
  drawLine(ctx, primary, Math.max(1, ...primary), width, height, "#2364aa", 2);
  drawLine(ctx, secondary, Math.max(1, ...secondary), width, height, "#b93232", 2);
  drawLegend(ctx, [["requests", "#2364aa"], ["errors", "#b93232"]], width);
}

function currentReport() {
  return selectedReportFromList(reportsForCurrentTab(state.data.reports || []));
}

function reportChartID(key) {
  return `reportChart_${String(key || "chart").replace(/[^a-zA-Z0-9_-]/g, "_")}`;
}

function drawBars(canvas, rows, options = {}) {
  const chart = setupCanvas(canvas);
  if (!chart) return;
  const { ctx, width, height } = chart;
  drawFrame(ctx, width, height);
  if (!rows.length) {
    drawEmptyChart(ctx, width, height);
    return;
  }
  const maxValue = Math.max(1, ...rows.map((item) => item.value || item.requests || 0));
  const labelWidth = Math.min(118, Math.max(76, width * 0.34));
  const valueWidth = 52;
  const barLeft = labelWidth + 10;
  const barMax = Math.max(20, width - barLeft - valueWidth - 18);
  const rowHeight = Math.min(26, (height - 46) / rows.length);
  rows.forEach((item, index) => {
    const value = item.value || item.requests || 0;
    const label = shortLabel(item.label || item.site_id || "", Math.max(8, Math.floor(labelWidth / 7)));
    const y = 24 + index * rowHeight;
    const barWidth = barMax * (value / maxValue);
    const color = item.color || options.colors?.[item.key || item.label] || "#2364aa";
    ctx.fillStyle = "#e8edf3";
    ctx.fillRect(barLeft, y, barMax, 12);
    ctx.fillStyle = color;
    ctx.fillRect(barLeft, y, barWidth, 12);
    ctx.fillStyle = "#1d252d";
    ctx.font = "12px sans-serif";
    ctx.fillText(label, 12, y + 10);
    ctx.fillStyle = "#64707d";
    ctx.fillText(compactNumber(value), barLeft + barMax + 8, y + 10);
  });
}

function setupCanvas(canvas) {
  if (!canvas) return null;
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height) return null;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.floor(rect.width * dpr);
  canvas.height = Math.floor(rect.height * dpr);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, rect.width, rect.height);
  return { ctx, width: rect.width, height: rect.height };
}

function drawFrame(ctx, width, height) {
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, width, height);
  ctx.strokeStyle = "#d9dee5";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(28, 18);
  ctx.lineTo(28, height - 28);
  ctx.lineTo(width - 16, height - 28);
  ctx.stroke();
}

function drawLine(ctx, values, maxValue, width, height, color, lineWidth) {
  const left = 28;
  const right = width - 16;
  const top = 18;
  const bottom = height - 28;
  ctx.strokeStyle = color;
  ctx.lineWidth = lineWidth;
  ctx.beginPath();
  values.forEach((value, index) => {
    const x = left + ((right - left) * index) / Math.max(1, values.length - 1);
    const y = bottom - ((bottom - top) * value) / maxValue;
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

function drawLegend(ctx, items, width) {
  let x = width - 170;
  items.forEach(([label, color]) => {
    ctx.fillStyle = color;
    ctx.fillRect(x, 14, 10, 10);
    ctx.fillStyle = "#64707d";
    ctx.font = "12px sans-serif";
    ctx.fillText(label, x + 14, 23);
    x += 78;
  });
}

function drawEmptyChart(ctx, width, height) {
  ctx.fillStyle = "#64707d";
  ctx.font = "13px sans-serif";
  ctx.fillText("No data", width / 2 - 24, height / 2);
}

function sumStatus(rows, low, high) {
  return rows.reduce((sum, item) => {
    const status = Number(item.status || 0);
    if (status >= low && status <= high) return sum + Number(item.requests || 0);
    return sum;
  }, 0);
}

function aggregateAgentClasses(agents) {
  const groups = new Map();
  (agents || []).forEach((item) => {
    const key = item.actor_type || "unknown";
    const existing = groups.get(key) || { key, label: key, value: 0 };
    existing.value += Number(item.requests || 0);
    groups.set(key, existing);
  });
  return Array.from(groups.values()).sort((a, b) => b.value - a.value).slice(0, 8);
}

function shortLabel(value, maxLength) {
  const text = String(value || "");
  if (text.length <= maxLength) return text;
  return `${text.slice(0, Math.max(1, maxLength - 3))}...`;
}

function compactNumber(value) {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(Number(value || 0));
}

async function login(event) {
  event.preventDefault();
  setText("#loginError", "");
  const button = event.currentTarget.querySelector("button");
  button.disabled = true;
  try {
    const result = await fetchJSON("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email: qs("#emailInput").value,
        password: qs("#passwordInput").value,
      }),
    });
    state.currentUser = result.user || null;
    showApp();
    await refreshAll();
  } catch (error) {
    setText("#loginError", error.message);
  } finally {
    button.disabled = false;
  }
}

async function logout() {
  await fetchJSON("/api/v1/auth/logout", { method: "POST" });
  state.currentUser = null;
  showLogin();
}

async function createUser(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button");
  await runAction(button, "User created", async () => {
    await fetchJSON("/api/v1/users", {
      method: "POST",
      body: JSON.stringify({
        email: qs("#newUserEmail").value,
        display_name: qs("#newUserDisplay").value,
        password: qs("#newUserPassword").value,
      }),
    });
    qs("#userForm").reset();
  });
}

async function handleManualIntelAction(button) {
  const ip = button.dataset.ipIntelIp || "";
  const action = button.dataset.ipIntelAction || "";
  const siteID = button.dataset.ipIntelSite || state.viewContext.site_id || state.siteID || "";
  if (!ip) return;
  button.disabled = true;
  try {
    const manualAction = action === "clear" ? "" : action;
    const detail = await fetchJSON(`/api/v1/investigate/ip/${encodeURIComponent(ip)}/manual-intel?${buildFilterQuery({ limit: 30, site_id: siteID })}`, {
      method: "PATCH",
      body: JSON.stringify({
        manual_action: manualAction,
        manual_label: manualAction ? button.dataset.ipIntelLabel || manualActionDefaultLabel(manualAction) : "",
      }),
    });
    updateLocalIPManualIntel(ip, detail.stored_intel || {}, manualAction);
    if (state.entity?.kind === "ip" && state.entity.value === ip) {
      state.entityDetails[entityKey(state.entity)] = detail;
    }
    toast(manualAction ? `IP marked ${formatManualAction(manualAction).toLowerCase()}` : "IP manual label cleared");
    render();
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

function updateLocalIPManualIntel(ip, stored = {}, fallbackAction = "") {
  const action = stored.manual_action || fallbackAction || "";
  const label = stored.manual_label || (action ? manualActionDefaultLabel(action) : "");
  (state.data.analysis?.source_ips || []).forEach((item) => {
    if (item.ip !== ip) return;
    item.manual_action = action;
    item.manual_label = label;
    if (action === "verified") {
      item.verified_actor = true;
      item.verified_source = true;
    }
    if (action === "suspicious") {
      item.risk_score = Math.max(Number(item.risk_score || 0), Number(stored.risk_score || 80));
    }
  });
}

async function enableBrowserPush() {
  if (!browserPushSupported()) {
    throw new Error("Browser push is not supported by this browser");
  }
  const webPush = state.data.webPush?.public_key ? state.data.webPush : await fetchJSON("/api/v1/notifications/web-push/public-key");
  if (!webPush.enabled || !webPush.configured || !webPush.public_key) {
    throw new Error("Browser push is not configured");
  }
  const permission = await Notification.requestPermission();
  if (permission !== "granted") {
    throw new Error("Notification permission was not granted");
  }
  const registration = await navigator.serviceWorker.register("/sw.js");
  const existing = await registration.pushManager.getSubscription();
  if (existing) {
    await fetchJSON("/api/v1/notifications/web-push/subscribe", {
      method: "POST",
      body: JSON.stringify(existing),
    });
    return;
  }
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
  const registration = await navigator.serviceWorker.getRegistration("/sw.js");
  const subscription = await registration?.pushManager.getSubscription();
  if (subscription) {
    await fetchJSON("/api/v1/notifications/web-push/subscribe", {
      method: "DELETE",
      body: JSON.stringify({ endpoint: subscription.endpoint }),
    });
    await subscription.unsubscribe();
  }
}

function browserPushSupported() {
  return "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
}

function urlBase64ToUint8Array(value) {
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = (value + padding).replaceAll("-", "+").replaceAll("_", "/");
  const raw = atob(base64);
  const output = new Uint8Array(raw.length);
  for (let index = 0; index < raw.length; index += 1) {
    output[index] = raw.charCodeAt(index);
  }
  return output;
}

async function runAction(button, successMessage, fn, refreshAfter = true) {
  button.disabled = true;
  try {
    await fn();
    toast(successMessage);
    if (refreshAfter) await refreshAll();
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

function showLogin() {
  qs("#loginView").classList.remove("hidden");
  qs(".shell").classList.add("hidden");
}

function showApp() {
  qs("#loginView").classList.add("hidden");
  qs(".shell").classList.remove("hidden");
}

function showRoute(route, push) {
  route = normalizeRoute(route);
  state.route = route;
  qsa("[data-view]").forEach((view) => view.classList.toggle("hidden", view.dataset.view !== route));
  qsa("[data-route]").forEach((link) => link.classList.toggle("active", link.dataset.route === route));
  setText("#pageTitle", routes[route].title);
  updateURL(Boolean(push));
  renderWorkspaceContext();
  requestAnimationFrame(() => renderCharts());
}

function routeFromPath(path) {
  const cleaned = path.replace(/^\/+/, "").split("/")[0];
  return normalizeRoute(cleaned || "overview");
}

function normalizeRoute(route) {
  const key = routeAliases[route] || route;
  return routes[key] ? key : "overview";
}

function encodePivot(pivot) {
  return escapeHTML(JSON.stringify(pivot || {}));
}

function decodePivot(value) {
  try {
    return JSON.parse(value || "{}");
  } catch {
    return {};
  }
}

async function handlePivot(pivot) {
  if (!pivot?.kind) return;
  const needsRefresh = applyPivotWindow(pivot);
  if (pivot.kind === "site" && (pivot.value || pivot.site_id)) {
    state.siteID = pivot.value || pivot.site_id || "";
    state.viewContext = {};
    state.signalKey = "";
    resetContextPages();
    showRoute("sites", true);
    await refreshWithValidation();
    return;
  }
  if (pivot.kind === "report") {
    state.reportTab = pivot.report_tab || state.reportTab || "daily";
    if (pivot.value) state.selectedReportIDs[state.reportTab] = pivot.value;
    if (pivot.site_id) state.siteID = pivot.site_id;
    state.viewContext = {};
    state.signalKey = "";
    resetContextPages();
    showRoute("reports", true);
    if (needsRefresh) await refreshWithValidation();
    else {
      renderReports();
      requestAnimationFrame(drawReportCharts);
    }
    return;
  }
  state.viewContext = pivotContext(pivot);
  if (isReportPivotOrigin(pivot) && pivot.site_id) {
    state.siteID = pivot.site_id;
  }
  resetContextPages();
  if (pivot.kind === "signal") {
    state.signalKey = pivot.key || pivot.value || "";
    state.entity = null;
    const signal = findSignalByKey(state.signalKey);
    if (signal) state.viewContext = signalContext(signal);
    showRoute("signals", true);
    if (needsRefresh) await refreshWithValidation();
    else renderSignals();
    return;
  }
  if (pivot.kind === "ip") {
    state.signalKey = "";
    state.entity = { kind: "ip", value: pivot.value };
    showRoute("investigate", true);
    if (needsRefresh) await refreshWithValidation();
    else renderInvestigate();
    await showIPDetailByValue(pivot.value, pivot);
    return;
  }
  if (pivot.kind === "actor") {
    state.signalKey = "";
    state.entity = { kind: "actor", value: pivot.value };
    showRoute("investigate", true);
    if (needsRefresh) await refreshWithValidation();
    else renderInvestigate();
    showActorDetail(pivot);
    return;
  }
  if (pivot.kind === "path") {
    state.signalKey = "";
    state.entity = { kind: "path", value: pivot.value || pivot.path || "/" };
    showRoute("investigate", true);
    if (needsRefresh) await refreshWithValidation();
    else renderInvestigate();
    return;
  }
  if (pivot.kind === "log_filter") {
    state.entity = null;
    state.signalKey = "";
    showRoute("logs", true);
    if (needsRefresh) await refreshWithValidation();
    else renderLogs();
  }
}

function applyPivotWindow(pivot) {
  let changed = false;
  if (pivot.range) {
    if (state.range !== pivot.range) changed = true;
    state.range = pivot.range;
  }
  if (pivot.from) {
    const next = dateToLocalInput(new Date(pivot.from));
    if (state.from !== next) changed = true;
    state.from = next;
  }
  if (pivot.to) {
    const next = dateToLocalInput(new Date(pivot.to));
    if (state.to !== next) changed = true;
    state.to = next;
  }
  if (pivot.log_type) {
    if (state.logType !== pivot.log_type) changed = true;
    state.logType = pivot.log_type;
  }
  if (pivot.site_id && pivot.kind !== "site" && state.siteID !== pivot.site_id) {
    changed = true;
    state.siteID = pivot.site_id;
  }
  return changed;
}

function isReportPivotOrigin(pivot) {
  return pivot?.origin === "report" || pivot?.origin === "report_chart";
}

function pivotContext(pivot) {
  const context = {};
  ["ip", "path", "known_actor", "actor_type", "status_class", "site_id", "user_agent"].forEach((key) => {
    if (pivot[key]) context[key] = pivot[key];
  });
  if (pivot.kind === "ip" && pivot.value) context.ip = pivot.value;
  if (pivot.kind === "actor" && pivot.value) context.known_actor = pivot.value;
  return context;
}

function resetContextPages() {
  ["sourceIPs", "userAgents", "sites", "signals", "logEvidence"].forEach((key) => {
    state.pages[key] = 0;
  });
}

function showSignalDetail(key) {
  const item = buildSignalItems().find((candidate) => candidate.key === key);
  if (!item) return;
  renderDetail({
    eyebrow: `${formatCategory(item.group || "Signal")} signal`,
    title: item.title || "Signal",
    facts: [
      ["Severity", item.severity || "-"],
      ["Risk", item.risk || "-"],
      ["Requests", formatNumber(item.requests || 0)],
      ["Errors", formatNumber(item.errors || 0)],
      ["Source IP", item.ip || "-"],
      ["Site", item.siteID ? `${item.siteID}${item.env ? ` / ${item.env}` : ""}` : "-"],
      ["Path", item.path || "-"],
      ["Last seen", formatTime(item.lastSeen)],
      ["Summary", item.summary || "-"],
    ],
    details: item.details ? JSON.stringify(item.details, null, 2) : "",
  });
  qs("#detailDrawer").classList.remove("hidden");
}

async function showIPDetailByValue(ip, pivot = {}) {
  if (!ip) return;
  const item = (state.data.analysis?.source_ips || []).find((candidate) => candidate.ip === ip) || { ip, site_id: pivot.site_id || "" };
  renderDetail({
    eyebrow: "Source IP",
    title: ip,
    facts: [
      ["Site", pivot.site_id || item.site_id || "-"],
      ["Requests", formatNumber(item.requests || 0)],
      ["Risk", item.risk_score === undefined ? "-" : item.risk_score],
    ],
    sections: [{ title: "Lookup", text: "Loading DNS, ASN, Whois, URLs, and recent requests..." }],
  });
  qs("#detailDrawer").classList.remove("hidden");
  try {
    const detail = await fetchJSON(`/api/v1/investigate/ip/${encodeURIComponent(ip)}?${buildFilterQuery({ limit: 30, site_id: pivot.site_id || state.viewContext.site_id || "" })}`);
    renderDetail(sourceIPDetailFor(item, detail));
  } catch (error) {
    renderDetail({
      eyebrow: "Source IP",
      title: ip,
      facts: [["Lookup failed", error.message]],
    });
  }
}

function showActorDetail(pivot) {
  const actors = aggregateActors();
  const actor = actors.find((item) => item.label === pivot.value && (!pivot.actor_type || item.type === pivot.actor_type));
  if (!actor) return;
  const ips = Array.from(contextActorIPs({ known_actor: actor.label, actor_type: actor.type }));
  renderDetail({
    eyebrow: "Known actor or service",
    title: actor.label,
    facts: [
      ["Type", formatCategory(actor.type || "-")],
      ["Requests", formatNumber(actor.requests || 0)],
      ["Errors", formatNumber(actor.errors || 0)],
      ["Source IPs", formatNumber(actor.ips || ips.length)],
      ["Risk", actor.risk || "-"],
      ["Last seen", formatTime(actor.lastSeen)],
    ],
    sections: [{
      title: "Known IPs in scope",
      items: ips.slice(0, 25).map((ip) => ({ title: ip, meta: actor.label, value: "" })),
      empty: "No IPs found for this actor in the current window.",
    }],
  });
  qs("#detailDrawer").classList.remove("hidden");
}

function renderUserBadge() {
  const badge = qs("#userBadge");
  const logoutButton = qs("#logoutButton");
  if (!state.currentUser) {
    badge.classList.add("hidden");
    logoutButton.classList.add("hidden");
    return;
  }
  badge.textContent = state.currentUser.display_name || state.currentUser.email;
  badge.classList.remove("hidden");
  logoutButton.classList.remove("hidden");
}

function renderPager(selector, key, items) {
  const container = qs(selector);
  if (!container) return;
  const size = pageSize[key] || 10;
  const page = clampNumber(state.pages[key] || 0, 0, Math.max(0, Math.ceil(items.length / size) - 1));
  state.pages[key] = page;
  const maxPage = Math.max(0, Math.ceil(items.length / size) - 1);
  container.innerHTML = `
    <button class="ghost mini" type="button" data-page-key="${key}" data-page-delta="-1" ${page <= 0 ? "disabled" : ""}>Prev</button>
    <span>${items.length ? page + 1 : 0}/${items.length ? maxPage + 1 : 0}</span>
    <button class="ghost mini" type="button" data-page-key="${key}" data-page-delta="1" ${page >= maxPage ? "disabled" : ""}>Next</button>
  `;
}

function paginate(key, items) {
  const size = pageSize[key] || 10;
  const page = state.pages[key] || 0;
  return items.slice(page * size, page * size + size);
}

function paginateWithIndex(key, items) {
  const size = pageSize[key] || 10;
  const page = state.pages[key] || 0;
  const start = page * size;
  return items.slice(start, start + size).map((item, offset) => ({ item, index: start + offset }));
}

async function showDetail(kind, index) {
  const detail = detailFor(kind, index);
  if (!detail) return;
  renderDetail(detail);
  qs("#detailDrawer").classList.remove("hidden");
  if (kind === "sourceIP") {
    await enrichSourceIPDetail(index);
  }
}

async function showReportSourceIPDetail(ip) {
  if (!ip) return;
  const report = currentReport();
  const item = reportDrilldownItem("source_ips", (candidate) => candidate.ip === ip)
    || reportDrilldownItem("admin_probes", (candidate) => candidate.ip === ip)
    || reportDrilldownItem("injection_probes", (candidate) => candidate.ip === ip)
    || reportDrilldownItem("tor_sources", (candidate) => candidate.ip === ip)
    || { ip, label: ip };
  renderDetail({
    eyebrow: "Report source IP",
    title: ip,
    facts: [
      ["Report", report ? `${reportPeriodLabel(reportTabForReport(report))} / ${report.range || "-"}` : "-"],
      ["Requests", formatNumber(item.requests || 0)],
      ["Errors", formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))],
    ],
    sections: [{ title: "Lookup", text: "Loading DNS, ASN, Whois, URLs, and recent requests..." }],
  });
  qs("#detailDrawer").classList.remove("hidden");
  try {
    const detail = await fetchJSON(`/api/v1/investigate/ip/${encodeURIComponent(ip)}?${reportDetailQuery(report)}`);
    renderDetail(sourceIPDetailFor(item, detail));
  } catch (error) {
    renderDetail({
      eyebrow: "Report source IP",
      title: ip,
      facts: [["Lookup failed", error.message]],
    });
  }
}

function showReportDrilldownDetail(key, index) {
  const report = currentReport();
  const drilldown = (report?.drilldowns || []).find((item) => item.key === key);
  const item = drilldown?.items?.[index];
  if (!item) return;
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  renderDetail({
    eyebrow: drilldown.title || "Report drilldown",
    title: item.label || item.ip || item.path || "Detail",
    facts: [
      ["Kind", formatCategory(item.kind || key)],
      ["Site", item.site_id ? `${item.site_id}${item.env ? ` / ${item.env}` : ""}` : "-"],
      ["Source IP", item.ip || "-"],
      ["Category", formatCategory(item.category || "-")],
      ["Reason", formatCategory(item.match_reason || "-")],
      ["Requests", formatNumber(item.requests || 0)],
      ["IP hits", formatNumber(item.total_ip_hits || 0)],
      ["Errors", formatNumber(errors)],
      ["Risk", item.risk_score || item.score || "-"],
      ["Last seen", formatTime(item.last_seen || item.timestamp)],
    ],
    sections: [
      item.path || item.query ? {
        title: "Request",
        facts: [
          ["Method", item.method || "-"],
          ["Path", item.path || "-"],
          ["Query", item.query || "-"],
          ["Status", item.status || "-"],
        ],
      } : null,
      item.meta ? { title: "Context", text: item.meta } : null,
    ].filter(Boolean),
    details: item.details ? JSON.stringify(item.details, null, 2) : "",
  });
  qs("#detailDrawer").classList.remove("hidden");
}

function renderDetail(detail) {
  setText("#detailEyebrow", detail.eyebrow);
  setText("#detailTitle", detail.title);
  qs("#detailBody").innerHTML = `
    <dl class="facts">${facts(detail.facts)}</dl>
    ${detailSections(detail.sections || [])}
    ${detail.details ? `<pre>${escapeHTML(detail.details)}</pre>` : ""}
  `;
}

function hideDetail() {
  qs("#detailDrawer").classList.add("hidden");
}

function reportDrilldownItem(key, predicate) {
  const report = currentReport();
  const drilldown = (report?.drilldowns || []).find((item) => item.key === key);
  return (drilldown?.items || []).find(predicate);
}

function reportDetailQuery(report) {
  const params = new URLSearchParams();
  params.set("limit", "30");
  if (report?.range_start && report?.range_end) {
    params.set("range", "custom");
    params.set("from", new Date(report.range_start).toISOString());
    params.set("to", new Date(report.range_end).toISOString());
  } else {
    params.set("range", report?.range || "24h");
  }
  if (report?.site_id) params.set("site_id", report.site_id);
  return params.toString();
}

function detailFor(kind, index) {
  if (kind === "issue") {
    const item = state.data.analysis?.issues?.[index];
    if (!item) return null;
    return {
      eyebrow: "Detected issue",
      title: item.title || item.rule_key || "Issue",
      facts: [
        ["Severity", item.severity || "-"],
        ["Actor", item.actor_value || item.actor_type || "-"],
        ["Site", item.site_id || "-"],
        ["Requests", formatNumber(item.requests || 0)],
        ["Last seen", formatTime(item.last_seen)],
        ["Summary", item.summary || "-"],
      ],
      details: item.evidence ? JSON.stringify(item.evidence, null, 2) : item.details ? JSON.stringify(item.details, null, 2) : "",
    };
  }
  if (kind === "sourceIP") {
    const item = state.data.analysis?.source_ips?.[index];
    if (!item) return null;
    return {
      eyebrow: "Source IP",
      title: item.ip || "Source IP",
      facts: [
        ["Requests", formatNumber(item.requests || 0)],
        ["Errors", formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))],
        ["4xx", formatNumber(item.status_4xx || 0)],
        ["5xx", formatNumber(item.status_5xx || 0)],
        ["Reverse DNS", item.reverse_dns || "-"],
        ["Known actor", item.known_actor || "-"],
        ["Actor type", item.actor_type || "-"],
        ["Verified source", item.verified_source ? "Yes" : "No"],
        ["Manual action", formatManualAction(item.manual_action)],
        ["Manual label", item.manual_label || "-"],
        ["Risk", item.risk_score === undefined ? "-" : item.risk_score],
        ["Last seen", formatTime(item.last_seen)],
      ],
      sections: [{ title: "Lookup", text: "Loading DNS, ASN, RDAP, and traffic detail..." }],
    };
  }
  if (kind === "userAgent") {
    const item = state.data.analysis?.user_agents?.[index];
    if (!item) return null;
    return {
      eyebrow: "User agent",
      title: item.family || "Unknown user agent",
      facts: [
        ["Requests", formatNumber(item.requests || 0)],
        ["Unique IPs", formatNumber(item.unique_ips || 0)],
        ["Errors", formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))],
        ["Actor type", item.actor_type || "-"],
        ["Risk", item.risk_score === undefined ? "-" : item.risk_score],
        ["Last seen", formatTime(item.last_seen)],
        ["Sample", item.sample || "(empty)"],
      ],
    };
  }
  if (kind === "adminProbe" || kind === "injectionProbe") {
    const collection = kind === "adminProbe" ? state.data.analysis?.admin_probes : state.data.analysis?.injection_probes;
    const item = collection?.[index];
    if (!item) return null;
    return {
      eyebrow: kind === "adminProbe" ? "Admin probe" : "Injection probe",
      title: `${item.method || "GET"} ${item.path || "/"}`,
      facts: [
        ["Category", formatCategory(item.category || "-")],
        ["Source IP", item.ip || "-"],
        ["Site", item.site_id || "-"],
        ["Environment", item.env || "-"],
        ["Reason", formatCategory(item.match_reason || "-")],
        ["Requests", formatNumber(item.requests || 0)],
        ["IP hits", formatNumber(item.total_ip_hits || item.requests || 0)],
        ["4xx", formatNumber(item.status_4xx || 0)],
        ["5xx", formatNumber(item.status_5xx || 0)],
        ["Risk", item.risk_score || 0],
        ["First seen", formatTime(item.first_seen)],
        ["Last seen", formatTime(item.last_seen)],
        ["Query", item.sample_query || "-"],
      ],
      details: item.evidence ? JSON.stringify(item.evidence, null, 2) : "",
    };
  }
  if (kind === "torSource") {
    const item = state.data.analysis?.tor_sources?.[index];
    if (!item) return null;
    return {
      eyebrow: "Tor source",
      title: item.ip || "Tor source",
      facts: [
        ["Requests", formatNumber(item.requests || 0)],
        ["Admin requests", formatNumber(item.admin_requests || 0)],
        ["Errors", formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))],
        ["Site", item.site_id || "-"],
        ["Environment", item.env || "-"],
        ["Reverse DNS", item.reverse_dns || "-"],
        ["Known actor", item.known_actor || "Tor exit"],
        ["Actor type", item.actor_type || "tor"],
        ["Verified source", item.verified_source ? "Yes" : "No"],
        ["Risk", item.risk_score || 0],
        ["Last seen", formatTime(item.last_seen)],
      ],
    };
  }
  if (kind === "alert") {
    const item = state.data.alerts?.[index];
    if (!item) return null;
    return {
      eyebrow: "Open alert",
      title: item.title || item.rule_key || "Alert",
      facts: [
        ["Severity", item.severity || "-"],
        ["Actor", item.actor_value || "-"],
        ["Site", item.site_id || "-"],
        ["Score", item.score || 0],
        ["Status", item.status || "open"],
        ["Last seen", formatTime(item.last_seen_at)],
        ["Summary", item.summary || "-"],
      ],
      details: item.details ? JSON.stringify(item.details, null, 2) : "",
    };
  }
  return null;
}

async function enrichSourceIPDetail(index) {
  const item = state.data.analysis?.source_ips?.[index];
  if (!item?.ip) return;
  try {
    const detail = await fetchJSON(`/api/v1/investigate/ip/${encodeURIComponent(item.ip)}?${buildFilterQuery({ limit: 20 })}`);
    renderDetail(sourceIPDetailFor(item, detail));
  } catch (error) {
    const fallback = detailFor("sourceIP", index);
    fallback.sections = [{ title: "Lookup", text: `IP detail lookup failed: ${error.message}` }];
    renderDetail(fallback);
  }
}

function sourceIPDetailFor(item, detail) {
  const traffic = detail.traffic || {};
  const stored = detail.stored_intel || {};
  const dns = detail.dns || {};
  const asn = detail.asn || {};
  const rdap = detail.rdap || {};
  const errorCount = Number(traffic.status_4xx || 0) + Number(traffic.status_5xx || 0);
  const asnValue = asn.asn || stored.asn;
  const asnName = asn.name || stored.asn_org;
  const network = asn.prefix || stored.network || (rdap.cidrs || []).join(", ");
  const country = asn.country_code || stored.country_code || rdap.country_code;
  const lookupErrors = detail.lookup_errors || [];
  return {
    eyebrow: "Source IP",
    title: detail.ip || item.ip || "Source IP",
    facts: [
      ["Requests", formatNumber(traffic.requests || item.requests || 0)],
      ["Errors", formatNumber(errorCount || (item.status_4xx || 0) + (item.status_5xx || 0))],
      ["Error rate", formatPercent(ratio(errorCount, traffic.requests || item.requests || 0))],
      ["Bytes sent", formatBytes(traffic.bytes_sent || item.bytes_sent || 0)],
      ["First seen", formatTime(traffic.first_seen || item.first_seen)],
      ["Last seen", formatTime(traffic.last_seen || item.last_seen)],
      ["Risk", stored.risk_score || item.risk_score || "-"],
    ],
    sections: [
      {
        title: "Identity",
        facts: [
          ["Reverse DNS", joinLimited(dns.reverse_names) || stored.reverse_dns || item.reverse_dns || "-"],
          ["Forward addresses", joinLimited(dns.forward_addresses) || "-"],
          ["Forward-confirmed", dns.forward_confirmed || stored.forward_confirmed || item.forward_confirmed ? "Yes" : "No"],
          ["Known actor", stored.known_actor || item.known_actor || "-"],
          ["Actor type", stored.actor_type || item.actor_type || "-"],
          ["Manual action", formatManualAction(stored.manual_action || item.manual_action)],
          ["Manual label", stored.manual_label || item.manual_label || "-"],
          ["Datacenter", stored.is_datacenter ? "Yes" : "No"],
          ["Tor exit", stored.is_tor_exit ? "Yes" : "No"],
        ],
      },
      {
        title: "ASN and Whois",
        facts: [
          ["ASN", asnValue ? `AS${asnValue}` : "-"],
          ["AS name", asnName || "-"],
          ["Network", network || "-"],
          ["Country", country || "-"],
          ["Registry", asn.registry || "-"],
          ["Allocated", asn.allocated || "-"],
          ["RDAP name", rdap.name || "-"],
          ["RDAP handle", rdap.handle || "-"],
          ["RDAP type", rdap.type || "-"],
          ["Address range", [rdap.start_address, rdap.end_address].filter(Boolean).join(" - ") || "-"],
          ["Registered", formatMaybeDate(rdap.registration)],
          ["Last changed", formatMaybeDate(rdap.last_changed)],
        ],
      },
      {
        title: "Sites",
        items: (detail.sites || []).map((site) => ({
          title: `${site.site_id || "-"} / ${site.env || "-"}`,
          meta: `${formatNumber((site.status_4xx || 0) + (site.status_5xx || 0))} errors - ${formatTime(site.last_seen)}`,
          value: formatNumber(site.requests || 0),
        })),
        empty: "No site traffic in this window.",
      },
      {
        title: "URLs hit",
        items: (detail.url_hits || []).map((hit) => ({
          title: formatURLTarget(hit),
          meta: `${hit.site_id || "-"} / ${hit.env || "-"} - ${formatStatusBuckets(hit)} - p95 ${formatMs(hit.p95_request_time_ms || 0)} - ${formatBytes(hit.bytes_sent || 0)} - last ${formatTime(hit.last_seen)}`,
          value: formatNumber(hit.requests || 0),
        })),
        empty: "No URL hits in this window.",
      },
      {
        title: "Recent requests",
        items: (detail.recent_requests || []).map((request) => ({
          title: formatURLTarget(request),
          meta: `${request.site_id || "-"} / ${request.env || "-"} - ${formatTime(request.ts)} - ${request.user_agent || "(empty user agent)"}`,
          value: `${request.status || "-"}`,
        })),
        empty: "No recent requests in this window.",
      },
      {
        title: "Top paths",
        items: (detail.top_paths || []).map((path) => ({
          title: path.path || "/",
          meta: `${formatNumber((path.status_4xx || 0) + (path.status_5xx || 0))} errors - ${formatBytes(path.bytes_sent || 0)}`,
          value: formatNumber(path.requests || 0),
        })),
        empty: "No paths in this window.",
      },
      {
        title: "User agents",
        items: (detail.top_user_agents || []).map((agent) => ({
          title: agent.sample || "(empty)",
          meta: `${formatNumber((agent.status_4xx || 0) + (agent.status_5xx || 0))} errors`,
          value: formatNumber(agent.requests || 0),
        })),
        empty: "No user agents in this window.",
      },
      lookupErrors.length ? { title: "Lookup errors", text: lookupErrors.join("\n") } : null,
      (rdap.entities || []).length ? {
        title: "RDAP contacts",
        items: rdap.entities.map((entity) => ({
          title: entity.name || entity.handle || "-",
          meta: (entity.roles || []).join(", ") || entity.handle || "",
          value: "",
        })),
      } : null,
    ].filter(Boolean),
    details: detail.database_source ? JSON.stringify({ database_source: detail.database_source, rdap_links: rdap.links || [] }, null, 2) : "",
  };
}

function detailSections(sections) {
  return sections.map((section) => `
    <section class="detail-section">
      <h3>${escapeHTML(section.title || "Detail")}</h3>
      ${section.text ? `<p class="detail-note">${escapeHTML(section.text)}</p>` : ""}
      ${section.facts ? `<dl class="facts compact-facts">${facts(section.facts)}</dl>` : ""}
      ${section.items ? detailItems(section.items, section.empty) : ""}
    </section>
  `).join("");
}

function detailItems(items, emptyMessage = "No rows.") {
  if (!items.length) return `<div class="empty">${escapeHTML(emptyMessage)}</div>`;
  return `
    <div class="detail-list">
      ${items.map((item) => `
        <div class="detail-row">
          <div>
            <strong>${escapeHTML(item.title || "-")}</strong>
            <span>${escapeHTML(item.meta || "")}</span>
          </div>
          <b>${escapeHTML(item.value || "")}</b>
        </div>
      `).join("")}
    </div>
  `;
}

function resetPages() {
  state.pages = {};
}

function facts(items) {
  return items.map(([label, value]) => `
    <div>
      <dt>${escapeHTML(label)}</dt>
      <dd>${escapeHTML(value)}</dd>
    </div>
  `).join("");
}

function setBusy(value) {
  qsa("button").forEach((button) => {
    if (button.id === "logoutButton") return;
    button.classList.toggle("busy", value);
  });
}

function toast(message, isError = false) {
  const el = qs("#toast");
  el.textContent = message;
  el.classList.toggle("error", isError);
  el.classList.remove("hidden");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.add("hidden"), 3500);
}

function setText(selector, value) {
  const el = qs(selector);
  if (el) el.textContent = value;
}

function emptyRow(cols, message) {
  return `<tr><td colspan="${cols}" class="empty">${escapeHTML(message)}</td></tr>`;
}

function formatTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

function formatMaybeDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function shortDateTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function localInputToISO(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString();
}

function dateToLocalInput(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return "";
  const pad = (value) => String(value).padStart(2, "0");
  return [
    date.getFullYear(),
    "-",
    pad(date.getMonth() + 1),
    "-",
    pad(date.getDate()),
    "T",
    pad(date.getHours()),
    ":",
    pad(date.getMinutes()),
  ].join("");
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
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
  const amount = number / 1024 ** index;
  return `${amount.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function formatMs(value) {
  return `${Math.round(Number(value || 0))}ms`;
}

function formatURLTarget(item) {
  const method = item.method || "GET";
  const path = item.path || "/";
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const host = item.host || "";
  const scheme = item.scheme || (host ? "https" : "");
  const base = host ? `${scheme}://${host}${normalizedPath}` : normalizedPath;
  const query = item.query ? `?${item.query}` : "";
  return `${method} ${base}${query}`;
}

function formatStatusBuckets(item) {
  const parts = [
    [`2xx`, item.status_2xx],
    [`3xx`, item.status_3xx],
    [`4xx`, item.status_4xx],
    [`5xx`, item.status_5xx],
  ].filter(([, value]) => Number(value || 0) > 0);
  if (!parts.length) return "no status";
  return parts.map(([label, value]) => `${formatNumber(value)} ${label}`).join(" / ");
}

function formatCategory(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function ratio(part, total) {
  const denominator = Number(total || 0);
  if (!denominator) return 0;
  return Number(part || 0) / denominator;
}

function joinLimited(values, limit = 4) {
  if (!Array.isArray(values) || !values.length) return "";
  const shown = values.slice(0, limit);
  const suffix = values.length > limit ? ` +${values.length - limit} more` : "";
  return `${shown.join(", ")}${suffix}`;
}

function renderMarkdown(value) {
  const lines = String(value || "").replace(/\r\n/g, "\n").split("\n");
  const html = [];
  let listType = "";
  let inCode = false;
  let codeLines = [];

  const closeList = () => {
    if (!listType) return;
    html.push(`</${listType}>`);
    listType = "";
  };

  const openList = (type) => {
    if (listType === type) return;
    closeList();
    listType = type;
    html.push(`<${type}>`);
  };

  lines.forEach((line) => {
    const trimmed = line.trim();
    if (/^```/.test(trimmed)) {
      if (inCode) {
        html.push(`<pre><code>${escapeHTML(codeLines.join("\n"))}</code></pre>`);
        codeLines = [];
        inCode = false;
      } else {
        closeList();
        inCode = true;
      }
      return;
    }

    if (inCode) {
      codeLines.push(line);
      return;
    }

    if (!trimmed) {
      closeList();
      return;
    }

    const heading = trimmed.match(/^(#{1,4})\s+(.+)$/);
    if (heading) {
      closeList();
      const level = Math.min(4, heading[1].length);
      html.push(`<h${level}>${renderInlineMarkdown(heading[2])}</h${level}>`);
      return;
    }

    const unordered = line.match(/^\s*[-*]\s+(.+)$/);
    if (unordered) {
      openList("ul");
      html.push(`<li>${renderInlineMarkdown(unordered[1])}</li>`);
      return;
    }

    const ordered = line.match(/^\s*\d+\.\s+(.+)$/);
    if (ordered) {
      openList("ol");
      html.push(`<li>${renderInlineMarkdown(ordered[1])}</li>`);
      return;
    }

    const quote = line.match(/^\s*>\s?(.+)$/);
    if (quote) {
      closeList();
      html.push(`<blockquote>${renderInlineMarkdown(quote[1])}</blockquote>`);
      return;
    }

    closeList();
    html.push(`<p>${renderInlineMarkdown(trimmed)}</p>`);
  });

  if (inCode) {
    html.push(`<pre><code>${escapeHTML(codeLines.join("\n"))}</code></pre>`);
  }
  closeList();
  return html.join("");
}

function renderInlineMarkdown(value) {
  let text = escapeHTML(value);
  const codeSegments = [];
  text = text.replace(/`([^`]+)`/g, (_, code) => {
    const token = `@@CODE_${codeSegments.length}@@`;
    codeSegments.push(`<code>${code}</code>`);
    return token;
  });
  text = text.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  text = text.replace(/__([^_]+)__/g, "<strong>$1</strong>");
  text = text.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, `<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>`);
  codeSegments.forEach((segment, index) => {
    text = text.replace(`@@CODE_${index}@@`, segment);
  });
  return text;
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function clampNumber(value, low, high) {
  return Math.max(low, Math.min(high, value));
}

boot();
