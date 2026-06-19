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
  siteSearch: "",
  siteStatusFilter: "all",
  siteSort: "risk",
  siteDetailID: "",
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
  qs("#siteSearchInput").addEventListener("input", (event) => {
    state.siteSearch = event.target.value || "";
    state.pages.sites = 0;
    renderSites();
    renderWorkspaceContext();
    updateURL(false);
  });
  qs("#siteStatusFilter").addEventListener("change", (event) => {
    state.siteStatusFilter = event.target.value || "all";
    state.pages.sites = 0;
    renderSites();
    renderWorkspaceContext();
    updateURL(false);
  });
  qs("#siteSortSelect").addEventListener("change", (event) => {
    state.siteSort = event.target.value || "risk";
    state.pages.sites = 0;
    renderSites();
    renderWorkspaceContext();
    updateURL(false);
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
      state.reportTab = normalizeReportTab(button.dataset.reportTab || "daily");
      state.pages.reports = 0;
      renderReports();
      renderWorkspaceContext();
      updateURL(true);
      requestAnimationFrame(drawReportCharts);
    });
  });
  qsa("[data-site-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      state.siteTab = normalizeSiteTab(button.dataset.siteTab || "overview");
      renderSites();
      renderWorkspaceContext();
      updateURL(true);
      requestAnimationFrame(() => renderCharts());
    });
  });
  qsa("[data-log-type]").forEach((button) => {
    button.addEventListener("click", () => {
      state.logType = button.dataset.logType || "nginx-access";
      state.pages.logEvidence = 0;
      updateURL(false);
      renderLogs();
      renderWorkspaceContext();
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
      renderWorkspaceContext();
    });
  });
  qsa("[data-signal-severity]").forEach((button) => {
    button.addEventListener("click", () => {
      const severity = normalizeSignalSeverity(button.dataset.signalSeverity || "all");
      if (severity === "all") delete state.viewContext.severity;
      else state.viewContext.severity = severity;
      state.signalKey = "";
      state.pages.signals = 0;
      updateURL(false);
      renderSignals();
      renderWorkspaceContext();
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

    const workspaceContextRemoveButton = event.target.closest("[data-workspace-context-remove]");
    if (workspaceContextRemoveButton) {
      await removeWorkspaceContextFilter(workspaceContextRemoveButton.dataset.workspaceContextRemove || "");
      return;
    }

    const siteActionButton = event.target.closest("[data-site-action]");
    if (siteActionButton) {
      await handleSiteAction(siteActionButton.dataset.siteAction || "focus");
      return;
    }

    const logContextRemoveButton = event.target.closest("[data-log-context-remove]");
    if (logContextRemoveButton) {
      await removeLogContextFilter(logContextRemoveButton.dataset.logContextRemove || "");
      return;
    }

    const siteTabTargetButton = event.target.closest("[data-site-tab-target]");
    if (siteTabTargetButton) {
      state.siteTab = normalizeSiteTab(siteTabTargetButton.dataset.siteTabTarget || "overview");
      state.pages.logEvidence = 0;
      renderSites();
      renderWorkspaceContext();
      updateURL(true);
      requestAnimationFrame(() => renderCharts());
      return;
    }

    const siteReportSelectButton = event.target.closest("[data-site-report-select]");
    if (siteReportSelectButton) {
      const tab = normalizeReportTab(siteReportSelectButton.dataset.siteReportTab || state.reportTab);
      state.reportTab = tab;
      state.selectedReportIDs[tab] = siteReportSelectButton.dataset.siteReportSelect || "";
      renderSites();
      renderWorkspaceContext();
      updateURL(true);
      requestAnimationFrame(drawReportCharts);
      return;
    }

    const siteQueueButton = event.target.closest("[data-site-queue-action]");
    if (siteQueueButton) {
      if (siteQueueButton.dataset.siteQueueAction === "clear") {
        state.siteSearch = "";
        state.siteStatusFilter = "all";
        state.siteSort = "risk";
        state.pages.sites = 0;
        renderSites();
        renderWorkspaceContext();
        updateURL(false);
      }
      return;
    }

    const signalFilterButton = event.target.closest("[data-signal-filter-target]");
    if (signalFilterButton) {
      state.signalFilter = signalFilterButton.dataset.signalFilterTarget || "all";
      state.signalKey = "";
      state.pages.signals = 0;
      renderSignals();
      renderWorkspaceContext();
      updateURL(true);
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
        renderWorkspaceContext();
        updateURL(true);
        requestAnimationFrame(drawReportCharts);
      }, false);
    }

    const reportSelectButton = event.target.closest("[data-report-select]");
    if (reportSelectButton) {
      state.selectedReportIDs[state.reportTab] = reportSelectButton.dataset.reportSelect || "";
      renderReports();
      renderWorkspaceContext();
      updateURL(true);
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
  const activeContext = workspaceContextItems(route);
  const hasDrilldownContext = workspaceHasDrilldownContext();
  setText("#workspaceContextTitle", `${routes[route].title} workspace`);
  setText("#workspaceContextSubtitle", workspaceContextSubtitle(route));
  qs("#workspaceContextChips").innerHTML = activeContext.map(workspaceContextChip).join("");
  qs("#workspaceContextActions").innerHTML = workspaceContextActions(route, hasDrilldownContext);
  qs("#workspaceInvestigationPath").innerHTML = workspaceInvestigationPath(route);
  bar.classList.toggle("has-drilldown", hasDrilldownContext);
}

function workspaceContextSubtitle(route = state.route) {
  const parts = [activeFilterLabel()];
  if (route === "logs") parts.push(formatLogType(state.logType));
  if (route === "signals" && state.signalFilter !== "all") parts.push(`${formatCategory(state.signalFilter)} signals`);
  if (route === "sites" && state.siteTab !== "overview") parts.push(`${formatCategory(state.siteTab)} tab`);
  if (route === "sites" && state.siteStatusFilter !== "all") parts.push(`${formatCategory(state.siteStatusFilter)} sites`);
  if (route === "sites" && state.siteSearch) parts.push(`search "${state.siteSearch}"`);
  if (route === "reports") parts.push(`${formatCategory(state.reportTab)} reports`);
  if (state.signalKey) parts.push("signal detail");
  if (state.entity?.kind && state.entity.value) parts.push(`${state.entity.kind === "asn" ? "ASN" : formatCategory(state.entity.kind)} detail`);
  const context = state.viewContext || {};
  if (context.severity) parts.push(`${signalSeverityLabel(context.severity)} severity`);
  if (context.status_class === "errors") parts.push("errors only");
  return parts.filter(Boolean).join(" / ");
}

function workspaceContextPairs(route = state.route) {
  return workspaceContextItems(route).map((item) => [item.label, item.value]);
}

function workspaceContextItems(route = state.route) {
  const context = state.viewContext || {};
  const siteID = state.siteID || context.site_id || "";
  const items = [
    { label: "Route", value: routes[route]?.title || "Overview", key: "route" },
    { label: "Range", value: workspaceRangeLabel(), key: "range", removable: state.range !== "24h" || Boolean(state.from || state.to) },
  ];
  if (siteID) {
    items.push({ label: "Site", value: siteLabel(siteID) || siteID, key: "site_id", removable: true, pivot: { kind: "site", value: siteID, origin: "workspace_context" } });
  } else {
    items.push({ label: "Site", value: "All sites", key: "site" });
  }
  if (route === "logs") items.push({ label: "Log type", value: formatLogType(state.logType), key: "log_type", removable: state.logType !== "nginx-access" });
  if (route === "signals") items.push({ label: "Signal tab", value: formatCategory(state.signalFilter || "all"), key: "signal_filter", removable: state.signalFilter !== "all" });
  if (route === "sites") items.push({ label: "Site tab", value: formatCategory(state.siteTab || "overview"), key: "site_tab", removable: state.siteTab !== "overview" });
  if (route === "sites" && state.siteStatusFilter !== "all") items.push({ label: "Site state", value: formatCategory(state.siteStatusFilter), key: "site_status", removable: true });
  if (route === "sites" && state.siteSearch) items.push({ label: "Site search", value: state.siteSearch, key: "site_q", removable: true });
  if (route === "sites" && state.siteSort !== "risk") items.push({ label: "Site sort", value: siteSortLabel(state.siteSort), key: "site_sort", removable: true });
  if (route === "reports") items.push({ label: "Report tab", value: formatCategory(state.reportTab || "daily"), key: "report_tab", removable: state.reportTab !== "daily" });
  if (route === "reports" && state.selectedReportIDs[state.reportTab]) {
    items.push({ label: "Report", value: shortLabel(state.selectedReportIDs[state.reportTab], 42), key: "report_id", removable: true });
  }
  if (state.entity?.kind && state.entity.value) {
    items.push({
      label: state.entity.kind === "asn" ? "ASN" : formatCategory(state.entity.kind),
      value: state.entity.kind === "asn" ? formatASN(state.entity.value) || state.entity.value : state.entity.value,
      key: "entity",
      removable: true,
      pivot: workspaceEntityPivot(state.entity, siteID, context),
    });
  }
  if (state.signalKey) {
    items.push({ label: "Signal", value: shortLabel(state.signalKey, 42), key: "signal", removable: true, pivot: { kind: "signal", key: state.signalKey, site_id: siteID, origin: "workspace_context" } });
  }
  if (context.ip && !(state.entity?.kind === "ip" && state.entity.value === context.ip)) {
    items.push({ label: "IP", value: context.ip, key: "ip", removable: true, pivot: { kind: "ip", value: context.ip, site_id: siteID, origin: "workspace_context" } });
  }
  if (context.asn && !(state.entity?.kind === "asn" && formatASN(state.entity.value) === formatASN(context.asn))) {
    items.push({ label: "ASN", value: formatASN(context.asn) || context.asn, key: "asn", removable: true, pivot: { kind: "asn", value: context.asn, site_id: siteID, origin: "workspace_context" } });
  }
  if (context.path && !(state.entity?.kind === "path" && state.entity.value === context.path)) {
    items.push({ label: "Path", value: context.path, key: "path", removable: true, pivot: { kind: "path", value: context.path, site_id: siteID, origin: "workspace_context" } });
  }
  if (context.known_actor && !(state.entity?.kind === "actor" && state.entity.value === context.known_actor)) {
    items.push({ label: "Actor", value: context.known_actor, key: "known_actor", removable: true, pivot: { kind: "actor", value: context.known_actor, actor_type: context.actor_type || "", site_id: siteID, origin: "workspace_context" } });
  }
  if (context.actor_type) items.push({ label: "Actor type", value: formatCategory(context.actor_type), key: "actor_type", removable: true });
  if (context.env) items.push({ label: "Env", value: context.env, key: "env", removable: true });
  if (context.severity) items.push({ label: "Min severity", value: signalSeverityLabel(context.severity), key: "severity", removable: true });
  if (context.status_class === "errors") items.push({ label: "Status", value: "Errors only", key: "status_class", removable: true });
  if (context.user_agent && !(state.entity?.kind === "user-agent" && state.entity.value === context.user_agent)) {
    items.push({ label: "User agent", value: context.user_agent, key: "user_agent", removable: true, pivot: { kind: "user-agent", value: context.user_agent, site_id: siteID, origin: "workspace_context" } });
  }
  if (context.evidence_kind) items.push({ label: "Evidence", value: formatCategory(context.evidence_kind), key: "evidence_kind", removable: true });
  return items;
}

function workspaceRangeLabel() {
  if (state.range === "custom" && state.from && state.to) return `${shortDateTime(state.from)} to ${shortDateTime(state.to)}`;
  return state.range || "24h";
}

function workspaceContextChip(item) {
  const actions = [
    item.pivot ? `<button class="context-chip-action" type="button" data-pivot='${encodePivot(item.pivot)}' aria-label="Open ${escapeHTML(item.label)} ${escapeHTML(item.value)}">Open</button>` : "",
    item.removable ? `<button class="context-chip-remove" type="button" data-workspace-context-remove="${escapeHTML(item.key)}" aria-label="Remove ${escapeHTML(item.label)} context">&times;</button>` : "",
  ].filter(Boolean).join("");
  return `
    <span class="context-chip context-chip-rich workspace-context-chip">
      <span><b>${escapeHTML(item.label)}</b>${escapeHTML(item.value || "-")}</span>
      ${actions}
    </span>
  `;
}

function workspaceInvestigationPath(route = state.route) {
  const steps = workspacePathSteps(route);
  if (!steps.length) return "";
  return `
    <div class="workspace-path-kicker">Investigation path</div>
    <div class="workspace-path-steps">
      ${steps.map(workspacePathStep).join("")}
    </div>
  `;
}

function workspacePathSteps(route = state.route) {
  const context = { ...(state.viewContext || {}), ...activeEntityContext() };
  const siteID = context.site_id || state.siteID || "";
  const steps = [
    {
      label: "Scope",
      value: siteID ? siteLabel(siteID) || shortLabel(siteID, 32) : "All sites",
      pivot: siteID ? { kind: "site", value: siteID, origin: "workspace_path" } : null,
    },
  ];
  const focus = workspaceFocusStep(context, siteID);
  if (focus) steps.push(focus);
  steps.push({
    label: "Evidence",
    value: workspaceEvidenceLabel(route, context),
    pivot: currentLogPivot("workspace_path"),
  });
  steps.push({
    label: "Signals",
    value: state.signalKey ? "Current signal" : formatCategory(state.signalFilter || "all"),
    pivot: state.signalKey ? { kind: "signal", key: state.signalKey, site_id: siteID, origin: "workspace_path" } : null,
    action: state.signalKey ? "" : "open-signals",
  });
  steps.push({
    label: "Report",
    value: workspaceReportLabel(),
    pivot: currentReportPivot("workspace_path"),
  });
  return steps;
}

function workspaceFocusStep(context, siteID = "") {
  if (state.signalKey) {
    return { label: "Signal", value: shortLabel(state.signalKey, 48), pivot: { kind: "signal", key: state.signalKey, site_id: siteID, origin: "workspace_path" } };
  }
  if (state.entity?.kind && state.entity.value) {
    return {
      label: workspaceEntityLabel(state.entity.kind),
      value: state.entity.kind === "asn" ? formatASN(state.entity.value) || state.entity.value : state.entity.value,
      pivot: workspaceEntityPivot(state.entity, siteID, context),
    };
  }
  if (context.ip) return { label: "IP", value: context.ip, pivot: { kind: "ip", value: context.ip, site_id: siteID, origin: "workspace_path" } };
  if (context.asn) return { label: "ASN", value: formatASN(context.asn) || context.asn, pivot: { kind: "asn", value: context.asn, site_id: siteID, origin: "workspace_path" } };
  if (context.path) return { label: "Path", value: context.path, pivot: { kind: "path", value: context.path, site_id: siteID, origin: "workspace_path" } };
  if (context.known_actor) {
    return { label: "Actor", value: context.known_actor, pivot: { kind: "actor", value: context.known_actor, actor_type: context.actor_type || "", site_id: siteID, origin: "workspace_path" } };
  }
  if (context.user_agent) {
    return { label: "User agent", value: context.user_agent, pivot: { kind: "user-agent", value: context.user_agent, site_id: siteID, origin: "workspace_path" } };
  }
  if (siteID) return { label: "Site", value: siteLabel(siteID) || siteID, pivot: { kind: "site", value: siteID, origin: "workspace_path" } };
  return null;
}

function workspaceEntityPivot(entity, siteID = "", context = {}) {
  if (entity.kind === "site") return { kind: "site", value: entity.value, origin: "workspace_path" };
  if (entity.kind === "ip") return { kind: "ip", value: entity.value, site_id: siteID, origin: "workspace_path" };
  if (entity.kind === "asn") return { kind: "asn", value: formatASN(entity.value) || entity.value, site_id: siteID, origin: "workspace_path" };
  if (entity.kind === "path") return { kind: "path", value: entity.value, site_id: siteID, origin: "workspace_path" };
  if (entity.kind === "actor") return { kind: "actor", value: entity.value, actor_type: context.actor_type || "", site_id: siteID, origin: "workspace_path" };
  if (entity.kind === "user-agent") return { kind: "user-agent", value: entity.value, site_id: siteID, origin: "workspace_path" };
  return { kind: entity.kind, value: entity.value, site_id: siteID, origin: "workspace_path" };
}

function workspaceEntityLabel(kind) {
  return kind === "asn" ? "ASN" : kind === "user-agent" ? "User agent" : formatCategory(kind || "Entity");
}

function workspaceEvidenceLabel(route = state.route, context = {}) {
  const parts = [formatLogType(state.logType || "nginx-access")];
  if (context.status_class === "errors") parts.push("errors");
  if (context.path) parts.push(shortLabel(context.path, 28));
  if (context.ip) parts.push(context.ip);
  if (route === "logs" && context.evidence_kind) parts.push(formatCategory(context.evidence_kind));
  return parts.filter(Boolean).join(" / ");
}

function workspaceReportLabel() {
  const tab = state.reportTab || "daily";
  const selected = state.selectedReportIDs[tab];
  return selected ? shortLabel(selected, 32) : formatCategory(tab);
}

function workspacePathStep(step) {
  const actionAttr = step.action ? ` data-context-action="${escapeHTML(step.action)}"` : "";
  const pivotAttr = step.pivot ? ` data-pivot='${encodePivot(step.pivot)}'` : "";
  const clickable = step.action || step.pivot;
  const tag = clickable ? "button" : "span";
  const typeAttr = clickable ? ` type="button"` : "";
  return `
    <${tag} class="workspace-path-step ${clickable ? "clickable" : ""}"${typeAttr}${actionAttr}${pivotAttr}>
      <b>${escapeHTML(step.label || "-")}</b>
      <span>${escapeHTML(step.value || "-")}</span>
    </${tag}>
  `;
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
    || (state.route === "sites" && (state.siteSearch || state.siteStatusFilter !== "all" || state.siteSort !== "risk"))
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
    ...activeEntityContext(),
  };
  if (state.siteID || state.viewContext.site_id) pivot.site_id = state.viewContext.site_id || state.siteID;
  return pivot;
}

function activeEntityContext() {
  const entity = state.entity;
  if (!entity?.kind || !entity.value) return {};
  if (entity.kind === "ip") return { ip: entity.value };
  if (entity.kind === "asn") return { asn: formatASN(entity.value) || entity.value };
  if (entity.kind === "path") return { path: entity.value };
  if (entity.kind === "actor") return { known_actor: entity.value };
  if (entity.kind === "user-agent") return { user_agent: entity.value };
  return {};
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
    state.siteSearch = "";
    state.siteStatusFilter = "all";
    state.siteSort = "risk";
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

async function removeWorkspaceContextFilter(key) {
  if (!key) return;
  let refetch = false;
  if (key === "range") {
    state.range = "24h";
    state.from = "";
    state.to = "";
    refetch = true;
  } else if (key === "site_id") {
    state.siteID = "";
    delete state.viewContext.site_id;
    refetch = true;
  } else if (key === "log_type") {
    state.logType = "nginx-access";
  } else if (key === "signal_filter") {
    state.signalFilter = "all";
  } else if (key === "site_tab") {
    state.siteTab = "overview";
  } else if (key === "site_status") {
    state.siteStatusFilter = "all";
  } else if (key === "site_q") {
    state.siteSearch = "";
  } else if (key === "site_sort") {
    state.siteSort = "risk";
  } else if (key === "report_tab") {
    state.reportTab = "daily";
  } else if (key === "report_id") {
    delete state.selectedReportIDs[state.reportTab];
  } else if (key === "signal") {
    state.signalKey = "";
  } else if (key === "entity") {
    clearActiveEntityContext();
  } else {
    delete state.viewContext[key];
  }
  if (key === "known_actor") delete state.viewContext.actor_type;
  resetContextPages();
  updateURL(false);
  if (refetch) {
    await refreshWithValidation();
    return;
  }
  render();
}

function clearActiveEntityContext() {
  const kind = state.entity?.kind || "";
  state.entity = null;
  if (kind === "ip") delete state.viewContext.ip;
  if (kind === "asn") delete state.viewContext.asn;
  if (kind === "path") delete state.viewContext.path;
  if (kind === "actor") {
    delete state.viewContext.known_actor;
    delete state.viewContext.actor_type;
  }
  if (kind === "user-agent") delete state.viewContext.user_agent;
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
    if (value) state.entity = { kind, value: kind === "asn" ? formatASN(value) || value : value };
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
  state.siteTab = normalizeSiteTab(params.get("site_tab") || state.siteTab || "overview");
  state.siteSearch = params.get("site_q") || "";
  state.siteStatusFilter = normalizeSiteStatusFilter(params.get("site_status") || state.siteStatusFilter || "all");
  state.siteSort = normalizeSiteSort(params.get("site_sort") || state.siteSort || "risk");
  state.reportTab = normalizeReportTab(params.get("report_tab") || state.reportTab || "daily");
  const selectedReportID = params.get("report_id");
  if (selectedReportID) state.selectedReportIDs[state.reportTab] = selectedReportID;
  state.viewContext = {};
  ["ip", "asn", "path", "known_actor", "actor_type", "status_class", "site_id", "env", "user_agent", "evidence_kind", "severity"].forEach((key) => {
    const value = params.get(key);
    if (!value) return;
    if (key === "severity") {
      const severity = normalizeSignalSeverity(value);
      if (severity !== "all") state.viewContext.severity = severity;
      return;
    }
    state.viewContext[key] = value;
  });
  if (state.entity?.kind === "ip") state.viewContext.ip = state.entity.value;
  if (state.entity?.kind === "asn") state.viewContext.asn = formatASN(state.entity.value) || state.entity.value;
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
  if (state.route === "sites") {
    if (state.siteTab && state.siteTab !== "overview") params.set("site_tab", state.siteTab);
    if (state.siteSearch) params.set("site_q", state.siteSearch);
    if (state.siteStatusFilter && state.siteStatusFilter !== "all") params.set("site_status", state.siteStatusFilter);
    if (state.siteSort && state.siteSort !== "risk") params.set("site_sort", state.siteSort);
    return params;
  }
  if (state.route === "investigate" && state.entity?.kind === "path" && state.entity.value) params.set("path", state.entity.value);
  if (state.siteID) params.set("site_id", state.siteID);
  if (state.route === "logs" && state.logType && state.logType !== "nginx-access") params.set("log_type", state.logType);
  if (state.route === "signals" && state.signalFilter && state.signalFilter !== "all") params.set("signal_filter", state.signalFilter);
  if (state.route === "reports") {
    params.set("report_tab", state.reportTab || "daily");
    const reportID = state.selectedReportIDs[state.reportTab];
    if (reportID) params.set("report_id", reportID);
  }
  Object.entries({ ...state.viewContext, ...extra }).forEach(([key, value]) => {
    if (state.route === "investigate" && state.entity?.kind === "ip" && key === "ip") return;
    if (state.route === "investigate" && state.entity?.kind === "asn" && key === "asn") return;
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

  const siteRows = aggregateSiteRows();
  renderPrioritySignals(signals);
  renderSiteRiskOverview(siteRows, signals);
  renderOverviewChartInsights(analysis, traffic);
  renderOverviewHealthMatrix(siteRows);
  renderOverviewSiteHeatmap(siteRows);
  renderOverviewHotspots(overviewHotspotRows());
  renderOverviewActorReview(overviewActorReviewRows());
  renderRecentErrors(traffic.recent_errors || []);
}

function renderOverviewChartInsights(analysis = state.data.analysis || {}, traffic = state.data.traffic || {}) {
  setHTML("#timelineChartInsight", overviewTimelineInsight(traffic.timeline || []));
  setHTML("#statusChartInsight", overviewStatusInsight(analysis.status_breakdown || [], analysis.totals || {}));
  setHTML("#siteChartInsight", overviewSiteChartInsight(analysis.sites || []));
  setHTML("#sourceChartInsight", overviewSourceChartInsight(analysis.source_ips || []));
  setHTML("#agentChartInsight", overviewAgentChartInsight(analysis.user_agents || []));
}

function overviewTimelineInsight(timeline = []) {
  const rows = [...timeline].filter((item) => item && (Number(item.requests || 0) || Number(item.value || 0)));
  if (!rows.length) return overviewChartEmptyInsight("No traffic buckets in this scope.");
  const lead = rows.sort((a, b) => {
    const bErrors = Number(b.status_4xx || 0) + Number(b.status_5xx || 0) + Number(b.errors || 0);
    const aErrors = Number(a.status_4xx || 0) + Number(a.status_5xx || 0) + Number(a.errors || 0);
    return bErrors - aErrors
      || Number(b.requests || b.value || 0) - Number(a.requests || a.value || 0)
      || new Date(b.bucket_ts || b.timestamp || 0) - new Date(a.bucket_ts || a.timestamp || 0);
  })[0];
  const requests = Number(lead.requests || lead.value || 0);
  const errors = Number(lead.status_4xx || 0) + Number(lead.status_5xx || 0) + Number(lead.errors || 0);
  const totalRequests = rows.reduce((sum, item) => sum + Number(item.requests || item.value || 0), 0);
  return overviewChartInsight({
    label: errors ? "Noisiest traffic bucket" : "Peak traffic bucket",
    title: shortDateTime(lead.bucket_ts || lead.timestamp),
    meta: [`${formatNumber(requests)} requests`, errors ? `${formatNumber(errors)} errors` : "", lead.bucket_ts ? "current chart window" : ""].filter(Boolean).join(" / "),
    actions: [
      overviewActionButton("Open logs", { kind: "log_filter", site_id: state.siteID || state.viewContext.site_id || "", origin: "overview_chart_timeline" }),
      errors ? overviewActionButton("Error rows", { kind: "log_filter", site_id: state.siteID || state.viewContext.site_id || "", status_class: "errors", origin: "overview_chart_timeline" }) : "",
    ],
    facts: [
      ["Chart total", `${formatNumber(totalRequests)} requests`],
      ["Bucket share", formatPercent(ratio(requests, totalRequests))],
      ["Scope", activeFilterLabel()],
    ],
  });
}

function overviewStatusInsight(statuses = [], totals = {}) {
  const groups = [
    { label: "2xx", value: sumStatus(statuses, 200, 299), statusClass: "" },
    { label: "3xx", value: sumStatus(statuses, 300, 399), statusClass: "" },
    { label: "4xx", value: sumStatus(statuses, 400, 499), statusClass: "errors" },
    { label: "5xx", value: sumStatus(statuses, 500, 599), statusClass: "errors" },
  ];
  const lead = groups.find((item) => item.label === "5xx" && item.value)
    || groups.find((item) => item.label === "4xx" && item.value)
    || groups.slice().sort((a, b) => b.value - a.value)[0];
  if (!lead?.value) return overviewChartEmptyInsight("No status-code mix in this scope.");
  const total = groups.reduce((sum, item) => sum + Number(item.value || 0), 0);
  return overviewChartInsight({
    label: lead.statusClass ? "Primary error bucket" : "Primary status bucket",
    title: lead.label,
    meta: [`${formatNumber(lead.value)} responses`, formatPercent(ratio(lead.value, total))].join(" / "),
    actions: [
      overviewActionButton(lead.statusClass ? "Open error rows" : "Open logs", { kind: "log_filter", site_id: state.siteID || state.viewContext.site_id || "", status_class: lead.statusClass, origin: "overview_chart_status" }),
      overviewActionButton("Reliability signals", { kind: "signal_filter", signal_filter: "reliability", severity: "medium", status_class: lead.statusClass, site_id: state.siteID || state.viewContext.site_id || "", origin: "overview_chart_status" }),
    ],
    facts: [
      ["4xx rate", formatPercent(totals.status_4xx_rate || ratio(groups[2].value, total))],
      ["5xx rate", formatPercent(totals.status_5xx_rate || ratio(groups[3].value, total))],
      ["Total", formatNumber(total)],
    ],
  });
}

function overviewSiteChartInsight(sites = []) {
  const lead = [...(sites || [])]
    .filter((item) => item.site_id)
    .sort((a, b) => Number(b.requests || 0) - Number(a.requests || 0))[0];
  if (!lead) return overviewChartEmptyInsight("No site traffic chart data.");
  const siteID = lead.site_id || "";
  const total = sites.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  const errors = Number(lead.status_4xx || 0) + Number(lead.status_5xx || 0);
  return overviewChartInsight({
    label: "Highest traffic site",
    title: siteLabel(siteID) || siteID,
    meta: [`${formatNumber(lead.requests || 0)} requests`, errors ? `${formatNumber(errors)} errors` : "", lead.env || ""].filter(Boolean).join(" / "),
    actions: [
      overviewActionButton("Open site", { kind: "site", value: siteID, origin: "overview_chart_site" }),
      overviewActionButton("Site logs", { kind: "log_filter", site_id: siteID, status_class: errors ? "errors" : "", origin: "overview_chart_site" }),
      overviewActionButton("Reports", { kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "overview_chart_site" }),
    ],
    facts: [
      ["Traffic share", formatPercent(ratio(lead.requests, total))],
      ["5xx rate", formatPercent(lead.status_5xx_rate || ratio(lead.status_5xx, lead.requests))],
      ["Sites", formatNumber(sites.length)],
    ],
  });
}

function overviewSourceChartInsight(sources = []) {
  const lead = [...(sources || [])]
    .filter((item) => item.ip)
    .sort((a, b) => Number(b.requests || 0) - Number(a.requests || 0))[0];
  if (!lead) return overviewChartEmptyInsight("No source IP chart data.");
  const siteID = lead.site_id || state.siteID || state.viewContext.site_id || "";
  const total = sources.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  const errors = Number(lead.status_4xx || 0) + Number(lead.status_5xx || 0);
  const actor = lead.known_actor || actorLabelFromType(lead.actor_type) || lead.reverse_dns || "";
  return overviewChartInsight({
    label: "Highest traffic source",
    title: lead.ip,
    meta: [actor, lead.asn ? formatASN(lead.asn) : "", `${formatNumber(lead.requests || 0)} requests`, errors ? `${formatNumber(errors)} errors` : ""].filter(Boolean).join(" / "),
    actions: [
      overviewActionButton("Open IP", { kind: "ip", value: lead.ip, site_id: siteID, origin: "overview_chart_source" }),
      overviewActionButton("IP logs", { kind: "log_filter", ip: lead.ip, site_id: siteID, status_class: errors ? "errors" : "", origin: "overview_chart_source" }),
      lead.asn ? overviewActionButton("ASN", { kind: "asn", value: formatASN(lead.asn), site_id: siteID, origin: "overview_chart_source" }) : "",
      actor ? overviewActionButton("Actor", { kind: "actor", value: actor, actor_type: lead.actor_type || "", site_id: siteID, origin: "overview_chart_source" }) : "",
    ],
    facts: [
      ["Traffic share", formatPercent(ratio(lead.requests, total))],
      ["Verification", actorSourceStatus(lead)],
      ["Risk", lead.risk_score ?? "-"],
    ],
  });
}

function overviewAgentChartInsight(agents = []) {
  const classes = aggregateAgentClasses(agents || []);
  const lead = classes[0];
  if (!lead) return overviewChartEmptyInsight("No user-agent class chart data.");
  const total = classes.reduce((sum, item) => sum + Number(item.value || 0), 0);
  return overviewChartInsight({
    label: "Dominant user-agent class",
    title: formatCategory(lead.label || lead.key || "unknown"),
    meta: [`${formatNumber(lead.value || 0)} requests`, formatPercent(ratio(lead.value, total))].join(" / "),
    actions: [
      overviewActionButton("Class logs", { kind: "log_filter", actor_type: lead.key || lead.label || "", site_id: state.siteID || state.viewContext.site_id || "", origin: "overview_chart_agents" }),
      overviewActionButton("Signals", { kind: "signal_filter", signal_filter: "traffic", actor_type: lead.key || lead.label || "", site_id: state.siteID || state.viewContext.site_id || "", origin: "overview_chart_agents" }),
    ],
    facts: [
      ["Classes", formatNumber(classes.length)],
      ["Share", formatPercent(ratio(lead.value, total))],
      ["Scope", activeFilterLabel()],
    ],
  });
}

function overviewChartInsight({ label, title, meta, actions = [], facts = [] } = {}) {
  return `
    <div class="report-chart-insight overview-chart-insight-card">
      <div class="report-chart-lead">
        <span>${escapeHTML(label || "Chart lead")}</span>
        <strong>${escapeHTML(title || "-")}</strong>
        <small>${escapeHTML(meta || "")}</small>
      </div>
      <div class="report-chart-pivots"><div class="signal-actions">${actions.filter(Boolean).join("")}</div></div>
      ${facts.length ? `<div class="report-chart-context">${facts.map(reportChartContextRow).join("")}</div>` : ""}
    </div>
  `;
}

function overviewChartEmptyInsight(message) {
  return `<div class="report-chart-insight overview-chart-insight-card"><div class="empty compact-empty">${escapeHTML(message)}</div></div>`;
}

function overviewActionButton(label, pivot) {
  if (!pivot) return "";
  return `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(pivot)}'>${escapeHTML(label)}</button>`;
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

function renderSiteRiskOverview(sites, signals = buildSignalItems()) {
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
  const topSignal = signals.find((item) => item.siteID === top.id) || signals[0] || null;
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
    ${overviewProblemBrief(top, { topIP, topPath, topSignal })}
  `;
  listContainer.innerHTML = sites.slice(0, 10).map(siteRiskRow).join("");
}

function overviewProblemBrief(site, { topIP = null, topPath = null, topSignal = null } = {}) {
  const siteID = site.id || "";
  const report = siteReports(siteID)[0] || null;
  const pathErrors = Number(topPath?.status_4xx || 0) + Number(topPath?.status_5xx || 0);
  const ipErrors = Number(topIP?.status_4xx || 0) + Number(topIP?.status_5xx || 0);
  const source = topIP?.ip ? sourceIPContextForIP(topIP.ip) : {};
  const reportAction = report
    ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: siteID, origin: "overview_brief" }))}'>Open report</button>`
    : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "overview_brief" })}'>Reports</button>`;
  const rows = [
    {
      title: "First response",
      meta: topSignal
        ? [topSignal.title, topSignal.summary, topSignal.lastSeen ? `last ${formatTime(topSignal.lastSeen)}` : ""].filter(Boolean).join(" - ")
        : "No ranked signal is attached to this site yet.",
      valueLabel: topSignal ? "risk" : "site",
      value: topSignal ? (topSignal.risk || severityRank(topSignal.severity) * 20 || 0) : (site.status || "watch"),
      actions: topSignal
        ? [
          `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: topSignal.key, site_id: topSignal.siteID || siteID, origin: "overview_brief" })}'>Open signal</button>`,
          topSignal.sourceKind === "job"
            ? `<button class="ghost mini inline-action" type="button" data-route-target="system">System</button>`
            : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(signalLogPivot({ ...topSignal, siteID: topSignal.siteID || siteID }, "overview_brief"))}'>Signal logs</button>`,
          `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: siteID, origin: "overview_brief" })}'>Open site</button>`,
        ].join("")
        : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: siteID, origin: "overview_brief" })}'>Open site</button>`,
    },
    {
      title: "Failing path",
      meta: topPath?.path
        ? [
          `${formatNumber(topPath.requests || 0)} requests`,
          pathErrors ? `${formatNumber(pathErrors)} errors` : "",
          topPath.last_seen ? `last ${formatTime(topPath.last_seen)}` : "",
        ].filter(Boolean).join(" - ")
        : "No dominant path in this scope.",
      valueLabel: pathErrors ? "errors" : "requests",
      value: formatNumber(pathErrors || topPath?.requests || 0),
      actions: topPath?.path
        ? [
          `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: topPath.path || "/", site_id: siteID, origin: "overview_brief" })}'>Open path</button>`,
          correlatedLogActions({ path: topPath.path || "/", siteID, statusClass: pathErrors ? "errors" : "", origin: "overview_brief" }),
        ].join("")
        : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, status_class: site.status5xx || site.status4xx ? "errors" : "", origin: "overview_brief" })}'>Open logs</button>`,
    },
    {
      title: "Source pressure",
      meta: topIP?.ip
        ? [
          topIP.ip,
          source.known_actor || actorLabelFromType(source.actor_type || topIP.actor_type),
          topIP.asn ? formatASN(topIP.asn) : "",
          `${formatNumber(topIP.requests || 0)} requests`,
        ].filter(Boolean).join(" - ")
        : "No dominant source IP in this scope.",
      valueLabel: ipErrors ? "errors" : "requests",
      value: formatNumber(ipErrors || topIP?.requests || 0),
      actions: topIP?.ip
        ? [
          `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: topIP.ip, site_id: siteID, origin: "overview_brief" })}'>Open IP</button>`,
          topIP.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(topIP.asn), site_id: siteID, origin: "overview_brief" })}'>Open ASN</button>` : "",
          (source.known_actor || source.actor_type || topIP.actor_type) ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: source.known_actor || actorLabelFromType(source.actor_type || topIP.actor_type), actor_type: source.actor_type || topIP.actor_type || "", site_id: siteID, origin: "overview_brief" })}'>Open actor</button>` : "",
          `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ip: topIP.ip, site_id: siteID, status_class: ipErrors ? "errors" : "", origin: "overview_brief" })}'>IP logs</button>`,
        ].filter(Boolean).join("")
        : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, origin: "overview_brief" })}'>Source logs</button>`,
    },
    {
      title: "Report context",
      meta: report
        ? [reportListLabel(report), reportWindowLabel(report), report.model || ""].filter(Boolean).join(" - ")
        : "Open the report workspace for this site and period.",
      valueLabel: report ? reportTabForReport(report) : "period",
      value: report ? formatNumber(report.summary?.requests || 0) : formatCategory(state.reportTab || "daily"),
      actions: [
        reportAction,
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, status_class: site.status5xx || site.status4xx ? "errors" : "", origin: "overview_brief" })}'>Report logs</button>`,
      ].join(""),
    },
  ];
  return `
    <section class="problem-brief" aria-label="Top site operator brief">
      <div class="problem-brief-title">
        <span>Operator brief</span>
        <strong>${escapeHTML(site.status || "watch")} / ${formatNumber(site.statusRank || 0)}</strong>
      </div>
      <div class="problem-brief-list">${rows.map(overviewProblemBriefRow).join("")}</div>
    </section>
  `;
}

function overviewProblemBriefRow(row) {
  return `
    <div class="problem-brief-row">
      <div>
        <strong>${escapeHTML(row.title || "-")}</strong>
        <span>${escapeHTML(row.meta || "")}</span>
        <div class="signal-actions">${row.actions || ""}</div>
      </div>
      <div class="signal-numbers">
        <span>${escapeHTML(row.valueLabel || "")}</span>
        <b>${escapeHTML(row.value || "0")}</b>
      </div>
    </div>
  `;
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

function renderOverviewHealthMatrix(sites) {
  const rows = overviewHealthRows(sites);
  setText("#healthMatrixSummary", rows.length ? `${formatNumber(rows.length)} sites` : "no sites");
  const container = qs("#overviewHealthMatrix");
  if (!container) return;
  container.innerHTML = rows.map(overviewHealthRow).join("") || emptyRow(7, "No health telemetry is available in this scope.");
}

function overviewHealthRows(sites) {
  return (sites || []).map((site) => {
    const topPath = siteTopPaths(site.id)[0] || {};
    const topIP = siteTopSourceIPs(site.id)[0] || {};
    const errors = Number(site.status4xx || 0) + Number(site.status5xx || 0);
    const pathErrors = Number(topPath.status_4xx || 0) + Number(topPath.status_5xx || 0);
    const actor = topIP.known_actor || actorLabelFromType(topIP.actor_type) || topIP.reverse_dns || "";
    const p95 = Number(topPath.p95_request_time_ms || site.p95 || 0);
    const matrixScore = Number(site.statusRank || 0) * 1000000
      + Number(site.status5xx || 0) * 1000
      + Number(site.status4xx || 0)
      + Math.round(p95 || 0)
      + Number(site.signalCount || 0) * 10000;
    return {
      ...site,
      topPath,
      topIP,
      actor,
      errors,
      pathErrors,
      p95,
      matrixScore,
    };
  }).sort((a, b) => b.matrixScore - a.matrixScore || b.requests - a.requests).slice(0, 12);
}

function overviewHealthRow(item) {
  const topPath = item.topPath || {};
  const topIP = item.topIP || {};
  const statusClass = item.errors ? "errors" : "";
  const actor = item.actor || "-";
  const siteID = item.id || "";
  const path = topPath.path || "";
  const pathMeta = [
    path || "-",
    topPath.requests ? `${formatNumber(topPath.requests)} requests` : "",
    item.pathErrors ? `${formatNumber(item.pathErrors)} errors` : "",
  ].filter(Boolean).join(" / ");
  const sourceMeta = [
    topIP.ip || "",
    topIP.asn ? formatASN(topIP.asn) : "",
    topIP.asn_org || topIP.network || "",
  ].filter(Boolean).join(" / ");
  return `
    <tr>
      <td>
        <strong>${escapeHTML(item.name || siteID || "-")}</strong><br>
        <span class="severity severity-${escapeHTML(item.severity || "low")}">${escapeHTML(item.status || "healthy")}</span>
        <span>${escapeHTML(`${formatNumber(item.requests || 0)} requests / ${formatNumber(item.signalCount || 0)} signals`)}</span>
      </td>
      <td>${formatPercent(item.status4xxRate || 0)}<br><span>${formatNumber(item.status4xx || 0)}</span></td>
      <td>${formatPercent(item.status5xxRate || 0)}<br><span>${formatNumber(item.status5xx || 0)}</span></td>
      <td>${item.p95 ? formatMs(item.p95) : "-"}<br><span>${escapeHTML(item.p95 ? "slowest path" : "no slow data")}</span></td>
      <td class="clip"><strong>${escapeHTML(path || "-")}</strong><br><span>${escapeHTML(pathMeta)}</span></td>
      <td class="clip"><strong>${escapeHTML(actor)}</strong><br><span>${escapeHTML(sourceMeta || "no source IP")}</span></td>
      <td class="row-actions">
        ${siteID ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: siteID, origin: "overview_health" })}'>Open site</button>` : ""}
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, status_class: statusClass, origin: "overview_health" })}'>Logs</button>
        ${path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: path, site_id: siteID, origin: "overview_health" })}'>Path</button>` : ""}
        ${topIP.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: topIP.ip, site_id: siteID, origin: "overview_health" })}'>IP</button>` : ""}
      </td>
    </tr>
  `;
}

function renderOverviewSiteHeatmap(sites) {
  const rows = overviewSiteHeatmapRows(sites);
  const requests = rows.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  setText("#siteHeatmapSummary", rows.length ? `${formatNumber(rows.length)} sites / ${formatNumber(requests)} req` : "no sites");
  const container = qs("#siteHeatmapGrid");
  if (!container) return;
  if (!rows.length) {
    container.innerHTML = `<div class="empty">No site pressure telemetry is available in this scope.</div>`;
    return;
  }
  container.innerHTML = `
    <div class="site-heatmap-head">
      <span>Site</span>
      <span>Traffic</span>
      <span>4xx</span>
      <span>5xx</span>
      <span>Slow</span>
      <span>Probes</span>
      <span>Fresh</span>
      <span>Drilldowns</span>
    </div>
    ${rows.map(overviewSiteHeatmapRow).join("")}
  `;
}

function overviewSiteHeatmapRows(sites) {
  const allSites = (sites || []).filter((site) => site?.id);
  const maxRequests = Math.max(...allSites.map((site) => Number(site.requests || 0)), 1);
  return allSites.map((site) => {
    const siteID = site.id || "";
    const topPath = siteTopPaths(siteID)[0] || {};
    const topIP = siteTopSourceIPs(siteID)[0] || {};
    const signals = siteSignalItems(siteID);
    const securitySignals = signals.filter((item) => item.group === "security");
    const topSignal = securitySignals[0] || signals[0] || null;
    const p95 = Math.max(Number(site.p95 || 0), Number(topPath.p95_request_time_ms || 0));
    const freshness = overviewSiteFreshness(site);
    const errors = Number(site.status4xx || 0) + Number(site.status5xx || 0);
    const cells = [
      overviewSiteHeatCell({
        key: "traffic",
        label: "Traffic",
        value: formatNumber(site.requests || 0),
        meta: `${formatNumber(site.uniqueIPs || 0)} IPs`,
        level: overviewHeatLevel(ratio(site.requests || 0, maxRequests), [0.2, 0.5, 0.8]),
        title: `${formatNumber(site.requests || 0)} requests in the active window`,
        pivot: { kind: "site", value: siteID, origin: "overview_heatmap" },
      }),
      overviewSiteHeatCell({
        key: "4xx",
        label: "4xx",
        value: formatPercent(site.status4xxRate || 0),
        meta: formatNumber(site.status4xx || 0),
        level: overviewHeatLevel(site.status4xxRate || 0, [0.02, 0.1, 0.25]),
        title: `${formatNumber(site.status4xx || 0)} client errors`,
        pivot: { kind: "log_filter", site_id: siteID, status_class: Number(site.status4xx || 0) ? "errors" : "", origin: "overview_heatmap_4xx" },
      }),
      overviewSiteHeatCell({
        key: "5xx",
        label: "5xx",
        value: formatPercent(site.status5xxRate || 0),
        meta: formatNumber(site.status5xx || 0),
        level: overviewHeatLevel(site.status5xxRate || 0, [0.001, 0.01, 0.05]),
        title: `${formatNumber(site.status5xx || 0)} origin/server errors`,
        pivot: { kind: "log_filter", site_id: siteID, status_class: Number(site.status5xx || 0) ? "errors" : "", origin: "overview_heatmap_5xx" },
      }),
      overviewSiteHeatCell({
        key: "slow",
        label: "Slow",
        value: p95 ? formatMs(p95) : "-",
        meta: topPath.path ? "top path" : "no p95",
        level: overviewHeatLevel(p95, [500, 1000, 2500]),
        title: topPath.path ? `Slowest path ${topPath.path}` : "No slow path data",
        pivot: topPath.path
          ? { kind: "path", value: topPath.path, site_id: siteID, origin: "overview_heatmap_slow" }
          : { kind: "log_filter", site_id: siteID, origin: "overview_heatmap_slow" },
      }),
      overviewSiteHeatCell({
        key: "probes",
        label: "Probes",
        value: formatNumber(site.securitySignals || 0),
        meta: `${formatNumber(signals.length)} signals`,
        level: overviewHeatLevel(site.securitySignals || 0, [1, 3, 8]),
        title: `${formatNumber(site.securitySignals || 0)} security signals`,
        pivot: topSignal
          ? { kind: "signal", key: topSignal.key, site_id: topSignal.siteID || siteID, origin: "overview_heatmap_probes" }
          : { kind: "log_filter", site_id: siteID, status_class: errors ? "errors" : "", origin: "overview_heatmap_probes" },
      }),
      overviewSiteHeatCell({
        key: "freshness",
        label: "Fresh",
        value: freshness.value,
        meta: freshness.meta,
        level: freshness.level,
        title: freshness.title,
        pivot: { kind: "log_filter", site_id: siteID, origin: "overview_heatmap_freshness" },
      }),
    ];
    const heatScore = cells.reduce((sum, cell) => sum + overviewHeatRank(cell.level), 0)
      + Number(site.statusRank || 0) * 2
      + Math.min(5, signals.length)
      + Math.min(5, Math.floor(errors / 100));
    return { ...site, topPath, topIP, topSignal, cells, heatScore, errors };
  }).sort((a, b) => b.heatScore - a.heatScore || b.requests - a.requests || String(a.name || a.id).localeCompare(String(b.name || b.id))).slice(0, 16);
}

function overviewSiteHeatmapRow(item) {
  const siteID = item.id || "";
  const topPath = item.topPath || {};
  const topIP = item.topIP || {};
  const report = siteReports(siteID)[0];
  const errorClass = item.errors ? "errors" : "";
  const meta = [
    `${formatNumber(item.requests || 0)} requests`,
    item.lastSeen ? `last ${formatTime(item.lastSeen)}` : "",
    topPath.path ? `path ${topPath.path}` : "",
    topIP.ip ? `IP ${topIP.ip}` : "",
  ].filter(Boolean).join(" - ");
  const reportButton = report
    ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: siteID, origin: "overview_heatmap" }))}'>Report</button>`
    : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "overview_heatmap" })}'>Report</button>`;
  return `
    <div class="site-heatmap-row">
      <div class="site-heatmap-site">
        <span class="severity severity-${escapeHTML(item.severity || "low")}">${escapeHTML(item.status || "healthy")}</span>
        <strong>${escapeHTML(item.name || siteID)}</strong>
        <small>${escapeHTML(meta || "No indexed traffic in this scope.")}</small>
      </div>
      ${item.cells.map(overviewSiteHeatCellMarkup).join("")}
      <div class="site-heatmap-actions">
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: siteID, origin: "overview_heatmap" })}'>Site</button>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, status_class: errorClass, origin: "overview_heatmap" })}'>Logs</button>
        ${topPath.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: topPath.path, site_id: siteID, origin: "overview_heatmap" })}'>Path</button>` : ""}
        ${topIP.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: topIP.ip, site_id: siteID, origin: "overview_heatmap" })}'>IP</button>` : ""}
        ${reportButton}
      </div>
    </div>
  `;
}

function overviewSiteHeatCell(cell) {
  return {
    key: cell.key || "",
    label: cell.label || "",
    value: cell.value || "-",
    meta: cell.meta || "",
    level: cell.level || "none",
    title: cell.title || "",
    pivot: cell.pivot || {},
  };
}

function overviewSiteHeatCellMarkup(cell) {
  return `
    <button class="site-heat-cell heat-level-${escapeHTML(cell.level || "none")}" type="button" title="${escapeHTML(cell.title || cell.label || "")}" data-pivot='${encodePivot(cell.pivot || {})}'>
      <span>${escapeHTML(cell.label || "")}</span>
      <strong>${escapeHTML(cell.value || "-")}</strong>
      <small>${escapeHTML(cell.meta || "")}</small>
    </button>
  `;
}

function overviewHeatLevel(value, thresholds) {
  const number = Number(value || 0);
  if (!number) return "none";
  if (number >= thresholds[2]) return "critical";
  if (number >= thresholds[1]) return "high";
  if (number >= thresholds[0]) return "medium";
  return "low";
}

function overviewHeatRank(level) {
  return { none: 0, low: 1, medium: 2, high: 3, critical: 4 }[level] || 0;
}

function overviewSiteFreshness(site) {
  const latest = latestObservedTime();
  const last = site?.lastSeen || "";
  if (!last) {
    return {
      value: "missing",
      meta: "no events",
      level: "high",
      title: "No indexed events for this site in the active scope",
    };
  }
  const lastDate = new Date(last);
  const latestDate = latest ? new Date(latest) : new Date();
  if (Number.isNaN(lastDate.getTime()) || Number.isNaN(latestDate.getTime())) {
    return {
      value: "unknown",
      meta: "bad time",
      level: "medium",
      title: "Freshness timestamp could not be parsed",
    };
  }
  const lagHours = Math.max(0, (latestDate.getTime() - lastDate.getTime()) / (60 * 60 * 1000));
  const level = lagHours >= 72 ? "critical" : lagHours >= 24 ? "high" : lagHours >= 6 ? "medium" : "low";
  const value = lagHours < 1 ? "current" : lagHours < 24 ? `${Math.round(lagHours)}h lag` : `${Math.round(lagHours / 24)}d lag`;
  return {
    value,
    meta: formatTime(last),
    level,
    title: `Latest indexed event ${formatTime(last)}`,
  };
}

function overviewHotspotRows() {
  return filteredTopPaths()
    .filter((item) => Number(item.status_5xx || 0) > 0 || Number(item.status_4xx || 0) > 0 || Number(item.p95_request_time_ms || 0) > 0)
    .sort((a, b) => {
      const aErrors = Number(a.status_4xx || 0) + Number(a.status_5xx || 0);
      const bErrors = Number(b.status_4xx || 0) + Number(b.status_5xx || 0);
      return Number(b.status_5xx || 0) - Number(a.status_5xx || 0)
        || bErrors - aErrors
        || Number(b.p95_request_time_ms || 0) - Number(a.p95_request_time_ms || 0)
        || Number(b.requests || 0) - Number(a.requests || 0);
    });
}

function renderOverviewHotspots(rows) {
  const container = qs("#overviewHotspotsList");
  if (!container) return;
  container.innerHTML = rows.slice(0, 8).map(overviewHotspotRow).join("") || `<div class="empty">No failing or slow paths in this scope.</div>`;
}

function overviewHotspotRow(item) {
  const siteID = item.site_id || state.viewContext.site_id || state.siteID || "";
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  const statusClass = errors ? "errors" : "";
  const meta = [
    siteID || "all sites",
    `${formatNumber(item.requests || 0)} requests`,
    Number(item.status_5xx || 0) ? `${formatNumber(item.status_5xx || 0)} 5xx` : "",
    Number(item.status_4xx || 0) ? `${formatNumber(item.status_4xx || 0)} 4xx` : "",
    Number(item.p95_request_time_ms || 0) ? `p95 ${formatMs(item.p95_request_time_ms)}` : "",
  ].filter(Boolean).join(" - ");
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.path || "/")}</strong>
        <span>${escapeHTML(meta)}</span>
        <div class="signal-actions">
          ${siteID ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: siteID, origin: "overview_hotspot" })}'>Open site</button>` : ""}
          <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path || "/", site_id: siteID, origin: "overview_hotspot" })}'>Open path</button>
          ${correlatedLogActions({ path: item.path || "/", siteID, statusClass, origin: "overview_hotspot" })}
        </div>
      </div>
      <div class="signal-numbers"><span>${formatNumber(errors)} errors</span><b>${formatNumber(item.requests || 0)}</b></div>
    </div>
  `;
}

function overviewActorReviewRows() {
  const rows = (state.data.analysis?.source_ips || []).slice();
  const reviewRows = rows.filter((item) => actorSourceNeedsReview(item) || item.manual_action);
  const selected = reviewRows.length ? reviewRows : rows;
  return selected.sort((a, b) => {
    const reviewDelta = Number(actorSourceNeedsReview(b)) - Number(actorSourceNeedsReview(a));
    if (reviewDelta) return reviewDelta;
    const bErrors = Number(b.status_4xx || 0) + Number(b.status_5xx || 0);
    const aErrors = Number(a.status_4xx || 0) + Number(a.status_5xx || 0);
    return Number(b.risk_score || 0) - Number(a.risk_score || 0)
      || bErrors - aErrors
      || Number(b.requests || 0) - Number(a.requests || 0);
  });
}

function renderOverviewActorReview(rows) {
  const container = qs("#overviewActorReviewList");
  if (!container) return;
  const reviewCount = rows.filter(actorSourceNeedsReview).length;
  const asns = aggregateASNs(state.data.analysis?.source_ips || rows).slice(0, 3);
  const sourceRows = rows.slice(0, 6);
  setText("#actorReviewCount", reviewCount ? `${formatNumber(reviewCount)} review` : `${formatNumber(rows.length)} sources`);
  container.innerHTML = [
    asns.length ? `<div class="list-kicker">Top networks</div>${asns.map((item) => asnRow(item, "overview_actor_review")).join("")}` : "",
    sourceRows.length ? `<div class="list-kicker">Source review</div>${sourceRows.map(overviewActorReviewRow).join("")}` : "",
  ].filter(Boolean).join("") || `<div class="empty">No source IPs need verification in this scope.</div>`;
}

function overviewActorReviewRow(item) {
  const siteID = item.site_id || state.viewContext.site_id || state.siteID || "";
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  const status = actorSourceStatus(item);
  const label = item.known_actor || actorLabelFromType(item.actor_type) || item.reverse_dns || "Source IP";
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.ip || "-")}</strong>
        <span>${escapeHTML([status, label, siteID, `${formatNumber(item.requests || 0)} requests`, errors ? `${formatNumber(errors)} errors` : ""].filter(Boolean).join(" - "))}</span>
        <div class="signal-actions">
          <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: siteID, origin: "overview_actor_review" })}'>Open IP</button>
          ${item.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(item.asn), site_id: siteID, origin: "overview_actor_review" })}'>Open ASN</button>` : ""}
          ${(item.known_actor || item.actor_type) ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: item.known_actor || actorLabelFromType(item.actor_type), actor_type: item.actor_type || "", site_id: siteID, origin: "overview_actor_review" })}'>Open actor</button>` : ""}
          <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ip: item.ip || "", known_actor: item.known_actor || "", actor_type: item.actor_type || "", site_id: siteID, status_class: errors ? "errors" : "", origin: "overview_actor_review" })}'>Open logs</button>
          ${ipManualButtons(item.ip, item, siteID, "mini")}
        </div>
      </div>
      <div class="signal-numbers"><span>${escapeHTML(status)}</span><b>${escapeHTML(item.risk_score ?? 0)}</b></div>
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
  const context = [
    ["Confidence", signalConfidence(item)],
    ["Blast", signalBlastRadius(item)],
    ["Source", formatCategory(item.sourceKind || "signal")],
  ];
  return `
    <div class="signal-card">
      <div class="signal-card-main">
        <span class="severity severity-${escapeHTML(item.severity || "low")}">${escapeHTML(item.severity || "low")}</span>
        <div>
          <strong>${escapeHTML(item.title || "Signal")}</strong>
          <span>${escapeHTML(item.summary || meta || "No extra context")}</span>
          <small>${escapeHTML(meta)}</small>
          <div class="signal-card-context">
            ${context.map(([label, value]) => `<span class="signal-chip"><b>${escapeHTML(label)}</b>${escapeHTML(value || "-")}</span>`).join("")}
          </div>
          <small class="signal-recommendation">${escapeHTML(signalRecommendation(item))}</small>
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
  const source = item.ip ? sourceIPContextForIP(item.ip) : {};
  const actions = [
    `<button class="${klass}" type="button" data-pivot='${encodePivot({ kind: "signal", key: item.key, origin })}'>Open signal</button>`,
    item.ip ? `<button class="${klass}" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: item.siteID, origin })}'>Open IP</button>` : "",
    source.asn ? `<button class="${klass}" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(source.asn), site_id: item.siteID, origin })}'>Open ASN</button>` : "",
    item.path ? `<button class="${klass}" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path, site_id: item.siteID, origin })}'>Open path</button>` : "",
    item.sourceKind === "job"
      ? `<button class="${klass}" type="button" data-route-target="system">System</button>`
      : `<button class="${klass}" type="button" data-pivot='${encodePivot(signalLogPivot(item, origin))}'>Open logs</button>`,
    `<button class="${klass}" type="button" data-pivot='${encodePivot(signalReportContextPivot(item, origin))}'>Reports</button>`,
  ];
  return actions.filter(Boolean).join("");
}

function signalQueueSections(signals) {
  const sectionDefs = [
    { key: "critical", title: "Critical now", filter: "all", summary: "Highest-risk work across every signal group.", items: signals.filter((item) => severityRank(item.severity) >= severityRank("high")) },
    { key: "security", title: "Security probes", filter: "security", summary: "Injection, admin, Tor, and hostile source activity.", items: signals.filter((item) => item.group === "security") },
    { key: "reliability", title: "Reliability", filter: "reliability", summary: "5xx, slow paths, and recent failing requests.", items: signals.filter((item) => item.group === "reliability") },
    { key: "traffic", title: "Traffic shape", filter: "traffic", summary: "Volume, concentration, and unusual traffic patterns.", items: signals.filter((item) => item.group === "traffic") },
    { key: "pipeline", title: "Data pipeline", filter: "pipeline", summary: "Collection, indexing, reporting, and freshness problems.", items: signals.filter((item) => item.group === "pipeline") },
  ];
  return sectionDefs.map((section) => ({
    ...section,
    items: section.items.slice().sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || Number(b.risk || 0) - Number(a.risk || 0)),
  }));
}

function signalQueueRow(section) {
  const top = section.items[0];
  const sites = new Set(section.items.map((item) => item.siteID).filter(Boolean));
  const requests = section.items.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  const errors = section.items.reduce((sum, item) => sum + Number(item.errors || 0), 0);
  const highCount = section.items.filter((item) => severityRank(item.severity) >= severityRank("high")).length;
  const active = state.signalFilter === section.filter || (section.key === "critical" && state.signalFilter === "all");
  return `
    <div class="signal-queue-row ${active ? "active" : ""}">
      <div class="signal-queue-head">
        <div>
          <strong>${escapeHTML(section.title)}</strong>
          <span>${escapeHTML(section.summary)}</span>
        </div>
        <b>${formatNumber(section.items.length)}</b>
      </div>
      ${top ? `
        <div class="signal-queue-top">
          <span class="severity severity-${escapeHTML(top.severity || "low")}">${escapeHTML(top.severity || "low")}</span>
          <div>
            <strong>${escapeHTML(top.title || "Signal")}</strong>
            <small>${escapeHTML([`${formatNumber(requests)} requests`, `${formatNumber(errors)} errors`, `${formatNumber(sites.size)} sites`, `${formatNumber(highCount)} high+`].join(" - "))}</small>
          </div>
        </div>
        <div class="signal-actions">
          <button class="ghost mini inline-action" type="button" data-signal-filter-target="${escapeHTML(section.filter)}">Open group</button>
          <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: top.key, origin: "signals_queue" })}'>Open top signal</button>
          ${top.sourceKind === "job" ? `<button class="ghost mini inline-action" type="button" data-route-target="system">System</button>` : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(signalLogPivot(top, "signals_queue"))}'>Open logs</button>`}
        </div>
      ` : `
        <div class="empty compact-empty">No active signals in this lane.</div>
      `}
    </div>
  `;
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
  renderLogLaneOverview();

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
  renderLogsScopePath(evidence, topPaths);
  renderLogTypeProfile({ evidence, topPaths });
  setText("#logsTimelineSummary", `${formatNumber(timeline.length)} buckets`);
  renderPager("#logsPager", "logEvidence", evidence);
  setText("#logsEvidenceCount", `${formatNumber(pageItems.length)} of ${formatNumber(evidence.length)} rows`);
  renderLogsInvestigationPlan(evidence, topPaths);
  qs("#logsEvidenceTable").innerHTML = pageItems.map(logEvidenceTableRow).join("") || emptyRow(7, "No matching access-log evidence in this scope.");
  qs("#logsFacetsList").innerHTML = logFacetSections(evidence, topPaths).join("");
  setText("#logsFacetSummary", `${formatNumber(logFacetCount(evidence, topPaths))} values`);
  renderLogCorrelationPack(evidence, topPaths);
  setText("#logsTopPathCount", `${formatNumber(topPaths.length)} paths`);
  qs("#logsTopPathsList").innerHTML = topPaths.slice(0, 12).map(topPathLogRow).join("") || `<div class="empty">No paths match this scope.</div>`;
  const relatedRows = logRelatedEvidenceRows(evidence, topPaths);
  setText("#logsRelatedCount", `${formatNumber(relatedRows.length)} links`);
  qs("#logsRelatedList").innerHTML = relatedRows.slice(0, 10).map(logRelatedEvidenceRow).join("") || `<div class="empty">No related signals or report contexts match this scope.</div>`;
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
  renderLogsScopePath(correlatedEvidence, correlatedPaths, { segments });
  renderLogTypeProfile({
    evidence: correlatedEvidence,
    topPaths: correlatedPaths,
    segments,
    extraHTML: unsupportedLogSegmentBoard(segments, correlatedEvidence, correlatedPaths),
  });
  setText("#logsTimelineSummary", segmentTimeline.length ? `${formatNumber(segmentTimeline.length)} segment buckets` : "no segments");
  setText("#logsEvidenceEyebrow", "Segment evidence");
  setText("#logsEvidenceTitle", `${formatLogType(state.logType)} combined segments`);
  renderPager("#logsPager", "logEvidence", segments);
  setText("#logsEvidenceCount", segments.length ? `${formatNumber(pageItems.length)} of ${formatNumber(segments.length)} segments` : "no segments");
  renderLogsInvestigationPlan(correlatedEvidence, correlatedPaths, { segments });
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
  renderLogCorrelationPack(correlatedEvidence, correlatedPaths, { origin: "logs_correlation", currentSegments: segments });
  setText("#logsTopPathCount", correlatedPaths.length ? `${formatNumber(correlatedPaths.length)} correlated paths` : "no correlated paths");
  qs("#logsTopPathsList").innerHTML = correlatedPaths.slice(0, 12).map(correlatedPathRow).join("") || `<div class="empty">No access-log path context matches this ${escapeHTML(formatLogType(state.logType))} scope yet.</div>`;
  const relatedRows = unsupportedLogRelatedEvidenceRows(correlatedEvidence, correlatedPaths, segments);
  setText("#logsRelatedCount", `${formatNumber(relatedRows.length)} links`);
  qs("#logsRelatedList").innerHTML = relatedRows.slice(0, 10).map(logRelatedEvidenceRow).join("") || `<div class="empty">No related access evidence or signals match this ${escapeHTML(formatLogType(state.logType))} scope.</div>`;
}

function renderLogLaneOverview(evidence = filteredLogEvidence(), topPaths = filteredTopPaths()) {
  const rows = logLaneRows(evidence, topPaths);
  const active = rows.find((row) => row.active);
  const available = rows.filter((row) => row.count || row.requests || row.active).length;
  setText("#logsLaneSummary", active ? `${active.label} / ${formatNumber(available)} lanes` : `${formatNumber(available)} lanes`);
  const container = qs("#logsLaneOverview");
  if (!container) return;
  container.innerHTML = rows.map(logLaneRow).join("") || `<div class="empty">No log lanes are configured.</div>`;
}

function renderLogTypeProfile({ evidence = [], topPaths = [], segments = [], extraHTML = "" } = {}) {
  const container = qs("#logsTypeProfile");
  if (!container) return;
  const profile = logTypeProfile(state.logType, { evidence, topPaths, segments });
  container.innerHTML = `
    <section class="log-profile-card" aria-label="Selected log type profile">
      <div class="log-profile-head">
        <span class="lane-state lane-state-${escapeHTML(profile.state)}">${escapeHTML(formatCategory(profile.state))}</span>
        <div>
          <strong>${escapeHTML(profile.title)}</strong>
          <span>${escapeHTML(profile.scope)}</span>
        </div>
      </div>
      <div class="log-profile-grid">
        ${profile.rows.map(logTypeProfileRow).join("")}
      </div>
      <div class="signal-actions">${profile.actions}</div>
    </section>
    ${extraHTML || ""}
  `;
}

function renderLogsScopePath(evidence = [], topPaths = [], options = {}) {
  const container = qs("#logsScopePath");
  if (!container) return;
  container.innerHTML = logsScopePath(evidence, topPaths, options);
}

function logsScopePath(evidence = [], topPaths = [], options = {}) {
  const context = state.viewContext || {};
  const siteID = context.site_id || state.siteID || "";
  const segments = options.segments || (state.logType === "nginx-access" ? [] : unsupportedLogSegments(state.logType));
  const isAccess = state.logType === "nginx-access";
  const segmentSummary = isAccess ? null : segmentSummaryForLogType(state.logType);
  const requests = evidence.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  const errors = evidence.reduce((sum, item) => {
    const status = Number(item.status || 0);
    return sum
      + Number(item.errors || 0)
      + Number(item.status_4xx || 0)
      + Number(item.status_5xx || 0)
      + (status >= 400 ? 1 : 0);
  }, 0);
  const segmentLines = segments.reduce((sum, item) => sum + Number(item.line_count || 0), 0);
  const pendingSegments = segments.filter((item) => !(item.indexed || item.status === "indexed")).length;
  const primaryEntity = logPrimaryEntity(evidence, topPaths);
  const topPath = context.path ? { path: context.path, site_id: siteID } : topPaths[0] || {};
  const topIP = context.ip || evidence[0]?.ip || "";
  const relatedSegments = correlatedLogTypeDefs(false)
    .map(([logType]) => segmentSummaryForLogType(logType))
    .reduce((sum, item) => sum + Number(item.count || 0), 0);
  const relatedPending = correlatedLogTypeDefs(false)
    .map(([logType]) => segmentSummaryForLogType(logType))
    .reduce((sum, item) => sum + Number(item.pending || 0), 0);
  const report = reportContextsForLogContext(evidence, topPaths)[0];
  const lanePivot = logFilterPivotForContext(state.logType, context, "logs_path");
  const accessPivot = logFilterPivotForContext("nginx-access", context, "logs_path");
  const evidencePivot = isAccess ? {
    ...accessPivot,
    status_class: context.status_class || (errors ? "errors" : ""),
  } : lanePivot;
  const steps = [
    {
      label: "Scope",
      value: activeFilterLabel(),
      meta: logContextLabel(),
      actions: [
        siteID ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: siteID, origin: "logs_path" })}'>Open site</button>` : "",
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", origin: "logs_path" })}'>Clear</button>`,
      ].filter(Boolean).join(""),
    },
    {
      label: "Log lane",
      value: formatLogType(state.logType),
      meta: isAccess
        ? [`${formatNumber(evidence.length)} rows`, `${formatNumber(requests)} requests`, errors ? `${formatNumber(errors)} errors` : ""].filter(Boolean).join(" / ")
        : [`${formatNumber(segments.length || segmentSummary?.count || 0)} segments`, `${formatNumber(segmentLines || segmentSummary?.lines || 0)} lines`, pendingSegments || segmentSummary?.pending ? `${formatNumber(pendingSegments || segmentSummary?.pending)} pending` : "indexed"].filter(Boolean).join(" / "),
      actions: [
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(lanePivot)}'>Open lane</button>`,
        !isAccess ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(accessPivot)}'>Access rows</button>` : errors && context.status_class !== "errors" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ ...accessPivot, status_class: "errors" })}'>Errors</button>` : "",
      ].filter(Boolean).join(""),
    },
    {
      label: "Primary entity",
      value: primaryEntity ? shortLabel(logEntityLabel(primaryEntity.kind, primaryEntity.value), 54) : "No entity",
      meta: primaryEntity ? primaryEntity.meta : "No matching IP, path, actor, or site in this scope",
      actions: primaryEntity ? logScopePrimaryEntityActions(primaryEntity) : "",
    },
    {
      label: isAccess ? "Raw evidence" : "Segment evidence",
      value: isAccess ? `${formatNumber(evidence.length)} rows` : `${formatNumber(segments.length || segmentSummary?.count || 0)} segments`,
      meta: isAccess
        ? [`${formatNumber(requests)} requests`, errors ? `${formatNumber(errors)} errors` : "", topPath.path || ""].filter(Boolean).join(" / ")
        : [`${formatNumber(segmentLines || segmentSummary?.lines || 0)} lines`, segmentSummary?.latest ? `latest ${formatTime(segmentSummary.latest)}` : ""].filter(Boolean).join(" / "),
      actions: [
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(evidencePivot)}'>Open evidence</button>`,
        isAccess && topPath.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: topPath.path, site_id: topPath.site_id || siteID, origin: "logs_path" })}'>Open path</button>` : "",
      ].filter(Boolean).join(""),
    },
    {
      label: "Correlate",
      value: `${formatNumber(correlatedLogTypeDefs(true).length)} lanes`,
      meta: [
        relatedSegments ? `${formatNumber(relatedSegments)} related segments` : "segment lanes ready",
        relatedPending ? `${formatNumber(relatedPending)} pending` : "",
        topPath.path || topIP ? "context carried" : "",
      ].filter(Boolean).join(" / "),
      actions: correlatedLogActions({
        path: topPath.path || "",
        siteID: topPath.site_id || siteID,
        ip: topIP,
        statusClass: context.status_class || (errors ? "errors" : ""),
        origin: "logs_path",
      }),
    },
    {
      label: "Report period",
      value: report ? reportListLabel(report) : formatCategory(state.reportTab || "daily"),
      meta: report ? reportWindowLabel(report) : activeFilterLabel(),
      actions: report
        ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: report.site_id || siteID, origin: "logs_path" }))}'>Open report</button>`
        : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "logs_path" })}'>Reports</button>`,
    },
  ];
  return steps.map(logsScopePathStep).join("");
}

function logScopePrimaryEntityActions(entity) {
  const entityPivot = {
    kind: entity.kind,
    value: entity.value,
    site_id: entity.siteID || state.viewContext.site_id || state.siteID || "",
    origin: "logs_path",
  };
  if (entity.kind === "actor" && entity.actor_type) entityPivot.actor_type = entity.actor_type;
  const logPivot = {
    ...logPrimaryEntityLogPivot(entity),
    origin: "logs_path",
  };
  return [
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(entityPivot)}'>Open ${escapeHTML(logEntityActionLabel(entity.kind))}</button>`,
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logPivot)}'>Entity logs</button>`,
  ].join("");
}

function logsScopePathStep(step) {
  return `
    <div class="logs-scope-step">
      <div>
        <span>${escapeHTML(step.label || "-")}</span>
        <strong>${escapeHTML(step.value || "-")}</strong>
        <small>${escapeHTML(step.meta || "")}</small>
      </div>
      <div class="signal-actions">${step.actions || ""}</div>
    </div>
  `;
}

function logTypeProfile(logType = state.logType, { evidence = [], topPaths = [], segments = [] } = {}) {
  const def = logTypeDefinition(logType);
  const isAccess = logType === "nginx-access";
  const summary = isAccess ? null : segmentSummaryForLogType(logType);
  const segmentRows = segments.length ? segments : unsupportedLogSegments(logType);
  const accessErrors = evidence.reduce((sum, item) => sum + Number(item.errors || 0) + Number(item.status_4xx || 0) + Number(item.status_5xx || 0), 0);
  const stateLabel = isAccess
    ? "active"
    : summary?.count ? summary.pending ? "pending" : "indexed" : "empty";
  const evidenceValue = isAccess
    ? `${formatNumber(evidence.length)} rows / ${formatNumber(evidence.reduce((sum, item) => sum + Number(item.requests || 0), 0))} requests`
    : `${formatNumber(segmentRows.length || summary?.count || 0)} segments / ${formatNumber(segmentRows.reduce((sum, item) => sum + Number(item.line_count || 0), 0) || summary?.lines || 0)} lines`;
  const rows = [
    ["Mode", def.mode],
    ["Evidence", evidenceValue],
    ["Fields", def.fields.join(", ")],
    ["Entity pivots", def.entities.join(", ")],
    ["Correlation", logTypeProfileCorrelation(logType, evidence, topPaths, segmentRows)],
  ];
  return {
    title: `${formatLogType(logType)} profile`,
    state: stateLabel,
    scope: logContextLabel(),
    rows,
    actions: logTypeProfileActions(logType, evidence, topPaths, accessErrors),
  };
}

function logTypeDefinition(logType = "nginx-access") {
  return {
    "nginx-access": {
      mode: "Parsed request evidence",
      fields: ["status", "method", "path/query", "source IP", "ASN/actor", "user-agent", "bytes/time"],
      entities: ["site", "IP", "ASN", "path", "user-agent", "signal"],
    },
    "nginx-error": {
      mode: "Error segment lane",
      fields: ["severity", "message fingerprint", "site/env/container", "correlated path", "request id"],
      entities: ["site", "path", "source IP", "signal", "access rows"],
    },
    "php-error": {
      mode: "Application error lane",
      fields: ["severity", "message fingerprint", "file/function", "site/env/container", "correlated path"],
      entities: ["site", "path", "source IP", "signal", "access rows"],
    },
    "php-slow": {
      mode: "Slow execution lane",
      fields: ["script", "duration", "stack fingerprint", "site/env/container", "correlated path"],
      entities: ["site", "path", "source IP", "slow signal", "access rows"],
    },
    "mysql-slow": {
      mode: "Database slow-query lane",
      fields: ["query fingerprint", "duration", "rows examined", "site/env/container"],
      entities: ["site", "path", "slow signal", "access rows"],
    },
  }[logType] || {
    mode: "Segment lane",
    fields: ["severity", "message", "site/env", "timestamp"],
    entities: ["site", "path", "source IP", "access rows"],
  };
}

function logTypeProfileCorrelation(logType, evidence = [], topPaths = [], segments = []) {
  const parts = [];
  if (logType !== "nginx-access") parts.push(`${formatNumber(evidence.length)} access rows`);
  if (topPaths.length) parts.push(`${formatNumber(topPaths.length)} paths`);
  if (segments.length) parts.push(`${formatNumber(segments.filter((item) => item.indexed || item.status === "indexed").length)} indexed`);
  if (state.viewContext.status_class === "errors") parts.push("errors only");
  return parts.join(" / ") || "current scope";
}

function logTypeProfileActions(logType, evidence = [], topPaths = [], accessErrors = 0) {
  const context = state.viewContext || {};
  const siteID = context.site_id || state.siteID || "";
  const report = reportContextsForLogContext(evidence, topPaths)[0];
  const actions = [
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logFilterPivotForContext(logType, context, "logs_profile"))}'>Open lane</button>`,
  ];
  if (logType !== "nginx-access") {
    actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logFilterPivotForContext("nginx-access", context, "logs_profile"))}'>Access rows</button>`);
  } else if (accessErrors && context.status_class !== "errors") {
    actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ ...logFilterPivotForContext(logType, context, "logs_profile"), status_class: "errors" })}'>Errors only</button>`);
  }
  if (context.ip) actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: context.ip, site_id: siteID, origin: "logs_profile" })}'>Open IP</button>`);
  else if (evidence[0]?.ip) actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: evidence[0].ip, site_id: evidence[0].site_id || siteID, origin: "logs_profile" })}'>Top IP</button>`);
  if (context.path) actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: context.path, site_id: siteID, origin: "logs_profile" })}'>Open path</button>`);
  else if (topPaths[0]?.path) actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: topPaths[0].path, site_id: topPaths[0].site_id || siteID, origin: "logs_profile" })}'>Top path</button>`);
  if (report) {
    actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: report.site_id || siteID, origin: "logs_profile" }))}'>Open report</button>`);
  }
  return actions.join("");
}

function logTypeProfileRow([label, value]) {
  return `
    <div class="log-profile-row">
      <span>${escapeHTML(label)}</span>
      <strong>${escapeHTML(value || "-")}</strong>
    </div>
  `;
}

function logLaneRows(evidence = [], topPaths = []) {
  const context = state.viewContext || {};
  const accessErrors = evidence.reduce((sum, item) => sum + Number(item.errors || 0) + Number(item.status_4xx || 0) + Number(item.status_5xx || 0), 0);
  const accessRequests = evidence.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  const latestAccess = latestLogEvidenceTime(evidence, topPaths);
  const rows = [{
    logType: "nginx-access",
    label: "Access",
    status: state.logType === "nginx-access" ? "active" : evidence.length ? "available" : "empty",
    count: evidence.length,
    requests: accessRequests,
    errors: accessErrors,
    canFilterErrors: accessErrors > 0,
    latest: latestAccess,
    meta: [
      `${formatNumber(evidence.length)} rows`,
      accessRequests ? `${formatNumber(accessRequests)} requests` : "",
      accessErrors ? `${formatNumber(accessErrors)} errors` : "",
      topPaths[0]?.path || "",
    ].filter(Boolean).join(" - "),
    active: state.logType === "nginx-access",
  }];
  correlatedLogTypeDefs(false).forEach(([logType, label]) => {
    const summary = segmentSummaryForLogType(logType);
    rows.push({
      logType,
      label,
      status: state.logType === logType ? "active" : summary.count ? summary.pending ? "pending" : "indexed" : "empty",
      count: summary.count,
      requests: summary.lines,
      errors: 0,
      canFilterErrors: false,
      latest: summary.latest,
      meta: [
        summary.count ? `${formatNumber(summary.count)} segments` : "no segments",
        summary.lines ? `${formatNumber(summary.lines)} lines` : "",
        summary.indexed ? `${formatNumber(summary.indexed)} indexed` : "",
        summary.pending ? `${formatNumber(summary.pending)} pending` : "",
      ].filter(Boolean).join(" - "),
      active: state.logType === logType,
      pending: summary.pending,
    });
  });
  return rows.map((row) => ({
    ...row,
    contextLabel: logLaneContextLabel(context),
  }));
}

function logLaneRow(item) {
  const context = state.viewContext || {};
  const openPivot = logFilterPivotForContext(item.logType, context, "logs_lane");
  const errorPivot = logFilterPivotForContext(item.logType, { ...context, status_class: "errors" }, "logs_lane");
  return `
    <div class="log-lane-row ${item.active ? "active" : ""}">
      <div class="log-lane-main">
        <span class="lane-state lane-state-${escapeHTML(item.status || "empty")}">${escapeHTML(formatCategory(item.status || "empty"))}</span>
        <div>
          <strong>${escapeHTML(item.label || formatLogType(item.logType))}</strong>
          <span>${escapeHTML(item.meta || item.contextLabel || "-")}</span>
          ${item.latest ? `<small>${escapeHTML(`latest ${formatTime(item.latest)}`)}</small>` : ""}
        </div>
      </div>
      <div class="log-lane-actions">
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(openPivot)}'>Open</button>
        ${item.canFilterErrors ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(errorPivot)}'>Errors</button>` : ""}
        ${item.pending ? `<button class="ghost mini inline-action" type="button" data-route-target="system">Index</button>` : ""}
      </div>
    </div>
  `;
}

function logLaneContextLabel(context = state.viewContext || {}) {
  return [
    context.site_id || state.siteID || "",
    context.path || "",
    context.ip ? `IP ${context.ip}` : "",
    context.asn ? formatASN(context.asn) : "",
    context.known_actor || "",
  ].filter(Boolean).join(" - ");
}

function latestLogEvidenceTime(evidence = [], topPaths = []) {
  const times = [
    ...evidence.map((item) => item.ts || item.last_seen || item.timestamp),
    ...topPaths.map((item) => item.last_seen || item.ts || item.timestamp),
  ].filter(Boolean)
    .map((value) => new Date(value))
    .filter((date) => !Number.isNaN(date.getTime()));
  if (!times.length) return "";
  return new Date(Math.max(...times.map((date) => date.getTime()))).toISOString();
}

function renderLogsInvestigationPlan(evidence = [], topPaths = [], options = {}) {
  const rows = logInvestigationPlanRows(evidence, topPaths, options);
  setText("#logsPlanSummary", rows.length ? `${formatNumber(rows.length)} steps` : "no steps");
  const container = qs("#logsInvestigationPlan");
  if (!container) return;
  container.innerHTML = rows.map(logInvestigationPlanRow).join("") || `<div class="empty">No investigation steps available for this scope.</div>`;
}

function logInvestigationPlanRows(evidence = [], topPaths = [], options = {}) {
  const context = state.viewContext || {};
  const currentSegments = options.segments || (state.logType === "nginx-access" ? [] : unsupportedLogSegments(state.logType));
  const isAccess = state.logType === "nginx-access";
  const siteID = context.site_id || state.siteID || "";
  const errors = evidence.reduce((sum, item) => sum + Number(item.errors || 0) + Number(item.status_4xx || 0) + Number(item.status_5xx || 0), 0);
  const requests = evidence.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  const segmentLines = currentSegments.reduce((sum, item) => sum + Number(item.line_count || 0), 0);
  const pendingSegments = currentSegments.filter((item) => !(item.indexed || item.status === "indexed")).length;
  const primaryEntity = logPrimaryEntity(evidence, topPaths);
  const topSignal = relatedSignalsForLogContext(evidence, topPaths)[0];
  const report = reportContextsForLogContext(evidence, topPaths)[0];
  const rows = [
    isAccess ? {
      title: "Review matching access evidence",
      meta: [
        logContextLabel(),
        `${formatNumber(evidence.length)} rows`,
        `${formatNumber(requests)} requests`,
        errors ? `${formatNumber(errors)} errors` : "",
      ].filter(Boolean).join(" - "),
      valueLabel: "rows",
      value: formatNumber(evidence.length),
      actions: [
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logFilterPivotForContext("nginx-access", context, "logs_plan"))}'>Open access</button>`,
        errors && context.status_class !== "errors" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ ...logFilterPivotForContext("nginx-access", context, "logs_plan"), status_class: "errors" })}'>Errors only</button>` : "",
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", log_type: "nginx-access", origin: "logs_plan" })}'>All access</button>`,
      ].filter(Boolean).join(""),
    } : {
      title: `Review ${formatLogType(state.logType)} segments`,
      meta: [
        logContextLabel(),
        `${formatNumber(segmentLines)} combined lines`,
        pendingSegments ? `${formatNumber(pendingSegments)} pending index` : "indexed",
        `${formatNumber(evidence.length)} correlated access rows`,
      ].filter(Boolean).join(" - "),
      valueLabel: "segments",
      value: formatNumber(currentSegments.length),
      actions: [
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logFilterPivotForContext(state.logType, context, "logs_plan"))}'>Open ${escapeHTML(formatLogType(state.logType))}</button>`,
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logFilterPivotForContext("nginx-access", context, "logs_plan"))}'>Access rows</button>`,
        pendingSegments ? `<button class="ghost mini inline-action" type="button" data-route-target="system">Index status</button>` : "",
      ].filter(Boolean).join(""),
    },
    primaryEntity ? {
      title: "Inspect primary entity",
      meta: primaryEntity.meta,
      valueLabel: primaryEntity.valueLabel,
      value: primaryEntity.metricValue,
      actions: logPrimaryEntityActions(primaryEntity),
    } : null,
    {
      title: "Correlate log lanes",
      meta: logCorrelationPlanMeta(context, topPaths, evidence),
      valueLabel: "lanes",
      value: formatNumber(correlatedLogTypeDefs(true).length),
      actions: correlatedLogActions({
        path: context.path || topPaths[0]?.path || "",
        ip: context.ip || evidence[0]?.ip || "",
        siteID,
        statusClass: context.status_class || (errors ? "errors" : ""),
        origin: "logs_plan",
      }),
    },
    {
      title: "Open signal and report context",
      meta: [
        topSignal ? topSignal.title : "No matching signal selected",
        report ? reportListLabel(report) : "No matching report selected",
      ].filter(Boolean).join(" - "),
      valueLabel: topSignal ? "risk" : report ? "report" : "context",
      value: topSignal ? topSignal.risk || severityRank(topSignal.severity) * 20 || 0 : report ? formatNumber(report.summary?.requests || 0) : "open",
      actions: [
        topSignal ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: topSignal.key, site_id: topSignal.siteID || siteID, origin: "logs_plan" })}'>Open signal</button>` : `<button class="ghost mini inline-action" type="button" data-route-target="signals">Signals</button>`,
        report ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: report.site_id || siteID, origin: "logs_plan" }))}'>Open report</button>` : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "logs_plan" })}'>Reports</button>`,
      ].join(""),
    },
  ];
  return rows.filter(Boolean);
}

function logInvestigationPlanRow(item) {
  return `
    <div class="signal-row logs-command-row">
      <div>
        <strong>${escapeHTML(item.title || "-")}</strong>
        <span>${escapeHTML(item.meta || "")}</span>
        <div class="signal-actions">${item.actions || ""}</div>
      </div>
      <div class="signal-numbers">
        <span>${escapeHTML(item.valueLabel || "")}</span>
        <b>${escapeHTML(item.value ?? "")}</b>
      </div>
    </div>
  `;
}

function logPrimaryEntity(evidence = [], topPaths = []) {
  const context = state.viewContext || {};
  const siteID = context.site_id || state.siteID || "";
  if (context.ip) return logPrimaryEntityFromParts("ip", context.ip, siteID, evidence, topPaths);
  if (context.asn) return logPrimaryEntityFromParts("asn", formatASN(context.asn) || context.asn, siteID, evidence, topPaths);
  if (context.path) return logPrimaryEntityFromParts("path", context.path, siteID, evidence, topPaths);
  if (context.known_actor) return logPrimaryEntityFromParts("actor", context.known_actor, siteID, evidence, topPaths, { actor_type: context.actor_type || "" });
  if (context.user_agent) return logPrimaryEntityFromParts("user-agent", context.user_agent, siteID, evidence, topPaths);
  const topIP = countFacet(evidence, (item) => item.ip, (item) => item.requests)[0];
  if (topIP?.label) return logPrimaryEntityFromParts("ip", topIP.label, topIP.site_id || siteID, evidence, topPaths, { requests: topIP.value, errors: topIP.errors });
  if (topPaths[0]?.path) return logPrimaryEntityFromParts("path", topPaths[0].path || "/", topPaths[0].site_id || siteID, evidence, topPaths, { requests: topPaths[0].requests, errors: Number(topPaths[0].status_4xx || 0) + Number(topPaths[0].status_5xx || 0) });
  if (siteID) return logPrimaryEntityFromParts("site", siteID, siteID, evidence, topPaths);
  return null;
}

function logPrimaryEntityFromParts(kind, value, siteID, evidence = [], topPaths = [], extra = {}) {
  const source = kind === "ip" ? sourceIPContextForIP(value) : {};
  const rows = kind === "path" ? topPaths.filter((item) => pathMatches(item.path, value)) : evidence.filter((item) => logEvidenceMatchesEntity(item, kind, value, extra));
  const requests = extra.requests ?? rows.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  const errors = extra.errors ?? rows.reduce((sum, item) => sum + Number(item.errors || 0) + Number(item.status_4xx || 0) + Number(item.status_5xx || 0), 0);
  return {
    kind,
    value,
    siteID,
    actor_type: extra.actor_type || source.actor_type || "",
    meta: [
      logEntityLabel(kind, value),
      source.known_actor || actorLabelFromType(source.actor_type) || "",
      source.asn ? formatASN(source.asn) : "",
      source.asn_org || source.network || "",
      requests ? `${formatNumber(requests)} requests` : "",
      errors ? `${formatNumber(errors)} errors` : "",
    ].filter(Boolean).join(" - "),
    valueLabel: kind === "ip" ? "risk" : kind === "path" ? "errors" : "rows",
    metricValue: kind === "ip" ? source.risk_score || 0 : kind === "path" ? formatNumber(errors) : formatNumber(rows.length || 1),
  };
}

function logEvidenceMatchesEntity(item, kind, value, extra = {}) {
  if (kind === "ip") return item.ip === value;
  if (kind === "asn") return normalizeASN(item.asn) === normalizeASN(value);
  if (kind === "path") return pathMatches(item.path, value);
  if (kind === "actor") return item.known_actor === value || (extra.actor_type && item.actor_type === extra.actor_type);
  if (kind === "user-agent") return userAgentMatches(item.user_agent || "", value);
  if (kind === "site") return item.site_id === value;
  return false;
}

function logPrimaryEntityActions(entity) {
  const logPivot = logPrimaryEntityLogPivot(entity);
  const entityPivot = {
    kind: entity.kind,
    value: entity.value,
    site_id: entity.siteID || "",
    origin: "logs_plan",
  };
  if (entity.kind === "site") {
    entityPivot.kind = "site";
  }
  if (entity.kind === "actor" && entity.actor_type) entityPivot.actor_type = entity.actor_type;
  return [
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(entityPivot)}'>Open ${escapeHTML(logEntityActionLabel(entity.kind))}</button>`,
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logPivot)}'>Matching logs</button>`,
  ].join("");
}

function logPrimaryEntityLogPivot(entity) {
  const pivot = { kind: "log_filter", log_type: state.logType || "nginx-access", site_id: entity.siteID || "", origin: "logs_plan" };
  if (entity.kind === "ip") pivot.ip = entity.value;
  if (entity.kind === "asn") pivot.asn = formatASN(entity.value) || entity.value;
  if (entity.kind === "path") pivot.path = entity.value;
  if (entity.kind === "actor") {
    pivot.known_actor = entity.value;
    if (entity.actor_type) pivot.actor_type = entity.actor_type;
  }
  if (entity.kind === "user-agent") pivot.user_agent = entity.value;
  return pivot;
}

function logEntityLabel(kind, value) {
  if (kind === "ip") return `IP ${value}`;
  if (kind === "asn") return formatASN(value) || value;
  if (kind === "path") return `Path ${value}`;
  if (kind === "actor") return `Actor ${value}`;
  if (kind === "user-agent") return `User agent ${shortLabel(value, 72)}`;
  if (kind === "site") return `Site ${value}`;
  return value;
}

function logEntityActionLabel(kind) {
  return {
    ip: "IP",
    asn: "ASN",
    path: "path",
    actor: "actor",
    "user-agent": "user agent",
    site: "site",
  }[kind] || "entity";
}

function logCorrelationPlanMeta(context = state.viewContext || {}, topPaths = [], evidence = []) {
  const summaries = correlatedLogTypeDefs(false).map(([logType]) => segmentSummaryForLogType(logType));
  const segments = summaries.reduce((sum, item) => sum + Number(item.count || 0), 0);
  const pending = summaries.reduce((sum, item) => sum + Number(item.pending || 0), 0);
  return [
    context.path || topPaths[0]?.path || "",
    context.ip ? `IP ${context.ip}` : evidence[0]?.ip ? `IP ${evidence[0].ip}` : "",
    segments ? `${formatNumber(segments)} related segments` : "segment lanes ready",
    pending ? `${formatNumber(pending)} pending index` : "",
  ].filter(Boolean).join(" - ");
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

function unsupportedLogSegmentBoard(segments = [], evidence = [], topPaths = []) {
  const logType = state.logType || "nginx-error";
  const current = segments[0];
  const def = logTypeDefinition(logType);
  const indexed = segments.filter((item) => item.indexed || item.status === "indexed").length;
  const pending = Math.max(0, segments.length - indexed);
  const lines = segments.reduce((sum, item) => sum + Number(item.line_count || 0), 0);
  const context = state.viewContext || {};
  const siteID = context.site_id || state.siteID || "";
  const topPath = context.path ? { path: context.path, site_id: siteID } : topPaths[0] || {};
  const topIP = context.ip || evidence[0]?.ip || "";
  const lanePivot = logFilterPivotForContext(logType, context, "logs_segment_board");
  const accessPivot = logFilterPivotForContext("nginx-access", context, "logs_segment_board");
  const boardActions = [
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(lanePivot)}'>Open lane</button>`,
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(accessPivot)}'>Access rows</button>`,
    topPath.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: topPath.path, site_id: topPath.site_id || siteID, origin: "logs_segment_board" })}'>Top path</button>` : "",
    topIP ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: topIP, site_id: siteID, origin: "logs_segment_board" })}'>Top IP</button>` : "",
    pending ? `<button class="ghost mini inline-action" type="button" data-route-target="system">System</button>` : "",
  ].filter(Boolean).join("");
  return `
    <section class="log-segment-board" aria-label="${escapeHTML(formatLogType(logType))} segment investigation board">
      <div class="log-segment-board-head">
        <div>
          <span>Segment investigation</span>
          <strong>${escapeHTML(current ? segmentTitle(current) : `${formatLogType(logType)} lane`)}</strong>
          <small>${escapeHTML(current ? segmentWindowLabel(current) : "No combined segments in the recent window")}</small>
        </div>
        <div class="signal-actions">${boardActions}</div>
      </div>
      <div class="log-segment-board-grid">
        ${segmentBoardCard("Coverage", [
          ["Segments", formatNumber(segments.length)],
          ["Lines", formatNumber(lines)],
          ["Latest bucket", formatTime(current?.bucket_start || current?.min_ts || current?.bucket_end)],
        ])}
        ${segmentBoardCard("Index state", [
          ["Indexed", formatNumber(indexed)],
          ["Parser pending", formatNumber(pending)],
          ["Current", current ? segmentStatusLabel(current) : "no segment"],
        ])}
        ${segmentBoardCard("Parsed fields", def.fields.map((field) => [field, "planned"]))}
        ${segmentBoardCard("Correlate", [
          ["Access rows", formatNumber(evidence.length)],
          ["Paths", formatNumber(topPaths.length)],
          ["Entity", topIP ? `IP ${topIP}` : topPath.path || "scope"],
        ])}
      </div>
      <div class="log-segment-strip">
        ${segments.slice(0, 4).map(unsupportedLogSegmentChip).join("") || `<div class="empty">Segment metadata will appear here after the combiner writes this log type.</div>`}
      </div>
    </section>
  `;
}

function segmentBoardCard(title, rows = []) {
  return `
    <div class="log-segment-card">
      <strong>${escapeHTML(title)}</strong>
      <div class="log-segment-facts">
        ${rows.slice(0, 6).map(([label, value]) => `
          <div>
            <span>${escapeHTML(label)}</span>
            <b>${escapeHTML(value || "-")}</b>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function unsupportedLogSegmentChip(segment) {
  const status = segmentStatusLabel(segment);
  const lanePivot = logFilterPivotForContext(segment.log_type || state.logType, state.viewContext || {}, "logs_segment_chip");
  return `
    <div class="log-segment-chip">
      <span class="lane-state lane-state-${escapeHTML(segmentStateClass(segment))}">${escapeHTML(status)}</span>
      <div>
        <strong>${escapeHTML(segmentTitle(segment))}</strong>
        <small>${escapeHTML([segmentWindowLabel(segment), `${formatNumber(segment.line_count || 0)} lines`, shortHash(segment.sha256 || segment.id || "")].filter(Boolean).join(" / "))}</small>
      </div>
      <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(lanePivot)}'>Lane</button>
    </div>
  `;
}

function logSegmentTableRow(segment) {
  const status = segmentStatusLabel(segment);
  const start = segment.min_ts || segment.bucket_start;
  const end = segment.max_ts || segment.bucket_end;
  const context = state.viewContext || {};
  const siteID = context.site_id || state.siteID || "";
  const lanePivot = logFilterPivotForContext(segment.log_type || state.logType, context, "logs_segment_row");
  const accessPivot = logFilterPivotForContext("nginx-access", context, "logs_segment_row");
  const pathPivot = context.path ? { kind: "path", value: context.path, site_id: siteID, origin: "logs_segment_row" } : null;
  const pending = !(segment.indexed || segment.status === "indexed");
  return `
    <tr>
      <td><strong>${formatTime(segment.bucket_start || start)}</strong><br><span>${formatTime(segment.bucket_end || end)}</span></td>
      <td><span class="status-${escapeHTML(status)}">${escapeHTML(status)}</span><br><span>${escapeHTML(formatLogType(segment.log_type))}</span></td>
      <td>${escapeHTML(siteID || "all sites")}<br><span>combined scope</span></td>
      <td><strong>${formatNumber(segment.line_count || 0)} lines</strong><br><span>${escapeHTML(shortHash(segment.sha256 || segment.id || ""))}</span></td>
      <td class="clip">${escapeHTML(segment.path || "-")}</td>
      <td>${escapeHTML([start ? `min ${formatTime(start)}` : "", end ? `max ${formatTime(end)}` : ""].filter(Boolean).join(" / ") || "parser pending")}</td>
      <td class="row-actions">
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(lanePivot)}'>Lane</button>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(accessPivot)}'>Access rows</button>
        ${pathPivot ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(pathPivot)}'>Path</button>` : ""}
        ${pending ? `<button class="ghost mini inline-action" type="button" data-route-target="system">System</button>` : ""}
      </td>
    </tr>
  `;
}

function segmentTitle(segment = {}) {
  return `${formatLogType(segment.log_type || state.logType)} ${formatTime(segment.bucket_start || segment.min_ts || segment.bucket_end)}`;
}

function segmentStatusLabel(segment = {}) {
  return segment.indexed || segment.status === "indexed" ? "indexed" : segment.status || "combined";
}

function segmentStateClass(segment = {}) {
  if (segment.indexed || segment.status === "indexed") return "indexed";
  if (segment.status === "failed") return "failed";
  return segment.status ? "pending" : "pending";
}

function segmentWindowLabel(segment = {}) {
  const start = segment.min_ts || segment.bucket_start;
  const end = segment.max_ts || segment.bucket_end;
  if (!start && !end) return "parser timestamp pending";
  if (!start || !end || start === end) return formatTime(start || end);
  return `${formatTime(start)} to ${formatTime(end)}`;
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
  return logContextItems().map(logContextChip);
}

function logContextPairs() {
  return logContextItems().map((item) => [item.label, item.value]);
}

function logContextItems() {
  const context = state.viewContext || {};
  const siteID = context.site_id || state.siteID || "";
  const entityPivot = (kind, value, extra = {}) => ({
    ...context,
    ...extra,
    kind,
    value,
    site_id: siteID,
    origin: "logs_context",
  });
  const items = [
    { label: "Scope", value: activeFilterLabel(), key: "scope" },
    { label: "Log type", value: formatLogType(state.logType), key: "log_type", removable: state.logType !== "nginx-access" },
  ];
  if (siteID) items.push({ label: "Site", value: siteID, key: "site_id", removable: true, pivot: { kind: "site", value: siteID, origin: "logs_context" } });
  if (context.ip) items.push({ label: "IP", value: context.ip, key: "ip", removable: true, pivot: entityPivot("ip", context.ip) });
  if (context.asn) items.push({ label: "ASN", value: formatASN(context.asn) || context.asn, key: "asn", removable: true, pivot: entityPivot("asn", context.asn) });
  if (context.path) items.push({ label: "Path", value: context.path, key: "path", removable: true, pivot: entityPivot("path", context.path) });
  if (context.known_actor) items.push({ label: "Actor", value: context.known_actor, key: "known_actor", removable: true, pivot: entityPivot("actor", context.known_actor, { actor_type: context.actor_type || "" }) });
  if (context.actor_type) items.push({ label: "Actor type", value: formatCategory(context.actor_type), key: "actor_type", removable: true });
  if (context.env) items.push({ label: "Env", value: context.env, key: "env", removable: true });
  if (context.status_class === "errors") items.push({ label: "Status", value: "Errors only", key: "status_class", removable: true });
  if (context.severity) items.push({ label: "Min severity", value: signalSeverityLabel(context.severity), key: "severity", removable: true });
  if (context.user_agent) items.push({ label: "User agent", value: context.user_agent, key: "user_agent", removable: true, pivot: entityPivot("user-agent", context.user_agent) });
  if (context.evidence_kind) items.push({ label: "Evidence", value: context.evidence_kind, key: "evidence_kind", removable: true });
  return items;
}

function logContextChip(item) {
  const actions = [
    item.pivot ? `<button class="context-chip-action" type="button" data-pivot='${encodePivot(item.pivot)}' aria-label="Open ${escapeHTML(item.label)} ${escapeHTML(item.value)}">Open</button>` : "",
    item.removable ? `<button class="context-chip-remove" type="button" data-log-context-remove="${escapeHTML(item.key)}" aria-label="Remove ${escapeHTML(item.label)} filter">&times;</button>` : "",
  ].filter(Boolean).join("");
  return `
    <span class="context-chip context-chip-rich">
      <span><b>${escapeHTML(item.label)}</b>${escapeHTML(item.value || "-")}</span>
      ${actions}
    </span>
  `;
}

async function removeLogContextFilter(key) {
  if (!key) return;
  if (key === "log_type") {
    state.logType = "nginx-access";
  } else if (key === "site_id") {
    state.siteID = "";
    delete state.viewContext.site_id;
  } else {
    delete state.viewContext[key];
  }
  if (key === "known_actor") delete state.viewContext.actor_type;
  resetContextPages();
  updateURL(false);
  if (key === "site_id") await refreshWithValidation();
  else {
    renderLogs();
    renderWorkspaceContext();
    requestAnimationFrame(() => renderCharts());
  }
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
    facetSectionMarkup("ASNs", countFacet(evidence, (item) => formatASN(item.asn), (item) => item.requests).slice(0, 6), "asn"),
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
    + countFacet(evidence, (item) => formatASN(item.asn)).length
    + topPaths.length
    + countFacet(evidence, (item) => item.site_id).length
    + countFacet(evidence, (item) => item.kind).length
    + statusFacets(evidence).length;
}

function logRelatedEvidenceRows(evidence, topPaths) {
  const rows = [];
  relatedSignalsForLogContext(evidence, topPaths).slice(0, 5).forEach((signal) => {
    rows.push({
      kind: "Signal",
      title: signal.title || "Signal",
      meta: [
        formatCategory(signal.group || "signal"),
        signal.siteID || "",
        signal.ip ? `IP ${signal.ip}` : "",
        signal.path || "",
        signal.lastSeen ? formatTime(signal.lastSeen) : "",
      ].filter(Boolean).join(" - "),
      valueLabel: "risk",
      value: signal.risk || severityRank(signal.severity) * 20 || 0,
      actions: signalActionButtons(signal, "logs_related", "mini"),
    });
  });
  reportContextsForLogContext(evidence, topPaths).slice(0, 3).forEach((report) => {
    rows.push({
      kind: "Report",
      title: reportListLabel(report),
      meta: reportWindowLabel(report),
      valueLabel: report.model || "local",
      value: formatNumber(report.summary?.requests || 0),
      actions: `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), origin: "logs_related" }))}'>Open report</button>`,
    });
  });
  correlatedLogTypeDefs(false).forEach(([logType]) => {
    const segmentCount = unsupportedLogSegments(logType).length;
    if (!segmentCount) return;
    rows.push({
      kind: "Related log type",
      title: `${formatLogType(logType)} segments`,
      meta: `${formatNumber(segmentCount)} combined segments available for correlation`,
      valueLabel: "segments",
      value: formatNumber(segmentCount),
      actions: `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ...state.viewContext, site_id: state.viewContext.site_id || state.siteID || "", log_type: logType, origin: "logs_related" })}'>Open ${escapeHTML(formatLogType(logType))}</button>`,
    });
  });
  return rows;
}

function renderLogCorrelationPack(evidence = filteredLogEvidence(), topPaths = filteredTopPaths(), options = {}) {
  const rows = logCorrelationRows(evidence, topPaths, options);
  setText("#logsCorrelationSummary", rows.length ? `${formatNumber(rows.length)} lanes` : "no lanes");
  const container = qs("#logsCorrelationPack");
  if (!container) return;
  container.innerHTML = rows.map(logCorrelationRow).join("") || `<div class="empty">No log correlation context is active.</div>`;
}

function logCorrelationRows(evidence = [], topPaths = [], options = {}) {
  const context = { ...(state.viewContext || {}), ...(options.context || {}) };
  const origin = options.origin || "logs_correlation";
  const siteID = context.site_id || state.siteID || "";
  const errors = evidence.reduce((sum, item) => sum + (Number(item.errors || 0) || Number(item.status_4xx || 0) + Number(item.status_5xx || 0)), 0);
  const requests = evidence.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  const topPath = topPaths[0] || {};
  const rows = [{
    kind: "Access evidence",
    title: "Matching access rows",
    meta: [
      siteID || "all sites",
      context.path ? `path ${context.path}` : "",
      context.ip ? `IP ${context.ip}` : "",
      context.asn ? formatASN(context.asn) : "",
      `${formatNumber(evidence.length)} rows`,
      `${formatNumber(requests)} requests`,
      errors ? `${formatNumber(errors)} errors` : "",
    ].filter(Boolean).join(" - "),
    valueLabel: "rows",
    value: formatNumber(evidence.length),
    actions: [
      `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logFilterPivotForContext("nginx-access", context, origin))}'>Open access</button>`,
      topPath.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: topPath.path, site_id: topPath.site_id || siteID, origin })}'>Open top path</button>` : "",
      siteID ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: siteID, origin })}'>Open site</button>` : "",
    ].filter(Boolean).join(""),
  }];

  correlatedLogTypeDefs(false).forEach(([logType, label]) => {
    const summary = segmentSummaryForLogType(logType);
    rows.push({
      kind: "Segment correlation",
      title: label,
      meta: [
        summary.count ? `${formatNumber(summary.count)} combined segments` : "no combined segments",
        summary.lines ? `${formatNumber(summary.lines)} lines` : "",
        summary.pending ? `${formatNumber(summary.pending)} pending index` : "",
        summary.latest ? `latest ${formatTime(summary.latest)}` : "",
        context.path ? "path context carried" : "",
      ].filter(Boolean).join(" - "),
      valueLabel: "segments",
      value: formatNumber(summary.count),
      actions: [
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logFilterPivotForContext(logType, context, origin))}'>Open ${escapeHTML(formatLogType(logType))}</button>`,
        summary.pending ? `<button class="ghost mini inline-action" type="button" data-route-target="system">Index status</button>` : "",
      ].filter(Boolean).join(""),
    });
  });
  return rows;
}

function logCorrelationRow(item) {
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.title || "-")}</strong>
        <span>${escapeHTML([item.kind, item.meta].filter(Boolean).join(" - "))}</span>
        <div class="signal-actions">${item.actions || ""}</div>
      </div>
      <div class="signal-numbers">
        <span>${escapeHTML(item.valueLabel || "")}</span>
        <b>${escapeHTML(item.value || "0")}</b>
      </div>
    </div>
  `;
}

function correlatedLogTypeDefs(includeAccess = true) {
  return [
    includeAccess ? ["nginx-access", "Access rows"] : null,
    ["nginx-error", "Nginx errors"],
    ["php-error", "PHP errors"],
    ["php-slow", "PHP slow"],
    ["mysql-slow", "MySQL slow"],
  ].filter(Boolean);
}

function logFilterPivotForContext(logType, context = state.viewContext || {}, origin = "correlation") {
  const pivot = { kind: "log_filter", log_type: logType, origin };
  ["path", "ip", "asn", "known_actor", "actor_type", "status_class", "env", "user_agent", "evidence_kind", "severity"].forEach((key) => {
    if (context[key]) pivot[key] = context[key];
  });
  const siteID = context.site_id || state.siteID || "";
  if (siteID) pivot.site_id = siteID;
  return pivot;
}

function segmentSummaryForLogType(logType) {
  const segments = unsupportedLogSegments(logType);
  const latest = segments[0]?.bucket_start || segments[0]?.max_ts || segments[0]?.bucket_end || "";
  const indexed = segments.filter((item) => item.indexed || item.status === "indexed").length;
  return {
    count: segments.length,
    lines: segments.reduce((sum, item) => sum + Number(item.line_count || 0), 0),
    indexed,
    pending: Math.max(0, segments.length - indexed),
    latest,
  };
}

function unsupportedLogRelatedEvidenceRows(correlatedEvidence, correlatedPaths, segments) {
  const rows = [];
  rows.push({
    kind: "Access correlation",
    title: "Matching access rows",
    meta: logContextLabel(),
    valueLabel: "rows",
    value: formatNumber(correlatedEvidence.length),
    actions: `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ...state.viewContext, site_id: state.viewContext.site_id || state.siteID || "", log_type: "nginx-access", origin: "logs_related" })}'>Open access rows</button>`,
  });
  correlatedPaths.slice(0, 3).forEach((path) => {
    const errors = Number(path.status_4xx || 0) + Number(path.status_5xx || 0);
    rows.push({
      kind: "Correlated path",
      title: path.path || "/",
      meta: `${formatNumber(path.requests || 0)} access requests${errors ? ` - ${formatNumber(errors)} errors` : ""}`,
      valueLabel: "requests",
      value: formatNumber(path.requests || 0),
      actions: correlatedLogActions({ path: path.path || "/", siteID: path.site_id || state.viewContext.site_id || state.siteID || "", statusClass: errors ? "errors" : "", origin: "logs_related" }),
    });
  });
  relatedSignalsForLogContext(correlatedEvidence, correlatedPaths).slice(0, 4).forEach((signal) => {
    rows.push({
      kind: "Signal",
      title: signal.title || "Signal",
      meta: [
        formatCategory(signal.group || "signal"),
        signal.siteID || "",
        signal.ip ? `IP ${signal.ip}` : "",
        signal.path || "",
      ].filter(Boolean).join(" - "),
      valueLabel: "risk",
      value: signal.risk || severityRank(signal.severity) * 20 || 0,
      actions: signalActionButtons(signal, "logs_related", "mini"),
    });
  });
  if (segments.length) {
    rows.push({
      kind: "Segment set",
      title: `${formatLogType(state.logType)} ingestion window`,
      meta: `${formatNumber(segments.reduce((sum, item) => sum + Number(item.line_count || 0), 0))} lines combined`,
      valueLabel: "segments",
      value: formatNumber(segments.length),
      actions: `<button class="ghost mini inline-action" type="button" data-route-target="system">System</button>`,
    });
  }
  return rows;
}

function relatedSignalsForLogContext(evidence, topPaths) {
  const context = state.viewContext || {};
  const ips = new Set(evidence.map((item) => item.ip).filter(Boolean));
  const asnIPs = context.asn ? new Set(sourceIPsForASN(context.asn).map((item) => item.ip).filter(Boolean)) : new Set();
  const paths = new Set(topPaths.map((item) => item.path).filter(Boolean));
  evidence.forEach((item) => {
    if (item.path) paths.add(item.path);
  });
  return buildSignalItems().filter((signal) => {
    if (context.site_id && signal.siteID && signal.siteID !== context.site_id) return false;
    if (state.siteID && signal.siteID && signal.siteID !== state.siteID) return false;
    if (context.ip && signal.ip && signal.ip !== context.ip) return false;
    if (context.asn && (!signal.ip || !asnIPs.has(signal.ip))) return false;
    if (context.path && signal.path && !pathMatches(signal.path, context.path)) return false;
    if (context.evidence_kind && !evidenceKindMatches(signal.sourceKind || signal.group, context.evidence_kind)) return false;
    return (signal.ip && ips.has(signal.ip)) || (signal.path && Array.from(paths).some((path) => pathMatches(path, signal.path))) || (!context.ip && !context.path && signal.siteID === (state.siteID || context.site_id));
  });
}

function reportContextsForLogContext(evidence, topPaths) {
  const context = state.viewContext || {};
  const siteID = context.site_id || state.siteID || "";
  const paths = new Set(topPaths.map((item) => item.path).filter(Boolean));
  return (state.data.reports || []).filter((report) => {
    if (siteID && report.site_id && report.site_id !== siteID) return false;
    const summary = report.summary || {};
    if (context.path && summary.top_path && !pathMatches(summary.top_path, context.path)) return false;
    if (context.ip && summary.top_source_ip && summary.top_source_ip !== context.ip) return false;
    if (!context.path && summary.top_path && paths.size && !paths.has(summary.top_path)) return false;
    if (!context.ip && !context.path && siteID && report.site_id !== siteID) return false;
    return true;
  }).sort((a, b) => new Date(b.generated_at || 0) - new Date(a.generated_at || 0));
}

function logRelatedEvidenceRow(item) {
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.title || "-")}</strong>
        <span>${escapeHTML([item.kind, item.meta].filter(Boolean).join(" - "))}</span>
        <div class="signal-actions">${item.actions || ""}</div>
      </div>
      <div class="signal-numbers">
        <span>${escapeHTML(item.valueLabel || "")}</span>
        <b>${escapeHTML(item.value || "0")}</b>
      </div>
    </div>
  `;
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
    asn: { kind: "log_filter", asn: label, site_id: siteID, origin: "logs" },
    path: { kind: "log_filter", path: label, site_id: siteID, status_class: item.errors ? "errors" : "", origin: "logs" },
    site: { kind: "log_filter", site_id: label, origin: "logs" },
    kind: { kind: "log_filter", evidence_kind: label, site_id: siteID, origin: "logs" },
    status: label === "Errors only" ? { kind: "log_filter", site_id: siteID, status_class: "errors", origin: "logs" } : null,
  }[type];
  const secondary = [
    type === "ip" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: label, site_id: siteID, origin: "logs" })}'>Open IP</button>` : "",
    type === "asn" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: label, site_id: siteID, origin: "logs" })}'>Open ASN</button>` : "",
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
  const context = { path, ip, site_id: siteID, status_class: statusClass };
  return correlatedLogTypeDefs(includeAccess).map(([logType, label]) => {
    const pivot = logFilterPivotForContext(logType, context, origin);
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
  if (context.asn) parts.push(formatASN(context.asn) || context.asn);
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
  const sourceContext = sourceIPContextMap();
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
      ...sourceIPLogFields(item.client_ip, sourceContext),
    });
  });
  (analysis.admin_probes || []).forEach((item) => rows.push(analysisEvidenceRow("Admin probe", item, sourceContext)));
  (analysis.injection_probes || []).forEach((item) => rows.push(analysisEvidenceRow("Injection probe", item, sourceContext)));
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
    ...sourceIPLogFields(item.ip, sourceContext),
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
  (analysis.user_agents || []).forEach((item) => rows.push({
    kind: "User-agent class",
    ts: item.last_seen,
    site_id: item.site_id || "",
    env: item.env || "",
    path: item.top_path || "/",
    status: "",
    requests: Number(item.requests || 0),
    errors: Number(item.status_4xx || 0) + Number(item.status_5xx || 0),
    user_agent: item.sample || "",
    known_actor: item.family || "",
    actor_type: item.actor_type || "",
    risk_score: item.risk_score || 0,
  }));
  return rows
    .filter(logMatchesContext)
    .sort((a, b) => new Date(b.ts || 0) - new Date(a.ts || 0));
}

function sourceIPLogFields(ip, map = sourceIPContextMap()) {
  const source = sourceIPContextForIP(ip, map);
  return {
    asn: source.asn || 0,
    asn_org: source.asn_org || "",
    network: source.network || "",
    country_code: source.country_code || "",
    known_actor: source.known_actor || "",
    actor_type: source.actor_type || "",
    risk_score: source.risk_score || 0,
  };
}

function analysisEvidenceRow(kind, item, sourceContext = sourceIPContextMap()) {
  const sourceFields = sourceIPLogFields(item.ip, sourceContext);
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
    ...sourceFields,
    risk_score: item.risk_score || sourceFields.risk_score || 0,
  };
}

function filteredTopPaths() {
  const seen = new Map();
  (state.data.traffic?.top_paths || []).forEach((item) => {
    if (!logMatchesContext({ ...item, errors: Number(item.status_4xx || 0) + Number(item.status_5xx || 0) })) return;
    const key = `${item.site_id || ""}|${item.path || "/"}`;
    const existing = seen.get(key) || { site_id: item.site_id || "", path: item.path || "/", requests: 0, bytes_sent: 0, status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0, avg_request_time_ms: 0, p95_request_time_ms: 0 };
    existing.requests += Number(item.requests || 0);
    existing.bytes_sent += Number(item.bytes_sent || 0);
    existing.status_2xx += Number(item.status_2xx || 0);
    existing.status_3xx += Number(item.status_3xx || 0);
    existing.status_4xx += Number(item.status_4xx || 0);
    existing.status_5xx += Number(item.status_5xx || 0);
    seen.set(key, existing);
  });
  (state.data.analysis?.slow_paths || []).forEach((item) => {
    if (!logMatchesContext({ ...item, status_4xx: item.status_4xx || 0, status_5xx: item.status_5xx || 0, errors: Number(item.status_4xx || 0) + Number(item.status_5xx || 0) })) return;
    const key = `${item.site_id || ""}|${item.path || "/"}`;
    const existing = seen.get(key) || { site_id: item.site_id || "", path: item.path || "/", requests: 0, bytes_sent: 0, status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0, avg_request_time_ms: 0, p95_request_time_ms: 0 };
    if (!seen.has(key)) {
      existing.requests += Number(item.requests || 0);
      existing.bytes_sent += Number(item.bytes_sent || 0);
      existing.status_4xx += Number(item.status_4xx || 0);
      existing.status_5xx += Number(item.status_5xx || 0);
    }
    existing.avg_request_time_ms = Math.max(existing.avg_request_time_ms || 0, Number(item.avg_request_time_ms || 0));
    existing.p95_request_time_ms = Math.max(existing.p95_request_time_ms || 0, Number(item.p95_request_time_ms || 0));
    seen.set(key, existing);
  });
  return Array.from(seen.values()).sort((a, b) => b.requests - a.requests);
}

function logMatchesContext(item) {
  const context = state.viewContext || {};
  if (context.site_id && item.site_id !== context.site_id) return false;
  if (context.env && item.env !== context.env) return false;
  if (context.ip && item.ip !== context.ip) return false;
  if (context.asn && normalizeASN(item.asn) !== normalizeASN(context.asn)) return false;
  if (context.path && !pathMatches(item.path, context.path)) return false;
  if (context.evidence_kind && !evidenceKindMatches(item.kind, context.evidence_kind)) return false;
  if (context.status_class === "errors") {
    const status = Number(item.status || 0);
    const errors = Number(item.errors || 0) + Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    if (status < 400 && errors <= 0) return false;
  }
  if (context.severity) {
    const severity = normalizeSignalSeverity(context.severity);
    if (severity !== "all" && logEvidenceSeverityRank(item) < severityRank(severity)) return false;
  }
  if (context.known_actor || context.actor_type) {
    const ips = contextActorIPs(context);
    if (item.ip && ips.size && !ips.has(item.ip)) return false;
    if (!item.ip && ips.size) return false;
  }
  if (context.user_agent && !userAgentMatches(item.user_agent || "", context.user_agent)) return false;
  return true;
}

function logEvidenceSeverityRank(item = {}) {
  if (item.risk_score) return severityRank(severityForScore(item.risk_score));
  const status = Number(item.status || 0);
  if (status >= 500) return severityRank("high");
  if (status >= 400) return severityRank("medium");
  const statusErrors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  const errors = Number(item.errors || 0) + statusErrors;
  if (Number(item.status_5xx || 0) > 0 || errors >= 100) return severityRank("high");
  if (errors > 0 || statusErrors > 0) return severityRank("medium");
  if (Number(item.p95_request_time_ms || 0) >= 5000) return severityRank("high");
  if (Number(item.p95_request_time_ms || 0) > 0) return severityRank("medium");
  return severityRank("low");
}

function evidenceKindMatches(value, expected) {
  const left = normalizeEvidenceKind(value);
  const right = normalizeEvidenceKind(expected);
  if (!right) return true;
  return left === right || left.includes(right) || right.includes(left);
}

function normalizeEvidenceKind(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
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
    item.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(item.asn), site_id: item.site_id, origin: "logs" })}'>Open ASN</button>` : "",
    item.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path, site_id: item.site_id, origin: "logs" })}'>Open path</button>` : "",
    item.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", path: item.path, ip: item.ip, asn: item.asn ? formatASN(item.asn) : "", site_id: item.site_id, status_class: item.errors ? "errors" : "", origin: "logs" })}'>Refine</button>` : "",
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
  const siteID = item.site_id || state.viewContext.site_id || state.siteID || "";
  const errors = Number(item.errors || 0);
  const signal = signalForLogEvidence(item);
  const actions = [
    signal ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: signal.key, site_id: siteID, origin: "logs" })}'>Open signal</button>` : "",
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logEvidenceFilterPivot(item, siteID, errors, "logs"))}'>Open rows</button>`,
  ].filter(Boolean).join("");
  return `
    <tr>
      <td>${formatTime(item.ts)}</td>
      <td><strong>${escapeHTML(item.kind || "Evidence")}</strong><br><span>${escapeHTML(logEvidenceStatus(item))}</span></td>
      <td>${escapeHTML(site)}</td>
      <td>${logEvidenceSourceCell(item, siteID)}</td>
      <td>${logEvidencePathCell(item, siteID, errors)}</td>
      <td>${logEvidenceSignalCell(item, signal, siteID)}</td>
      <td class="row-actions">${actions}</td>
    </tr>
  `;
}

function logEvidenceSourceCell(item, siteID) {
  const actor = item.known_actor || actorLabelFromType(item.actor_type);
  const sourceLabel = item.ip || actor || shortLabel(item.user_agent || "", 42) || "-";
  const meta = [
    item.asn ? formatASN(item.asn) : "",
    item.asn_org || item.network || "",
    actor && actor !== sourceLabel ? actor : "",
    item.user_agent ? shortLabel(item.user_agent, 52) : "",
  ].filter(Boolean).join(" / ");
  const actions = [
    item.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: siteID, origin: "logs_source" })}'>Open IP</button>` : "",
    item.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(item.asn), site_id: siteID, origin: "logs_source" })}'>Open ASN</button>` : "",
    actor ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: actor, actor_type: item.actor_type || "", site_id: siteID, origin: "logs_source" })}'>Open actor</button>` : "",
    item.user_agent ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "user-agent", value: item.user_agent, site_id: siteID, origin: "logs_source" })}'>Open UA</button>` : "",
  ].filter(Boolean).join("");
  return `
    <div class="log-cell">
      <strong>${escapeHTML(sourceLabel)}</strong>
      ${meta ? `<span>${escapeHTML(meta)}</span>` : ""}
      ${actions ? `<div class="signal-actions">${actions}</div>` : ""}
    </div>
  `;
}

function logEvidencePathCell(item, siteID, errors) {
  const target = formatURLTarget(item);
  const meta = [
    item.query ? `?${item.query}` : "",
    item.p95_request_time_ms ? `p95 ${formatMs(item.p95_request_time_ms)}` : "",
  ].filter(Boolean).join(" / ");
  const actions = [
    item.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path, site_id: siteID, origin: "logs_path" })}'>Open path</button>` : "",
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logEvidenceFilterPivot(item, siteID, errors, "logs_path"))}'>Open rows</button>`,
  ].filter(Boolean).join("");
  return `
    <div class="log-cell">
      <strong>${escapeHTML(target || "-")}</strong>
      ${meta ? `<span>${escapeHTML(meta)}</span>` : ""}
      ${actions ? `<div class="signal-actions">${actions}</div>` : ""}
    </div>
  `;
}

function logEvidenceSignalCell(item, signal, siteID) {
  const title = signal?.title || logSignalMeta(item);
  const meta = signal
    ? [
      formatCategory(signal.group || "signal"),
      signal.ip ? `IP ${signal.ip}` : "",
      signal.path || "",
      signal.lastSeen ? formatTime(signal.lastSeen) : "",
    ].filter(Boolean).join(" / ")
    : "";
  const actions = signal
    ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: signal.key, site_id: siteID, origin: "logs_signal" })}'>Open signal</button>`
    : "";
  return `
    <div class="log-cell">
      <strong>${escapeHTML(title || "-")}</strong>
      ${meta ? `<span>${escapeHTML(meta)}</span>` : ""}
      ${actions ? `<div class="signal-actions">${actions}</div>` : ""}
    </div>
  `;
}

function logEvidenceFilterPivot(item, siteID, errors, origin = "logs") {
  return {
    kind: "log_filter",
    path: item.path || "",
    ip: item.ip || "",
    asn: item.asn ? formatASN(item.asn) : "",
    known_actor: item.known_actor || "",
    actor_type: item.actor_type || "",
    user_agent: item.user_agent || "",
    evidence_kind: item.kind || "",
    site_id: siteID,
    status_class: errors ? "errors" : "",
    origin,
  };
}

function signalForLogEvidence(item) {
  const sourceKind = signalSourceKindForEvidence(item.kind);
  return buildSignalItems().find((signal) => {
    if (sourceKind && signal.sourceKind !== sourceKind) return false;
    if (item.site_id && signal.siteID && signal.siteID !== item.site_id) return false;
    if (item.ip && signal.ip && signal.ip !== item.ip) return false;
    if (item.path && signal.path && !pathMatches(signal.path, item.path) && !pathMatches(item.path, signal.path)) return false;
    if (sourceKind === "recentError" && item.ts && signal.lastSeen && signal.lastSeen !== item.ts) return false;
    return Boolean(sourceKind || (item.ip && signal.ip === item.ip) || (signal.path && item.path && pathMatches(signal.path, item.path)));
  }) || null;
}

function signalSourceKindForEvidence(kind) {
  const normalized = normalizeEvidenceKind(kind);
  if (normalized.includes("injection")) return "injectionProbe";
  if (normalized.includes("admin")) return "adminProbe";
  if (normalized.includes("tor")) return "torSource";
  if (normalized.includes("slow")) return "slowPath";
  if (normalized.includes("recenterror")) return "recentError";
  return "";
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
    item.asn ? formatASN(item.asn) : "",
    item.asn_org || "",
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
  const severityFilter = currentSignalSeverityFilter();
  qsa("[data-signal-severity]").forEach((button) => {
    const active = normalizeSignalSeverity(button.dataset.signalSeverity || "all") === severityFilter;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  });
  const allSignals = buildSignalItems();
  renderSignalDetail(allSignals);
  const severitySignals = filterSignalsBySeverity(allSignals, severityFilter);
  const signals = state.signalFilter === "all" ? severitySignals : severitySignals.filter((item) => item.group === state.signalFilter);
  renderPager("#signalsPager", "signals", signals);
  const pageItems = paginate("signals", signals);
  qs("#signalsList").innerHTML = pageItems.map(signalRow).join("") || `<div class="empty">No ${escapeHTML(signalFilterEmptyLabel(severityFilter))} signals in this scope.</div>`;
  setText("#signalsSummary", `${formatNumber(pageItems.length)} of ${formatNumber(signals.length)} shown${severityFilter !== "all" ? ` / ${signalSeverityLabel(severityFilter)}` : ""}`);
  qs("#signalsGroupStats").innerHTML = signalQueueSections(severitySignals).map(signalQueueRow).join("");
}

function currentSignalSeverityFilter() {
  return normalizeSignalSeverity(state.viewContext?.severity || "all");
}

function filterSignalsBySeverity(signals, severity = currentSignalSeverityFilter()) {
  const normalized = normalizeSignalSeverity(severity);
  if (normalized === "all") return signals || [];
  const minRank = severityRank(normalized);
  return (signals || []).filter((item) => severityRank(item.severity) >= minRank);
}

function signalFilterEmptyLabel(severity = currentSignalSeverityFilter()) {
  return [
    state.signalFilter === "all" ? "" : state.signalFilter,
    severity !== "all" ? signalSeverityLabel(severity) : "",
  ].filter(Boolean).join(" ") || "matching";
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
    ${signalInvestigationPath(signal, { evidence, paths, sites })}
    ${signalTriagePath(signal, { evidence, paths, sites })}
    ${signalEvidenceMatrix(signal, { evidence, paths })}
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

function signalInvestigationPath(signal, context = {}) {
  const evidence = context.evidence || [];
  const paths = context.paths || [];
  const sites = context.sites || [];
  const siteID = signal.siteID || state.viewContext.site_id || state.siteID || evidence[0]?.site_id || "";
  const source = signal.ip ? sourceIPContextForIP(signal.ip) : {};
  const primaryIP = signal.ip || evidence[0]?.ip || "";
  const primaryPath = signal.path || paths[0]?.path || evidence[0]?.path || "";
  const errors = evidence.reduce((sum, item) => sum + Number(item.errors || 0) + Number(item.status_4xx || 0) + Number(item.status_5xx || 0), 0) || Number(signal.errors || 0);
  const actor = source.known_actor || actorLabelFromType(source.actor_type) || signal.actor || evidence[0]?.known_actor || "";
  const report = reportContextsForLogContext(evidence, paths)[0];
  const steps = [
    {
      label: "Signal",
      value: formatCategory(signal.sourceKind || signal.group || "signal"),
      meta: `${formatCategory(signal.severity || "low")} / risk ${formatNumber(signal.risk || severityRank(signal.severity) * 20 || 0)}`,
      actions: `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: signal.key, site_id: siteID, origin: "signal_path" })}'>Current signal</button>`,
    },
    {
      label: "Source",
      value: primaryIP || actor || "Unknown source",
      meta: [
        actor && actor !== primaryIP ? actor : "",
        source.asn ? formatASN(source.asn) : "",
        source.asn_org || source.network || "",
      ].filter(Boolean).join(" / "),
      actions: [
        primaryIP ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: primaryIP, site_id: siteID, origin: "signal_path" })}'>Open IP</button>` : "",
        source.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(source.asn), site_id: siteID, origin: "signal_path" })}'>Open ASN</button>` : "",
        actor ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: actor, actor_type: source.actor_type || "", site_id: siteID, origin: "signal_path" })}'>Open actor</button>` : "",
      ].filter(Boolean).join(""),
    },
    {
      label: "Target",
      value: primaryPath || siteID || "Current scope",
      meta: [
        sites.length ? `${formatNumber(sites.length)} affected sites` : siteID ? siteLabel(siteID) || siteID : "",
        paths.length ? `${formatNumber(paths.length)} affected paths` : "",
      ].filter(Boolean).join(" / "),
      actions: [
        primaryPath ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: primaryPath, site_id: siteID, origin: "signal_path" })}'>Open path</button>` : "",
        siteID ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: siteID, origin: "signal_path" })}'>Open site</button>` : "",
      ].filter(Boolean).join(""),
    },
    {
      label: "Raw evidence",
      value: `${formatNumber(evidence.length)} rows`,
      meta: [
        `${formatNumber(signal.requests || 0)} signal requests`,
        errors ? `${formatNumber(errors)} errors` : "",
      ].filter(Boolean).join(" / "),
      actions: [
        signal.sourceKind === "job"
          ? `<button class="ghost mini inline-action" type="button" data-route-target="system">Open system</button>`
          : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(signalLogPivot(signal, "signal_path"))}'>Matching logs</button>`,
        primaryPath ? correlatedLogActions({ path: primaryPath, siteID, ip: primaryIP, statusClass: errors ? "errors" : "", origin: "signal_path" }) : "",
      ].filter(Boolean).join(""),
    },
    {
      label: "Report period",
      value: report ? reportListLabel(report) : formatCategory(state.reportTab || "daily"),
      meta: report ? reportWindowLabel(report) : activeFilterLabel(),
      actions: report
        ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: report.site_id || siteID, origin: "signal_path" }))}'>Open report</button>`
        : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(signalReportContextPivot(signal, "signal_path"))}'>Report context</button>`,
    },
  ];
  return `
    <section class="signal-path-board" aria-label="Signal investigation path">
      ${steps.map(signalInvestigationPathStep).join("")}
    </section>
  `;
}

function signalInvestigationPathStep(step) {
  return `
    <div class="signal-path-step">
      <div>
        <span>${escapeHTML(step.label || "-")}</span>
        <strong>${escapeHTML(step.value || "-")}</strong>
        <small>${escapeHTML(step.meta || "")}</small>
      </div>
      <div class="signal-actions">${step.actions || ""}</div>
    </div>
  `;
}

function signalEvidenceMatrix(signal, context = {}) {
  const rows = signalEvidenceMatrixRows(signal, context).slice(0, 12);
  return `
    <section class="signal-evidence-panel" aria-label="Signal evidence matrix">
      <div class="entity-next-title">
        <span>Evidence matrix</span>
        <strong>${escapeHTML(rows.length ? `${formatNumber(rows.length)} rows` : "no rows")}</strong>
      </div>
      <div class="table-wrap signal-evidence-wrap">
        <table class="signal-evidence-table">
          <thead>
            <tr>
              <th>Evidence</th>
              <th>Source</th>
              <th>Impact</th>
              <th>Latest</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            ${rows.map((row) => signalEvidenceMatrixRow(signal, row)).join("") || emptyRow(5, "No structured evidence rows are available for this signal.")}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function signalEvidenceMatrixRows(signal, context = {}) {
  const rows = new Map();
  const sourceRecord = signalSourceRecord(signal);
  const sourceContext = signal.ip ? sourceIPContextForIP(signal.ip) : {};
  const add = (kind, item = {}, weight = 0) => {
    const siteID = item.site_id || signal.siteID || state.viewContext.site_id || state.siteID || "";
    const ip = item.ip || item.client_ip || signal.ip || "";
    const path = item.path || signal.path || "";
    const query = item.sample_query || item.query || "";
    const key = [siteID, ip, path || "/", query, kind || ""].join("|");
    const source = ip ? sourceIPContextForIP(ip) : sourceContext;
    const existing = rows.get(key) || {
      siteID,
      env: item.env || signal.env || "",
      ip,
      path,
      query,
      method: item.method || "",
      status: item.status || "",
      kinds: new Set(),
      requests: 0,
      totalHits: 0,
      errors: 0,
      status4xx: 0,
      status5xx: 0,
      risk: 0,
      asn: item.asn || source.asn || 0,
      actor: item.known_actor || source.known_actor || actorLabelFromType(item.actor_type || source.actor_type) || signal.actor || "",
      actorType: item.actor_type || source.actor_type || "",
      userAgent: item.user_agent || item.sample || "",
      latest: "",
      weight,
    };
    const status = Number(item.status || 0);
    const status4xx = Number(item.status_4xx || 0) + (status >= 400 && status < 500 ? 1 : 0);
    const status5xx = Number(item.status_5xx || 0) + (status >= 500 ? 1 : 0);
    const errors = Number(item.errors || 0) + status4xx + status5xx;
    existing.kinds.add(kind || item.kind || signalEvidenceKind(signal) || formatCategory(signal.sourceKind || "signal"));
    existing.requests = Math.max(existing.requests, Number(item.requests || item.events || 0) || (status ? 1 : 0));
    existing.totalHits = Math.max(existing.totalHits, Number(item.total_ip_hits || 0));
    existing.errors = Math.max(existing.errors, errors);
    existing.status4xx = Math.max(existing.status4xx, status4xx);
    existing.status5xx = Math.max(existing.status5xx, status5xx);
    existing.risk = Math.max(existing.risk, Number(item.risk_score || item.score || signal.risk || 0));
    existing.latest = latestISO(existing.latest, item.last_seen || item.last_seen_at || item.ts || item.timestamp || signal.lastSeen || "");
    existing.weight = Math.max(existing.weight, weight);
    if (!existing.method && item.method) existing.method = item.method;
    if (!existing.status && item.status) existing.status = item.status;
    if (!existing.userAgent && (item.user_agent || item.sample)) existing.userAgent = item.user_agent || item.sample;
    rows.set(key, existing);
  };
  if (sourceRecord) add(signalEvidenceKind(signal) || formatCategory(signal.sourceKind || "signal"), sourceRecord, 2);
  (context.evidence || []).forEach((item) => add(item.kind || signalEvidenceKind(signal), item, 1));
  if (!rows.size) {
    (context.paths || []).forEach((item) => add("Affected path", item, 0));
  }
  return Array.from(rows.values())
    .map((row) => ({ ...row, kindList: Array.from(row.kinds) }))
    .sort((a, b) => Number(b.weight || 0) - Number(a.weight || 0)
      || Number(b.risk || 0) - Number(a.risk || 0)
      || Number(b.errors || 0) - Number(a.errors || 0)
      || Number(b.totalHits || 0) - Number(a.totalHits || 0)
      || Number(b.requests || 0) - Number(a.requests || 0)
      || new Date(b.latest || 0) - new Date(a.latest || 0));
}

function signalSourceRecord(signal) {
  const index = Number(signal.sourceIndex || 0);
  if (signal.sourceKind === "injectionProbe") return state.data.analysis?.injection_probes?.[index] || null;
  if (signal.sourceKind === "adminProbe") return state.data.analysis?.admin_probes?.[index] || null;
  if (signal.sourceKind === "torSource") return state.data.analysis?.tor_sources?.[index] || null;
  if (signal.sourceKind === "slowPath") return state.data.analysis?.slow_paths?.[index] || null;
  if (signal.sourceKind === "recentError") return state.data.traffic?.recent_errors?.[index] || null;
  if (signal.sourceKind === "issue") return state.data.analysis?.issues?.[index] || null;
  return null;
}

function signalEvidenceMatrixRow(signal, row) {
  const siteID = row.siteID || signal.siteID || state.viewContext.site_id || state.siteID || "";
  const errors = Number(row.errors || 0);
  const evidenceLabel = row.kindList.join(", ") || signalEvidenceKind(signal) || formatCategory(signal.sourceKind || "signal");
  const target = [row.method || "", row.path || signal.path || "/", row.query ? `?${row.query}` : ""].filter(Boolean).join(" ");
  const sourceLabel = row.ip || row.actor || row.userAgent || "-";
  const sourceMeta = [
    siteID ? siteLabel(siteID) || siteID : "",
    row.env || "",
    row.asn ? formatASN(row.asn) : "",
    row.actor && row.actor !== sourceLabel ? row.actor : "",
    row.actorType ? formatCategory(row.actorType) : "",
    row.userAgent ? shortLabel(row.userAgent, 52) : "",
  ].filter(Boolean).join(" / ");
  const impact = [
    row.totalHits ? `${formatNumber(row.totalHits)} total IP hits` : "",
    errors ? `${formatNumber(errors)} errors` : "",
    row.status4xx ? `${formatNumber(row.status4xx)} 4xx` : "",
    row.status5xx ? `${formatNumber(row.status5xx)} 5xx` : "",
    row.status ? `status ${row.status}` : "",
    row.risk ? `risk ${formatNumber(row.risk)}` : "",
  ].filter(Boolean).join(" / ");
  return `
    <tr>
      <td class="clip"><strong>${escapeHTML(evidenceLabel)}</strong><br><span>${escapeHTML(target || signal.title || "signal evidence")}</span></td>
      <td class="clip"><strong>${escapeHTML(sourceLabel)}</strong><br><span>${escapeHTML(sourceMeta || "current scope")}</span></td>
      <td>${formatNumber(row.requests || signal.requests || 0)}<br><span>${escapeHTML(impact || "no impact count")}</span></td>
      <td>${formatTime(row.latest || signal.lastSeen)}</td>
      <td class="row-actions">${signalEvidenceMatrixActions(signal, row, siteID, errors)}</td>
    </tr>
  `;
}

function signalEvidenceMatrixActions(signal, row, siteID, errors) {
  const actions = [
    siteID ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: siteID, origin: "signal_evidence" })}'>Site</button>` : "",
    row.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: row.ip, site_id: siteID, origin: "signal_evidence" })}'>IP</button>` : "",
    row.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(row.asn), site_id: siteID, origin: "signal_evidence" })}'>ASN</button>` : "",
    row.actor ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: row.actor, actor_type: row.actorType || "", site_id: siteID, origin: "signal_evidence" })}'>Actor</button>` : "",
    row.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: row.path, site_id: siteID, origin: "signal_evidence" })}'>Path</button>` : "",
    signalEvidenceLogButton("Access", signal, row, siteID, "nginx-access", false),
    errors ? signalEvidenceLogButton("Errors", signal, row, siteID, "nginx-access", true) : "",
    (row.path || errors) ? signalEvidenceLogButton("Nginx", signal, row, siteID, "nginx-error", true) : "",
    (row.path || errors) ? signalEvidenceLogButton("PHP", signal, row, siteID, "php-error", true) : "",
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(signalReportContextPivot(signal, "signal_evidence"))}'>Reports</button>`,
  ];
  return actions.filter(Boolean).join("");
}

function signalEvidenceLogButton(label, signal, row, siteID, logType, errorsOnly) {
  const pivot = {
    kind: "log_filter",
    log_type: logType,
    site_id: siteID || "",
    ip: row.ip || signal.ip || "",
    path: row.path || signal.path || "",
    asn: row.asn ? formatASN(row.asn) : "",
    known_actor: row.actor || signal.actor || "",
    actor_type: row.actorType || "",
    user_agent: row.userAgent || "",
    evidence_kind: signalEvidenceKind(signal) || row.kindList?.[0] || "",
    status_class: errorsOnly ? "errors" : "",
    origin: "signal_evidence",
  };
  return `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(pivot)}'>${escapeHTML(label)}</button>`;
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

function signalTriagePath(signal, context = {}) {
  const evidence = context.evidence || [];
  const paths = context.paths || [];
  const sites = context.sites || [];
  const siteID = signal.siteID || state.viewContext.site_id || state.siteID || "";
  const errors = evidence.reduce((sum, item) => sum + Number(item.errors || 0), 0) || Number(signal.errors || 0);
  const source = signal.ip ? sourceIPContextForIP(signal.ip) : {};
  const report = reportContextsForLogContext(evidence, paths)[0];
  const rows = [
    {
      title: "Open supporting evidence",
      meta: [
        `${formatNumber(evidence.length)} evidence rows`,
        `${formatNumber(signal.requests || 0)} signal requests`,
        errors ? `${formatNumber(errors)} errors` : "",
      ].filter(Boolean).join(" - "),
      valueLabel: "rows",
      value: formatNumber(evidence.length),
      actions: signal.sourceKind === "job"
        ? `<button class="ghost mini inline-action" type="button" data-route-target="system">Open system</button>`
        : [
          `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(signalLogPivot(signal, "signal_triage"))}'>Open logs</button>`,
          signal.path ? correlatedLogActions({ path: signal.path, siteID, ip: signal.ip || "", statusClass: errors ? "errors" : "", origin: "signal_triage" }) : "",
        ].filter(Boolean).join(""),
    },
    {
      title: "Inspect primary entity",
      meta: signalPrimaryEntityMeta(signal, source),
      valueLabel: signal.ip ? "risk" : signal.path ? "path" : "entity",
      value: signal.ip ? source.risk_score || signal.risk || 0 : signal.path ? formatNumber(paths.length || 1) : formatCategory(signal.sourceKind || "signal"),
      actions: signalPrimaryEntityActions(signal, source, siteID),
    },
    {
      title: "Check blast radius",
      meta: [
        sites.length ? `${formatNumber(sites.length)} affected sites` : signal.siteID ? `site ${signal.siteID}` : "all selected sites",
        paths.length ? `${formatNumber(paths.length)} affected paths` : signal.path || "",
        signal.lastSeen ? `last ${formatTime(signal.lastSeen)}` : "",
      ].filter(Boolean).join(" - "),
      valueLabel: "severity",
      value: formatCategory(signal.severity || "low"),
      actions: [
        siteID ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: siteID, origin: "signal_triage" })}'>Open site</button>` : "",
        paths[0]?.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: paths[0].path || "/", site_id: paths[0].site_id || siteID, origin: "signal_triage" })}'>Top path</button>` : "",
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(signalReportContextPivot(signal, "signal_triage"))}'>Reports</button>`,
      ].filter(Boolean).join(""),
    },
    report ? {
      title: "Review report context",
      meta: [reportListLabel(report), reportWindowLabel(report)].filter(Boolean).join(" - "),
      valueLabel: report.model || "report",
      value: formatNumber(report.summary?.requests || 0),
      actions: `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: report.site_id || siteID, origin: "signal_triage" }))}'>Open report</button>`,
    } : {
      title: "Open report workspace",
      meta: activeFilterLabel(),
      valueLabel: "period",
      value: formatCategory(state.reportTab || "daily"),
      actions: `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(signalReportContextPivot(signal, "signal_triage"))}'>Report context</button>`,
    },
  ];
  return `
    <section class="entity-next-steps signal-triage-path" aria-label="Signal triage path">
      <div class="entity-next-title">
        <span>Triage path</span>
        <strong>${escapeHTML(signalTriageSummary(signal, evidence, errors))}</strong>
      </div>
      <div class="entity-next-list">${rows.map(entityNextStepRow).join("")}</div>
    </section>
  `;
}

function signalPrimaryEntityMeta(signal, source = {}) {
  if (signal.ip) {
    return [
      `IP ${signal.ip}`,
      source.known_actor || actorLabelFromType(source.actor_type) || "",
      source.asn ? formatASN(source.asn) : "",
      source.asn_org || source.network || "",
    ].filter(Boolean).join(" - ");
  }
  if (signal.path) return `Path ${signal.path}`;
  if (signal.actor) return `Actor ${signal.actor}`;
  if (signal.siteID) return `Site ${signal.siteID}`;
  return formatCategory(signal.sourceKind || "signal");
}

function signalPrimaryEntityActions(signal, source = {}, siteID = "") {
  const actor = source.known_actor || actorLabelFromType(source.actor_type) || signal.actor || "";
  return [
    signal.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: signal.ip, site_id: siteID, origin: "signal_triage" })}'>Open IP</button>` : "",
    source.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(source.asn), site_id: siteID, origin: "signal_triage" })}'>Open ASN</button>` : "",
    actor ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: actor, actor_type: source.actor_type || "", site_id: siteID, origin: "signal_triage" })}'>Open actor</button>` : "",
    signal.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: signal.path, site_id: siteID, origin: "signal_triage" })}'>Open path</button>` : "",
  ].filter(Boolean).join("") || `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(signalLogPivot(signal, "signal_triage"))}'>Open logs</button>`;
}

function signalTriageSummary(signal, evidence, errors) {
  return [
    formatCategory(signal.group || "signal"),
    signal.ip ? `IP ${signal.ip}` : "",
    signal.path || "",
    `${formatNumber(evidence.length)} evidence rows`,
    errors ? `${formatNumber(errors)} errors` : "",
  ].filter(Boolean).join(" / ");
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
  renderInvestigationQueue();
  renderSourceIPs();
  renderASNs();
  renderUserAgents();
  renderActors();
}

function renderInvestigationQueue() {
  const cases = investigationCases();
  setText("#investigationQueueSummary", `${formatNumber(cases.length)} cases`);
  const container = qs("#investigationQueue");
  if (!container) return;
  container.innerHTML = cases.map(investigationCaseRow).join("") || `<div class="empty">No investigation cases match the current scope.</div>`;
}

function investigationCases() {
  const signals = buildSignalItems();
  const evidence = filteredLogEvidence();
  const paths = filteredTopPaths();
  const cases = [];
  const seen = new Set();
  const add = (item) => {
    if (!item?.key || seen.has(item.key)) return;
    seen.add(item.key);
    cases.push(item);
  };

  signals.slice(0, 10).forEach((signal) => {
    add(investigationCaseFromSignal(signal, evidence, paths));
  });

  (state.data.analysis?.source_ips || [])
    .filter(actorSourceNeedsReview)
    .slice(0, 8)
    .forEach((source) => add(investigationCaseFromSourceIP(source, evidence, paths)));

  paths.slice(0, 8).forEach((pathItem) => {
    const errors = Number(pathItem.status_4xx || 0) + Number(pathItem.status_5xx || 0);
    if (errors || Number(pathItem.p95_request_time_ms || 0) >= 1000) {
      add(investigationCaseFromPath(pathItem, evidence, paths));
    }
  });

  return cases
    .filter(Boolean)
    .sort((a, b) => Number(b.risk || 0) - Number(a.risk || 0) || Number(b.errors || 0) - Number(a.errors || 0) || Number(b.requests || 0) - Number(a.requests || 0))
    .slice(0, 8);
}

function investigationCaseFromSignal(signal, allEvidence = filteredLogEvidence(), allPaths = filteredTopPaths()) {
  const siteID = signal.siteID || state.viewContext.site_id || state.siteID || "";
  const evidence = allEvidence.filter((item) => {
    if (siteID && item.site_id && item.site_id !== siteID) return false;
    if (signal.ip && item.ip !== signal.ip) return false;
    if (signal.path && !pathMatches(item.path, signal.path)) return false;
    return signal.ip || signal.path || signal.siteID ? true : evidenceKindMatches(item.kind, signal.sourceKind || signal.group);
  });
  const paths = allPaths.filter((item) => (!siteID || !item.site_id || item.site_id === siteID) && (!signal.path || pathMatches(item.path, signal.path)));
  const errors = signal.errors || evidence.reduce((sum, item) => sum + Number(item.errors || 0) + Number(item.status_4xx || 0) + Number(item.status_5xx || 0), 0);
  const report = reportContextsForLogContext(evidence, paths)[0];
  const entity = signalCaseEntity(signal);
  return {
    key: `signal:${signal.key}`,
    lane: formatCategory(signal.group || "signal"),
    severity: signal.severity || severityForScore(signal.risk || 0),
    risk: signal.risk || severityRank(signal.severity) * 20 || 0,
    title: signal.title || "Signal investigation",
    summary: signal.summary || signalRecommendation(signal),
    siteID,
    entity,
    requests: Number(signal.requests || 0),
    errors,
    evidenceCount: evidence.length,
    path: signal.path || paths[0]?.path || "",
    ip: signal.ip || "",
    report,
    actions: investigationCaseActions({ signal, entity, siteID, report, errors, origin: "investigate_case" }),
  };
}

function investigationCaseFromSourceIP(source, allEvidence = filteredLogEvidence(), allPaths = filteredTopPaths()) {
  const siteID = source.site_id || state.viewContext.site_id || state.siteID || "";
  const evidence = allEvidence.filter((item) => item.ip === source.ip && (!siteID || !item.site_id || item.site_id === siteID));
  const paths = allPaths.filter((item) => evidence.some((row) => pathMatches(row.path, item.path)));
  const errors = Number(source.status_4xx || 0) + Number(source.status_5xx || 0);
  const report = reportContextsForLogContext(evidence, paths)[0];
  const actor = source.known_actor || actorLabelFromType(source.actor_type) || source.reverse_dns || "unknown source";
  return {
    key: `source:${source.ip}:${siteID}`,
    lane: "Source review",
    severity: severityForScore(source.risk_score || (errors ? 65 : 35)),
    risk: Number(source.risk_score || 0),
    title: `Verify ${source.ip || "source IP"}`,
    summary: [
      actor,
      source.asn ? formatASN(source.asn) : "",
      source.asn_org || source.network || "",
      actorSourceStatus(source),
    ].filter(Boolean).join(" - "),
    siteID,
    entity: { kind: "ip", value: source.ip },
    requests: Number(source.requests || 0),
    errors,
    evidenceCount: evidence.length,
    path: paths[0]?.path || "",
    ip: source.ip || "",
    report,
    actions: investigationCaseActions({ entity: { kind: "ip", value: source.ip }, siteID, report, errors, origin: "investigate_case", source }),
  };
}

function investigationCaseFromPath(pathItem, allEvidence = filteredLogEvidence(), allPaths = filteredTopPaths()) {
  const siteID = pathItem.site_id || state.viewContext.site_id || state.siteID || "";
  const evidence = allEvidence.filter((item) => pathMatches(item.path, pathItem.path) && (!siteID || !item.site_id || item.site_id === siteID));
  const paths = allPaths.filter((item) => pathMatches(item.path, pathItem.path));
  const errors = Number(pathItem.status_4xx || 0) + Number(pathItem.status_5xx || 0);
  const report = reportContextsForLogContext(evidence, paths)[0];
  const p95 = Number(pathItem.p95_request_time_ms || 0);
  return {
    key: `path:${siteID}:${pathItem.path || "/"}`,
    lane: errors ? "Reliability" : "Performance",
    severity: severityForScore(Math.max(errors ? 65 : 0, Math.min(90, Math.round(p95 / 100)))),
    risk: Math.max(errors ? 65 : 0, Math.min(90, Math.round(p95 / 100))),
    title: `${errors ? "Failing" : "Slow"} path ${pathItem.path || "/"}`,
    summary: [
      formatStatusBuckets(pathItem),
      p95 ? `p95 ${formatMs(p95)}` : "",
      siteID || "all sites",
    ].filter(Boolean).join(" - "),
    siteID,
    entity: { kind: "path", value: pathItem.path || "/" },
    requests: Number(pathItem.requests || 0),
    errors,
    evidenceCount: evidence.length,
    path: pathItem.path || "/",
    ip: evidence[0]?.ip || "",
    report,
    actions: investigationCaseActions({ entity: { kind: "path", value: pathItem.path || "/" }, siteID, report, errors, path: pathItem.path || "/", origin: "investigate_case" }),
  };
}

function signalCaseEntity(signal) {
  if (signal.ip) return { kind: "ip", value: signal.ip };
  if (signal.path) return { kind: "path", value: signal.path };
  if (signal.actor) return { kind: "actor", value: signal.actor };
  if (signal.siteID) return { kind: "site", value: signal.siteID };
  return null;
}

function investigationCaseActions({ signal = null, entity = null, siteID = "", report = null, errors = 0, path = "", origin = "investigate_case", source = null } = {}) {
  const actions = [];
  if (signal) actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: signal.key, site_id: signal.siteID || siteID, origin })}'>Open signal</button>`);
  if (entity?.kind && entity.value) actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(investigationEntityPivot(entity, siteID, origin, source))}'>Open ${escapeHTML(investigationEntityActionLabel(entity.kind))}</button>`);
  if (siteID) actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: siteID, origin })}'>Open site</button>`);
  actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(investigationLogPivot({ signal, entity, siteID, errors, path, source, origin }))}'>Open logs</button>`);
  if ((signal?.path || path || entity?.kind === "path") && entity?.kind !== "path") {
    actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: signal?.path || path, site_id: siteID, origin })}'>Open path</button>`);
  }
  if (report) {
    actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: report.site_id || siteID, origin }))}'>Open report</button>`);
  } else {
    actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin })}'>Reports</button>`);
  }
  return actions.join("");
}

function investigationEntityPivot(entity, siteID = "", origin = "investigate_case", source = null) {
  if (entity.kind === "site") return { kind: "site", value: entity.value, origin };
  const pivot = { kind: entity.kind, value: entity.value, site_id: siteID, origin };
  if (entity.kind === "actor" && source?.actor_type) pivot.actor_type = source.actor_type;
  return pivot;
}

function investigationLogPivot({ signal = null, entity = null, siteID = "", errors = 0, path = "", source = null, origin = "investigate_case" } = {}) {
  if (signal) return signalLogPivot({ ...signal, siteID: signal.siteID || siteID, errors: signal.errors || errors }, origin);
  const pivot = { kind: "log_filter", site_id: siteID, origin };
  if (entity?.kind === "ip") pivot.ip = entity.value;
  if (entity?.kind === "asn") pivot.asn = formatASN(entity.value) || entity.value;
  if (entity?.kind === "path") pivot.path = entity.value;
  if (entity?.kind === "actor") pivot.known_actor = entity.value;
  if (entity?.kind === "user-agent") pivot.user_agent = entity.value;
  if (source?.actor_type) pivot.actor_type = source.actor_type;
  if (path) pivot.path = path;
  if (errors) pivot.status_class = "errors";
  return pivot;
}

function investigationEntityActionLabel(kind) {
  return {
    ip: "IP",
    asn: "ASN",
    path: "path",
    actor: "actor",
    "user-agent": "user agent",
    site: "site",
  }[kind] || "entity";
}

function investigationCaseRow(item) {
  const context = [
    item.siteID ? siteLabel(item.siteID) : "All sites",
    item.ip ? `IP ${item.ip}` : "",
    item.path || "",
    `${formatNumber(item.evidenceCount || 0)} evidence rows`,
    item.report ? reportListLabel(item.report) : "",
  ].filter(Boolean).join(" - ");
  return `
    <div class="investigation-case-row">
      <div class="investigation-case-main">
        <span class="severity severity-${escapeHTML(item.severity || "low")}">${escapeHTML(item.severity || "low")}</span>
        <div>
          <strong>${escapeHTML(item.title || "Investigation case")}</strong>
          <span>${escapeHTML(item.summary || context)}</span>
          <small>${escapeHTML(context)}</small>
          <div class="signal-actions">${item.actions || ""}</div>
        </div>
      </div>
      <div class="investigation-case-numbers">
        <span>${escapeHTML(item.lane || "case")}</span>
        <b>${escapeHTML(item.risk || 0)}</b>
        <small>${formatNumber(item.requests || 0)} req / ${formatNumber(item.errors || 0)} err</small>
      </div>
    </div>
  `;
}

function siteLabel(siteID) {
  const site = (state.data.sites || []).find((item) => item.id === siteID);
  return site?.name || siteID || "";
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
  setText("#entityPageEyebrow", `${entity.kind === "asn" ? "ASN" : formatCategory(entity.kind)} investigation`);
  setText("#entityPageTitle", entity.kind === "asn" ? formatASN(entity.value) || entity.value : entity.value);
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
  if (entity.kind === "asn") return { kind: "log_filter", asn: formatASN(entity.value) || entity.value, site_id: siteID, origin: "entity" };
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
  const sourceIPs = entitySourceIPs(entity).slice(0, 16);
  const timeline = entityTimelineRows(entity, { detail, signals, evidence, paths, sites, agents, sourceIPs }).slice(0, 18);
  return `
    <div class="field-grid entity-facts">${facts.map(statTile).join("")}</div>
    ${entityInvestigationPath(entity, { detail, signals, evidence, paths, sites, agents, sourceIPs })}
    ${entityNextSteps(entity, { detail, signals, evidence, paths, sites, agents, sourceIPs })}
    ${entityIdentityPanel(entity, { detail, signals, evidence, paths, sites, agents, sourceIPs })}
    ${entityImpactMatrix(entity, { evidence, paths, sites, agents })}
    <section class="entity-detail-grid">
      ${entitySection("Investigation timeline", entityTimeline(timeline), "No timeline events in this scope.", "entity-section-wide")}
      ${entitySection("Related signals", signals.map(signalRow).join(""), "No related signals in this scope.")}
      ${entitySection("Recent evidence", evidence.map(logEvidenceRow).join(""), "No recent evidence in this scope.")}
      ${entitySection("Multi-log correlation", entityCorrelationPack(entity, evidence, paths), "No correlated log lanes are available in this scope.")}
      ${entity.kind === "actor" ? entitySection("Source IP verification", actorVerificationPanel(entity), "No source IPs are tied to this actor in the current scope.") : ""}
      ${entity.kind === "asn" ? entitySection("Source IPs in ASN", sourceIPs.map(entitySourceIPRow).join(""), "No source IPs in this ASN for the current scope.") : ""}
      ${entitySection("Sites touched", sites.map(entitySiteRow).join(""), "No site distribution available.")}
      ${entitySection("Paths", paths.map(entityPathRow).join(""), "No path distribution available.")}
      ${entitySection("User agents", agents.map(entityUserAgentRow).join(""), "No user-agent distribution available.")}
      ${entity.lookup_errors?.length || detail.lookup_errors?.length ? entitySection("Lookup notes", `<div class="empty">${escapeHTML((entity.lookup_errors || detail.lookup_errors || []).join("\\n"))}</div>`, "") : ""}
    </section>
  `;
}

function entityImpactMatrix(entity, context = {}) {
  const rows = entityImpactRows(entity, context).slice(0, 12);
  const title = entity.kind === "path" ? "Affected sources" : "Affected URLs";
  const summary = rows.length ? `${formatNumber(rows.length)} rows` : "no rows";
  return `
    <section class="entity-impact-panel" aria-label="Entity impact matrix">
      <div class="entity-next-title">
        <span>${escapeHTML(title)}</span>
        <strong>${escapeHTML(summary)}</strong>
      </div>
      <div class="table-wrap entity-impact-wrap">
        <table class="entity-impact-table">
          <thead>
            <tr>
              <th>Site</th>
              <th>${entity.kind === "path" ? "Source" : "Path"}</th>
              <th>Requests</th>
              <th>Errors</th>
              <th>Latest</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            ${rows.map((row) => entityImpactRow(entity, row)).join("") || emptyRow(6, "No affected site/path rows in this scope.")}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function entityImpactRows(entity, context = {}) {
  const evidence = context.evidence || [];
  const paths = context.paths || [];
  const rows = new Map();
  const add = (item = {}) => {
    const siteID = item.site_id || state.viewContext.site_id || state.siteID || "";
    const path = item.path || (entity.kind === "path" ? entity.value : "/");
    const source = item.ip || item.client_ip || "";
    const sourceKey = entity.kind === "path" ? source || item.user_agent || "" : path;
    const key = [siteID, item.env || "", sourceKey || "-", entity.kind === "path" ? path : ""].join("|");
    const existing = rows.get(key) || {
      site_id: siteID,
      env: item.env || "",
      path,
      ip: source,
      user_agent: item.user_agent || item.sample || "",
      requests: 0,
      errors: 0,
      status_4xx: 0,
      status_5xx: 0,
      bytes_sent: 0,
      p95_request_time_ms: 0,
      latest: "",
    };
    const requests = Number(item.requests || item.events || 0) || 1;
    const status = Number(item.status || 0);
    const status4xx = Number(item.status_4xx || 0) + (status >= 400 && status < 500 ? 1 : 0);
    const status5xx = Number(item.status_5xx || 0) + (status >= 500 ? 1 : 0);
    const errors = Number(item.errors || 0) + status4xx + status5xx;
    existing.requests += requests;
    existing.errors += errors;
    existing.status_4xx += status4xx;
    existing.status_5xx += status5xx;
    existing.bytes_sent += Number(item.bytes_sent || 0);
    existing.p95_request_time_ms = Math.max(existing.p95_request_time_ms || 0, Number(item.p95_request_time_ms || 0));
    if (!existing.ip && source) existing.ip = source;
    if (!existing.user_agent && (item.user_agent || item.sample)) existing.user_agent = item.user_agent || item.sample;
    const latest = item.ts || item.last_seen || item.timestamp || item.max_ts || "";
    if (latest && (!existing.latest || new Date(latest) > new Date(existing.latest || 0))) existing.latest = latest;
    rows.set(key, existing);
  };
  evidence.forEach(add);
  if (!rows.size) paths.forEach(add);
  return Array.from(rows.values()).sort((a, b) => {
    return Number(b.errors || 0) - Number(a.errors || 0)
      || Number(b.requests || 0) - Number(a.requests || 0)
      || new Date(b.latest || 0) - new Date(a.latest || 0);
  });
}

function entityImpactRow(entity, row) {
  const siteID = row.site_id || state.viewContext.site_id || state.siteID || "";
  const errors = Number(row.errors || 0);
  const path = row.path || (entity.kind === "path" ? entity.value : "/");
  const sourceLabel = row.ip || shortLabel(row.user_agent || "", 72) || "-";
  const mainLabel = entity.kind === "path" ? sourceLabel : path;
  const mainMeta = entity.kind === "path"
    ? [path, row.user_agent && row.ip ? shortLabel(row.user_agent, 72) : ""].filter(Boolean).join(" / ")
    : [row.ip ? `IP ${row.ip}` : "", row.user_agent ? shortLabel(row.user_agent, 72) : "", row.p95_request_time_ms ? `p95 ${formatMs(row.p95_request_time_ms)}` : ""].filter(Boolean).join(" / ");
  const logContext = {
    path,
    ip: row.ip || (entity.kind === "ip" ? entity.value : ""),
    site_id: siteID,
  };
  const actions = [
    siteID && siteID !== "unknown" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: siteID, origin: "entity_impact" })}'>Site</button>` : "",
    path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: path, site_id: siteID, origin: "entity_impact" })}'>Path</button>` : "",
    row.ip && entity.kind !== "ip" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: row.ip, site_id: siteID, origin: "entity_impact" })}'>IP</button>` : "",
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ...logContext, log_type: "nginx-access", origin: "entity_impact" })}'>Access</button>`,
    errors ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ...logContext, status_class: "errors", log_type: "nginx-access", origin: "entity_impact" })}'>Errors</button>` : "",
  ].filter(Boolean).join("");
  return `
    <tr>
      <td><strong>${escapeHTML(siteLabel(siteID) || siteID || "All sites")}</strong><br><span>${escapeHTML([siteID, row.env].filter(Boolean).join(" / ") || "current scope")}</span></td>
      <td class="clip"><strong>${escapeHTML(mainLabel || "-")}</strong><br><span>${escapeHTML(mainMeta || "matching evidence")}</span></td>
      <td>${formatNumber(row.requests || 0)}<br><span>${row.bytes_sent ? formatBytes(row.bytes_sent) : ""}</span></td>
      <td>${formatNumber(errors)}<br><span>${escapeHTML(entityImpactStatusLabel(row))}</span></td>
      <td>${formatTime(row.latest)}</td>
      <td class="row-actions">${actions}</td>
    </tr>
  `;
}

function entityImpactStatusLabel(row) {
  const status = formatStatusBuckets(row);
  if (status !== "no status") return status;
  return Number(row.errors || 0) ? `${formatNumber(row.errors || 0)} errors` : "no status";
}

function entityInvestigationPath(entity, context = {}) {
  const evidence = context.evidence || [];
  const paths = context.paths || [];
  const sites = context.sites || [];
  const signals = context.signals || [];
  const sourceIPs = context.sourceIPs || [];
  const siteID = state.viewContext.site_id || state.siteID || sites[0]?.site_id || paths[0]?.site_id || evidence[0]?.site_id || "";
  const topPath = paths[0] || evidence.find((item) => item.path) || {};
  const topSite = sites.find((item) => item.site_id && item.site_id !== "unknown") || {};
  const topSignal = signals[0];
  const topSource = sourceIPs[0] || evidence.find((item) => item.ip || item.client_ip) || {};
  const topIP = topSource.ip || topSource.client_ip || (entity.kind === "ip" ? entity.value : "");
  const sourceCount = new Set(evidence.map((item) => item.ip || item.client_ip).filter(Boolean)).size;
  const errors = evidence.reduce((sum, item) => {
    const status = Number(item.status || 0);
    return sum
      + Number(item.errors || 0)
      + Number(item.status_4xx || 0)
      + Number(item.status_5xx || 0)
      + (status >= 400 ? 1 : 0);
  }, 0);
  const logPivot = {
    ...entityLogPivot(entity, siteID),
    status_class: errors ? "errors" : state.viewContext.status_class || "",
    origin: "entity_path",
  };
  const report = reportContextsForLogContext(evidence, paths)[0];
  const entityLabel = entity.kind === "asn" ? "ASN" : formatCategory(entity.kind);
  const entityValue = entity.kind === "asn" ? formatASN(entity.value) || entity.value : entity.value;
  const steps = [
    {
      label: "Entity",
      value: entityValue,
      meta: [entityLabel, activeFilterLabel()].filter(Boolean).join(" / "),
      actions: `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logPivot)}'>Matching logs</button>`,
    },
    {
      label: entity.kind === "path" ? "Sources" : "Sites touched",
      value: entity.kind === "path" ? `${formatNumber(sourceCount)} sources` : `${formatNumber(sites.length || (siteID ? 1 : 0))} sites`,
      meta: entity.kind === "path"
        ? [topIP ? `Top IP ${topIP}` : "", topSource.known_actor || actorLabelFromType(topSource.actor_type) || ""].filter(Boolean).join(" / ")
        : [topSite.site_id ? siteLabel(topSite.site_id) || topSite.site_id : siteID ? siteLabel(siteID) || siteID : "", topSite.requests ? `${formatNumber(topSite.requests)} requests` : ""].filter(Boolean).join(" / "),
      actions: [
        entity.kind === "path" && topIP ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: topIP, site_id: topSource.site_id || siteID, origin: "entity_path" })}'>Open IP</button>` : "",
        topSource.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(topSource.asn), site_id: topSource.site_id || siteID, origin: "entity_path" })}'>Open ASN</button>` : "",
        entity.kind !== "path" && topSite.site_id && topSite.site_id !== "unknown" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: topSite.site_id, origin: "entity_path" })}'>Top site</button>` : "",
      ].filter(Boolean).join(""),
    },
    {
      label: entity.kind === "path" ? "Request target" : "URLs hit",
      value: topPath.path || (entity.kind === "path" ? entity.value : `${formatNumber(paths.length)} paths`),
      meta: [
        topPath.requests ? `${formatNumber(topPath.requests)} requests` : "",
        Number(topPath.status_5xx || 0) ? `${formatNumber(topPath.status_5xx)} 5xx` : "",
        topPath.p95_request_time_ms ? `p95 ${formatMs(topPath.p95_request_time_ms)}` : "",
      ].filter(Boolean).join(" / "),
      actions: [
        topPath.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: topPath.path, site_id: topPath.site_id || siteID, origin: "entity_path" })}'>Open path</button>` : "",
        topPath.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", path: topPath.path, ip: entity.kind === "ip" ? entity.value : topIP, site_id: topPath.site_id || siteID, status_class: errors ? "errors" : "", log_type: "nginx-access", origin: "entity_path" })}'>Access rows</button>` : "",
      ].filter(Boolean).join(""),
    },
    {
      label: "Signals",
      value: topSignal ? shortLabel(topSignal.title || "Signal", 52) : `${formatNumber(signals.length)} signals`,
      meta: topSignal ? [formatCategory(topSignal.group || "signal"), topSignal.siteID || "", topSignal.risk ? `risk ${formatNumber(topSignal.risk)}` : ""].filter(Boolean).join(" / ") : "No related signal in scope",
      actions: topSignal
        ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: topSignal.key, site_id: topSignal.siteID || siteID, origin: "entity_path" })}'>Open signal</button>`
        : `<button class="ghost mini inline-action" type="button" data-route-target="signals">Signals</button>`,
    },
    {
      label: "Raw evidence",
      value: `${formatNumber(evidence.length)} rows`,
      meta: errors ? `${formatNumber(errors)} errors across matching rows` : "Access and derived evidence",
      actions: [
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logPivot)}'>Open rows</button>`,
        topPath.path ? correlatedLogActions({ path: topPath.path, siteID: topPath.site_id || siteID, ip: entity.kind === "ip" ? entity.value : topIP, statusClass: errors ? "errors" : "", origin: "entity_path" }) : "",
      ].filter(Boolean).join(""),
    },
    {
      label: "Report period",
      value: report ? reportListLabel(report) : formatCategory(state.reportTab || "daily"),
      meta: report ? reportWindowLabel(report) : activeFilterLabel(),
      actions: report
        ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: report.site_id || siteID, origin: "entity_path" }))}'>Open report</button>`
        : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "entity_path" })}'>Reports</button>`,
    },
  ];
  return `
    <section class="entity-path-board" aria-label="Entity investigation path">
      ${steps.map(entityInvestigationPathStep).join("")}
    </section>
  `;
}

function entityInvestigationPathStep(step) {
  return `
    <div class="entity-path-step">
      <div>
        <span>${escapeHTML(step.label || "-")}</span>
        <strong>${escapeHTML(step.value || "-")}</strong>
        <small>${escapeHTML(step.meta || "")}</small>
      </div>
      <div class="signal-actions">${step.actions || ""}</div>
    </div>
  `;
}

function entityNextSteps(entity, context = {}) {
  const evidence = context.evidence || [];
  const signals = context.signals || [];
  const paths = context.paths || [];
  const sites = context.sites || [];
  const agents = context.agents || [];
  const sourceIPs = context.sourceIPs || [];
  const siteID = state.viewContext.site_id || state.siteID || "";
  const errors = evidence.reduce((sum, item) => sum + Number(item.errors || 0), 0);
  const logPivot = {
    ...entityLogPivot(entity, siteID),
    status_class: errors ? "errors" : state.viewContext.status_class || "",
    origin: "entity_next",
  };
  const topSignal = signals[0];
  const report = reportContextsForLogContext(evidence, paths)[0];
  const rows = [
    {
      title: "Open matching evidence",
      meta: [
        `${formatNumber(evidence.length)} evidence rows`,
        errors ? `${formatNumber(errors)} errors` : "",
        activeFilterLabel(),
      ].filter(Boolean).join(" - "),
      valueLabel: "rows",
      value: formatNumber(evidence.length),
      actions: [
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(logPivot)}'>Open logs</button>`,
        paths[0]?.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: paths[0].path || "/", site_id: paths[0].site_id || siteID, origin: "entity_next" })}'>Top path</button>` : "",
      ].filter(Boolean).join(""),
    },
    topSignal ? {
      title: "Review highest signal",
      meta: [
        formatCategory(topSignal.group || "signal"),
        topSignal.siteID || "",
        topSignal.ip ? `IP ${topSignal.ip}` : "",
        topSignal.path || "",
      ].filter(Boolean).join(" - "),
      valueLabel: "risk",
      value: topSignal.risk || severityRank(topSignal.severity) * 20 || 0,
      actions: [
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: topSignal.key, site_id: topSignal.siteID || siteID, origin: "entity_next" })}'>Open signal</button>`,
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(signalLogPivot(topSignal, "entity_next"))}'>Signal logs</button>`,
      ].join(""),
    } : null,
    entitySpecificNextStep(entity, { evidence, paths, sites, agents, sourceIPs }),
    report ? {
      title: "Review report context",
      meta: [reportListLabel(report), reportWindowLabel(report)].filter(Boolean).join(" - "),
      valueLabel: report.model || "report",
      value: formatNumber(report.summary?.requests || 0),
      actions: `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: report.site_id || siteID, origin: "entity_next" }))}'>Open report</button>`,
    } : {
      title: "Open report workspace",
      meta: activeFilterLabel(),
      valueLabel: "period",
      value: formatCategory(state.reportTab || "daily"),
      actions: `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "entity_next" })}'>Reports</button>`,
    },
  ].filter(Boolean);
  return `
    <section class="entity-next-steps" aria-label="Recommended next steps">
      <div class="entity-next-title">
        <span>Next steps</span>
        <strong>${escapeHTML(entityNextStepSummary(entity, signals, errors))}</strong>
      </div>
      <div class="entity-next-list">${rows.map(entityNextStepRow).join("")}</div>
    </section>
  `;
}

function entitySpecificNextStep(entity, context = {}) {
  const evidence = context.evidence || [];
  const paths = context.paths || [];
  const sites = context.sites || [];
  const agents = context.agents || [];
  const siteID = state.viewContext.site_id || state.siteID || "";
  if (entity.kind === "ip") {
    const local = (state.data.analysis?.source_ips || []).find((item) => item.ip === entity.value) || {};
    const actor = local.known_actor || actorLabelFromType(local.actor_type);
    const action = formatManualAction(local.manual_action);
    return {
      title: "Verify source identity",
      meta: [
        actor || "unknown actor",
        local.asn ? formatASN(local.asn) : "",
        local.asn_org || local.network || "",
        action !== "-" ? action : "",
      ].filter(Boolean).join(" - "),
      valueLabel: "risk",
      value: local.risk_score || 0,
      actions: [
        local.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(local.asn), site_id: local.site_id || siteID, origin: "entity_next" })}'>Open ASN</button>` : "",
        actor ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: actor, actor_type: local.actor_type || "", site_id: local.site_id || siteID, origin: "entity_next" })}'>Open actor</button>` : "",
        ipManualButtons(entity.value, local, local.site_id || siteID, "mini"),
      ].filter(Boolean).join(""),
    };
  }
  if (entity.kind === "asn") {
    const sourceIPs = context.sourceIPs || [];
    const topSource = sourceIPs[0] || {};
    const review = sourceIPs.filter(actorSourceNeedsReview).length;
    return {
      title: "Audit source IPs",
      meta: [
        `${formatNumber(sourceIPs.length)} IPs`,
        review ? `${formatNumber(review)} need review` : "",
        topSource.asn_org || topSource.network || "",
      ].filter(Boolean).join(" - "),
      valueLabel: "risk",
      value: topSource.risk_score || 0,
      actions: [
        topSource.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: topSource.ip, site_id: topSource.site_id || siteID, origin: "entity_next" })}'>Top IP</button>` : "",
        topSource.known_actor || topSource.actor_type ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: topSource.known_actor || actorLabelFromType(topSource.actor_type), actor_type: topSource.actor_type || "", site_id: topSource.site_id || siteID, origin: "entity_next" })}'>Open actor</button>` : "",
      ].filter(Boolean).join(""),
    };
  }
  if (entity.kind === "path") {
    const ips = new Set(evidence.map((item) => item.ip).filter(Boolean));
    const topSite = sites[0] || {};
    return {
      title: "Compare affected scope",
      meta: [
        `${formatNumber(sites.length)} sites`,
        `${formatNumber(ips.size)} source IPs`,
        paths[0]?.p95_request_time_ms ? `p95 ${formatMs(paths[0].p95_request_time_ms)}` : "",
      ].filter(Boolean).join(" - "),
      valueLabel: "sites",
      value: formatNumber(sites.length),
      actions: [
        topSite.site_id && topSite.site_id !== "unknown" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: topSite.site_id, origin: "entity_next" })}'>Top site</button>` : "",
        evidence[0]?.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: evidence[0].ip, site_id: evidence[0].site_id || siteID, origin: "entity_next" })}'>Top IP</button>` : "",
      ].filter(Boolean).join(""),
    };
  }
  if (entity.kind === "actor") {
    const actor = aggregateActors().find((item) => item.label === entity.value) || {};
    const sources = actorSourceRows(entity.value, state.viewContext.actor_type || actor.type);
    const topSource = sources[0] || {};
    return {
      title: "Verify service sources",
      meta: [
        actorVerificationState(actor),
        `${formatNumber(actor.reviewIPs || 0)} review`,
        `${formatNumber(actor.verifiedIPs || 0)} verified`,
      ].join(" - "),
      valueLabel: "IPs",
      value: formatNumber(actor.ips || sources.length || 0),
      actions: [
        topSource.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: topSource.ip, site_id: topSource.site_id || siteID, origin: "entity_next" })}'>Top IP</button>` : "",
        topSource.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(topSource.asn), site_id: topSource.site_id || siteID, origin: "entity_next" })}'>Open ASN</button>` : "",
      ].filter(Boolean).join(""),
    };
  }
  if (entity.kind === "user-agent") {
    return {
      title: "Inspect user-agent footprint",
      meta: [
        `${formatNumber(sites.length)} sites`,
        `${formatNumber(paths.length)} paths`,
        agents[0]?.sample ? shortLabel(agents[0].sample, 58) : "",
      ].filter(Boolean).join(" - "),
      valueLabel: "paths",
      value: formatNumber(paths.length),
      actions: [
        paths[0]?.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: paths[0].path || "/", site_id: paths[0].site_id || siteID, origin: "entity_next" })}'>Top path</button>` : "",
        evidence[0]?.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: evidence[0].ip, site_id: evidence[0].site_id || siteID, origin: "entity_next" })}'>Top IP</button>` : "",
      ].filter(Boolean).join(""),
    };
  }
  return null;
}

function entityNextStepRow(item) {
  return `
    <div class="signal-row entity-next-row">
      <div>
        <strong>${escapeHTML(item.title || "-")}</strong>
        <span>${escapeHTML(item.meta || "")}</span>
        <div class="signal-actions">${item.actions || ""}</div>
      </div>
      <div class="signal-numbers">
        <span>${escapeHTML(item.valueLabel || "")}</span>
        <b>${escapeHTML(item.value ?? "")}</b>
      </div>
    </div>
  `;
}

function entityNextStepSummary(entity, signals, errors) {
  const parts = [
    entity.kind === "asn" ? formatASN(entity.value) || entity.value : entity.value,
    signals.length ? `${formatNumber(signals.length)} signals` : "",
    errors ? `${formatNumber(errors)} errors` : "",
  ];
  return parts.filter(Boolean).join(" / ");
}

function entityIdentityPanel(entity, context = {}) {
  const model = entityIdentityModel(entity, context);
  if (!model) return "";
  const facts = entityIdentityFacts(model.facts || []);
  const actions = (model.actions || []).filter(Boolean).join("");
  const notes = (model.notes || []).filter(Boolean);
  return `
    <section class="entity-identity-panel" aria-label="Entity identity and attribution">
      <div class="entity-next-title">
        <span>Identity and attribution</span>
        <strong>${escapeHTML(model.summary || "")}</strong>
      </div>
      <div class="entity-identity-grid">
        <div class="entity-identity-main">
          <div class="entity-identity-heading">
            <h3>${escapeHTML(model.title || "Entity identity")}</h3>
            <p>${escapeHTML(model.description || "Attribution, verification state, and source intelligence for this entity.")}</p>
          </div>
          <dl class="entity-identity-facts">${facts}</dl>
          ${notes.length ? `<div class="entity-identity-notes">${notes.map((note) => `<span>${escapeHTML(note)}</span>`).join("")}</div>` : ""}
        </div>
        <div class="entity-identity-actions">
          <strong>Useful pivots</strong>
          <div class="signal-actions">${actions || `<span class="muted">No pivots available in this scope.</span>`}</div>
        </div>
      </div>
    </section>
  `;
}

function entityIdentityModel(entity, context = {}) {
  if (entity.kind === "ip") return entityIPIdentityModel(entity, context);
  if (entity.kind === "asn") return entityASNIdentityModel(entity, context);
  if (entity.kind === "actor") return entityActorIdentityModel(entity, context);
  if (entity.kind === "path") return entityPathIdentityModel(entity, context);
  if (entity.kind === "user-agent") return entityUserAgentIdentityModel(entity, context);
  return null;
}

function entityIPIdentityModel(entity, context = {}) {
  const detail = context.detail || {};
  const siteID = state.viewContext.site_id || state.siteID || "";
  const local = sourceIPContextForIP(entity.value);
  const stored = detail.stored_intel || {};
  const dns = detail.dns || {};
  const asn = detail.asn || {};
  const rdap = detail.rdap || {};
  const traffic = detail.traffic || {};
  const asnValue = asn.asn || stored.asn || local.asn;
  const asnLabel = asnValue ? formatASN(asnValue) : "";
  const actorType = stored.actor_type || local.actor_type || "";
  const actor = stored.known_actor || local.known_actor || actorLabelFromType(actorType);
  const reverseDNS = joinLimited(dns.reverse_names) || stored.reverse_dns || local.reverse_dns || "";
  const forwardAddresses = joinLimited(dns.forward_addresses);
  const forwardConfirmed = Boolean(dns.forward_confirmed || stored.forward_confirmed || local.forward_confirmed);
  const verifiedActor = Boolean(stored.verified_actor || local.verified_actor || local.verified_source);
  const network = asn.prefix || stored.network || local.network || joinLimited(rdap.cidrs);
  const country = asn.country_code || stored.country_code || local.country_code || rdap.country_code || "";
  const asnOrg = asn.name || stored.asn_org || local.asn_org || "";
  const rdapRange = [rdap.start_address, rdap.end_address].filter(Boolean).join(" - ");
  const rdapContacts = entityRDAPContacts(rdap.entities);
  const verification = entityIPVerificationLabel({ local, stored, reverseDNS, forwardConfirmed, verifiedActor });
  const lookupErrors = [
    ...(detail.lookup_errors || []),
    dns.reverse_lookup_error,
    dns.forward_lookup_error,
    asn.error,
    rdap.error,
  ].filter(Boolean);
  const notes = [
    state.entityDetailLoading[entityKey(entity)] ? "Refreshing DNS, ASN, RDAP, and stored intelligence." : "",
    detail.external_provider ? `External provider: ${detail.external_provider}` : "",
    lookupErrors.length ? `Lookup notes: ${lookupErrors.join("; ")}` : "",
  ];
  const topPath = (context.paths || [])[0] || {};
  const errors = Number(traffic.status_4xx || local.status_4xx || 0) + Number(traffic.status_5xx || local.status_5xx || 0);
  return {
    title: `Source IP ${entity.value}`,
    summary: [verification, actor || actorType ? actor || formatCategory(actorType) : "", asnLabel, country].filter(Boolean).join(" / ") || "Unattributed source",
    description: "DNS, ASN, RDAP, manual labels, and verification proof collected for this source IP.",
    facts: [
      ["Verification", verification, forwardConfirmed ? "DNS forward-confirmed" : ""],
      ["Reverse DNS", reverseDNS || "-"],
      ["Forward DNS", forwardAddresses || "-", forwardConfirmed ? "confirmed" : ""],
      ["Known actor", actor || "-", actorType ? formatCategory(actorType) : ""],
      ["Manual label", stored.manual_label || local.manual_label || "-", formatManualAction(stored.manual_action || local.manual_action)],
      ["ASN", asnLabel || "-", asnOrg],
      ["Network", network || "-"],
      ["Country", country || "-"],
      ["RDAP object", [rdap.name, rdap.handle].filter(Boolean).join(" / ") || "-", rdap.type || ""],
      ["RDAP range", rdapRange || "-"],
      ["RDAP contacts", rdapContacts || "-"],
      ["Registered", formatMaybeDate(rdap.registration), rdap.last_changed ? `changed ${formatMaybeDate(rdap.last_changed)}` : ""],
      ["Tor/datacenter", [stored.is_tor_exit || local.is_tor_exit ? "Tor exit" : "", stored.is_datacenter || local.is_datacenter ? "Datacenter" : ""].filter(Boolean).join(" / ") || "-"],
      ["Intel refreshed", formatMaybeDate(stored.refreshed_at || local.refreshed_at || detail.generated_at)],
    ],
    actions: [
      `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ip: entity.value, site_id: siteID, log_type: "nginx-access", origin: "entity_identity" })}'>Access logs</button>`,
      errors ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ip: entity.value, site_id: siteID, status_class: "errors", log_type: "nginx-access", origin: "entity_identity" })}'>Error rows</button>` : "",
      asnLabel ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: asnLabel, site_id: siteID, origin: "entity_identity" })}'>Open ASN</button>` : "",
      actor ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: actor, actor_type: actorType, site_id: siteID, origin: "entity_identity" })}'>Open actor</button>` : "",
      topPath.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: topPath.path, site_id: topPath.site_id || siteID, origin: "entity_identity" })}'>Top path</button>` : "",
      ipManualButtons(entity.value, stored.manual_action || stored.manual_label ? stored : local, siteID, "mini"),
    ],
    notes,
  };
}

function entityASNIdentityModel(entity, context = {}) {
  const sourceIPs = context.sourceIPs?.length ? context.sourceIPs : sourceIPsForASN(entity.value);
  const first = sourceIPs[0] || {};
  const actors = new Set(sourceIPs.map((item) => item.known_actor || actorLabelFromType(item.actor_type)).filter(Boolean));
  const sites = new Set(sourceIPs.map((item) => item.site_id).filter(Boolean));
  const verified = sourceIPs.filter(actorSourceIsVerified).length;
  const review = sourceIPs.filter(actorSourceNeedsReview).length;
  const requests = sourceIPs.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  const errors = sourceIPs.reduce((sum, item) => sum + Number(item.status_4xx || 0) + Number(item.status_5xx || 0), 0);
  const siteID = state.viewContext.site_id || state.siteID || "";
  const topActor = Array.from(actors)[0] || "";
  return {
    title: formatASN(entity.value) || entity.value,
    summary: [first.asn_org || first.network || "Network", `${formatNumber(sourceIPs.length)} IPs`, review ? `${formatNumber(review)} need review` : ""].filter(Boolean).join(" / "),
    description: "Network-level source concentration, actor labels, verification state, and affected sites.",
    facts: [
      ["Organization", first.asn_org || "-"],
      ["Network", first.network || "-"],
      ["Country", first.country_code || "-"],
      ["Source IPs", formatNumber(sourceIPs.length)],
      ["Actors", formatNumber(actors.size), Array.from(actors).slice(0, 3).join(", ")],
      ["Sites", formatNumber(sites.size)],
      ["Requests", formatNumber(requests)],
      ["Errors", formatNumber(errors)],
      ["Verified IPs", formatNumber(verified)],
      ["Need review", formatNumber(review)],
    ],
    actions: [
      `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", asn: formatASN(entity.value) || entity.value, site_id: siteID, log_type: "nginx-access", origin: "entity_identity" })}'>Access logs</button>`,
      errors ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", asn: formatASN(entity.value) || entity.value, site_id: siteID, status_class: "errors", log_type: "nginx-access", origin: "entity_identity" })}'>Error rows</button>` : "",
      first.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: first.ip, site_id: first.site_id || siteID, origin: "entity_identity" })}'>Highest risk IP</button>` : "",
      topActor ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: topActor, actor_type: first.actor_type || "", site_id: first.site_id || siteID, origin: "entity_identity" })}'>Top actor</button>` : "",
    ],
    notes: review ? [`${formatNumber(review)} source IPs need service/actor verification.`] : [],
  };
}

function entityActorIdentityModel(entity, context = {}) {
  const actor = aggregateActors().find((item) => item.label === entity.value) || {};
  const rows = actorSourceRows(entity.value, state.viewContext.actor_type || actor.type);
  const topSource = rows[0] || {};
  const siteID = state.viewContext.site_id || state.siteID || "";
  const errors = rows.reduce((sum, item) => sum + Number(item.status_4xx || 0) + Number(item.status_5xx || 0), 0);
  return {
    title: entity.value,
    summary: [formatCategory(actor.type || state.viewContext.actor_type || "actor"), actorVerificationState(actor), `${formatNumber(actor.ips || rows.length)} IPs`].join(" / "),
    description: "Known service, crawler, scanner, or manually labeled actor with source proof and verification state.",
    facts: [
      ["Type", formatCategory(actor.type || state.viewContext.actor_type || "-")],
      ["Verification", actorVerificationState(actor)],
      ["Requests", formatNumber(actor.requests || rows.reduce((sum, item) => sum + Number(item.requests || 0), 0))],
      ["Errors", formatNumber(actor.errors || errors)],
      ["Source IPs", formatNumber(actor.ips || rows.length)],
      ["Verified IPs", formatNumber(actor.verifiedIPs || rows.filter(actorSourceIsVerified).length)],
      ["Need review", formatNumber(actor.reviewIPs || rows.filter(actorSourceNeedsReview).length)],
      ["Top ASN", topSource.asn ? formatASN(topSource.asn) : "-", topSource.asn_org || topSource.network || ""],
      ["Top source", topSource.ip || "-", topSource.reverse_dns || ""],
      ["Last seen", formatTime(actor.lastSeen || topSource.last_seen)],
    ],
    actions: [
      `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", known_actor: entity.value, actor_type: actor.type || state.viewContext.actor_type || "", site_id: siteID, log_type: "nginx-access", origin: "entity_identity" })}'>Access logs</button>`,
      topSource.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: topSource.ip, site_id: topSource.site_id || siteID, origin: "entity_identity" })}'>Top IP</button>` : "",
      topSource.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(topSource.asn), site_id: topSource.site_id || siteID, origin: "entity_identity" })}'>Open ASN</button>` : "",
      errors ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", known_actor: entity.value, actor_type: actor.type || state.viewContext.actor_type || "", site_id: siteID, status_class: "errors", log_type: "nginx-access", origin: "entity_identity" })}'>Error rows</button>` : "",
    ],
    notes: actor.reviewIPs ? [`${formatNumber(actor.reviewIPs)} actor sources still need verification.`] : [],
  };
}

function entityPathIdentityModel(entity, context = {}) {
  const evidence = context.evidence || entityEvidence(entity);
  const paths = context.paths || entityPaths(entity);
  const sites = context.sites || entitySites(entity);
  const sourceIPs = new Set(evidence.map((item) => item.ip || item.client_ip).filter(Boolean));
  const topPath = paths[0] || {};
  const topEvidence = evidence[0] || {};
  const siteID = state.viewContext.site_id || state.siteID || topEvidence.site_id || "";
  const requests = paths.reduce((sum, item) => sum + Number(item.requests || 0), 0) || evidence.length;
  const errors = evidence.reduce((sum, item) => sum + Number(item.errors || 0) + Number(item.status_4xx || 0) + Number(item.status_5xx || 0), 0);
  return {
    title: entity.value,
    summary: [`${formatNumber(requests)} requests`, `${formatNumber(sourceIPs.size)} sources`, errors ? `${formatNumber(errors)} errors` : ""].filter(Boolean).join(" / "),
    description: "URL target footprint across sites, source IPs, user agents, and matching evidence.",
    facts: [
      ["Path", entity.value],
      ["Requests", formatNumber(requests)],
      ["Errors", formatNumber(errors)],
      ["Source IPs", formatNumber(sourceIPs.size)],
      ["Sites", formatNumber(sites.length)],
      ["Bytes sent", formatBytes(topPath.bytes_sent || 0)],
      ["p95 latency", topPath.p95_request_time_ms ? formatMs(topPath.p95_request_time_ms) : "-"],
      ["Top source", topEvidence.ip || "-", topEvidence.known_actor || actorLabelFromType(topEvidence.actor_type) || ""],
      ["Top site", topEvidence.site_id || siteID || "-"],
    ],
    actions: [
      `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", path: entity.value, site_id: siteID, log_type: "nginx-access", origin: "entity_identity" })}'>Access logs</button>`,
      errors ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", path: entity.value, site_id: siteID, status_class: "errors", log_type: "nginx-access", origin: "entity_identity" })}'>Error rows</button>` : "",
      topEvidence.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: topEvidence.ip, site_id: topEvidence.site_id || siteID, origin: "entity_identity" })}'>Top IP</button>` : "",
      topEvidence.user_agent ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "user-agent", value: topEvidence.user_agent, site_id: topEvidence.site_id || siteID, origin: "entity_identity" })}'>Top user-agent</button>` : "",
    ],
    notes: [],
  };
}

function entityUserAgentIdentityModel(entity, context = {}) {
  const evidence = context.evidence || entityEvidence(entity);
  const row = (state.data.analysis?.user_agents || []).find((item) => userAgentMatches(item.sample || item.family || "", entity.value)) || {};
  const ips = new Set(evidence.map((item) => item.ip).filter(Boolean));
  const sites = new Set(evidence.map((item) => item.site_id).filter(Boolean));
  const paths = context.paths || entityPaths(entity);
  const topEvidence = evidence[0] || {};
  const siteID = state.viewContext.site_id || state.siteID || topEvidence.site_id || "";
  const errors = Number(row.status_4xx || 0) + Number(row.status_5xx || 0) || evidence.reduce((sum, item) => sum + Number(item.errors || 0), 0);
  return {
    title: row.family || "User agent",
    summary: [formatCategory(row.actor_type || "unknown"), `${formatNumber(row.requests || evidence.length)} requests`, `${formatNumber(ips.size || row.unique_ips || 0)} IPs`].join(" / "),
    description: "User-agent family/sample footprint, affected paths, source IPs, and actor classification.",
    facts: [
      ["Family", row.family || "-"],
      ["Actor type", formatCategory(row.actor_type || "-")],
      ["Requests", formatNumber(row.requests || evidence.length)],
      ["Errors", formatNumber(errors)],
      ["Source IPs", formatNumber(row.unique_ips || ips.size)],
      ["Sites", formatNumber(sites.size)],
      ["Risk", row.risk_score || "-"],
      ["Sample", entity.value],
      ["Top path", paths[0]?.path || topEvidence.path || "-"],
      ["Top source", topEvidence.ip || "-"],
    ],
    actions: [
      `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", user_agent: entity.value, site_id: siteID, log_type: "nginx-access", origin: "entity_identity" })}'>Access logs</button>`,
      errors ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", user_agent: entity.value, site_id: siteID, status_class: "errors", log_type: "nginx-access", origin: "entity_identity" })}'>Error rows</button>` : "",
      paths[0]?.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: paths[0].path, site_id: paths[0].site_id || siteID, origin: "entity_identity" })}'>Top path</button>` : "",
      topEvidence.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: topEvidence.ip, site_id: topEvidence.site_id || siteID, origin: "entity_identity" })}'>Top IP</button>` : "",
    ],
    notes: [],
  };
}

function entityIdentityFacts(rows = []) {
  return rows.map(([label, value, meta]) => `
    <div>
      <dt>${escapeHTML(label)}</dt>
      <dd>${escapeHTML(value === undefined || value === null || value === "" ? "-" : value)}</dd>
      ${meta ? `<small>${escapeHTML(meta)}</small>` : ""}
    </div>
  `).join("");
}

function entityIPVerificationLabel({ local = {}, stored = {}, reverseDNS = "", forwardConfirmed = false, verifiedActor = false } = {}) {
  const manualAction = String(stored.manual_action || local.manual_action || "").toLowerCase();
  if (manualAction === "verified") return "operator verified";
  if (manualAction === "suspicious") return "operator suspicious";
  if (manualAction === "watch") return "operator watch";
  if (verifiedActor) return "verified actor";
  if (forwardConfirmed) return "forward-confirmed DNS";
  if (reverseDNS) return "reverse DNS only";
  return "unverified";
}

function entityRDAPContacts(entities = []) {
  if (!Array.isArray(entities) || !entities.length) return "";
  const preferred = entities.filter((entity) => {
    const roles = (entity.roles || []).map((role) => String(role).toLowerCase());
    return roles.some((role) => ["abuse", "admin", "technical", "registrant"].includes(role));
  });
  const shown = (preferred.length ? preferred : entities).map((entity) => {
    const roles = (entity.roles || []).join(", ");
    return [entity.name || entity.handle || "", roles ? `(${roles})` : ""].filter(Boolean).join(" ");
  }).filter(Boolean);
  return joinLimited(shown, 3);
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
      ["ASN", (detail.asn?.asn || stored.asn || local.asn) ? formatASN(detail.asn?.asn || stored.asn || local.asn) : "-"],
      ["Last seen", formatTime(traffic.last_seen || local.last_seen)],
    ];
  }
  if (entity.kind === "asn") {
    const ips = sourceIPsForASN(entity.value);
    const requests = ips.reduce((sum, item) => sum + Number(item.requests || 0), 0);
    const errors = ips.reduce((sum, item) => sum + Number(item.status_4xx || 0) + Number(item.status_5xx || 0), 0);
    const first = ips[0] || {};
    const sites = new Set(ips.map((item) => item.site_id).filter(Boolean));
    const actors = new Set(ips.map((item) => item.known_actor || actorLabelFromType(item.actor_type)).filter(Boolean));
    return [
      ["ASN", formatASN(entity.value) || entity.value],
      ["Organization", first.asn_org || "-"],
      ["Network", first.network || "-"],
      ["Country", first.country_code || "-"],
      ["Source IPs", formatNumber(ips.length)],
      ["Requests", formatNumber(requests)],
      ["Errors", formatNumber(errors)],
      ["Sites", formatNumber(sites.size)],
      ["Actors", formatNumber(actors.size)],
      ["Window", activeFilterLabel()],
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
  if (entity.kind === "user-agent") {
    const row = (state.data.analysis?.user_agents || []).find((item) => userAgentMatches(item.sample || item.family || "", entity.value)) || {};
    const evidence = entityEvidence(entity);
    const rowErrors = Number(row.status_4xx || 0) + Number(row.status_5xx || 0);
    const evidenceErrors = evidence.reduce((sum, item) => sum + Number(item.errors || 0), 0);
    const errors = row.requests ? rowErrors : evidenceErrors;
    const ips = new Set(evidence.map((item) => item.ip).filter(Boolean));
    const sites = new Set(evidence.map((item) => item.site_id).filter(Boolean));
    return [
      ["Family", row.family || "-"],
      ["Actor type", formatCategory(row.actor_type || "-")],
      ["Requests", formatNumber(row.requests || evidence.length)],
      ["Errors", formatNumber(errors)],
      ["Source IPs", formatNumber(row.unique_ips || ips.size)],
      ["Sites", formatNumber(sites.size)],
      ["Risk", row.risk_score || "-"],
      ["Current site", state.siteID || state.viewContext.site_id || "All sites"],
      ["Window", activeFilterLabel()],
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
    if (entity.kind === "asn") {
      const ips = new Set(sourceIPsForASN(entity.value).map((source) => source.ip).filter(Boolean));
      return item.ip && ips.has(item.ip);
    }
    if (entity.kind === "path") return item.path && pathMatches(item.path, entity.value);
    if (entity.kind === "actor") return item.actor === entity.value || item.summary?.includes(entity.value) || item.title?.includes(entity.value);
    if (entity.kind === "user-agent") return item.summary?.includes(entity.value) || item.title?.includes(entity.value);
    return false;
  });
}

function entityEvidence(entity) {
  const rows = filteredLogEvidence();
  if (entity.kind === "ip") return rows.filter((item) => item.ip === entity.value);
  if (entity.kind === "asn") {
    const normalized = normalizeASN(entity.value);
    const ips = new Set(sourceIPsForASN(entity.value).map((source) => source.ip).filter(Boolean));
    return rows.filter((item) => normalizeASN(item.asn) === normalized || (item.ip && ips.has(item.ip)));
  }
  if (entity.kind === "path") return rows.filter((item) => pathMatches(item.path, entity.value));
  if (entity.kind === "actor") {
    const ips = contextActorIPs({ known_actor: entity.value, actor_type: state.viewContext.actor_type || "" });
    return rows.filter((item) => item.known_actor === entity.value || (item.ip && ips.has(item.ip)));
  }
  if (entity.kind === "user-agent") return rows.filter((item) => userAgentMatches(item.user_agent || item.sample || "", entity.value));
  return rows;
}

function userAgentMatches(sample, value) {
  const needle = String(value || "").trim();
  const haystack = String(sample || "").trim();
  if (!needle || needle === "-") return false;
  if (needle === "(empty)") return haystack === "";
  if (!haystack) return false;
  return haystack.includes(needle) || needle.includes(haystack);
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

function entitySourceIPs(entity) {
  if (entity.kind === "asn") return sourceIPsForASN(entity.value);
  return [];
}

function entityCorrelationPack(entity, evidence = entityEvidence(entity), paths = entityPaths(entity)) {
  const context = {
    ...activeEntityContext(),
    site_id: state.viewContext.site_id || state.siteID || "",
    status_class: state.viewContext.status_class || "",
  };
  const rows = logCorrelationRows(evidence, paths, { context, origin: "entity_correlation" });
  return `<div class="correlation-pack">${rows.map(logCorrelationRow).join("")}</div>`;
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
    item.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(item.asn), site_id: siteID, origin: "entity_timeline" })}'>Open ASN</button>` : "",
    item.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path, site_id: siteID, origin: "entity_timeline" })}'>Open path</button>` : "",
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", path: item.path || "", ip: item.ip || "", asn: item.asn ? formatASN(item.asn) : "", site_id: siteID, status_class: statusClass, origin: "entity_timeline" })}'>Open logs</button>`,
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
  const value = item.sample || item.family || "(empty)";
  const siteID = state.siteID || state.viewContext.site_id || "";
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.family || "User agent")}</strong>
        <span>${escapeHTML(value)}</span>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "user-agent", value, site_id: siteID, origin: "entity" })}'>Open user-agent</button>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", user_agent: value, site_id: siteID, status_class: errors ? "errors" : "", origin: "entity" })}'>Open logs</button>
      </div>
      <div class="signal-numbers"><span>${formatNumber(errors)} errors</span><b>${formatNumber(item.requests || 0)}</b></div>
    </div>
  `;
}

function entitySourceIPRow(item) {
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  const siteID = item.site_id || state.siteID || state.viewContext.site_id || "";
  const actor = item.known_actor || actorLabelFromType(item.actor_type);
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.ip || "-")}</strong>
        <span>${escapeHTML([
          item.reverse_dns || "",
          actor || "",
          item.network || "",
          item.country_code || "",
          siteID || "",
          `${formatNumber(item.requests || 0)} requests`,
          errors ? `${formatNumber(errors)} errors` : "",
          item.manual_label || "",
        ].filter(Boolean).join(" - "))}</span>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: siteID, origin: "entity" })}'>Open IP</button>
        ${actor ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: actor, actor_type: item.actor_type || "", site_id: siteID, origin: "entity" })}'>Open actor</button>` : ""}
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", asn: formatASN(item.asn), ip: item.ip || "", site_id: siteID, status_class: errors ? "errors" : "", origin: "entity" })}'>Open logs</button>
        ${ipManualButtons(item.ip, item, siteID, "mini")}
      </div>
      <div class="signal-numbers"><span>risk</span><b>${escapeHTML(item.risk_score || 0)}</b></div>
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
  return actorVerificationBoard(rows, {
    actorLabel: entity.value,
    actorType: state.viewContext.actor_type || actor.type || "",
    siteID: state.viewContext.site_id || state.siteID || "",
    origin: "actor_verification",
  });
}

function actorVerificationBoard(rows = [], options = {}) {
  const sorted = actorVerificationRows(rows).slice(0, 16);
  if (!sorted.length) return "";
  const verified = sorted.filter(actorSourceIsVerified).length;
  const review = sorted.filter(actorSourceNeedsReview).length;
  const suspicious = sorted.filter((item) => ["suspicious", "watch"].includes(actorSourceStatus(item))).length;
  const actorCount = new Set(sorted.map((item) => item.known_actor || actorLabelFromType(item.actor_type)).filter(Boolean)).size;
  const summary = `
    <div class="verification-summary">
      ${statTile(["Verification", actorVerificationState({ verifiedIPs: verified, unverifiedIPs: sorted.length - verified, reviewIPs: review })])}
      ${statTile(["Verified IPs", formatNumber(verified)])}
      ${statTile(["Needs review", formatNumber(review)])}
      ${statTile(["Suspicious", formatNumber(suspicious)])}
      ${statTile(["Actor labels", formatNumber(actorCount)])}
    </div>
  `;
  return `
    <div class="actor-verification-board">
      ${summary}
      <div class="table-wrap actor-verification-wrap">
        <table class="actor-verification-table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Verification</th>
              <th>Proof</th>
              <th>Impact</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            ${sorted.map((item) => actorVerificationTableRow(item, options)).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function actorVerificationRows(rows = []) {
  return (rows || [])
    .filter((item) => item.ip && (actorSourceNeedsReview(item) || actorSourceIsVerified(item) || item.manual_action || item.known_actor || item.actor_type || Number(item.risk_score || 0) >= 40))
    .sort((a, b) => actorSourceStatusRank(b) - actorSourceStatusRank(a)
      || Number(b.risk_score || 0) - Number(a.risk_score || 0)
      || actorSourceErrors(b) - actorSourceErrors(a)
      || Number(b.requests || 0) - Number(a.requests || 0));
}

function actorVerificationTableRow(item, options = {}) {
  const status = actorSourceStatus(item);
  const siteID = item.site_id || options.siteID || state.siteID || state.viewContext.site_id || "";
  const actor = item.known_actor || actorLabelFromType(item.actor_type) || options.actorLabel || "";
  const errors = actorSourceErrors(item);
  const proof = actorSourceProofs(item);
  const actions = [
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: siteID, origin: options.origin || "actor_verification" })}'>Open IP</button>`,
    actor ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: actor, actor_type: item.actor_type || options.actorType || "", site_id: siteID, origin: options.origin || "actor_verification" })}'>Open actor</button>` : "",
    item.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(item.asn), site_id: siteID, origin: options.origin || "actor_verification" })}'>Open ASN</button>` : "",
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ip: item.ip, known_actor: item.known_actor || actor, actor_type: item.actor_type || options.actorType || "", site_id: siteID, status_class: errors ? "errors" : "", origin: options.origin || "actor_verification" })}'>Open logs</button>`,
    ipManualButtons(item.ip, item, siteID, "mini"),
  ].filter(Boolean).join("");
  const sourceMeta = [
    actor,
    item.actor_type ? formatCategory(item.actor_type) : "",
    item.asn ? formatASN(item.asn) : "",
    item.asn_org || item.network || "",
    siteID ? siteLabel(siteID) || siteID : "",
  ].filter(Boolean).join(" - ");
  return `
    <tr>
      <td class="clip"><strong>${escapeHTML(item.ip || "-")}</strong><br><span>${escapeHTML(sourceMeta || "source IP")}</span></td>
      <td><span class="severity severity-${escapeHTML(actorSourceStatusSeverity(status))}">${escapeHTML(formatManualAction(status))}</span><br><span>${escapeHTML(item.manual_label || actorVerificationDecision(status))}</span></td>
      <td class="clip">${proof.map((label) => `<span class="actor-proof">${escapeHTML(label)}</span>`).join("") || `<span class="actor-proof">No proof stored</span>`}</td>
      <td>${formatNumber(item.requests || 0)}<br><span>${escapeHTML([errors ? `${formatNumber(errors)} errors` : "", item.risk_score ? `risk ${formatNumber(item.risk_score)}` : "", item.last_seen ? `last ${formatTime(item.last_seen)}` : ""].filter(Boolean).join(" / ") || "no impact")}</span></td>
      <td class="row-actions">${actions}</td>
    </tr>
  `;
}

function actorSourceIsVerified(item = {}) {
  const manualAction = String(item.manual_action || "").toLowerCase();
  return manualAction === "verified" || Boolean(item.verified_source || item.verified_actor || item.forward_confirmed);
}

function actorSourceErrors(item = {}) {
  return Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
}

function actorSourceStatusRank(item = {}) {
  return {
    suspicious: 6,
    watch: 5,
    review: 4,
    unverified: 3,
    verified: 2,
    ignored: 1,
  }[actorSourceStatus(item)] || 0;
}

function actorSourceStatusSeverity(status) {
  if (status === "suspicious") return "critical";
  if (status === "watch" || status === "review") return "high";
  if (status === "unverified") return "medium";
  return "low";
}

function actorVerificationDecision(status) {
  return {
    suspicious: "Operator marked suspicious",
    watch: "Operator watch",
    review: "Verify source claim",
    unverified: "No verification proof",
    verified: "Verified source",
    ignored: "Operator ignored",
  }[status] || "Review source";
}

function actorSourceProofs(item = {}) {
  const proofs = [];
  const manualAction = String(item.manual_action || "").toLowerCase();
  if (manualAction) proofs.push(`manual ${formatManualAction(manualAction).toLowerCase()}`);
  if (actorSourceIsVerified(item)) proofs.push("verified source");
  if (item.known_actor) proofs.push(`claims ${item.known_actor}`);
  if (item.actor_type) proofs.push(formatCategory(item.actor_type));
  if (item.reverse_dns) proofs.push(`rdns ${shortLabel(item.reverse_dns, 56)}`);
  if (item.asn_org || item.network) proofs.push(shortLabel(item.asn_org || item.network, 56));
  if (item.is_tor_exit) proofs.push("Tor exit");
  if (actorSourceErrors(item)) proofs.push(`${formatNumber(actorSourceErrors(item))} errors`);
  if (Number(item.risk_score || 0) >= 50) proofs.push(`risk ${formatNumber(item.risk_score)}`);
  if (!actorSourceIsVerified(item) && (item.known_actor || item.actor_type)) proofs.push("verification needed");
  return Array.from(new Set(proofs.filter(Boolean))).slice(0, 6);
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
        ${item.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(item.asn), site_id: siteID, origin: "actor" })}'>Open ASN</button>` : ""}
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

function normalizeASN(value) {
  const text = String(value || "").trim().toUpperCase();
  if (!text) return "";
  const stripped = text.startsWith("AS") ? text.slice(2) : text;
  return stripped.replace(/[^0-9]/g, "");
}

function formatASN(value) {
  const normalized = normalizeASN(value);
  return normalized ? `AS${normalized}` : "";
}

function sourceIPContextMap() {
  const map = new Map();
  (state.data.analysis?.source_ips || []).forEach((item) => {
    if (item.ip) map.set(item.ip, item);
  });
  return map;
}

function sourceIPContextForIP(ip, map = sourceIPContextMap()) {
  return map.get(ip || "") || {};
}

function sourceIPsForASN(asn) {
  const normalized = normalizeASN(asn);
  if (!normalized) return [];
  return (state.data.analysis?.source_ips || [])
    .filter((item) => normalizeASN(item.asn) === normalized)
    .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0) || Number(b.requests || 0) - Number(a.requests || 0));
}

function aggregateASNs(rows = state.data.analysis?.source_ips || []) {
  const groups = new Map();
  rows.forEach((item) => {
    const normalized = normalizeASN(item.asn);
    if (!normalized) return;
    const label = formatASN(normalized);
    const existing = groups.get(normalized) || {
      asn: normalized,
      label,
      org: "",
      network: "",
      country: "",
      requests: 0,
      errors: 0,
      risk: 0,
      ips: new Set(),
      sites: new Set(),
      actors: new Set(),
      verifiedIPs: 0,
      reviewIPs: 0,
      lastSeen: "",
    };
    existing.requests += Number(item.requests || 0);
    existing.errors += Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    existing.risk = Math.max(existing.risk, Number(item.risk_score || 0));
    if (item.ip) existing.ips.add(item.ip);
    if (item.site_id) existing.sites.add(item.site_id);
    const actor = item.known_actor || actorLabelFromType(item.actor_type);
    if (actor) existing.actors.add(actor);
    if (!existing.org && item.asn_org) existing.org = item.asn_org;
    if (!existing.network && item.network) existing.network = item.network;
    if (!existing.country && item.country_code) existing.country = item.country_code;
    if (item.verified_source) existing.verifiedIPs += 1;
    if (actorSourceNeedsReview(item)) existing.reviewIPs += 1;
    if (!existing.lastSeen || new Date(item.last_seen || 0) > new Date(existing.lastSeen || 0)) existing.lastSeen = item.last_seen || "";
    groups.set(normalized, existing);
  });
  return Array.from(groups.values())
    .map((item) => ({
      ...item,
      ipCount: item.ips.size,
      siteCount: item.sites.size,
      actorCount: item.actors.size,
      actors: Array.from(item.actors),
    }))
    .sort((a, b) => Number(b.risk || 0) - Number(a.risk || 0) || Number(b.requests || 0) - Number(a.requests || 0) || a.label.localeCompare(b.label));
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
      item.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(item.asn), site_id: item.site_id, origin: "investigate" })}'>Open ASN</button>` : "",
      `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ip: item.ip, site_id: item.site_id, origin: "investigate" })}'>Logs</button>`,
      ipManualButtons(item.ip, item, item.site_id || state.siteID, "mini"),
    ].filter(Boolean).join("");
    const network = [item.asn ? formatASN(item.asn) : "", item.asn_org || item.network || ""].filter(Boolean).join(" / ");
    return `
      <tr>
        <td><strong>${escapeHTML(item.ip)}</strong><br><span>${escapeHTML([item.reverse_dns || "", network].filter(Boolean).join(" - "))}</span></td>
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

function renderASNs() {
  const items = aggregateASNs();
  setText("#asnSummary", `${formatNumber(items.length)} networks`);
  const container = qs("#asnsList");
  if (!container) return;
  container.innerHTML = items.slice(0, 12).map((item) => asnRow(item)).join("") || `<div class="empty">No ASN metadata has been collected yet.</div>`;
}

function asnRow(item, origin = "investigate") {
  const siteID = state.viewContext.site_id || state.siteID || (item.siteCount === 1 ? Array.from(item.sites || [])[0] : "");
  const actor = item.actors?.[0] || "";
  const review = item.reviewIPs ? `${formatNumber(item.reviewIPs)} review` : item.verifiedIPs ? `${formatNumber(item.verifiedIPs)} verified` : "unverified";
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.label || "-")}</strong>
        <span>${escapeHTML([
          item.org || item.network || "",
          item.country || "",
          `${formatNumber(item.ipCount || 0)} IPs`,
          `${formatNumber(item.siteCount || 0)} sites`,
          actor || "",
          review,
          `${formatNumber(item.errors || 0)} errors`,
        ].filter(Boolean).join(" - "))}</span>
        <div class="signal-actions">
          <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: item.label, site_id: siteID, origin })}'>Open ASN</button>
          <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", asn: item.label, site_id: siteID, status_class: item.errors ? "errors" : "", origin })}'>Open logs</button>
          ${actor ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: actor, site_id: siteID, origin })}'>Open actor</button>` : ""}
        </div>
      </div>
      <div class="signal-numbers">
        <span>risk</span>
        <b>${escapeHTML(item.risk || 0)}</b>
      </div>
    </div>
  `;
}

function renderUserAgents() {
  const items = state.data.analysis?.user_agents || [];
  renderPager("#userAgentPager", "userAgents", items);
  const rows = paginateWithIndex("userAgents", items).map(({ item, index }) => {
    const value = item.sample || item.family || "(empty)";
    const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    const actions = [
      `<button class="ghost mini inline-action" type="button" data-detail-kind="userAgent" data-detail-index="${index}">Details</button>`,
      `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "user-agent", value, site_id: item.site_id || state.siteID || "", origin: "investigate" })}'>Open user-agent</button>`,
      `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", user_agent: value, site_id: item.site_id || state.siteID || "", status_class: errors ? "errors" : "", origin: "investigate" })}'>Open logs</button>`,
      item.actor_type && item.actor_type !== "browser" && item.actor_type !== "unknown" ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: item.family || actorLabelFromType(item.actor_type), actor_type: item.actor_type || "", site_id: item.site_id || state.siteID || "", origin: "investigate" })}'>Open actor</button>` : "",
    ].filter(Boolean).join("");
    return `
      <tr>
        <td><strong>${escapeHTML(item.family || "unknown")}</strong><br><span>${escapeHTML(item.actor_type || "")}</span></td>
        <td class="clip">${escapeHTML(value)}</td>
        <td>${formatNumber(item.requests || 0)}</td>
        <td>${formatNumber(item.unique_ips || 0)}</td>
        <td>${formatNumber(errors)}</td>
        <td>${escapeHTML(item.risk_score || 0)}</td>
        <td class="row-actions">${actions}</td>
      </tr>
    `;
  });
  qs("#userAgentsTable").innerHTML = rows.join("") || emptyRow(7, "No user agents found.");
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
  const allSites = aggregateSiteRows();
  const sites = sortSiteRows(filterSiteRows(allSites));
  syncSiteQueueControls();
  renderSiteQueueSummary(allSites, sites);
  renderPager("#sitesPager", "sites", sites);
  const selectedID = currentSiteIDForView(sites, allSites);
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
  renderSiteDetail(allSites.find((site) => site.id === selectedID) || sites[0] || allSites[0] || null);
}

function syncSiteQueueControls() {
  const searchInput = qs("#siteSearchInput");
  const statusSelect = qs("#siteStatusFilter");
  const sortSelect = qs("#siteSortSelect");
  if (searchInput && searchInput.value !== state.siteSearch) searchInput.value = state.siteSearch || "";
  if (statusSelect) statusSelect.value = normalizeSiteStatusFilter(state.siteStatusFilter);
  if (sortSelect) sortSelect.value = normalizeSiteSort(state.siteSort);
}

function renderSiteQueueSummary(allSites, visibleSites) {
  const container = qs("#siteQueueSummary");
  if (!container) return;
  const counts = siteStatusCounts(allSites);
  const active = state.siteStatusFilter !== "all" || state.siteSearch || state.siteSort !== "risk";
  const chips = [
    ["Visible", `${formatNumber(visibleSites.length)} of ${formatNumber(allSites.length)}`],
    ["Degraded", formatNumber(counts.degraded || 0)],
    ["Elevated", formatNumber(counts.elevated || 0)],
    ["Watch", formatNumber(counts.watch || 0)],
    ["Stale", formatNumber(counts.stale || 0)],
    ["Healthy", formatNumber(counts.healthy || 0)],
  ];
  container.innerHTML = `
    <div class="site-queue-chips">
      ${chips.map(([label, value]) => `<span class="context-chip"><b>${escapeHTML(label)}</b>${escapeHTML(value)}</span>`).join("")}
    </div>
    ${active ? `<button class="ghost mini" type="button" data-site-queue-action="clear">Clear queue filters</button>` : ""}
  `;
}

function siteStatusCounts(sites) {
  return (sites || []).reduce((counts, site) => {
    const key = site.status || "unknown";
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
}

function filterSiteRows(sites) {
  const search = String(state.siteSearch || "").trim().toLowerCase();
  const status = normalizeSiteStatusFilter(state.siteStatusFilter);
  return (sites || []).filter((site) => {
    if (status !== "all" && site.status !== status) return false;
    if (!search) return true;
    return siteSearchText(site).includes(search);
  });
}

function siteSearchText(site) {
  return [
    site.name,
    site.id,
    site.pantheon_site_id,
    site.status,
    ...(site.envs || []),
    ...(site.tags || []),
  ].filter(Boolean).join(" ").toLowerCase();
}

function sortSiteRows(sites) {
  const sort = normalizeSiteSort(state.siteSort);
  const rows = [...(sites || [])];
  const byName = (a, b) => String(a.name || a.id).localeCompare(String(b.name || b.id));
  const byRisk = (a, b) => (b.statusRank - a.statusRank) || (b.signalCount - a.signalCount) || (b.requests - a.requests) || byName(a, b);
  const comparisons = {
    risk: byRisk,
    traffic: (a, b) => (b.requests - a.requests) || byRisk(a, b),
    "5xx": (a, b) => (b.status5xx - a.status5xx) || (b.status5xxRate - a.status5xxRate) || byRisk(a, b),
    signals: (a, b) => (b.signalCount - a.signalCount) || (b.securitySignals - a.securitySignals) || byRisk(a, b),
    freshness: (a, b) => new Date(b.lastSeen || 0) - new Date(a.lastSeen || 0) || byRisk(a, b),
    name: byName,
  };
  return rows.sort(comparisons[sort] || byRisk);
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

function currentSiteIDForView(sites, allSites = sites) {
  if (state.siteID) return state.siteID;
  return sites[0]?.id || allSites[0]?.id || "";
}

function renderSiteDetail(site) {
  if (!site) {
    state.siteDetailID = "";
    setText("#siteDetailName", "No sites configured");
    setText("#siteDetailMeta", "Add sites to start building a workspace.");
    setText("#siteTabSummary", "-");
    qs("#siteRiskStrip").innerHTML = "";
    qs("#siteScopeMatrix").innerHTML = "";
    qs("#siteCommandStrip").innerHTML = "";
    qs("#siteEvidenceBridge").innerHTML = "";
    qs("#siteTabBody").innerHTML = `<div class="empty">No enabled sites configured.</div>`;
    return;
  }
  state.siteDetailID = site.id || "";
  const focused = state.siteID === site.id;
  const signals = siteSignalItems(site.id);
  const topIP = siteTopSourceIPs(site.id)[0];
  const topPath = siteTopPaths(site.id)[0];
  const topActor = siteTopActor(site.id);
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
    ["Top actor", topActor?.label || "-"],
  ].map(statTile).join("");
  qs("#siteScopeMatrix").innerHTML = siteScopeMatrix(site, { topIP, topPath, topActor });
  qs("#siteCommandStrip").innerHTML = siteCommandStrip(site, { signals, topIP, topPath, topActor });
  qs("#siteEvidenceBridge").innerHTML = siteEvidenceBridge(site, { signals, topIP, topPath, topActor });
  qs("#siteFocusButton").textContent = focused ? "Focused" : "Focus site";
  qs("#siteFocusButton").disabled = focused;
  qsa("[data-site-tab]").forEach((button) => {
    const active = button.dataset.siteTab === state.siteTab;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  renderSiteTab(site);
}

function siteTopActor(siteID) {
  const groups = new Map();
  const add = (label, type, item = {}) => {
    if (!label) return;
    const key = `${type || "actor"}|${label}`;
    const existing = groups.get(key) || {
      label,
      type: type || "actor",
      requests: 0,
      errors: 0,
      risk: 0,
      ips: new Set(),
      verifiedIPs: 0,
      reviewIPs: 0,
      lastSeen: "",
    };
    existing.requests += Number(item.requests || 0);
    existing.errors += Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    existing.risk = Math.max(existing.risk, Number(item.risk_score || 0));
    if (item.ip) existing.ips.add(item.ip);
    if (item.verified_source) existing.verifiedIPs += 1;
    if (actorSourceNeedsReview(item)) existing.reviewIPs += 1;
    if (!existing.lastSeen || new Date(item.last_seen || 0) > new Date(existing.lastSeen || 0)) existing.lastSeen = item.last_seen || "";
    groups.set(key, existing);
  };
  siteScopedRows(state.data.analysis?.source_ips || [], siteID).forEach((item) => {
    add(item.known_actor || actorLabelFromType(item.actor_type), item.actor_type || "source", item);
  });
  siteScopedRows(state.data.analysis?.user_agents || [], siteID).forEach((item) => {
    if (!item.actor_type || item.actor_type === "browser" || item.actor_type === "unknown") return;
    add(item.family || actorLabelFromType(item.actor_type), item.actor_type, item);
  });
  return Array.from(groups.values())
    .map((item) => ({ ...item, ipCount: item.ips.size }))
    .sort((a, b) => Number(b.risk || 0) - Number(a.risk || 0) || Number(b.requests || 0) - Number(a.requests || 0))[0] || null;
}

function siteCommandStrip(site, { signals = [], topIP = null, topPath = null, topActor = null } = {}) {
  const siteID = site.id || "";
  const envs = (site.envs || []).filter(Boolean).slice(0, 3);
  const topSignal = signals[0];
  const report = siteReports(siteID)[0];
  const errors = Number(site.status4xx || 0) + Number(site.status5xx || 0);
  const rows = [
    topSignal ? {
      title: "First signal",
      meta: [
        formatCategory(topSignal.group || "signal"),
        topSignal.ip ? `IP ${topSignal.ip}` : "",
        topSignal.path || "",
        topSignal.lastSeen ? formatTime(topSignal.lastSeen) : "",
      ].filter(Boolean).join(" - "),
      valueLabel: "risk",
      value: topSignal.risk || severityRank(topSignal.severity) * 20 || 0,
      actions: [
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: topSignal.key, site_id: siteID, origin: "site_header" })}'>Open signal</button>`,
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(signalLogPivot(topSignal, "site_header"))}'>Signal logs</button>`,
      ].join(""),
    } : {
      title: "No active signal",
      meta: "Open the site logs or reports for routine review.",
      valueLabel: "status",
      value: site.status || "healthy",
      actions: `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, origin: "site_header" })}'>Open logs</button>`,
    },
    {
      title: "Attack surface",
      meta: [
        topActor?.label || "No actor classified",
        topIP?.ip ? `top IP ${topIP.ip}` : "",
        topActor?.reviewIPs ? `${formatNumber(topActor.reviewIPs)} review` : "",
      ].filter(Boolean).join(" - "),
      valueLabel: topActor ? "risk" : "actors",
      value: topActor ? topActor.risk || 0 : 0,
      actions: [
        topActor ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: topActor.label, actor_type: topActor.type || "", site_id: siteID, origin: "site_header" })}'>Open actor</button>` : "",
        topIP?.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: topIP.ip, site_id: siteID, origin: "site_header" })}'>Open IP</button>` : "",
        topIP?.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(topIP.asn), site_id: siteID, origin: "site_header" })}'>Open ASN</button>` : "",
      ].filter(Boolean).join(""),
    },
    {
      title: "Evidence filters",
      meta: [
        `${formatNumber(site.requests || 0)} requests`,
        errors ? `${formatNumber(errors)} errors` : "",
        topPath?.path || "",
      ].filter(Boolean).join(" - "),
      valueLabel: "paths",
      value: formatNumber(siteTopPaths(siteID).length),
      actions: [
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, log_type: "nginx-access", status_class: errors ? "errors" : "", origin: "site_header" })}'>Access logs</button>`,
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, log_type: "nginx-error", status_class: errors ? "errors" : "", origin: "site_header" })}'>Nginx errors</button>`,
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, log_type: "php-error", status_class: errors ? "errors" : "", origin: "site_header" })}'>PHP errors</button>`,
        ...envs.map((env) => `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, env, log_type: "nginx-access", status_class: errors ? "errors" : "", origin: "site_header" })}'>${escapeHTML(env)}</button>`),
        topPath?.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: topPath.path || "/", site_id: siteID, origin: "site_header" })}'>Top path</button>` : "",
      ].filter(Boolean).join(""),
    },
    {
      title: "Time and report",
      meta: report ? [reportListLabel(report), reportWindowLabel(report)].filter(Boolean).join(" - ") : activeFilterLabel(),
      valueLabel: report?.model || "range",
      value: report ? formatNumber(report.summary?.requests || 0) : state.range || "24h",
      actions: [
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, range: "24h", origin: "site_header" })}'>24h</button>`,
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, range: "7d", origin: "site_header" })}'>7d</button>`,
        report ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: siteID, origin: "site_header" }))}'>Open report</button>` : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "site_header" })}'>Reports</button>`,
      ].join(""),
    },
  ];
  return `
    <section class="site-command-board" aria-label="Site quick investigation commands">
      ${rows.map(siteCommandRow).join("")}
    </section>
  `;
}

function siteScopeMatrix(site, { topIP = null, topPath = null, topActor = null } = {}) {
  const siteID = site.id || "";
  const envs = (site.envs || []).filter(Boolean).slice(0, 5);
  const errors = Number(site.status4xx || 0) + Number(site.status5xx || 0);
  const report = siteReports(siteID)[0];
  const envActions = [
    siteScopeButton("All envs", { kind: "log_filter", site_id: siteID, log_type: "nginx-access", origin: "site_scope" }),
    ...envs.map((env) => siteScopeButton(env, { kind: "log_filter", site_id: siteID, env, log_type: "nginx-access", origin: "site_scope" })),
  ].join("");
  const laneActions = correlatedLogTypeDefs(true)
    .map(([logType, label]) => siteScopeButton(label, {
      kind: "log_filter",
      site_id: siteID,
      log_type: logType,
      status_class: errors ? "errors" : "",
      origin: "site_scope",
    }))
    .join("");
  const timeActions = [
    siteScopeButton("24h", { kind: "log_filter", site_id: siteID, range: "24h", origin: "site_scope" }),
    siteScopeButton("7d", { kind: "log_filter", site_id: siteID, range: "7d", origin: "site_scope" }),
    siteScopeButton("30d", { kind: "log_filter", site_id: siteID, range: "30d", origin: "site_scope" }),
    report
      ? siteScopeButton("Report", reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: siteID, origin: "site_scope" }))
      : siteScopeButton("Reports", { kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "site_scope" }),
  ].join("");
  const contextActions = [
    topPath?.path ? siteScopeButton("Top path", { kind: "path", value: topPath.path || "/", site_id: siteID, origin: "site_scope" }) : "",
    topIP?.ip ? siteScopeButton("Top IP", { kind: "ip", value: topIP.ip, site_id: siteID, origin: "site_scope" }) : "",
    topActor?.label ? siteScopeButton("Top actor", { kind: "actor", value: topActor.label, actor_type: topActor.type || "", site_id: siteID, origin: "site_scope" }) : "",
    siteScopeButton("Site logs", { kind: "log_filter", site_id: siteID, status_class: errors ? "errors" : "", origin: "site_scope" }),
  ].filter(Boolean).join("");
  return `
    <section class="site-scope-board" aria-label="Site quick scope controls">
      ${siteScopeGroup("Environment", envs.length ? `${formatNumber(envs.length)} envs` : "site scope", envActions)}
      ${siteScopeGroup("Log lanes", errors ? `${formatNumber(errors)} errors` : "all requests", laneActions)}
      ${siteScopeGroup("Time", activeFilterLabel(), timeActions)}
      ${siteScopeGroup("Top context", siteScopeContextMeta(topIP, topPath, topActor), contextActions)}
    </section>
  `;
}

function siteScopeGroup(title, meta, actions) {
  return `
    <div class="site-scope-group">
      <div>
        <strong>${escapeHTML(title)}</strong>
        <span>${escapeHTML(meta || "")}</span>
      </div>
      <div class="site-scope-actions">${actions || ""}</div>
    </div>
  `;
}

function siteScopeButton(label, pivot) {
  return `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(pivot)}'>${escapeHTML(label)}</button>`;
}

function siteScopeContextMeta(topIP, topPath, topActor) {
  return [
    topPath?.path || "",
    topIP?.ip ? `IP ${topIP.ip}` : "",
    topActor?.label || "",
  ].filter(Boolean).join(" / ") || "no dominant entity";
}

function siteEvidenceBridge(site, { signals = siteSignalItems(site.id || ""), topIP = null, topPath = null, topActor = null } = {}) {
  const siteID = site.id || "";
  const reports = siteSortedReports(siteReports(siteID));
  const report = reports[0] || null;
  const evidence = siteLogEvidence(siteID);
  const recentErrors = siteRecentErrors(siteID);
  const securitySignals = signals.filter((item) => item.group === "security");
  const reliabilitySignals = signals.filter((item) => item.group === "reliability");
  const securityLead = securitySignals[0] || null;
  const reliabilityLead = reliabilitySignals[0] || null;
  const paths = siteTopPaths(siteID);
  const sourceIPs = siteTopSourceIPs(siteID);
  const segmentCount = correlatedLogTypeDefs(false)
    .reduce((sum, [logType]) => sum + siteLogSegments(logType, siteID).length, 0);
  const errors = Number(site.status4xx || 0) + Number(site.status5xx || 0);
  const actorLabel = topActor?.label || topActor?.known_actor || actorLabelFromType(topActor?.actor_type) || topIP?.known_actor || "";
  const actorType = topActor?.type || topActor?.actor_type || topIP?.actor_type || "";
  const rows = [
    {
      label: "Security",
      title: securityLead?.title || `${formatNumber(securitySignals.length)} security signals`,
      meta: securityLead ? siteInvestigationSignalMeta(securityLead) : `${formatNumber(securitySignals.length)} active signals / ${formatNumber(sourceIPs.filter((item) => item.is_tor_exit).length)} Tor sources`,
      valueLabel: securityLead ? "risk" : "signals",
      value: securityLead ? securityLead.risk || severityRank(securityLead.severity) * 20 || 0 : formatNumber(securitySignals.length),
      actions: [
        siteTabButton("Security", "security"),
        securityLead ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: securityLead.key, site_id: siteID, origin: "site_bridge" })}'>Open signal</button>` : "",
        securityLead?.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: securityLead.ip, site_id: siteID, origin: "site_bridge" })}'>Source IP</button>` : "",
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, evidence_kind: securityLead?.kind || "", status_class: securityLead?.errors ? "errors" : "", origin: "site_bridge" })}'>Security logs</button>`,
      ].filter(Boolean).join(""),
    },
    {
      label: "Reliability",
      title: reliabilityLead?.title || (recentErrors[0] ? `${recentErrors[0].status || "-"} ${recentErrors[0].path || "/"}` : `${formatNumber(recentErrors.length)} recent errors`),
      meta: reliabilityLead ? siteInvestigationSignalMeta(reliabilityLead) : `${formatNumber(errors)} 4xx/5xx / ${formatNumber(paths.filter((item) => Number(item.status_5xx || 0) > 0).length)} 5xx paths`,
      valueLabel: reliabilityLead ? "risk" : "errors",
      value: reliabilityLead ? reliabilityLead.risk || severityRank(reliabilityLead.severity) * 20 || 0 : formatNumber(errors),
      actions: [
        siteTabButton("Reliability", "reliability"),
        reliabilityLead ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: reliabilityLead.key, site_id: siteID, origin: "site_bridge" })}'>Open signal</button>` : "",
        topPath?.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: topPath.path, site_id: siteID, origin: "site_bridge" })}'>Top path</button>` : "",
        correlatedLogActions({ path: reliabilityLead?.path || topPath?.path || "", siteID, ip: reliabilityLead?.ip || recentErrors[0]?.client_ip || "", statusClass: errors ? "errors" : "", origin: "site_bridge" }),
      ].filter(Boolean).join(""),
    },
    {
      label: "Actors",
      title: actorLabel || topIP?.ip || `${formatNumber(sourceIPs.length)} sources`,
      meta: [
        topActor ? actorSourceStatus(topActor) : topIP ? actorSourceStatus(topIP) : "",
        topIP?.ip ? `IP ${topIP.ip}` : "",
        topIP?.asn ? formatASN(topIP.asn) : "",
        sourceIPs.filter(actorSourceNeedsReview).length ? `${formatNumber(sourceIPs.filter(actorSourceNeedsReview).length)} need review` : "",
      ].filter(Boolean).join(" / ") || "No classified actor pressure for this site.",
      valueLabel: topActor || topIP ? "requests" : "sources",
      value: topActor || topIP ? formatNumber((topActor || topIP).requests || 0) : formatNumber(sourceIPs.length),
      actions: [
        siteTabButton("Actors", "actors"),
        topIP?.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: topIP.ip, site_id: siteID, origin: "site_bridge" })}'>Top IP</button>` : "",
        actorLabel ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: actorLabel, actor_type: actorType, site_id: siteID, origin: "site_bridge" })}'>Actor</button>` : "",
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, ip: topIP?.ip || "", known_actor: actorLabel, actor_type: actorType, status_class: topIP && Number(topIP.status_4xx || 0) + Number(topIP.status_5xx || 0) ? "errors" : "", origin: "site_bridge" })}'>Actor logs</button>`,
      ].filter(Boolean).join(""),
    },
    {
      label: "Logs",
      title: `${formatNumber(evidence.length)} rows / ${formatNumber(segmentCount)} segments`,
      meta: [
        topPath?.path || "",
        topIP?.ip ? `IP ${topIP.ip}` : "",
        errors ? `${formatNumber(errors)} errors` : "",
      ].filter(Boolean).join(" / ") || "Access rows and segment lanes for this site.",
      valueLabel: "paths",
      value: formatNumber(paths.length),
      actions: [
        siteTabButton("Logs", "logs"),
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, log_type: "nginx-access", origin: "site_bridge" })}'>Access</button>`,
        `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, status_class: errors ? "errors" : "", origin: "site_bridge" })}'>All lanes</button>`,
        topPath?.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: topPath.path, site_id: siteID, origin: "site_bridge" })}'>Path detail</button>` : "",
      ].filter(Boolean).join(""),
    },
    {
      label: "Reports",
      title: report ? reportListLabel(report) : `${formatNumber(reports.length)} reports`,
      meta: report ? reportWindowLabel(report) : "No generated reports scoped to this site yet.",
      valueLabel: report?.model || "reports",
      value: report ? formatNumber(report.summary?.requests || 0) : formatNumber(reports.length),
      actions: [
        siteTabButton("Reports", "reports"),
        report ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: siteID, origin: "site_bridge" }))}'>Open report</button>` : "",
        report ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "log_filter", site_id: siteID, status_class: errors ? "errors" : "", origin: "site_bridge" }))}'>Period logs</button>` : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "site_bridge" })}'>Report list</button>`,
      ].filter(Boolean).join(""),
    },
  ];
  return `
    <section class="site-evidence-board" aria-label="Site evidence bridge">
      ${rows.map(siteEvidenceBridgeRow).join("")}
    </section>
  `;
}

function siteEvidenceBridgeRow(item) {
  return `
    <div class="site-evidence-step">
      <div>
        <span>${escapeHTML(item.label || "")}</span>
        <strong>${escapeHTML(item.title || "-")}</strong>
        <small>${escapeHTML(item.meta || "")}</small>
      </div>
      <div class="signal-actions">${item.actions || ""}</div>
      <div class="site-evidence-value">
        <span>${escapeHTML(item.valueLabel || "")}</span>
        <b>${escapeHTML(item.value ?? "")}</b>
      </div>
    </div>
  `;
}

function siteCommandRow(item) {
  return `
    <div class="signal-row site-command-row">
      <div>
        <strong>${escapeHTML(item.title || "-")}</strong>
        <span>${escapeHTML(item.meta || "")}</span>
        <div class="signal-actions">${item.actions || ""}</div>
      </div>
      <div class="signal-numbers">
        <span>${escapeHTML(item.valueLabel || "")}</span>
        <b>${escapeHTML(item.value ?? "")}</b>
      </div>
    </div>
  `;
}

function siteInvestigationMap(site, { signals = [], recentErrors = [], topPaths = [], actors = [] } = {}) {
  const siteID = site.id || "";
  const securityLead = signals.find((item) => item.group === "security");
  const reliabilityLead = signals.find((item) => item.group === "reliability");
  const topError = recentErrors[0] || null;
  const topPath = topPaths[0] || siteTopPaths(siteID)[0] || null;
  const topActor = actors[0] || siteActorsToVerify(siteID)[0] || siteTopSourceIPs(siteID)[0] || null;
  const report = siteReports(siteID)[0] || null;
  const evidenceCount = siteLogEvidence(siteID).length;
  const rows = [
    siteInvestigationSecurity(site, securityLead),
    siteInvestigationReliability(site, reliabilityLead, topError, topPath),
    siteInvestigationActor(site, topActor),
    siteInvestigationEvidence(site, report, evidenceCount),
  ];
  return `
    <div class="site-investigation-map">
      ${rows.map(siteInvestigationNode).join("")}
    </div>
  `;
}

function siteInvestigationSecurity(site, signal) {
  const siteID = site.id || "";
  const actions = [
    siteTabButton("Security tab", "security"),
    signal ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: signal.key, site_id: siteID, origin: "site_map" })}'>Open signal</button>` : "",
    signal?.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: signal.ip, site_id: siteID, origin: "site_map" })}'>Open IP</button>` : "",
    signal?.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: signal.path, site_id: siteID, origin: "site_map" })}'>Open path</button>` : "",
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(signal ? signalLogPivot(signal, "site_map") : { kind: "log_filter", site_id: siteID, evidence_kind: "Admin probe", origin: "site_map" })}'>Security logs</button>`,
  ].filter(Boolean).join("");
  return {
    title: signal?.title || "No active security lead",
    meta: signal ? signal.summary || siteInvestigationSignalMeta(signal) : "Review admin, injection, Tor, and datacenter activity for this site.",
    valueLabel: signal ? "risk" : "state",
    value: signal ? signal.risk || severityRank(signal.severity) * 20 || 0 : site.status || "healthy",
    actions,
  };
}

function siteInvestigationReliability(site, signal, topError, topPath) {
  const siteID = site.id || "";
  const path = signal?.path || topError?.path || topPath?.path || "";
  const ip = signal?.ip || topError?.client_ip || "";
  const errors = Number(site.status4xx || 0) + Number(site.status5xx || 0);
  const actions = [
    siteTabButton("Reliability tab", "reliability"),
    signal ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: signal.key, site_id: siteID, origin: "site_map" })}'>Open signal</button>` : "",
    path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: path, site_id: siteID, origin: "site_map" })}'>Open path</button>` : "",
    correlatedLogActions({ path, siteID, ip, statusClass: errors ? "errors" : "", origin: "site_map" }),
  ].filter(Boolean).join("");
  return {
    title: signal?.title || (topError ? `${topError.status || "-"} on ${topError.path || "/"}` : topPath?.path || "No active reliability lead"),
    meta: signal ? signal.summary || siteInvestigationSignalMeta(signal) : siteInvestigationReliabilityMeta(site, topError, topPath),
    valueLabel: signal ? "risk" : "errors",
    value: signal ? signal.risk || severityRank(signal.severity) * 20 || 0 : formatNumber(errors),
    actions,
  };
}

function siteInvestigationActor(site, actor) {
  const siteID = site.id || "";
  const actorLabel = actor?.label || actor?.known_actor || actorLabelFromType(actor?.actor_type) || actor?.ip || "";
  const errors = Number(actor?.status_4xx || 0) + Number(actor?.status_5xx || 0) + Number(actor?.errors || 0);
  const actions = [
    siteTabButton("Actors tab", "actors"),
    actor?.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: actor.ip, site_id: siteID, origin: "site_map" })}'>Open IP</button>` : "",
    actor?.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(actor.asn), site_id: siteID, origin: "site_map" })}'>Open ASN</button>` : "",
    actorLabel ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: actorLabel, actor_type: actor?.type || actor?.actor_type || "", site_id: siteID, origin: "site_map" })}'>Open actor</button>` : "",
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ip: actor?.ip || "", known_actor: actor?.known_actor || "", actor_type: actor?.type || actor?.actor_type || "", site_id: siteID, status_class: errors ? "errors" : "", origin: "site_map" })}'>Actor logs</button>`,
  ].filter(Boolean).join("");
  return {
    title: actorLabel || "No notable actor",
    meta: actor ? [
      actorSourceStatus(actor),
      actor.reverse_dns || "",
      actor.asn ? formatASN(actor.asn) : "",
      actor.asn_org || actor.network || "",
      `${formatNumber(actor.requests || 0)} requests`,
      errors ? `${formatNumber(errors)} errors` : "",
    ].filter(Boolean).join(" - ") : "Actor classifications are quiet for this site.",
    valueLabel: actor ? "risk" : "actors",
    value: actor ? actor.risk || actor.risk_score || 0 : 0,
    actions,
  };
}

function siteInvestigationEvidence(site, report, evidenceCount) {
  const siteID = site.id || "";
  const actions = [
    siteTabButton("Logs tab", "logs"),
    siteTabButton("Reports tab", "reports"),
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, origin: "site_map" })}'>Open logs</button>`,
    report ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: siteID, origin: "site_map" }))}'>Open report</button>` : `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "site_map" })}'>Report list</button>`,
  ].join("");
  return {
    title: report ? reportListLabel(report) : "Evidence pack",
    meta: report ? reportWindowLabel(report) : "Use matching rows and generated reports as supporting evidence.",
    valueLabel: report?.model || "rows",
    value: report ? formatNumber(report.summary?.requests || 0) : formatNumber(evidenceCount),
    actions,
  };
}

function siteInvestigationSignalMeta(signal) {
  return [
    formatCategory(signal.group || "signal"),
    signal.siteID || "",
    signal.ip ? `IP ${signal.ip}` : "",
    signal.path || "",
    signal.requests ? `${formatNumber(signal.requests)} requests` : "",
    signal.errors ? `${formatNumber(signal.errors)} errors` : "",
    signal.lastSeen ? formatTime(signal.lastSeen) : "",
  ].filter(Boolean).join(" - ");
}

function siteInvestigationReliabilityMeta(site, topError, topPath) {
  if (topError) {
    return [
      topError.client_ip ? `IP ${topError.client_ip}` : "",
      topError.method || "",
      topError.path || "",
      topError.ts ? formatTime(topError.ts) : "",
    ].filter(Boolean).join(" - ");
  }
  if (topPath) {
    const errors = Number(topPath.status_4xx || 0) + Number(topPath.status_5xx || 0);
    return [
      `${formatNumber(topPath.requests || 0)} requests`,
      `${formatNumber(errors)} errors`,
      `p95 ${formatMs(topPath.p95_request_time_ms || 0)}`,
    ].join(" - ");
  }
  return `${formatPercent(site.status5xxRate || 0)} 5xx / ${formatPercent(site.status4xxRate || 0)} 4xx in this scope.`;
}

function siteTabButton(label, tab) {
  return `<button class="ghost mini inline-action" type="button" data-site-tab-target="${escapeHTML(normalizeSiteTab(tab))}">${escapeHTML(label)}</button>`;
}

function siteInvestigationNode(item) {
  return `
    <div class="signal-row site-investigation-node">
      <div>
        <strong>${escapeHTML(item.title || "-")}</strong>
        <span>${escapeHTML(item.meta || "")}</span>
        <div class="signal-actions">${item.actions || ""}</div>
      </div>
      <div class="signal-numbers">
        <span>${escapeHTML(item.valueLabel || "")}</span>
        <b>${escapeHTML(item.value ?? "")}</b>
      </div>
    </div>
  `;
}

function renderSiteTab(site) {
  const id = site.id;
  const signals = siteSignalItems(id);
  const recentErrors = siteRecentErrors(id);
  const title = formatCategory(state.siteTab || "overview");
  setText("#siteTabTitle", `${title} / ${site.name || site.id}`);
  const body = qs("#siteTabBody");
  if (state.siteTab === "security") {
    const injection = siteScopedRows(state.data.analysis?.injection_probes || [], id)
      .map((item) => ({ ...item, kind: "Injection probe" }))
      .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
    const admin = siteScopedRows(state.data.analysis?.admin_probes || [], id)
      .map((item) => ({ ...item, kind: "Admin probe" }))
      .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
    const tor = siteScopedRows(state.data.analysis?.tor_sources || [], id)
      .map((item) => ({ ...item, kind: "Tor source" }))
      .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
    const probes = [...injection, ...admin, ...tor].sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
    const securityTimeline = siteActivityEvents(id).filter((event) => event.group === "security").slice(0, 12);
    setText("#siteTabSummary", `${formatNumber(Math.min(30, probes.length))} of ${formatNumber(probes.length)} shown`);
    body.innerHTML = `
      <section class="site-tab-grid">
        ${siteSubsection("Probe pressure", siteTrendPanel(site, "security"), "No timestamped probe evidence in this scope.", "span-2")}
        ${siteSubsection("Security timeline", entityTimeline(securityTimeline), "No timestamped security events in this scope.", "span-2")}
        ${siteSubsection("Injection probes", siteRowsMarkup(injection.slice(0, 12), siteSecurityRow, "No injection probes for this site."))}
        ${siteSubsection("Admin/login probes", siteRowsMarkup(admin.slice(0, 12), siteSecurityRow, "No admin probes for this site."))}
        ${siteSubsection("Tor/datacenter sources", siteRowsMarkup(tor.slice(0, 12), siteSecurityRow, "No Tor source rows for this site."), "", "span-2")}
      </section>
    `;
    return;
  }
  if (state.siteTab === "reliability") {
    const slowPaths = siteScopedRows(state.data.analysis?.slow_paths || [], id)
      .map((item) => ({ ...item, kind: "Slow path" }))
      .sort((a, b) => Number(b.p95_request_time_ms || 0) - Number(a.p95_request_time_ms || 0));
    const failingPaths = siteTopPaths(id)
      .filter((item) => Number(item.status_5xx || 0) > 0)
      .sort((a, b) => Number(b.status_5xx || 0) - Number(a.status_5xx || 0));
    const reliabilityTimeline = siteActivityEvents(id).filter((event) => event.group === "reliability").slice(0, 12);
    const totalFindings = recentErrors.length + slowPaths.length + failingPaths.length;
    setText("#siteTabSummary", `${formatNumber(totalFindings)} reliability findings`);
    body.innerHTML = `
      <section class="site-tab-grid">
        ${siteSubsection("Error and latency trend", siteTrendPanel(site, "reliability"), "No timestamped reliability evidence in this scope.", "span-2")}
        ${siteSubsection("Reliability timeline", entityTimeline(reliabilityTimeline), "No timestamped reliability events in this scope.", "span-2")}
        ${siteSubsection("Cross-log reliability matrix", siteReliabilityMatrix(site, { slowPaths, failingPaths, recentErrors }), "No failing paths, slow paths, or recent errors for this site.", "span-2")}
        ${siteSubsection("Top failing paths", siteRowsMarkup(failingPaths.slice(0, 12), sitePathRow, "No 5xx path concentration for this site."))}
        ${siteSubsection("Top slow paths", siteRowsMarkup(slowPaths.slice(0, 12), siteReliabilityRow, "No slow paths for this site."))}
        ${siteSubsection("Recent errors", siteRowsMarkup(recentErrors.slice(0, 16).map((item) => ({ ...item, kind: "Recent error" })), siteReliabilityRow, "No recent errors for this site."), "", "span-2")}
      </section>
    `;
    return;
  }
  if (state.siteTab === "actors") {
    const sourceIPs = siteTopSourceIPs(id).map((item) => ({ ...item, kind: "Source IP" }));
    const asns = aggregateASNs(siteScopedRows(state.data.analysis?.source_ips || [], id));
    const userAgents = siteTopUserAgents(id).map((item) => ({ ...item, kind: "User agent" }));
    const verificationRows = siteActorVerificationRows(id);
    const rows = [...sourceIPs, ...asns, ...userAgents];
    setText("#siteTabSummary", `${formatNumber(Math.min(30, rows.length))} of ${formatNumber(rows.length)} shown`);
    body.innerHTML = `
      <section class="site-tab-grid">
        ${siteSubsection("Actor pressure", siteActorMixPanel(site), "No actor telemetry for this site.", "span-2")}
        ${siteSubsection("Service verification queue", actorVerificationBoard(verificationRows, { siteID: id, origin: "site_actor_verification" }), "No service or crawler sources need verification for this site.", "span-2")}
        ${siteSubsection("Source IPs", siteRowsMarkup(sourceIPs.slice(0, 15), siteActorRow, "No source IP rows for this site."))}
        ${siteSubsection("ASNs and networks", siteRowsMarkup(asns.slice(0, 12), (item) => asnRow(item, "site"), "No ASN rows for this site."))}
        ${siteSubsection("User agents", siteRowsMarkup(userAgents.slice(0, 15), siteActorRow, "No user-agent rows for this site."))}
      </section>
    `;
    return;
  }
  if (state.siteTab === "paths") {
    const rows = sitePathInvestigationRows(id);
    const failing = rows.filter((item) => item.errors > 0 || item.status5xx > 0);
    const slow = rows.filter((item) => item.p95 > 0);
    setText("#siteTabSummary", `${formatNumber(rows.length)} paths / ${formatNumber(failing.length)} failing / ${formatNumber(slow.length)} slow`);
    body.innerHTML = sitePathsWorkspace(site, rows);
    return;
  }
  if (state.siteTab === "logs") {
    setText("#siteTabSummary", siteLogsSummary(id));
    body.innerHTML = siteLogsWorkspace(site);
    return;
  }
  if (state.siteTab === "reports") {
    const rows = siteReports(id);
    const selected = siteSelectedReport(rows);
    setText("#siteTabSummary", selected ? `${formatNumber(rows.length)} reports / ${reportListLabel(selected)}` : "no reports");
    body.innerHTML = siteReportsWorkspace(site, rows, selected);
    return;
  }
  const timeline = siteActivityEvents(id).slice(0, 14);
  const topPaths = siteTopPaths(id).slice(0, 8);
  const actors = siteActorsToVerify(id).slice(0, 8);
  setText("#siteTabSummary", `${formatNumber(signals.length)} signals / ${formatNumber(timeline.length)} timeline events`);
  body.innerHTML = `
    <section class="site-tab-grid site-overview-grid">
      ${siteSubsection("Site health trend", siteTrendPanel(site, "overview"), "No timestamped site evidence in this scope.", "span-2")}
      ${siteSubsection("Investigation map", siteInvestigationMap(site, { signals, recentErrors, topPaths, actors }), "", "span-2 site-map-section")}
      ${siteSubsection("Activity timeline", entityTimeline(timeline), "No timestamped site activity in this scope.", "span-2")}
      ${siteSubsection("Priority signals", `<div class="signal-stack">${signals.slice(0, 8).map(signalRow).join("") || `<div class="empty">No active signals for this site.</div>`}</div>`)}
      ${siteSubsection("Recent errors", siteRowsMarkup(recentErrors.slice(0, 10).map((item) => ({ ...item, kind: "Recent error" })), siteReliabilityRow, "No recent errors for this site."))}
      ${siteSubsection("Hot paths", siteRowsMarkup(topPaths, sitePathRow, "No path data for this site in scope."))}
      ${siteSubsection("Actors to verify", siteRowsMarkup(actors, siteActorRow, "No unverified or notable actors in this scope."))}
    </section>
  `;
}

function siteRowsMarkup(rows, renderer, emptyMessage) {
  return `<div class="signal-list">${rows.map(renderer).join("") || `<div class="empty">${escapeHTML(emptyMessage)}</div>`}</div>`;
}

function siteSubsection(title, html, emptyMessage = "", className = "") {
  const classes = ["site-subsection", className].filter(Boolean).join(" ");
  return `
    <div class="${escapeHTML(classes)}">
      <h3>${escapeHTML(title)}</h3>
      ${html || `<div class="empty">${escapeHTML(emptyMessage || "No rows in this scope.")}</div>`}
    </div>
  `;
}

function siteTrendPanel(site, mode = "overview") {
  const siteID = site.id || "";
  const rows = siteTrendRows(siteID, mode);
  const stats = siteTrendStats(site, mode, rows);
  return `
    <div class="site-trend-panel">
      <div class="site-trend-main">
        <div class="chart-box site-trend-chart">
          <canvas id="${escapeHTML(siteTrendCanvasID(mode))}"></canvas>
        </div>
        <div class="field-grid site-trend-facts">
          ${stats.map(statTile).join("")}
        </div>
      </div>
      <div class="site-trend-actions">
        ${siteTrendActions(site, mode)}
      </div>
    </div>
  `;
}

function siteActorMixPanel(site) {
  const rows = siteActorMixRows(site.id || "");
  const sourceIPs = siteTopSourceIPs(site.id || "");
  const reviewCount = sourceIPs.filter(actorSourceNeedsReview).length;
  const verifiedCount = sourceIPs.filter((item) => item.verified_source).length;
  return `
    <div class="site-trend-panel">
      <div class="site-trend-main">
        <div class="chart-box site-trend-chart">
          <canvas id="siteActorMixChart"></canvas>
        </div>
        <div class="field-grid site-trend-facts">
          ${[
            ["Actor groups", formatNumber(rows.length)],
            ["Source IPs", formatNumber(sourceIPs.length)],
            ["Need review", formatNumber(reviewCount)],
            ["Verified", formatNumber(verifiedCount)],
          ].map(statTile).join("")}
        </div>
      </div>
      <div class="site-trend-actions">
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: site.id || "", actor_type: "crawler", origin: "site_actor_panel" })}'>Crawler logs</button>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: site.id || "", actor_type: "scanner", origin: "site_actor_panel" })}'>Scanner logs</button>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: site.id || "", status_class: "errors", origin: "site_actor_panel" })}'>Actor errors</button>
      </div>
    </div>
  `;
}

function siteTrendCanvasID(mode) {
  return {
    overview: "siteOverviewTrendChart",
    security: "siteSecurityTrendChart",
    reliability: "siteReliabilityTrendChart",
  }[mode] || "siteOverviewTrendChart";
}

function siteTrendRows(siteID, mode = "overview") {
  const rows = siteTrendEvidence(siteID, mode);
  const bucketMs = logTimelineBucketMs();
  const buckets = new Map();
  rows.forEach((item) => {
    const date = new Date(item.ts || item.last_seen || item.timestamp || 0);
    if (Number.isNaN(date.getTime())) return;
    const bucket = new Date(Math.floor(date.getTime() / bucketMs) * bucketMs).toISOString();
    const existing = buckets.get(bucket) || { bucket_ts: bucket, requests: 0, secondary: 0, status_4xx: 0, status_5xx: 0 };
    existing.requests += Math.max(1, Number(item.requests || item.events || 1));
    const errors = Number(item.errors || 0) + Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
    existing.secondary += errors;
    existing.status_4xx += Number(item.status_4xx || 0);
    existing.status_5xx += Number(item.status_5xx || 0);
    buckets.set(bucket, existing);
  });
  const out = Array.from(buckets.values()).sort((a, b) => new Date(a.bucket_ts) - new Date(b.bucket_ts));
  if (out.length === 1) {
    const previous = new Date(new Date(out[0].bucket_ts).getTime() - bucketMs).toISOString();
    out.unshift({ bucket_ts: previous, requests: 0, secondary: 0, status_4xx: 0, status_5xx: 0 });
  }
  return out;
}

function siteTrendEvidence(siteID, mode = "overview") {
  const evidence = siteLogEvidence(siteID);
  if (mode === "security") return evidence.filter((item) => siteEvidenceGroup(item) === "security");
  if (mode === "reliability") return evidence.filter((item) => siteEvidenceGroup(item) === "reliability");
  return evidence;
}

function siteEvidenceGroup(item) {
  const kind = String(item.kind || "").toLowerCase();
  if (kind.includes("admin") || kind.includes("injection") || kind.includes("tor") || kind.includes("user-agent")) return "security";
  if (kind.includes("error") || kind.includes("slow")) return "reliability";
  return "traffic";
}

function siteTrendStats(site, mode, rows) {
  const siteID = site.id || "";
  const evidence = siteTrendEvidence(siteID, mode);
  const requests = rows.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  const errors = rows.reduce((sum, item) => sum + Number(item.secondary || 0), 0);
  const latest = latestSiteEvidenceTime(evidence) || site.lastSeen || "";
  if (mode === "security") {
    const ips = new Set(evidence.map((item) => item.ip).filter(Boolean));
    const highSignals = siteSignalItems(siteID).filter((item) => item.group === "security" && severityRank(item.severity) >= severityRank("high")).length;
    return [
      ["Probe requests", formatNumber(requests)],
      ["Probe errors", formatNumber(errors)],
      ["Source IPs", formatNumber(ips.size)],
      ["High+ signals", formatNumber(highSignals)],
      ["Latest probe", formatTime(latest)],
    ];
  }
  if (mode === "reliability") {
    const slowPaths = siteScopedRows(state.data.analysis?.slow_paths || [], siteID).length;
    const failingPaths = siteTopPaths(siteID).filter((item) => Number(item.status_5xx || 0) > 0).length;
    return [
      ["Reliability events", formatNumber(evidence.length)],
      ["Event requests", formatNumber(requests)],
      ["Event errors", formatNumber(errors)],
      ["5xx paths", formatNumber(failingPaths)],
      ["Slow paths", formatNumber(slowPaths)],
      ["Latest error", formatTime(latest)],
    ];
  }
  return [
    ["Requests", formatNumber(site.requests || requests)],
    ["4xx / 5xx", `${formatNumber(site.status4xx || 0)} / ${formatNumber(site.status5xx || 0)}`],
    ["Trend events", formatNumber(evidence.length)],
    ["Signals", formatNumber(siteSignalItems(siteID).length)],
    ["Latest event", formatTime(latest)],
  ];
}

function latestSiteEvidenceTime(rows) {
  const times = (rows || [])
    .map((item) => item.ts || item.last_seen || item.timestamp)
    .filter(Boolean)
    .map((value) => new Date(value))
    .filter((date) => !Number.isNaN(date.getTime()));
  if (!times.length) return "";
  return new Date(Math.max(...times.map((date) => date.getTime()))).toISOString();
}

function siteTrendActions(site, mode) {
  const siteID = site.id || "";
  const topIP = siteTopSourceIPs(siteID)[0];
  const topPath = siteTopPaths(siteID)[0];
  const actions = [];
  const add = (label, pivot) => actions.push(`<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(pivot)}'>${escapeHTML(label)}</button>`);
  if (mode === "security") {
    add("Admin logs", { kind: "log_filter", site_id: siteID, evidence_kind: "Admin probe", log_type: "nginx-access", origin: "site_security_trend" });
    add("Injection logs", { kind: "log_filter", site_id: siteID, evidence_kind: "Injection probe", log_type: "nginx-access", origin: "site_security_trend" });
    if (topIP?.ip) add("Top IP", { kind: "ip", value: topIP.ip, site_id: siteID, origin: "site_security_trend" });
  } else if (mode === "reliability") {
    add("Error logs", { kind: "log_filter", site_id: siteID, status_class: "errors", log_type: "nginx-access", origin: "site_reliability_trend" });
    add("Slow evidence", { kind: "log_filter", site_id: siteID, evidence_kind: "Slow path", log_type: "nginx-access", origin: "site_reliability_trend" });
    if (topPath?.path) add("Top path", { kind: "path", value: topPath.path, site_id: siteID, origin: "site_reliability_trend" });
  } else {
    add("Access logs", { kind: "log_filter", site_id: siteID, log_type: "nginx-access", origin: "site_overview_trend" });
    add("Errors", { kind: "log_filter", site_id: siteID, status_class: "errors", log_type: "nginx-access", origin: "site_overview_trend" });
    add("Reports", { kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "site_overview_trend" });
  }
  return actions.join("");
}

function siteReliabilityMatrix(site, { slowPaths = [], failingPaths = [], recentErrors = [] } = {}) {
  const siteID = site.id || "";
  const rows = siteReliabilityMatrixRows(siteID, { slowPaths, failingPaths, recentErrors }).slice(0, 12);
  const laneStats = siteReliabilityLaneStats(siteID);
  if (!rows.length) return "";
  return `
    <div class="table-wrap site-reliability-matrix-wrap">
      <table class="site-reliability-matrix">
        <thead>
          <tr>
            <th>Evidence</th>
            <th>Impact</th>
            <th>Error lanes</th>
            <th>Latest</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${rows.map((row) => siteReliabilityMatrixRow(siteID, row, laneStats)).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function siteReliabilityMatrixRows(siteID, { slowPaths = [], failingPaths = [], recentErrors = [] } = {}) {
  const rows = new Map();
  const add = (kind, item = {}) => {
    const path = item.path || "/";
    const key = path || item.client_ip || item.ip || kind;
    const existing = rows.get(key) || {
      key,
      siteID: item.site_id || siteID,
      path,
      ips: new Set(),
      methods: new Set(),
      envs: new Set(),
      kinds: new Set(),
      statuses: new Set(),
      requests: 0,
      errors: 0,
      status5xx: 0,
      p95: 0,
      latest: "",
    };
    const ip = item.client_ip || item.ip || "";
    if (ip) existing.ips.add(ip);
    if (item.method) existing.methods.add(item.method);
    if (item.env) existing.envs.add(item.env);
    if (item.status) existing.statuses.add(item.status);
    existing.kinds.add(kind);
    existing.siteID = existing.siteID || item.site_id || siteID;
    existing.requests = Math.max(existing.requests, Number(item.requests || 1));
    const errorCount = Number(item.status_4xx || 0) + Number(item.status_5xx || 0) + (Number(item.status || 0) >= 400 ? 1 : 0);
    existing.errors = Math.max(existing.errors, errorCount);
    existing.status5xx = Math.max(existing.status5xx, Number(item.status_5xx || 0) + (Number(item.status || 0) >= 500 ? 1 : 0));
    existing.p95 = Math.max(existing.p95, Number(item.p95_request_time_ms || 0));
    existing.latest = latestISO(existing.latest, item.last_seen || item.ts || item.timestamp || item.max_ts || item.bucket_start || "");
    rows.set(key, existing);
  };
  failingPaths.forEach((item) => add("5xx path", item));
  slowPaths.forEach((item) => add("Slow path", item));
  recentErrors.forEach((item) => add("Recent error", item));
  return Array.from(rows.values())
    .map((row) => ({
      ...row,
      ip: Array.from(row.ips)[0] || "",
      ipCount: row.ips.size,
      methodList: Array.from(row.methods),
      envList: Array.from(row.envs),
      kindList: Array.from(row.kinds),
      statusList: Array.from(row.statuses),
    }))
    .sort((a, b) => Number(b.status5xx || 0) - Number(a.status5xx || 0)
      || Number(b.errors || 0) - Number(a.errors || 0)
      || Number(b.p95 || 0) - Number(a.p95 || 0)
      || Number(b.requests || 0) - Number(a.requests || 0)
      || new Date(b.latest || 0) - new Date(a.latest || 0));
}

function latestISO(current, next) {
  if (!next) return current || "";
  const nextDate = new Date(next);
  if (Number.isNaN(nextDate.getTime())) return current || "";
  if (!current) return nextDate.toISOString();
  const currentDate = new Date(current);
  if (Number.isNaN(currentDate.getTime()) || nextDate > currentDate) return nextDate.toISOString();
  return current;
}

function siteReliabilityMatrixRow(siteID, row, laneStats = {}) {
  const actions = [
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "site", value: siteID, origin: "site_reliability_matrix" })}'>Site</button>`,
    row.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: row.path, site_id: siteID, origin: "site_reliability_matrix" })}'>Path</button>` : "",
    row.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: row.ip, site_id: siteID, origin: "site_reliability_matrix" })}'>IP</button>` : "",
    correlatedLogActions({ path: row.path, siteID, ip: row.ip, statusClass: row.errors ? "errors" : "", origin: "site_reliability_matrix" }),
  ].filter(Boolean).join("");
  const meta = [
    row.kindList.join(", "),
    row.envList.join(", "),
    row.methodList.join(", "),
    row.ipCount ? `${formatNumber(row.ipCount)} source IP${row.ipCount === 1 ? "" : "s"}` : "",
    row.statusList.length ? `status ${row.statusList.join(", ")}` : "",
  ].filter(Boolean).join(" - ");
  const lanes = correlatedLogTypeDefs(false)
    .map(([logType, label]) => {
      const stats = laneStats[logType] || {};
      const suffix = stats.count ? `${formatNumber(stats.count)} seg / ${formatNumber(stats.lines || 0)} lines` : "open lane";
      return `<span><b>${escapeHTML(label)}</b>${escapeHTML(suffix)}</span>`;
    }).join("");
  return `
    <tr>
      <td class="clip"><strong>${escapeHTML(row.path || row.ip || "-")}</strong><br><span>${escapeHTML(meta || "Reliability evidence")}</span></td>
      <td>${formatNumber(row.requests || 0)}<br><span>${escapeHTML([row.errors ? `${formatNumber(row.errors)} errors` : "", row.status5xx ? `${formatNumber(row.status5xx)} 5xx` : "", row.p95 ? `p95 ${formatMs(row.p95)}` : ""].filter(Boolean).join(" / ") || "no impact count")}</span></td>
      <td><div class="site-reliability-lanes">${lanes}</div></td>
      <td>${formatTime(row.latest)}</td>
      <td class="row-actions">${actions}</td>
    </tr>
  `;
}

function siteReliabilityLaneStats(siteID) {
  const stats = {};
  (state.data.segments || []).forEach((segment) => {
    if (siteID && segment.site_id && segment.site_id !== siteID) return;
    const logType = segment.log_type || "unknown";
    const existing = stats[logType] || { count: 0, lines: 0, latest: "" };
    existing.count += 1;
    existing.lines += Number(segment.line_count || 0);
    existing.latest = latestISO(existing.latest, segment.max_ts || segment.bucket_end || segment.bucket_start || segment.indexed_at || "");
    stats[logType] = existing;
  });
  return stats;
}

function sitePathsWorkspace(site, rows = sitePathInvestigationRows(site.id || "")) {
  const siteID = site.id || "";
  const failing = rows.filter((item) => item.errors > 0 || item.status5xx > 0)
    .sort((a, b) => Number(b.status5xx || 0) - Number(a.status5xx || 0) || Number(b.errors || 0) - Number(a.errors || 0) || Number(b.requests || 0) - Number(a.requests || 0));
  const slow = rows.filter((item) => item.p95 > 0)
    .sort((a, b) => Number(b.p95 || 0) - Number(a.p95 || 0) || Number(b.requests || 0) - Number(a.requests || 0));
  const traffic = rows.slice().sort((a, b) => Number(b.requests || 0) - Number(a.requests || 0));
  return `
    <section class="site-tab-grid site-paths-grid">
      ${siteSubsection("Path command board", sitePathCommandBoard(site, rows), "No path telemetry in this scope.", "span-2")}
      ${siteSubsection("Path investigation matrix", sitePathMatrix(siteID, rows.slice(0, 16)), "No path rows are available.", "span-2")}
      ${siteSubsection("Failing paths", siteRowsMarkup(failing.slice(0, 8), sitePathFindingRow, "No failing paths for this site."))}
      ${siteSubsection("Slow paths", siteRowsMarkup(slow.slice(0, 8), sitePathFindingRow, "No slow paths for this site."))}
      ${siteSubsection("Highest traffic paths", siteRowsMarkup(traffic.slice(0, 10), sitePathFindingRow, "No high-traffic path rows for this site."), "", "span-2")}
    </section>
  `;
}

function sitePathInvestigationRows(siteID) {
  const evidence = siteLogEvidence(siteID);
  const signals = siteSignalItems(siteID);
  const reports = siteReports(siteID);
  return siteTopPaths(siteID).map((path) => {
    const value = path.path || "/";
    const pathEvidence = evidence.filter((item) => item.path && pathMatches(item.path, value));
    const source = countFacet(pathEvidence, (item) => item.ip, (item) => item.requests)[0] || {};
    const signal = signals.find((item) => item.path && pathMatches(item.path, value)) || null;
    const report = reports.find((item) => item.summary?.top_path && pathMatches(item.summary.top_path, value)) || null;
    const evidenceRequests = pathEvidence.reduce((sum, item) => sum + Number(item.requests || 0), 0);
    const evidenceErrors = pathEvidence.reduce((sum, item) => sum + Number(item.errors || 0), 0);
    const status4xx = Number(path.status_4xx || 0);
    const status5xx = Number(path.status_5xx || 0);
    const errors = Math.max(status4xx + status5xx, evidenceErrors);
    const latest = latestSiteEvidenceTime(pathEvidence) || path.last_seen || path.ts || "";
    const p95 = Number(path.p95_request_time_ms || 0);
    const requests = Math.max(Number(path.requests || 0), evidenceRequests);
    const score = Number(status5xx || 0) * 100000
      + Number(errors || 0) * 1000
      + Math.round(p95 || 0)
      + Math.min(999, requests)
      + (signal ? severityRank(signal.severity) * 5000 : 0);
    return {
      ...path,
      siteID,
      path: value,
      requests,
      status4xx,
      status5xx,
      errors,
      p95,
      latest,
      evidenceCount: pathEvidence.length,
      topIP: source.label || "",
      topIPRequests: source.value || 0,
      topIPErrors: source.errors || 0,
      signal,
      report,
      score,
    };
  }).sort((a, b) => Number(b.score || 0) - Number(a.score || 0) || Number(b.requests || 0) - Number(a.requests || 0));
}

function sitePathCommandBoard(site, rows = []) {
  if (!rows.length) return "";
  const siteID = site.id || "";
  const totalRequests = rows.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  const totalErrors = rows.reduce((sum, item) => sum + Number(item.errors || 0), 0);
  const failing = rows.filter((item) => item.errors > 0 || item.status5xx > 0);
  const slow = rows.filter((item) => item.p95 > 0);
  const top = rows[0] || {};
  const topIP = rows.find((item) => item.topIP)?.topIP || "";
  const actions = [
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, log_type: "nginx-access", origin: "site_paths_board" })}'>All access rows</button>`,
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, status_class: "errors", log_type: "nginx-access", origin: "site_paths_board" })}'>Errors only</button>`,
    top.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: top.path, site_id: siteID, origin: "site_paths_board" })}'>Top path</button>` : "",
    topIP ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: topIP, site_id: siteID, origin: "site_paths_board" })}'>Top IP</button>` : "",
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "site_paths_board" })}'>Reports</button>`,
  ].filter(Boolean).join("");
  const facts = [
    ["Paths", formatNumber(rows.length)],
    ["Requests", formatNumber(totalRequests)],
    ["Errors", formatNumber(totalErrors)],
    ["Failing paths", formatNumber(failing.length)],
    ["Slow paths", formatNumber(slow.length)],
    ["Top path", top.path || "-"],
  ];
  return `
    <div class="site-path-command">
      <div class="field-grid site-path-facts">${facts.map(statTile).join("")}</div>
      <div class="site-trend-actions">${actions}</div>
    </div>
  `;
}

function sitePathMatrix(siteID, rows = []) {
  if (!rows.length) return "";
  return `
    <div class="table-wrap site-path-matrix-wrap">
      <table class="site-path-matrix">
        <thead>
          <tr>
            <th>Path</th>
            <th>Impact</th>
            <th>Source</th>
            <th>Signal / report</th>
            <th>Latest</th>
            <th></th>
          </tr>
        </thead>
        <tbody>${rows.map((row) => sitePathMatrixRow(siteID, row)).join("")}</tbody>
      </table>
    </div>
  `;
}

function sitePathMatrixRow(siteID, row) {
  const signal = row.signal;
  const report = row.report;
  const statusClass = row.errors ? "errors" : "";
  const impact = [
    `${formatNumber(row.requests || 0)} requests`,
    row.errors ? `${formatNumber(row.errors)} errors` : "",
    row.status5xx ? `${formatNumber(row.status5xx)} 5xx` : "",
    row.p95 ? `p95 ${formatMs(row.p95)}` : "",
  ].filter(Boolean).join(" / ");
  const signalMeta = signal
    ? [signal.title, signal.ip ? `IP ${signal.ip}` : "", signal.lastSeen ? formatTime(signal.lastSeen) : ""].filter(Boolean).join(" / ")
    : report ? [reportListLabel(report), reportWindowLabel(report)].filter(Boolean).join(" / ") : "No attached signal or report lead";
  const actions = [
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: row.path || "/", site_id: siteID, origin: "site_path_matrix" })}'>Path</button>`,
    row.topIP ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: row.topIP, site_id: siteID, origin: "site_path_matrix" })}'>IP</button>` : "",
    signal ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: signal.key, site_id: siteID, origin: "site_path_matrix" })}'>Signal</button>` : "",
    report ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: siteID, origin: "site_path_matrix" }))}'>Report</button>` : "",
    correlatedLogActions({ path: row.path || "/", siteID, ip: row.topIP || "", statusClass, origin: "site_path_matrix" }),
  ].filter(Boolean).join("");
  return `
    <tr>
      <td class="clip"><strong>${escapeHTML(row.path || "/")}</strong><br><span>${escapeHTML(`${formatBytes(row.bytes_sent || 0)} transferred / ${formatNumber(row.evidenceCount || 0)} evidence rows`)}</span></td>
      <td>${escapeHTML(impact || "no impact count")}</td>
      <td class="clip"><strong>${escapeHTML(row.topIP || "-")}</strong><br><span>${escapeHTML(row.topIP ? `${formatNumber(row.topIPRequests || 0)} requests / ${formatNumber(row.topIPErrors || 0)} errors` : "no source concentration")}</span></td>
      <td class="clip"><strong>${escapeHTML(signal ? formatCategory(signal.group || "signal") : report ? "Report" : "-")}</strong><br><span>${escapeHTML(signalMeta)}</span></td>
      <td>${formatTime(row.latest)}</td>
      <td class="row-actions">${actions}</td>
    </tr>
  `;
}

function sitePathFindingRow(row) {
  const siteID = row.siteID || state.siteID || state.viewContext.site_id || "";
  const errors = Number(row.errors || 0);
  const meta = [
    `${formatNumber(row.requests || 0)} requests`,
    errors ? `${formatNumber(errors)} errors` : "",
    row.status5xx ? `${formatNumber(row.status5xx)} 5xx` : "",
    row.p95 ? `p95 ${formatMs(row.p95)}` : "",
    row.topIP ? `top IP ${row.topIP}` : "",
  ].filter(Boolean).join(" - ");
  const actions = [
    `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: row.path || "/", site_id: siteID, origin: "site_path_finding" })}'>Open path</button>`,
    row.topIP ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: row.topIP, site_id: siteID, origin: "site_path_finding" })}'>Open IP</button>` : "",
    row.signal ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "signal", key: row.signal.key, site_id: siteID, origin: "site_path_finding" })}'>Open signal</button>` : "",
    correlatedLogActions({ path: row.path || "/", siteID, ip: row.topIP || "", statusClass: errors ? "errors" : "", origin: "site_path_finding" }),
  ].filter(Boolean).join("");
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(row.path || "/")}</strong>
        <span>${escapeHTML(meta)}</span>
        <div class="signal-actions">${actions}</div>
      </div>
      <div class="signal-numbers">
        <span>${errors ? "errors" : row.p95 ? "p95" : "requests"}</span>
        <b>${errors ? formatNumber(errors) : row.p95 ? formatMs(row.p95) : formatNumber(row.requests || 0)}</b>
      </div>
    </div>
  `;
}

function siteLogsSummary(siteID) {
  return withSiteLogContext(siteID, () => {
    const evidence = siteLogEvidence(siteID);
    const topPaths = siteTopPaths(siteID);
    const segmentCount = correlatedLogTypeDefs(false)
      .reduce((sum, [logType]) => sum + siteLogSegments(logType, siteID).length, 0);
    return `${formatNumber(evidence.length)} evidence rows / ${formatNumber(topPaths.length)} paths / ${formatNumber(segmentCount)} segments`;
  });
}

function siteLogsWorkspace(site) {
  const siteID = site.id || "";
  return withSiteLogContext(siteID, () => {
    const evidence = siteLogEvidence(siteID);
    const topPaths = siteTopPaths(siteID);
    const currentSegments = siteLogSegments(state.logType, siteID);
    const planRows = logInvestigationPlanRows(evidence, topPaths, { segments: currentSegments });
    const relatedRows = [
      ...logRelatedEvidenceRows(evidence, topPaths),
      ...logCorrelationRows(evidence, topPaths, { context: { site_id: siteID }, origin: "site_logs_correlation" }),
    ];
    const laneRows = siteLogLaneRows(siteID, evidence, topPaths);
    return `
      <section class="site-tab-grid site-logs-grid">
        ${siteSubsection("Log scope path", `<div class="site-logs-scope">${logsScopePath(evidence, topPaths, { segments: currentSegments })}</div>`, "No log scope is active.", "span-2")}
        ${siteSubsection("Log lane board", siteLogLaneBoard(laneRows), "No log lanes are configured.")}
        ${siteSubsection("Context plan", siteLogPlanBoard(planRows), "No investigation steps available for this site.")}
        ${siteSubsection("Field facets", siteLogFacetBoard(evidence, topPaths), "No facets for this site.")}
        ${siteSubsection("Related signals and reports", siteRowsMarkup(relatedRows.slice(0, 10), logRelatedEvidenceRow, "No related signals, reports, or log lanes for this site."))}
        ${siteSubsection("Access evidence", siteLogEvidenceTable(evidence.slice(0, 18)), "No matching access-log evidence for this site.", "span-2")}
      </section>
    `;
  });
}

function withSiteLogContext(siteID, renderFn) {
  const previousSiteID = state.siteID;
  const previousContext = { ...(state.viewContext || {}) };
  state.siteID = siteID || previousSiteID || "";
  state.viewContext = { ...previousContext, site_id: siteID || previousContext.site_id || "" };
  try {
    return renderFn();
  } finally {
    state.siteID = previousSiteID;
    state.viewContext = previousContext;
  }
}

function siteLogLaneRows(siteID, evidence = siteLogEvidence(siteID), topPaths = siteTopPaths(siteID)) {
  const accessErrors = evidence.reduce((sum, item) => sum + Number(item.errors || 0) + Number(item.status_4xx || 0) + Number(item.status_5xx || 0), 0);
  const accessRequests = evidence.reduce((sum, item) => sum + Number(item.requests || 0), 0);
  const latestAccess = latestLogEvidenceTime(evidence, topPaths);
  const rows = [{
    logType: "nginx-access",
    label: "Access",
    status: state.logType === "nginx-access" ? "active" : evidence.length ? "available" : "empty",
    count: evidence.length,
    requests: accessRequests,
    errors: accessErrors,
    canFilterErrors: accessErrors > 0,
    latest: latestAccess,
    meta: [
      `${formatNumber(evidence.length)} rows`,
      accessRequests ? `${formatNumber(accessRequests)} requests` : "",
      accessErrors ? `${formatNumber(accessErrors)} errors` : "",
      topPaths[0]?.path || "",
    ].filter(Boolean).join(" - "),
    active: state.logType === "nginx-access",
  }];
  correlatedLogTypeDefs(false).forEach(([logType, label]) => {
    const summary = siteLogSegmentSummary(logType, siteID);
    rows.push({
      logType,
      label,
      status: state.logType === logType ? "active" : summary.count ? summary.pending ? "pending" : "indexed" : "empty",
      count: summary.count,
      requests: summary.lines,
      errors: 0,
      canFilterErrors: false,
      latest: summary.latest,
      meta: [
        summary.count ? `${formatNumber(summary.count)} segments` : "no segments",
        summary.lines ? `${formatNumber(summary.lines)} lines` : "",
        summary.indexed ? `${formatNumber(summary.indexed)} indexed` : "",
        summary.pending ? `${formatNumber(summary.pending)} pending` : "",
      ].filter(Boolean).join(" - "),
      active: state.logType === logType,
      pending: summary.pending,
    });
  });
  return rows.map((row) => ({
    ...row,
    contextLabel: siteID || logLaneContextLabel({ site_id: siteID }),
  }));
}

function siteLogSegments(logType, siteID) {
  return unsupportedLogSegments(logType)
    .filter((segment) => !segment.site_id || segment.site_id === siteID);
}

function siteLogSegmentSummary(logType, siteID) {
  const segments = siteLogSegments(logType, siteID);
  const latest = segments[0]?.bucket_start || segments[0]?.max_ts || segments[0]?.bucket_end || "";
  const indexed = segments.filter((item) => item.indexed || item.status === "indexed").length;
  return {
    count: segments.length,
    lines: segments.reduce((sum, item) => sum + Number(item.line_count || 0), 0),
    indexed,
    pending: Math.max(0, segments.length - indexed),
    latest,
  };
}

function siteLogLaneBoard(rows = []) {
  return `<div class="log-lane-list site-log-lane-list">${rows.map(logLaneRow).join("") || `<div class="empty">No log lanes are configured.</div>`}</div>`;
}

function siteLogPlanBoard(rows = []) {
  return `<div class="logs-command-list site-log-plan">${rows.map(logInvestigationPlanRow).join("") || `<div class="empty">No investigation steps available for this site.</div>`}</div>`;
}

function siteLogFacetBoard(evidence, topPaths) {
  return `<div class="facet-list site-log-facets">${logFacetSections(evidence, topPaths).join("")}</div>`;
}

function siteLogEvidenceTable(rows = []) {
  return `
    <div class="table-wrap site-log-evidence-wrap">
      <table class="logs-table site-log-evidence-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Evidence</th>
            <th>Site</th>
            <th>Source</th>
            <th>Target</th>
            <th>Signal</th>
            <th></th>
          </tr>
        </thead>
        <tbody>${rows.map(logEvidenceTableRow).join("") || emptyRow(7, "No matching access-log evidence for this site.")}</tbody>
      </table>
    </div>
  `;
}

function siteActorMixRows(siteID) {
  const groups = new Map();
  const add = (label, value, type) => {
    if (!label) return;
    const key = `${type || "actor"}|${label}`;
    const existing = groups.get(key) || { key, label, value: 0, type: type || "actor" };
    existing.value += Number(value || 0);
    groups.set(key, existing);
  };
  siteTopSourceIPs(siteID).forEach((item) => {
    add(item.known_actor || actorLabelFromType(item.actor_type) || item.asn_org || "Unknown source", item.requests, item.actor_type || "source");
  });
  siteTopUserAgents(siteID).forEach((item) => {
    add(item.family || actorLabelFromType(item.actor_type) || "User agents", item.requests, item.actor_type || "user-agent");
  });
  const colors = {
    crawler: "#2364aa",
    scanner: "#b93232",
    tor: "#a96216",
    browser: "#178a5f",
    monitor: "#0f766e",
    source: "#65717d",
  };
  return Array.from(groups.values())
    .sort((a, b) => Number(b.value || 0) - Number(a.value || 0))
    .slice(0, 8)
    .map((item) => ({ ...item, color: colors[item.type] || "#2364aa" }));
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
  trafficPaths.forEach((item) => {
    const key = item.path || "/";
    const existing = byPath.get(key) || { ...item, site_id: item.site_id || siteID, path: key, requests: 0, status_4xx: 0, status_5xx: 0, bytes_sent: 0, avg_request_time_ms: 0, p95_request_time_ms: 0 };
    existing.requests += Number(item.requests || 0);
    existing.status_4xx += Number(item.status_4xx || 0);
    existing.status_5xx += Number(item.status_5xx || 0);
    existing.bytes_sent += Number(item.bytes_sent || 0);
    existing.site_id = existing.site_id || item.site_id || siteID;
    byPath.set(key, existing);
  });
  slowPaths.forEach((item) => {
    const key = item.path || "/";
    const existing = byPath.get(key) || { ...item, site_id: item.site_id || siteID, path: key, requests: 0, status_4xx: 0, status_5xx: 0, bytes_sent: 0, avg_request_time_ms: 0, p95_request_time_ms: 0 };
    if (!byPath.has(key)) {
      existing.requests += Number(item.requests || 0);
      existing.status_4xx += Number(item.status_4xx || 0);
      existing.status_5xx += Number(item.status_5xx || 0);
      existing.bytes_sent += Number(item.bytes_sent || 0);
    }
    existing.avg_request_time_ms = Math.max(existing.avg_request_time_ms || 0, Number(item.avg_request_time_ms || 0));
    existing.p95_request_time_ms = Math.max(existing.p95_request_time_ms || 0, Number(item.p95_request_time_ms || 0));
    existing.site_id = existing.site_id || item.site_id || siteID;
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

function siteActorsToVerify(siteID) {
  return siteTopSourceIPs(siteID)
    .filter((item) => item.verified_source === false || item.manual_action || item.is_tor_exit || item.known_actor || item.actor_type || Number(item.risk_score || 0) >= 40)
    .map((item) => ({ ...item, kind: "Source IP" }))
    .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0) || Number(b.requests || 0) - Number(a.requests || 0));
}

function siteActorVerificationRows(siteID) {
  return actorVerificationRows(siteScopedRows(state.data.analysis?.source_ips || [], siteID));
}

function siteActivityEvents(siteID) {
  const events = [];
  const seen = new Set();
  const addEvent = (event) => {
    const time = event.time || "";
    if (!time) return;
    const parsed = new Date(time);
    if (Number.isNaN(parsed.getTime())) return;
    const key = [event.group, event.kind, parsed.toISOString(), event.title, event.meta].join("|");
    if (seen.has(key)) return;
    seen.add(key);
    events.push({ ...event, time: parsed.toISOString() });
  };

  siteSignalItems(siteID).forEach((signal) => {
    addEvent({
      group: signal.group || "signal",
      kind: `${formatCategory(signal.group || "Signal")} signal`,
      time: signal.lastSeen,
      title: signal.title || "Signal",
      meta: [
        signal.summary || "",
        signal.ip ? `IP ${signal.ip}` : "",
        signal.path || "",
        signal.requests ? `${formatNumber(signal.requests)} requests` : "",
        signal.errors ? `${formatNumber(signal.errors)} errors` : "",
      ].filter(Boolean).join(" / "),
      valueLabel: "risk",
      value: signal.risk || severityRank(signal.severity) * 20 || 0,
      actions: signalActionButtons(signal, "site_activity", "mini"),
    });
  });

  siteRecentErrors(siteID).forEach((item) => {
    const status = Number(item.status || 0);
    addEvent({
      group: "reliability",
      kind: status >= 500 ? "5xx error" : "4xx error",
      time: item.ts,
      title: `${item.status || "-"} ${[item.method || "GET", item.path || "/"].join(" ")}`,
      meta: [
        item.env || "",
        item.client_ip ? `IP ${item.client_ip}` : "",
        item.query ? `?${item.query}` : "",
        item.user_agent || "",
      ].filter(Boolean).join(" / "),
      valueLabel: "status",
      value: item.status || "-",
      actions: siteLogEventActions({
        siteID: item.site_id || siteID,
        ip: item.client_ip || "",
        path: item.path || "",
        statusClass: "errors",
      }),
    });
  });

  siteScopedRows(state.data.analysis?.slow_paths || [], siteID).forEach((item) => {
    const errors = Number(item.status_5xx || 0);
    addEvent({
      group: "reliability",
      kind: "Slow path",
      time: item.last_seen,
      title: item.path || "/",
      meta: [
        item.env || "",
        `avg ${formatMs(item.avg_request_time_ms || 0)}`,
        errors ? `${formatNumber(errors)} 5xx` : "",
        `${formatNumber(item.requests || 0)} requests`,
      ].filter(Boolean).join(" / "),
      valueLabel: "p95",
      value: formatMs(item.p95_request_time_ms || 0),
      actions: siteLogEventActions({
        siteID: item.site_id || siteID,
        path: item.path || "",
        statusClass: errors ? "errors" : "",
      }),
    });
  });

  [
    ...(siteScopedRows(state.data.analysis?.injection_probes || [], siteID).map((item) => ({ ...item, kind: "Injection probe" }))),
    ...(siteScopedRows(state.data.analysis?.admin_probes || [], siteID).map((item) => ({ ...item, kind: "Admin probe" }))),
  ].forEach((item) => {
    addEvent({
      group: "security",
      kind: item.kind,
      time: item.last_seen,
      title: `${formatCategory(item.category || item.match_reason || "Probe")} ${item.path || "/"}`,
      meta: [
        item.env || "",
        item.ip ? `IP ${item.ip}` : "",
        item.sample_query ? `?${item.sample_query}` : "",
        `${formatNumber(item.requests || 0)} requests`,
        item.total_ip_hits ? `${formatNumber(item.total_ip_hits)} total IP hits` : "",
      ].filter(Boolean).join(" / "),
      valueLabel: "risk",
      value: item.risk_score || 0,
      actions: siteLogEventActions({
        siteID: item.site_id || siteID,
        ip: item.ip || "",
        path: item.path || "",
        statusClass: Number(item.status_4xx || 0) + Number(item.status_5xx || 0) ? "errors" : "",
      }),
    });
  });

  siteScopedRows(state.data.analysis?.tor_sources || [], siteID).forEach((item) => {
    addEvent({
      group: "security",
      kind: "Tor source",
      time: item.last_seen,
      title: item.ip || "Tor source",
      meta: [
        item.env || "",
        item.reverse_dns || "",
        item.known_actor || item.actor_type || "",
        item.admin_requests ? `${formatNumber(item.admin_requests)} admin requests` : "",
      ].filter(Boolean).join(" / "),
      valueLabel: "risk",
      value: item.risk_score || 0,
      actions: siteLogEventActions({
        siteID: item.site_id || siteID,
        ip: item.ip || "",
        statusClass: Number(item.status_4xx || 0) + Number(item.status_5xx || 0) ? "errors" : "",
      }),
    });
  });

  siteReports(siteID).forEach((report) => {
    addEvent({
      group: "reports",
      kind: "Report",
      time: report.generated_at,
      title: reportListLabel(report),
      meta: reportWindowLabel(report),
      valueLabel: report.model || "local",
      value: formatNumber(report.summary?.requests || 0),
      actions: `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), origin: "site_activity" }))}'>Open report</button>`,
    });
  });

  return events.sort((a, b) => new Date(b.time) - new Date(a.time));
}

function siteLogEventActions({ siteID = "", ip = "", path = "", statusClass = "", origin = "site_activity" } = {}) {
  return [
    ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: ip, site_id: siteID, origin })}'>Open IP</button>` : "",
    path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: path, site_id: siteID, origin })}'>Open path</button>` : "",
    correlatedLogActions({ path, siteID, ip, statusClass, origin }),
  ].filter(Boolean).join("");
}

function siteSecurityRow(item) {
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  const path = item.path || "/";
  const siteID = item.site_id || state.siteID || state.viewContext.site_id || "";
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.kind || formatCategory(item.category || "Security"))}: ${escapeHTML(path)}</strong>
        <span>${escapeHTML([item.ip, formatCategory(item.match_reason || item.category || ""), `${formatNumber(item.requests || 0)} requests`, `${formatNumber(errors)} errors`].filter(Boolean).join(" - "))}</span>
        ${item.ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: siteID, origin: "site" })}'>Open IP</button>` : ""}
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: path, site_id: siteID, origin: "site" })}'>Open path</button>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", path, ip: item.ip || "", site_id: siteID, status_class: errors ? "errors" : "", origin: "site" })}'>Open logs</button>
      </div>
      <div class="signal-numbers"><span>risk</span><b>${escapeHTML(item.risk_score || 0)}</b></div>
    </div>
  `;
}

function siteReliabilityRow(item) {
  if (item.kind === "Recent error") return siteRecentErrorRow(item);
  const siteID = item.site_id || state.siteID || state.viewContext.site_id || "";
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(item.path || "/")}</strong>
        <span>${escapeHTML(`p95 ${formatMs(item.p95_request_time_ms || 0)} - avg ${formatMs(item.avg_request_time_ms || 0)} - ${formatNumber(item.status_5xx || 0)} 5xx`)}</span>
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "path", value: item.path || "/", site_id: siteID, origin: "site" })}'>Open path</button>
        ${correlatedLogActions({ path: item.path || "/", siteID, statusClass: Number(item.status_5xx || 0) ? "errors" : "", origin: "site" })}
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
  const siteID = item.site_id || state.siteID || state.viewContext.site_id || "";
  const meta = isIP
    ? [verification, item.reverse_dns, item.known_actor, item.actor_type, item.manual_label, `${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))} errors`].filter(Boolean).join(" - ")
    : [item.actor_type, `${formatNumber(item.unique_ips || 0)} IPs`, `${formatNumber((item.status_4xx || 0) + (item.status_5xx || 0))} errors`].filter(Boolean).join(" - ");
  return `
    <div class="signal-row">
      <div>
        <strong>${escapeHTML(label)}</strong>
        <span>${escapeHTML(meta)}</span>
        ${isIP ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "ip", value: item.ip, site_id: siteID, origin: "site" })}'>Open IP</button>` : ""}
        ${isIP && item.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "asn", value: formatASN(item.asn), site_id: siteID, origin: "site" })}'>Open ASN</button>` : ""}
        ${isIP && (item.known_actor || item.actor_type) ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "actor", value: item.known_actor || actorLabelFromType(item.actor_type), actor_type: item.actor_type || "", site_id: siteID, origin: "site" })}'>Open actor</button>` : ""}
        <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", ip: isIP ? item.ip : "", user_agent: isIP ? "" : item.sample || "", site_id: siteID, origin: "site" })}'>Open logs</button>
        ${isIP ? ipManualButtons(item.ip, item, siteID, "mini") : ""}
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

function siteReportsWorkspace(site, reports = siteReports(site.id || ""), selected = siteSelectedReport(reports)) {
  const siteID = site.id || "";
  if (!reports.length) {
    return `
      <section class="site-tab-grid site-reports-grid">
        ${siteSubsection("Report periods", siteReportEmptyState(siteID), "No generated reports are scoped to this site yet.", "span-2")}
      </section>
    `;
  }
  if (!selected) selected = reports[0];
  const summary = selected.summary || {};
  return `
    <section class="site-tab-grid site-reports-grid">
      ${siteSubsection("Report periods", siteReportPeriodNavigator(siteID, reports, selected), "No generated reports are scoped to this site yet.", "span-2")}
      ${siteSubsection("Selected report metrics", siteReportMetricBand(selected), "", "span-2")}
      ${siteSubsection("LLM summary", `<div class="report-copy markdown-body site-report-copy">${renderMarkdown(selected.output || "No LLM summary stored for this report.")}</div>`, "", "span-2")}
      <div class="span-2">${reportPeriodPath(selected)}</div>
      <div class="span-2">${reportInvestigationBoard(selected)}</div>
      <div class="span-2">${reportEvidenceMatrix(selected)}</div>
      <section class="report-chart-grid span-2 site-report-chart-grid">
        ${reportChartsMarkup(selected)}
      </section>
      <section class="report-drilldown-grid span-2 site-report-drilldown-grid">
        ${reportDrilldownsMarkup(selected)}
      </section>
      ${siteSubsection("Report actions", siteReportActionPanel(siteID, selected, summary), "", "span-2")}
    </section>
  `;
}

function siteSelectedReport(reports = []) {
  const rows = siteSortedReports(reports);
  if (!rows.length) return null;
  const selected = Object.values(state.selectedReportIDs || {})
    .map((key) => rows.find((report) => reportKey(report) === key))
    .find(Boolean);
  const report = selected || rows[0];
  const tab = reportTabForReport(report);
  state.reportTab = tab;
  state.selectedReportIDs[tab] = reportKey(report);
  return report;
}

function siteSortedReports(reports = []) {
  return [...(reports || [])].sort((a, b) => new Date(b.created_at || b.range_end || 0) - new Date(a.created_at || a.range_end || 0));
}

function siteReportPeriodNavigator(siteID, reports = [], selected = null) {
  const rows = siteSortedReports(reports);
  const tabs = ["daily", "weekly", "monthly", "quarterly", "annual"];
  return `
    <div class="site-report-period-board">
      ${tabs.map((tab) => siteReportPeriodGroup(siteID, tab, rows.filter((report) => reportTabForReport(report) === tab), selected)).join("")}
    </div>
  `;
}

function siteReportPeriodGroup(siteID, tab, reports = [], selected = null) {
  const activeKey = selected ? reportKey(selected) : "";
  const rows = reports.slice(0, 6);
  return `
    <section class="site-report-period-group">
      <div class="site-report-period-head">
        <strong>${escapeHTML(reportPeriodLabel(tab))}</strong>
        <span>${formatNumber(reports.length)}</span>
      </div>
      <div class="site-report-period-list">
        ${rows.map((report) => siteReportPeriodRow(siteID, tab, report, reportKey(report) === activeKey)).join("") || `<div class="compact-empty">No ${escapeHTML(reportPeriodLabel(tab).toLowerCase())} reports.</div>`}
      </div>
    </section>
  `;
}

function siteReportPeriodRow(siteID, tab, report, active) {
  const summary = report.summary || {};
  const errors = Number(summary.status_4xx_rate || 0) + Number(summary.status_5xx_rate || 0);
  const meta = [
    `${formatNumber(summary.requests || 0)} requests`,
    `${formatPercent(summary.status_5xx_rate || 0)} 5xx`,
    summary.issue_count ? `${formatNumber(summary.issue_count)} issues` : "",
  ].filter(Boolean).join(" / ");
  return `
    <button class="site-report-period-row ${active ? "active" : ""}" type="button" data-site-report-tab="${escapeHTML(tab)}" data-site-report-select="${escapeHTML(reportKey(report))}" aria-pressed="${active ? "true" : "false"}">
      <span>${escapeHTML(reportListLabel(report))}</span>
      <strong>${escapeHTML(meta)}</strong>
      <small>${escapeHTML(reportWindowLabel(report))}</small>
      <small>${escapeHTML(report.model || "local")}${errors ? ` / ${formatPercent(errors)} error rate` : ""}</small>
    </button>
  `;
}

function siteReportMetricBand(report) {
  const summary = report.summary || {};
  return `
    <section class="metrics report-metrics site-report-metrics" aria-label="Selected site report metrics">
      ${reportMetric("Requests", formatNumber(summary.requests || 0))}
      ${reportMetric("4xx rate", formatPercent(summary.status_4xx_rate || 0))}
      ${reportMetric("5xx rate", formatPercent(summary.status_5xx_rate || 0))}
      ${reportMetric("Slow rate", formatPercent(summary.slow_requests_rate || 0))}
      ${reportMetric("Issues", formatNumber(summary.issue_count || 0))}
      ${reportMetric("Security probes", formatNumber((summary.admin_probe_requests || 0) + (summary.injection_probe_requests || 0)))}
      ${reportMetric("Top IP", summary.top_source_ip || "-")}
      ${reportMetric("Top path", summary.top_path || "-")}
    </section>
  `;
}

function siteReportActionPanel(siteID, report, summary = report.summary || {}) {
  return `
    <div class="site-report-actions">
      <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: siteID, origin: "site_reports" }))}'>Open in Reports</button>
      <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "log_filter", site_id: siteID, origin: "site_reports" }))}'>Period logs</button>
      <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "log_filter", site_id: siteID, status_class: "errors", origin: "site_reports" }))}'>Error logs</button>
      ${summary.top_source_ip ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "ip", value: summary.top_source_ip, site_id: siteID, origin: "site_reports" }))}'>Top IP</button>` : ""}
      ${summary.top_path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "path", value: summary.top_path, site_id: siteID, origin: "site_reports" }))}'>Top path</button>` : ""}
    </div>
  `;
}

function siteReportEmptyState(siteID) {
  return `
    <div class="empty">No generated reports are scoped to this site yet.</div>
    <div class="site-report-actions">
      <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "report", report_tab: state.reportTab || "daily", site_id: siteID, origin: "site_reports" })}'>Open Reports</button>
      <button class="ghost mini inline-action" type="button" data-pivot='${encodePivot({ kind: "log_filter", site_id: siteID, origin: "site_reports" })}'>Open logs</button>
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

    ${reportPeriodPath(report)}
    ${reportInvestigationBoard(report)}
    ${reportEvidenceMatrix(report)}

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
    log_type: extra.log_type || "nginx-access",
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

function reportPeriodPath(report) {
  const summary = report.summary || {};
  const siteID = report.site_id || summary.top_site || "";
  const evidenceRows = reportEvidenceRows(report);
  const sourceLead = reportLeadFor(report, ["source_ips", "tor_sources", "admin_probes", "injection_probes"]);
  const targetLead = reportLeadFor(report, ["top_paths", "slow_paths", "recent_errors"], (item) => Boolean(item.path || item.site_id));
  const signalLead = reportLeadFor(report, ["issues", "injection_probes", "admin_probes", "tor_sources", "slow_paths", "recent_errors"]);
  const sourceItem = sourceLead?.item || {};
  const targetItem = targetLead?.item || {};
  const signalItem = signalLead?.item || {};
  const sourceSiteID = sourceItem.site_id || siteID;
  const targetSiteID = targetItem.site_id || siteID;
  const sourceIP = sourceItem.ip || summary.top_source_ip || "";
  const sourceASN = sourceItem.asn ? formatASN(sourceItem.asn) : "";
  const sourceActor = sourceItem.known_actor || sourceItem.actor_value || actorLabelFromType(sourceItem.actor_type);
  const targetPath = targetItem.path || summary.top_path || "";
  const targetErrors = Number(targetItem.status_4xx || 0) + Number(targetItem.status_5xx || 0) + (Number(targetItem.status || 0) >= 400 ? 1 : 0);
  const signalErrors = Number(signalItem.status_4xx || 0) + Number(signalItem.status_5xx || 0) + (Number(signalItem.status || 0) >= 400 ? 1 : 0);
  const signalKey = signalLead ? reportSignalKey(signalLead.key, signalItem) : "";
  const periodLogs = reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", origin: "report_path" });
  const errorLogs = reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", status_class: "errors", origin: "report_path" });
  const steps = [
    {
      label: "Period",
      value: reportListLabel(report),
      meta: [reportWindowLabel(report), report.model || "local"].filter(Boolean).join(" / "),
      actions: [
        reportActionButton("Open report", reportPivot(report, { kind: "report", value: reportKey(report), report_tab: reportTabForReport(report), site_id: report.site_id || "", origin: "report_path" })),
        reportActionButton("Period logs", periodLogs),
      ].join(""),
    },
    {
      label: "Scope",
      value: siteID ? siteLabel(siteID) || siteID : "All sites",
      meta: [
        `${formatNumber(summary.requests || 0)} requests`,
        `${formatPercent(summary.status_5xx_rate || 0)} 5xx`,
        summary.issue_count ? `${formatNumber(summary.issue_count)} issues` : "",
      ].filter(Boolean).join(" / "),
      actions: [
        siteID ? reportActionButton("Open site", reportPivot(report, { kind: "site", value: siteID, site_id: siteID, origin: "report_path" })) : "",
        reportActionButton("Error logs", errorLogs),
      ].filter(Boolean).join(""),
    },
    {
      label: "Top source",
      value: sourceIP || sourceActor || sourceASN || "No source",
      meta: [
        sourceActor,
        sourceASN,
        sourceItem.asn_org || sourceItem.network || "",
        sourceItem.requests ? `${formatNumber(sourceItem.requests)} requests` : "",
      ].filter(Boolean).join(" / "),
      actions: [
        sourceIP ? reportActionButton("Open IP", reportPivot(report, { kind: "ip", value: sourceIP, site_id: sourceSiteID, origin: "report_path" })) : "",
        sourceASN ? reportActionButton("Open ASN", reportPivot(report, { kind: "asn", value: sourceASN, site_id: sourceSiteID, origin: "report_path" })) : "",
        sourceActor ? reportActionButton("Open actor", reportPivot(report, { kind: "actor", value: sourceActor, actor_type: sourceItem.actor_type || "", site_id: sourceSiteID, origin: "report_path" })) : "",
        sourceIP || sourceASN || sourceActor ? reportActionButton("Source logs", reportPivot(report, { kind: "log_filter", ip: sourceIP, asn: sourceASN, known_actor: sourceActor || "", actor_type: sourceItem.actor_type || "", site_id: sourceSiteID, origin: "report_path" })) : "",
      ].filter(Boolean).join(""),
    },
    {
      label: "Top target",
      value: targetPath || (targetSiteID ? siteLabel(targetSiteID) || targetSiteID : "No target"),
      meta: [
        targetLead?.title || "",
        targetItem.requests ? `${formatNumber(targetItem.requests)} requests` : "",
        targetErrors ? `${formatNumber(targetErrors)} errors` : "",
        targetItem.p95_request_time_ms ? `p95 ${formatMs(targetItem.p95_request_time_ms)}` : "",
      ].filter(Boolean).join(" / "),
      actions: [
        targetPath ? reportActionButton("Open path", reportPivot(report, { kind: "path", value: targetPath, site_id: targetSiteID, origin: "report_path" })) : "",
        targetSiteID ? reportActionButton("Open site", reportPivot(report, { kind: "site", value: targetSiteID, site_id: targetSiteID, origin: "report_path" })) : "",
        targetPath ? reportActionButton("Target logs", reportPivot(report, { kind: "log_filter", path: targetPath, site_id: targetSiteID, status_class: targetErrors ? "errors" : "", origin: "report_path" })) : "",
      ].filter(Boolean).join(""),
    },
    {
      label: "Signal",
      value: signalLead ? signalLead.title || formatCategory(signalLead.key) : "No signal",
      meta: signalLead ? reportLeadMeta(signalItem, signalErrors) : "No stored signal drilldown for this report",
      actions: [
        signalKey ? reportActionButton("Open signal", reportPivot(report, {
          kind: "signal",
          key: signalKey,
          site_id: signalItem.site_id || siteID,
          ip: signalItem.ip || "",
          path: signalItem.path || "",
          known_actor: signalItem.actor_value || signalItem.known_actor || "",
          status_class: signalErrors || Number(signalItem.status || 0) >= 400 ? "errors" : "",
          origin: "report_path",
          report_tab: reportTabForReport(report),
        })) : "",
        reportActionButton("Signal logs", reportPivot(report, {
          kind: "log_filter",
          path: signalItem.path || targetPath,
          ip: signalItem.ip || sourceIP,
          site_id: signalItem.site_id || siteID,
          status_class: signalErrors || targetErrors ? "errors" : "",
          origin: "report_path",
        })),
      ].filter(Boolean).join(""),
    },
    {
      label: "Raw evidence",
      value: `${formatNumber(evidenceRows.length)} rows`,
      meta: [
        "Evidence matrix",
        targetPath ? "path context" : "",
        sourceIP ? "source context" : "",
      ].filter(Boolean).join(" / "),
      actions: [
        reportActionButton("Access", reportPivot(report, { kind: "log_filter", path: targetPath, ip: sourceIP, site_id: targetSiteID || sourceSiteID || report.site_id || "", log_type: "nginx-access", origin: "report_path" })),
        reportActionButton("Nginx", reportPivot(report, { kind: "log_filter", path: targetPath, ip: sourceIP, site_id: targetSiteID || sourceSiteID || report.site_id || "", log_type: "nginx-error", status_class: targetErrors || signalErrors ? "errors" : "", origin: "report_path" })),
        reportActionButton("PHP", reportPivot(report, { kind: "log_filter", path: targetPath, ip: sourceIP, site_id: targetSiteID || sourceSiteID || report.site_id || "", log_type: "php-error", status_class: targetErrors || signalErrors ? "errors" : "", origin: "report_path" })),
      ].join(""),
    },
  ];
  return `
    <section class="report-path-board" aria-label="Report period investigation path">
      ${steps.map(reportPeriodPathStep).join("")}
    </section>
  `;
}

function reportPeriodPathStep(step) {
  return `
    <div class="report-path-step">
      <div>
        <span>${escapeHTML(step.label || "-")}</span>
        <strong>${escapeHTML(step.value || "-")}</strong>
        <small>${escapeHTML(step.meta || "")}</small>
      </div>
      <div class="signal-actions">${step.actions || ""}</div>
    </div>
  `;
}

function reportInvestigationBoard(report) {
  const rows = reportInvestigationRows(report);
  return `
    <section class="report-investigation-board" aria-label="Report investigation next steps">
      <div class="entity-next-title">
        <span>Investigation path</span>
        <strong>${escapeHTML(reportWindowLabel(report) || report.range || "current report")}</strong>
      </div>
      <div class="entity-next-list report-investigation-list">
        ${rows.map(reportInvestigationRow).join("")}
      </div>
    </section>
  `;
}

function reportEvidenceMatrix(report) {
  const rows = reportEvidenceRows(report).slice(0, 14);
  return `
    <section class="report-evidence-panel" aria-label="Report evidence matrix">
      <div class="entity-next-title">
        <span>Evidence matrix</span>
        <strong>${escapeHTML(rows.length ? `${formatNumber(rows.length)} rows` : "no rows")}</strong>
      </div>
      <div class="table-wrap report-evidence-wrap">
        <table class="report-evidence-table">
          <thead>
            <tr>
              <th>Evidence</th>
              <th>Scope</th>
              <th>Requests</th>
              <th>Risk / errors</th>
              <th>Latest</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            ${rows.map((row) => reportEvidenceRow(report, row)).join("") || emptyRow(6, "No report evidence rows are stored for this period.")}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function reportEvidenceRows(report) {
  const summary = report.summary || {};
  const defs = [
    ["issues", "Issue", "signal"],
    ["admin_probes", "Admin probe", "security"],
    ["injection_probes", "Injection probe", "security"],
    ["tor_sources", "Tor source", "security"],
    ["source_ips", "Source IP", "source"],
    ["top_paths", "Top path", "path"],
    ["slow_paths", "Slow path", "reliability"],
    ["recent_errors", "Recent error", "reliability"],
  ];
  const seen = new Set();
  const rows = [];
  defs.forEach(([key, label, lane]) => {
    const drilldown = (report.drilldowns || []).find((item) => item.key === key);
    (drilldown?.items || []).forEach((item, index) => {
      const siteID = item.site_id || report.site_id || "";
      const title = item.label || item.ip || item.path || item.actor_value || item.known_actor || item.rule_key || label;
      const identity = [key, siteID, item.ip || "", item.path || "", title].join("|");
      if (seen.has(identity)) return;
      seen.add(identity);
      const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0) + (Number(item.status || 0) >= 400 ? 1 : 0);
      rows.push({
        key,
        label: drilldown?.title || label,
        lane,
        index,
        title,
        item,
        siteID,
        env: item.env || "",
        ip: item.ip || "",
        asn: item.asn ? formatASN(item.asn) : "",
        path: item.path || "",
        actor: item.known_actor || item.actor_value || actorLabelFromType(item.actor_type) || "",
        actorType: item.actor_type || "",
        userAgent: item.user_agent || item.sample || "",
        requests: Number(item.requests || item.events || 0) || (item.status ? 1 : 0),
        errors,
        risk: Number(item.risk_score || item.score || 0),
        status: item.status || "",
        p95: Number(item.p95_request_time_ms || 0),
        latest: item.last_seen || item.last_seen_at || item.ts || item.timestamp || item.max_ts || "",
        signalKey: reportSignalKey(key, item),
      });
    });
  });
  if (!rows.length) {
    if (summary.top_source_ip) {
      rows.push(reportEvidenceSummaryRow("source_ips", "Top source IP", "source", report, { ip: summary.top_source_ip, requests: summary.requests || 0 }));
    }
    if (summary.top_path) {
      rows.push(reportEvidenceSummaryRow("top_paths", "Top path", "path", report, { path: summary.top_path, requests: summary.requests || 0 }));
    }
    if (summary.top_site) {
      rows.push(reportEvidenceSummaryRow("site", "Top site", "site", report, { siteID: summary.top_site, requests: summary.requests || 0 }));
    }
  }
  return rows.sort((a, b) => {
    return Number(b.errors || 0) - Number(a.errors || 0)
      || Number(b.risk || 0) - Number(a.risk || 0)
      || Number(b.requests || 0) - Number(a.requests || 0)
      || new Date(b.latest || 0) - new Date(a.latest || 0);
  });
}

function reportEvidenceSummaryRow(key, label, lane, report, fields = {}) {
  return {
    key,
    label,
    lane,
    title: fields.ip || fields.path || fields.siteID || label,
    item: {},
    siteID: fields.siteID || report.site_id || "",
    env: "",
    ip: fields.ip || "",
    asn: "",
    path: fields.path || "",
    actor: "",
    actorType: "",
    userAgent: "",
    requests: Number(fields.requests || 0),
    errors: 0,
    risk: 0,
    status: "",
    p95: 0,
    latest: report.range_end || report.created_at || "",
    signalKey: "",
  };
}

function reportEvidenceRow(report, row) {
  const actions = reportEvidenceActions(report, row);
  const scope = [
    row.siteID ? siteLabel(row.siteID) || row.siteID : report.site_id || "All sites",
    row.env,
  ].filter(Boolean).join(" / ");
  const meta = [
    row.lane ? formatCategory(row.lane) : "",
    row.path || "",
    row.ip ? `IP ${row.ip}` : "",
    row.asn || "",
    row.actor || "",
    row.userAgent ? shortLabel(row.userAgent, 68) : "",
  ].filter(Boolean).join(" / ");
  return `
    <tr>
      <td class="clip"><strong>${escapeHTML(row.title || row.label || "-")}</strong><br><span>${escapeHTML([row.label, meta].filter(Boolean).join(" - "))}</span></td>
      <td><strong>${escapeHTML(scope || "All sites")}</strong><br><span>${escapeHTML(row.siteID || report.site_id || "report scope")}</span></td>
      <td>${formatNumber(row.requests || 0)}<br><span>${row.p95 ? `p95 ${formatMs(row.p95)}` : ""}</span></td>
      <td>${escapeHTML(reportEvidenceRiskLabel(row))}<br><span>${escapeHTML(reportEvidenceStatusLabel(row))}</span></td>
      <td>${formatTime(row.latest)}</td>
      <td class="row-actions">${actions}</td>
    </tr>
  `;
}

function reportEvidenceActions(report, row) {
  const primary = [];
  const details = [];
  const logs = [reportActionButton("Access", reportEvidenceLogPivot(report, row, "nginx-access", false))];
  if (row.signalKey) primary.push(reportActionButton("Signal", reportSignalPivot(report, row.key, row.item, row.signalKey, row.siteID, row.errors)));
  if (row.siteID) primary.push(reportActionButton("Site", reportPivot(report, { kind: "site", value: row.siteID, site_id: row.siteID, origin: "report_matrix" })));
  if (row.ip) primary.push(reportActionButton("IP", reportPivot(report, { kind: "ip", value: row.ip, site_id: row.siteID, origin: "report_matrix" })));
  if (row.path) primary.push(reportActionButton("Path", reportPivot(report, { kind: "path", value: row.path, site_id: row.siteID, origin: "report_matrix" })));
  if (row.errors || Number(row.status || 0) >= 400) logs.push(reportActionButton("Errors", reportEvidenceLogPivot(report, row, "nginx-access", true)));
  if (row.errors || row.path) logs.push(reportActionButton("Nginx", reportEvidenceLogPivot(report, row, "nginx-error", true)));
  if (row.errors || row.path) logs.push(reportActionButton("PHP", reportEvidenceLogPivot(report, row, "php-error", true)));
  if (row.asn) details.push(reportActionButton("ASN", reportPivot(report, { kind: "asn", value: row.asn, site_id: row.siteID, origin: "report_matrix" })));
  if (row.actor) details.push(reportActionButton("Actor", reportPivot(report, { kind: "actor", value: row.actor, actor_type: row.actorType, site_id: row.siteID, origin: "report_matrix" })));
  return [...primary, ...logs, ...details].filter(Boolean).slice(0, 9).join("");
}

function reportEvidenceLogPivot(report, row, logType, errorsOnly) {
  return reportPivot(report, {
    kind: "log_filter",
    site_id: row.siteID || report.site_id || "",
    path: row.path || "",
    ip: row.ip || "",
    asn: row.asn || "",
    known_actor: row.actor || "",
    actor_type: row.actorType || "",
    user_agent: row.userAgent || "",
    status_class: errorsOnly ? "errors" : "",
    log_type: logType,
    origin: "report_matrix",
  });
}

function reportEvidenceRiskLabel(row) {
  if (row.risk) return `risk ${formatNumber(row.risk)}`;
  if (row.status) return String(row.status);
  if (row.p95) return formatMs(row.p95);
  return row.errors ? `${formatNumber(row.errors)} errors` : "-";
}

function reportEvidenceStatusLabel(row) {
  const parts = [];
  if (row.errors) parts.push(`${formatNumber(row.errors)} errors`);
  if (row.status) parts.push(`status ${row.status}`);
  if (row.actorType) parts.push(formatCategory(row.actorType));
  return parts.join(" / ") || formatCategory(row.lane || "evidence");
}

function reportInvestigationRows(report) {
  const summary = report.summary || {};
  const scopedSite = report.site_id || summary.top_site || "";
  const securityLead = reportLeadFor(report, ["admin_probes", "injection_probes", "tor_sources", "issues"]);
  const reliabilityLead = reportLeadFor(report, ["slow_paths", "recent_errors", "top_paths"], (item, key) => {
    if (key === "top_paths") return Number(item.status_5xx || 0) > 0 || Number(item.status_4xx || 0) > 0;
    return true;
  });
  const sourceLead = reportLeadFor(report, ["source_ips", "tor_sources", "admin_probes", "injection_probes"]);
  return [
    {
      title: "Scope and period",
      meta: [report.site_id || "All sites", reportWindowLabel(report), report.model || ""].filter(Boolean).join(" - "),
      valueLabel: "requests",
      value: formatNumber(summary.requests || 0),
      actions: [
        scopedSite ? reportActionButton("Open site", reportPivot(report, { kind: "site", value: scopedSite, site_id: scopedSite, origin: "report_next" })) : "",
        reportActionButton("Report logs", reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", origin: "report_next" })),
        reportActionButton("Error logs", reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", status_class: "errors", origin: "report_next" })),
      ].filter(Boolean).join(""),
    },
    reportLeadRow(report, securityLead, {
      fallbackTitle: "Security lead",
      fallbackMeta: "No stored security drilldown rows for this report.",
      fallbackActions: reportActionButton("Security logs", reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", status_class: "errors", origin: "report_next" })),
    }),
    reportLeadRow(report, reliabilityLead, {
      fallbackTitle: "Reliability lead",
      fallbackMeta: "No stored reliability drilldown rows for this report.",
      fallbackActions: reportActionButton("Error logs", reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", status_class: "errors", origin: "report_next" })),
    }),
    reportLeadRow(report, sourceLead, {
      fallbackTitle: "Source pressure",
      fallbackMeta: "No source IP drilldown rows for this report.",
      fallbackActions: summary.top_source_ip
        ? reportActionButton("Open top IP", reportPivot(report, { kind: "ip", value: summary.top_source_ip, site_id: report.site_id || "", origin: "report_next" }))
        : reportActionButton("Source logs", reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", origin: "report_next" })),
    }),
  ];
}

function reportLeadFor(report, keys, predicate = () => true) {
  for (const key of keys) {
    const drilldown = (report?.drilldowns || []).find((item) => item.key === key);
    const item = (drilldown?.items || []).find((candidate) => predicate(candidate, key));
    if (item) return { key, item, title: drilldown.title || formatCategory(key) };
  }
  return null;
}

function reportLeadRow(report, lead, fallback) {
  if (!lead?.item) {
    return {
      title: fallback.fallbackTitle,
      meta: fallback.fallbackMeta,
      valueLabel: "status",
      value: "quiet",
      actions: fallback.fallbackActions || "",
    };
  }
  const item = lead.item;
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  return {
    title: lead.title || formatCategory(lead.key),
    meta: reportLeadMeta(item, errors),
    valueLabel: reportLeadValueLabel(item),
    value: reportDrilldownValue(item),
    actions: reportLeadActions(report, lead.key, item, errors),
  };
}

function reportLeadMeta(item, errors) {
  const primary = item.label || item.ip || item.path || item.actor_value || item.known_actor || "";
  return [
    primary,
    reportDrilldownMeta(item, errors),
  ].filter(Boolean).join(" - ") || "Report drilldown row";
}

function reportLeadValueLabel(item) {
  if (item.risk_score || item.score) return "risk";
  if (item.status) return "status";
  if (item.p95_request_time_ms) return "p95";
  return "requests";
}

function reportLeadActions(report, key, item, errors) {
  const siteID = item.site_id || report.site_id || "";
  const signalKey = reportSignalKey(key, item);
  const actions = [];
  if (signalKey) actions.push(reportActionButton("Open signal", reportSignalPivot(report, key, item, signalKey, siteID, errors)));
  if (siteID) actions.push(reportActionButton("Open site", reportPivot(report, { kind: "site", value: siteID, site_id: siteID, origin: "report_next" })));
  if (item.ip) actions.push(reportActionButton("Open IP", reportPivot(report, { kind: "ip", value: item.ip, site_id: siteID, origin: "report_next" })));
  if (item.asn) actions.push(reportActionButton("Open ASN", reportPivot(report, { kind: "asn", value: formatASN(item.asn), site_id: siteID, origin: "report_next" })));
  const actorValue = item.known_actor || item.actor_value || actorLabelFromType(item.actor_type);
  if (actorValue) {
    actions.push(reportActionButton("Open actor", reportPivot(report, {
      kind: "actor",
      value: actorValue,
      actor_type: item.actor_type || "",
      site_id: siteID,
      origin: "report_next",
    })));
  }
  if (item.path) actions.push(reportActionButton("Open path", reportPivot(report, { kind: "path", value: item.path, site_id: siteID, origin: "report_next" })));
  actions.push(reportActionButton("Open logs", reportPivot(report, {
    kind: "log_filter",
    path: item.path || "",
    ip: item.ip || "",
    asn: item.asn ? formatASN(item.asn) : "",
    known_actor: item.known_actor || item.actor_value || "",
    actor_type: item.actor_type || "",
    site_id: siteID,
    status_class: errors || Number(item.status || 0) >= 400 ? "errors" : "",
    origin: "report_next",
  })));
  return actions.filter(Boolean).slice(0, 5).join("");
}

function reportActionButton(label, pivot) {
  if (!pivot) return "";
  return `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(pivot)}'>${escapeHTML(label)}</button>`;
}

function reportInvestigationRow(item) {
  return `
    <div class="signal-row entity-next-row report-investigation-row">
      <div>
        <strong>${escapeHTML(item.title || "-")}</strong>
        <span>${escapeHTML(item.meta || "")}</span>
        <div class="signal-actions">${item.actions || ""}</div>
      </div>
      <div class="signal-numbers">
        <span>${escapeHTML(item.valueLabel || "")}</span>
        <b>${escapeHTML(item.value ?? "")}</b>
      </div>
    </div>
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
  const insight = reportChartInsight(report, chart);
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
      ${insight}
    </article>
  `;
}

function reportChartInsight(report, chart) {
  const lead = reportChartLeadDatum(chart);
  if (!lead) return "";
  const actions = reportChartDatumActions(report, chart, lead).join("");
  const contextRows = reportChartContextRows(report, chart, lead);
  return `
    <div class="report-chart-insight">
      <div class="report-chart-lead">
        <span>${escapeHTML(reportChartLeadLabel(chart))}</span>
        <strong>${escapeHTML(reportChartDatumTitle(chart, lead))}</strong>
        <small>${escapeHTML(reportChartDatumMeta(chart, lead))}</small>
      </div>
      <div class="report-chart-pivots">
        <div class="signal-actions">${actions || reportActionButton("Open report logs", reportPivot(report, { kind: "log_filter", site_id: report.site_id || "", origin: "report_chart_datum" }))}</div>
      </div>
      ${contextRows.length ? `<div class="report-chart-context">${contextRows.map(reportChartContextRow).join("")}</div>` : ""}
    </div>
  `;
}

function reportChartLeadDatum(chart) {
  const rows = (chart.data || []).filter((item) => item && (Number(item.value || 0) || Number(item.secondary || 0)));
  if (!rows.length) return null;
  if (chart.key === "status_mix") {
    return rows.find((item) => item.label === "5xx" && Number(item.value || 0) > 0)
      || rows.find((item) => item.label === "4xx" && Number(item.value || 0) > 0)
      || rows.slice().sort(reportDatumValueSort)[0];
  }
  if (chart.key === "traffic_timeline") {
    return rows.slice().sort((a, b) => {
      return Number(b.secondary || 0) - Number(a.secondary || 0)
        || Number(b.value || 0) - Number(a.value || 0)
        || new Date(b.timestamp || 0) - new Date(a.timestamp || 0);
    })[0];
  }
  return rows.slice().sort(reportDatumValueSort)[0];
}

function reportDatumValueSort(a, b) {
  return Number(b.value || 0) - Number(a.value || 0)
    || Number(b.secondary || 0) - Number(a.secondary || 0)
    || String(a.label || "").localeCompare(String(b.label || ""));
}

function reportChartLeadLabel(chart) {
  if (chart.key === "status_mix") return "Error bucket";
  if (chart.key === "traffic_timeline") return "Peak bucket";
  if (chart.key === "site_traffic") return "Top site";
  if (chart.key === "source_ips") return "Top source";
  if (chart.key === "slow_paths") return "Slowest path";
  if (chart.key === "security_signals") return "Primary signal family";
  if (chart.key === "user_agent_classes") return "Top user-agent class";
  return "Top datum";
}

function reportChartDatumTitle(chart, datum) {
  if (chart.key === "traffic_timeline" && datum.timestamp) return shortDateTime(datum.timestamp);
  return datum.label || chart.title || chart.key || "Chart datum";
}

function reportChartDatumMeta(chart, datum) {
  const unit = chart.unit || "value";
  const parts = [
    `${formatNumber(datum.value || 0)} ${unit}`,
    Number(datum.secondary || 0) ? `${formatNumber(datum.secondary)} ${reportChartSecondaryLabel(chart)}` : "",
    datum.meta || "",
  ];
  return parts.filter(Boolean).join(" / ");
}

function reportChartSecondaryLabel(chart) {
  if (chart.key === "traffic_timeline" || chart.key === "source_ips") return "errors";
  if (chart.key === "site_traffic") return "5xx";
  if (chart.key === "security_signals") return "rows";
  if (chart.key === "slow_paths") return "requests";
  return "secondary";
}

function reportChartDatumActions(report, chart, datum) {
  const key = chart.key || "";
  const siteID = report.site_id || "";
  const actions = [];
  const add = (label, pivot) => {
    const button = reportActionButton(label, pivot);
    if (button) actions.push(button);
  };
  if (key === "traffic_timeline") {
    add("Open period logs", reportPivot(report, { kind: "log_filter", site_id: siteID, origin: "report_chart_datum" }));
    if (Number(datum.secondary || 0)) add("Error rows", reportPivot(report, { kind: "log_filter", site_id: siteID, status_class: "errors", origin: "report_chart_datum" }));
  } else if (key === "status_mix") {
    const errorsOnly = ["4xx", "5xx"].includes(String(datum.label || ""));
    add(errorsOnly ? "Open error rows" : "Open matching logs", reportPivot(report, { kind: "log_filter", site_id: siteID, status_class: errorsOnly ? "errors" : "", origin: "report_chart_datum" }));
  } else if (key === "site_traffic") {
    const chartSiteID = reportChartSiteID(datum);
    if (chartSiteID) add("Open site", reportPivot(report, { kind: "site", value: chartSiteID, site_id: chartSiteID, origin: "report_chart_datum" }));
    add("Site logs", reportPivot(report, { kind: "log_filter", site_id: chartSiteID || siteID, status_class: Number(datum.secondary || 0) ? "errors" : "", origin: "report_chart_datum" }));
  } else if (key === "source_ips") {
    const item = reportDrilldownItemFor(report, "source_ips", (candidate) => candidate.ip === datum.label) || {};
    add("Open IP", reportPivot(report, { kind: "ip", value: datum.label, site_id: item.site_id || siteID, origin: "report_chart_datum" }));
    add("IP logs", reportPivot(report, { kind: "log_filter", ip: datum.label, site_id: item.site_id || siteID, status_class: Number(datum.secondary || 0) ? "errors" : "", origin: "report_chart_datum" }));
    if (item.asn) add("ASN", reportPivot(report, { kind: "asn", value: formatASN(item.asn), site_id: item.site_id || siteID, origin: "report_chart_datum" }));
  } else if (key === "user_agent_classes") {
    add("Class logs", reportPivot(report, { kind: "log_filter", actor_type: datum.label || "", site_id: siteID, origin: "report_chart_datum" }));
  } else if (key === "security_signals") {
    const signalPivot = reportChartSecurityPivot(report, datum);
    add("Open signal", signalPivot);
    add("Security logs", reportPivot(report, { kind: "log_filter", site_id: siteID, status_class: "errors", origin: "report_chart_datum" }));
  } else if (key === "slow_paths") {
    const item = reportDrilldownItemFor(report, "slow_paths", (candidate) => candidate.path === datum.label)
      || reportDrilldownItemFor(report, "top_paths", (candidate) => candidate.path === datum.label)
      || {};
    add("Open path", reportPivot(report, { kind: "path", value: datum.label, site_id: item.site_id || siteID, origin: "report_chart_datum" }));
    add("Path logs", reportPivot(report, { kind: "log_filter", path: datum.label, site_id: item.site_id || siteID, status_class: "errors", origin: "report_chart_datum" }));
  } else {
    add("Open logs", reportPivot(report, { kind: "log_filter", site_id: siteID, origin: "report_chart_datum" }));
  }
  return actions.slice(0, 4);
}

function reportChartSiteID(datum) {
  return String(datum.label || "").split("/")[0] || "";
}

function reportChartSecurityPivot(report, datum) {
  const label = String(datum.label || "").toLowerCase();
  const key = label.includes("injection") ? "injection_probes"
    : label.includes("admin") ? "admin_probes"
      : label.includes("tor") ? "tor_sources"
        : "issues";
  const item = reportFirstDrilldownItem(report, key);
  if (!item) return null;
  const signalKey = reportSignalKey(key, item);
  if (!signalKey) return null;
  const errors = Number(item.status_4xx || 0) + Number(item.status_5xx || 0);
  return reportSignalPivot(report, key, item, signalKey, item.site_id || report.site_id || "", errors);
}

function reportChartContextRows(report, chart, lead) {
  const rows = [];
  const summary = report.summary || {};
  const total = (chart.data || []).reduce((sum, item) => sum + Number(item.value || 0), 0);
  rows.push(["Chart total", `${formatNumber(total)} ${chart.unit || "value"}`]);
  if (lead?.value && total) rows.push(["Lead share", formatPercent(ratio(lead.value, total))]);
  if (summary.top_site) rows.push(["Report top site", summary.top_site]);
  if (summary.top_source_ip && chart.key !== "source_ips") rows.push(["Top source IP", summary.top_source_ip]);
  if (summary.top_path && chart.key !== "slow_paths") rows.push(["Top path", summary.top_path]);
  return rows.slice(0, 4);
}

function reportChartContextRow([label, value]) {
  return `
    <div>
      <span>${escapeHTML(label)}</span>
      <strong>${escapeHTML(value || "-")}</strong>
    </div>
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
    ${item.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "asn", value: formatASN(item.asn), site_id: siteID, origin: "report" }))}'>Open ASN</button>` : ""}
    ${item.path ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "path", value: item.path, site_id: siteID, origin: "report" }))}'>Open path</button>` : ""}
    ${item.path || item.ip || item.asn ? `<button class="ghost mini inline-action" type="button" data-pivot='${encodePivot(reportPivot(report, { kind: "log_filter", path: item.path || "", ip: item.ip || "", asn: item.asn ? formatASN(item.asn) : "", site_id: siteID, status_class: errors || item.status >= 400 ? "errors" : "", origin: "report" }))}'>Open logs</button>` : ""}
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
  drawSiteTabCharts();
  drawReportCharts();
}

function drawSiteTabCharts() {
  const siteID = state.siteDetailID || state.siteID || "";
  if (!siteID) return;
  drawTimeline(qs("#siteOverviewTrendChart"), siteTrendRows(siteID, "overview"), ["requests", "errors"]);
  drawTimeline(qs("#siteSecurityTrendChart"), siteTrendRows(siteID, "security"), ["probes", "errors"]);
  drawTimeline(qs("#siteReliabilityTrendChart"), siteTrendRows(siteID, "reliability"), ["requests", "errors"]);
  drawBars(qs("#siteActorMixChart"), siteActorMixRows(siteID));
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

function normalizeSiteTab(tab) {
  return ["overview", "security", "reliability", "actors", "paths", "logs", "reports"].includes(tab) ? tab : "overview";
}

function normalizeSiteStatusFilter(status) {
  return ["all", "degraded", "elevated", "watch", "stale", "healthy"].includes(status) ? status : "all";
}

function normalizeSiteSort(sort) {
  return ["risk", "traffic", "5xx", "signals", "freshness", "name"].includes(sort) ? sort : "risk";
}

function siteSortLabel(sort) {
  return {
    risk: "Risk first",
    traffic: "Traffic",
    "5xx": "5xx",
    signals: "Signals",
    freshness: "Freshness",
    name: "Name",
  }[normalizeSiteSort(sort)] || "Risk first";
}

function normalizeReportTab(tab) {
  return ["daily", "weekly", "monthly", "quarterly", "annual"].includes(tab) ? tab : "daily";
}

function normalizeSignalSeverity(value) {
  const normalized = String(value || "").toLowerCase();
  return ["medium", "high", "critical"].includes(normalized) ? normalized : "all";
}

function signalSeverityLabel(value) {
  const severity = normalizeSignalSeverity(value);
  if (severity === "all") return "All";
  return severity === "critical" ? "Critical" : `${formatCategory(severity)}+`;
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
  if (pivot.kind === "signal_filter") {
    state.entity = null;
    state.signalKey = "";
    state.signalFilter = pivot.signal_filter || pivot.group || state.signalFilter || "all";
    showRoute("signals", true);
    if (needsRefresh) await refreshWithValidation();
    else renderSignals();
    return;
  }
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
  if (pivot.kind === "asn") {
    state.signalKey = "";
    state.entity = { kind: "asn", value: formatASN(pivot.value || pivot.asn) || pivot.value || pivot.asn || "" };
    showRoute("investigate", true);
    if (needsRefresh) await refreshWithValidation();
    else renderInvestigate();
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
  if (pivot.kind === "user-agent") {
    state.signalKey = "";
    state.entity = { kind: "user-agent", value: pivot.value || pivot.user_agent || "" };
    showRoute("investigate", true);
    if (needsRefresh) await refreshWithValidation();
    else renderInvestigate();
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
  ["ip", "asn", "path", "known_actor", "actor_type", "status_class", "site_id", "env", "user_agent", "evidence_kind", "severity"].forEach((key) => {
    if (!pivot[key]) return;
    if (key === "severity") {
      const severity = normalizeSignalSeverity(pivot[key]);
      if (severity !== "all") context.severity = severity;
      return;
    }
    context[key] = pivot[key];
  });
  if (pivot.kind === "ip" && pivot.value) context.ip = pivot.value;
  if (pivot.kind === "asn" && (pivot.value || pivot.asn)) context.asn = formatASN(pivot.value || pivot.asn) || pivot.value || pivot.asn;
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
        ["ASN", item.asn ? formatASN(item.asn) : "-"],
        ["ASN org", item.asn_org || "-"],
        ["Network", item.network || "-"],
        ["Country", item.country_code || "-"],
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
  const asnValue = asn.asn || stored.asn || item.asn;
  const asnName = asn.name || stored.asn_org || item.asn_org;
  const network = asn.prefix || stored.network || item.network || (rdap.cidrs || []).join(", ");
  const country = asn.country_code || stored.country_code || item.country_code || rdap.country_code;
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
          ["ASN", asnValue ? formatASN(asnValue) : "-"],
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

function setHTML(selector, value) {
  const el = qs(selector);
  if (el) el.innerHTML = value;
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
