package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"originpulse/internal/accessanalysis"
	"originpulse/internal/alerts"
	"originpulse/internal/analytics"
	"originpulse/internal/auth"
	"originpulse/internal/combiner"
	"originpulse/internal/config"
	"originpulse/internal/db"
	"originpulse/internal/frontend"
	"originpulse/internal/indexer"
	"originpulse/internal/investigation"
	"originpulse/internal/ipintel"
	"originpulse/internal/jobs"
	"originpulse/internal/notifications"
	"originpulse/internal/pantheon"
	"originpulse/internal/pipeline"
	"originpulse/internal/reports"
	"originpulse/internal/retention"
	"originpulse/internal/sites"
)

type Dependencies struct {
	Config         config.Config
	DB             *db.Store
	Auth           *auth.Service
	Sites          *sites.Repository
	RawFiles       *pantheon.RawFileRepository
	Combiner       *combiner.Service
	Segments       *combiner.Repository
	Indexer        *indexer.Service
	Analytics      *analytics.Service
	AccessAnalysis *accessanalysis.Service
	Investigation  *investigation.Service
	IPIntel        *ipintel.Service
	Alerts         *alerts.Service
	Reports        *reports.Service
	Notifications  *notifications.Service
	Retention      *retention.Service
	Jobs           *jobs.Store
	Collector      *pantheon.Collector
	Pipeline       *pipeline.Service
}

type API struct {
	cfg            config.Config
	db             *db.Store
	auth           *auth.Service
	sites          *sites.Repository
	rawFiles       *pantheon.RawFileRepository
	combiner       *combiner.Service
	segments       *combiner.Repository
	indexer        *indexer.Service
	analytics      *analytics.Service
	accessAnalysis *accessanalysis.Service
	investigation  *investigation.Service
	ipIntel        *ipintel.Service
	alerts         *alerts.Service
	reports        *reports.Service
	notifications  *notifications.Service
	retention      *retention.Service
	jobs           *jobs.Store
	collector      *pantheon.Collector
	pipeline       *pipeline.Service
	startedAt      time.Time
}

func NewRouter(deps Dependencies) http.Handler {
	api := API{
		cfg:            deps.Config,
		db:             deps.DB,
		auth:           deps.Auth,
		sites:          deps.Sites,
		rawFiles:       deps.RawFiles,
		combiner:       deps.Combiner,
		segments:       deps.Segments,
		indexer:        deps.Indexer,
		analytics:      deps.Analytics,
		accessAnalysis: deps.AccessAnalysis,
		investigation:  deps.Investigation,
		ipIntel:        deps.IPIntel,
		alerts:         deps.Alerts,
		reports:        deps.Reports,
		notifications:  deps.Notifications,
		retention:      deps.Retention,
		jobs:           deps.Jobs,
		collector:      deps.Collector,
		pipeline:       deps.Pipeline,
		startedAt:      time.Now().UTC(),
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(secureHeaders)

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/healthz", api.healthz)
		r.Get("/auth/me", api.me)
		r.Post("/auth/login", api.login)
		r.Post("/auth/logout", api.logout)

		r.Group(func(r chi.Router) {
			r.Use(api.requireAuth)
			r.Get("/dashboard/overview", api.dashboardOverview)
			r.Get("/analysis/access-log", api.accessLogAnalysis)
			r.Get("/investigate/traffic", api.investigateTraffic)
			r.Get("/investigate/ip/{ip}", api.ipDetails)
			r.Get("/alerts", api.openAlerts)
			r.Post("/alerts/evaluate", api.evaluateAlerts)
			r.Get("/reports/recent", api.recentReports)
			r.Post("/reports/generate", api.generateReport)
			r.Post("/reports/daily/generate", api.generateDailyReport)
			r.Get("/notifications", api.notificationStatus)
			r.Post("/notifications/send", api.sendNotifications)
			r.Post("/notifications/test", api.testNotifications)
			r.Get("/notifications/web-push/public-key", api.webPushPublicKey)
			r.Post("/notifications/web-push/subscribe", api.subscribeWebPush)
			r.Delete("/notifications/web-push/subscribe", api.unsubscribeWebPush)
			r.Get("/sites", api.listSites)
			r.Get("/system/credentials", api.credentials)
			r.Get("/system/collector-health", api.collectorHealth)
			r.Get("/system/jobs", api.recentJobs)
			r.Get("/system/retention", api.retentionDryRun)
			r.Get("/system/collection-plan", api.collectionPlan)
			r.Get("/system/segments", api.recentSegments)
			r.Post("/system/collect", api.collectNow)
			r.Post("/system/combine", api.combineNow)
			r.Post("/system/index", api.indexSegment)
			r.Post("/system/pipeline", api.runPipeline)
			r.Post("/system/retention", api.runRetention)
			r.Post("/system/refresh-ip-intel", api.refreshIPIntel)
			r.Get("/users", api.listUsers)
			r.Post("/users", api.createUser)
			r.Patch("/users/{id}", api.updateUser)
			r.Delete("/users/{id}", api.deleteUser)
		})
	})

	r.Mount("/", frontend.Handler())
	return r
}

func (api API) healthz(w http.ResponseWriter, r *http.Request) {
	dbOK := false
	if api.db != nil && api.db.Enabled() {
		dbOK = api.db.Ping(r.Context()) == nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"service":    "originpulse",
		"started_at": api.startedAt,
		"uptime_sec": int64(time.Since(api.startedAt).Seconds()),
		"database": map[string]any{
			"configured": api.db != nil && api.db.Enabled(),
			"ok":         dbOK,
		},
	})
}

func (api API) dashboardOverview(w http.ResponseWriter, r *http.Request) {
	stats := api.jobs.Stats()
	siteList, err := api.sites.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sites_failed", err.Error())
		return
	}
	credentials := api.cfg.CredentialSummary()
	from, to, err := parseTimeFilters(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_time_window", err.Error())
		return
	}
	analyticsOverview, err := api.analytics.DashboardOverviewFor(r.Context(), analytics.Options{
		Range:  r.URL.Query().Get("range"),
		SiteID: r.URL.Query().Get("site_id"),
		From:   from,
		To:     to,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dashboard_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service":             "OriginPulse",
		"api_base":            "/api/v1",
		"auth_required":       api.auth.Enabled(),
		"database_configured": api.db != nil && api.db.Enabled(),
		"sites_enabled":       len(siteList),
		"collection_enabled":  api.cfg.Collection.Enabled,
		"collection_interval": api.cfg.Collection.Interval.String(),
		"retention_enabled":   api.cfg.Retention.Enabled,
		"retention_max_age":   api.cfg.Retention.MaxAge.String(),
		"raw_dir":             api.cfg.RawDir(),
		"machine_token":       credentials.MachineTokenConfigured,
		"ssh_key":             credentials.SSHKeyConfigured,
		"analytics":           analyticsOverview,
		"jobs": map[string]int{
			"running": int(stats[jobs.StatusRunning]),
			"skipped": int(stats[jobs.StatusSkipped]),
			"success": int(stats[jobs.StatusSuccess]),
			"failed":  int(stats[jobs.StatusFailed]),
		},
		"next_steps": []string{
			"Add real site UUIDs in config.yml",
			"Mount an SSH private key accepted by Pantheon",
			"Enable collection when ready",
		},
	})
}

func (api API) accessLogAnalysis(w http.ResponseWriter, r *http.Request) {
	if api.accessAnalysis == nil {
		writeJSON(w, http.StatusOK, accessanalysis.Report{})
		return
	}

	from, to, err := parseTimeFilters(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_time_window", err.Error())
		return
	}
	report, err := api.accessAnalysis.Analyze(r.Context(), accessanalysis.Options{
		Range:  r.URL.Query().Get("range"),
		Limit:  parseLimit(r, 25, 250),
		SiteID: r.URL.Query().Get("site_id"),
		From:   from,
		To:     to,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "access_log_analysis_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (api API) investigateTraffic(w http.ResponseWriter, r *http.Request) {
	if api.investigation == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"database_enabled": false,
			"top_ips":          []investigation.IPSummary{},
			"top_paths":        []investigation.PathSummary{},
			"recent_errors":    []investigation.EventSummary{},
			"status_breakdown": []investigation.StatusSummary{},
			"timeline":         []investigation.TimelineBucket{},
		})
		return
	}

	from, to, err := parseTimeFilters(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_time_window", err.Error())
		return
	}
	traffic, err := api.investigation.Traffic(r.Context(), investigation.Options{
		Range:  r.URL.Query().Get("range"),
		Limit:  parseLimit(r, 10, 100),
		SiteID: r.URL.Query().Get("site_id"),
		From:   from,
		To:     to,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "investigation_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, traffic)
}

func (api API) ipDetails(w http.ResponseWriter, r *http.Request) {
	if api.ipIntel == nil {
		writeJSON(w, http.StatusOK, ipintel.Detail{DatabaseEnabled: false})
		return
	}

	from, to, err := parseTimeFilters(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_time_window", err.Error())
		return
	}
	detail, err := api.ipIntel.Details(r.Context(), ipintel.DetailOptions{
		IP:     chi.URLParam(r, "ip"),
		Range:  r.URL.Query().Get("range"),
		Limit:  parseLimit(r, 8, 25),
		SiteID: r.URL.Query().Get("site_id"),
		From:   from,
		To:     to,
	})
	if err != nil {
		if errors.Is(err, ipintel.ErrInvalidIP) {
			writeError(w, http.StatusBadRequest, "invalid_ip", "IP address is invalid")
			return
		}
		writeError(w, http.StatusInternalServerError, "ip_details_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (api API) openAlerts(w http.ResponseWriter, r *http.Request) {
	if api.alerts == nil {
		writeJSON(w, http.StatusOK, map[string]any{"alerts": []alerts.Alert{}})
		return
	}

	openAlerts, err := api.alerts.Open(r.Context(), parseLimit(r, 25, 100))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "alerts_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": openAlerts})
}

func (api API) evaluateAlerts(w http.ResponseWriter, r *http.Request) {
	if api.alerts == nil {
		writeJSON(w, http.StatusOK, alerts.Result{})
		return
	}

	req := struct {
		Range string `json:"range"`
		Limit int    `json:"limit"`
	}{
		Range: r.URL.Query().Get("range"),
		Limit: parseLimit(r, 50, 500),
	}
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "bad_json", "request body must be JSON")
			return
		}
	}
	if req.Range == "" {
		req.Range = r.URL.Query().Get("range")
	}
	if req.Limit <= 0 {
		req.Limit = parseLimit(r, 50, 500)
	}

	result, err := api.alerts.Evaluate(r.Context(), alerts.Options{
		Range: req.Range,
		Limit: req.Limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "alert_evaluation_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (api API) refreshIPIntel(w http.ResponseWriter, r *http.Request) {
	if api.ipIntel == nil {
		writeJSON(w, http.StatusOK, ipintel.Result{})
		return
	}

	req := struct {
		Range string `json:"range"`
		Limit int    `json:"limit"`
	}{
		Range: r.URL.Query().Get("range"),
		Limit: parseLimit(r, 25, 250),
	}
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "bad_json", "request body must be JSON")
			return
		}
	}
	if req.Range == "" {
		req.Range = r.URL.Query().Get("range")
	}
	if req.Limit <= 0 {
		req.Limit = parseLimit(r, 25, 250)
	}

	result, err := api.ipIntel.RefreshTop(r.Context(), ipintel.Options{
		Range: req.Range,
		Limit: req.Limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ip_intel_refresh_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (api API) recentReports(w http.ResponseWriter, r *http.Request) {
	if api.reports == nil {
		writeJSON(w, http.StatusOK, map[string]any{"reports": []reports.Report{}})
		return
	}

	recentReports, err := api.reports.Recent(r.Context(), parseLimit(r, 25, 100), r.URL.Query().Get("site_id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reports_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": recentReports})
}

func (api API) generateReport(w http.ResponseWriter, r *http.Request) {
	if api.reports == nil {
		writeJSON(w, http.StatusOK, reports.Report{})
		return
	}

	req := struct {
		Range      string `json:"range"`
		ReportType string `json:"report_type"`
		SiteID     string `json:"site_id"`
	}{
		Range:  r.URL.Query().Get("range"),
		SiteID: r.URL.Query().Get("site_id"),
	}
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "bad_json", "request body must be JSON")
			return
		}
	}
	if req.Range == "" {
		req.Range = r.URL.Query().Get("range")
	}
	if req.SiteID == "" {
		req.SiteID = r.URL.Query().Get("site_id")
	}

	report, err := api.reports.Generate(r.Context(), reports.Options{Range: req.Range, ReportType: req.ReportType, SiteID: req.SiteID})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report_generation_failed", err.Error())
		return
	}
	writeReport(w, http.StatusOK, report)
}

func (api API) generateDailyReport(w http.ResponseWriter, r *http.Request) {
	if api.reports == nil {
		writeJSON(w, http.StatusOK, reports.Report{})
		return
	}

	req := struct {
		Range  string `json:"range"`
		SiteID string `json:"site_id"`
	}{
		Range:  r.URL.Query().Get("range"),
		SiteID: r.URL.Query().Get("site_id"),
	}
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "bad_json", "request body must be JSON")
			return
		}
	}
	if req.Range == "" {
		req.Range = r.URL.Query().Get("range")
	}
	if req.SiteID == "" {
		req.SiteID = r.URL.Query().Get("site_id")
	}

	report, err := api.reports.Daily(r.Context(), reports.Options{Range: req.Range, SiteID: req.SiteID})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report_generation_failed", err.Error())
		return
	}
	writeReport(w, http.StatusOK, report)
}

func (api API) notificationStatus(w http.ResponseWriter, r *http.Request) {
	if api.notifications == nil {
		writeJSON(w, http.StatusOK, notifications.Status{})
		return
	}
	status, err := api.notifications.Status(r.Context(), parseLimit(r, 25, 100))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notifications_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (api API) sendNotifications(w http.ResponseWriter, r *http.Request) {
	if api.notifications == nil {
		writeJSON(w, http.StatusOK, notifications.Result{})
		return
	}
	result, err := api.notifications.NotifyOpenAlerts(r.Context(), parseLimit(r, 100, 500))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notifications_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (api API) testNotifications(w http.ResponseWriter, r *http.Request) {
	if api.notifications == nil {
		writeJSON(w, http.StatusOK, notifications.Result{})
		return
	}
	result, err := api.notifications.Test(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notifications_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (api API) webPushPublicKey(w http.ResponseWriter, r *http.Request) {
	if api.notifications == nil {
		writeJSON(w, http.StatusOK, notifications.WebPushStatus{})
		return
	}
	status, err := api.notifications.WebPushStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "web_push_status_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (api API) subscribeWebPush(w http.ResponseWriter, r *http.Request) {
	if api.notifications == nil {
		writeError(w, http.StatusServiceUnavailable, "notifications_unavailable", "notifications are unavailable")
		return
	}
	user, err := api.authenticatedUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "login required")
		return
	}
	var subscription webpush.Subscription
	if err := json.NewDecoder(r.Body).Decode(&subscription); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", "request body must be a PushSubscription JSON object")
		return
	}
	saved, err := api.notifications.SaveWebPushSubscription(r.Context(), user.ID, r.UserAgent(), subscription)
	if err != nil {
		writeError(w, http.StatusBadRequest, "web_push_subscribe_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscription": saved})
}

func (api API) unsubscribeWebPush(w http.ResponseWriter, r *http.Request) {
	if api.notifications == nil {
		writeError(w, http.StatusServiceUnavailable, "notifications_unavailable", "notifications are unavailable")
		return
	}
	user, err := api.authenticatedUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "login required")
		return
	}
	var req struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_json", "request body must be JSON")
		return
	}
	if err := api.notifications.DeleteWebPushSubscription(r.Context(), user.ID, req.Endpoint); err != nil {
		writeError(w, http.StatusBadRequest, "web_push_unsubscribe_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (api API) listSites(w http.ResponseWriter, r *http.Request) {
	siteList, err := api.sites.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sites_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sites": siteList,
	})
}

func (api API) credentials(w http.ResponseWriter, r *http.Request) {
	summary := api.collector.CredentialSummary()
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": summary,
		"requirements": map[string]any{
			"log_downloads": []string{
				"Pantheon site UUID and environment",
				"SSH private key for a Pantheon user with site access",
				"SFTP/SSH access to env.site_uuid@appserver.env.site_uuid.drush.in on port 2222",
			},
			"machine_token": "Optional for this first log downloader; required later if OriginPulse uses Terminus to discover sites or manage Pantheon resources.",
		},
	})
}

func (api API) recentJobs(w http.ResponseWriter, r *http.Request) {
	limit := parseLimit(r, 25, 100)
	writeJSON(w, http.StatusOK, map[string]any{
		"jobs": api.jobs.Recent(limit),
	})
}

func (api API) collectorHealth(w http.ResponseWriter, r *http.Request) {
	stats, err := api.rawFiles.Stats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "collector_health_failed", err.Error())
		return
	}

	recent, err := api.rawFiles.Recent(r.Context(), 25)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "collector_health_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"database_configured": api.db != nil && api.db.Enabled(),
		"raw_files": map[string]any{
			"stats":  stats,
			"recent": recent,
		},
	})
}

func (api API) retentionDryRun(w http.ResponseWriter, r *http.Request) {
	if api.retention == nil || !api.retention.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "retention_unavailable", "retention requires DATABASE_URL")
		return
	}
	result, err := api.retention.Run(r.Context(), retention.Options{DryRun: true})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "retention_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (api API) runRetention(w http.ResponseWriter, r *http.Request) {
	if api.retention == nil || !api.retention.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "retention_unavailable", "retention requires DATABASE_URL")
		return
	}
	req := struct {
		DryRun bool `json:"dry_run"`
	}{}
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "bad_json", "request body must be JSON")
			return
		}
	}
	result, err := api.retention.Run(r.Context(), retention.Options{DryRun: req.DryRun})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "retention_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (api API) collectionPlan(w http.ResponseWriter, r *http.Request) {
	targets, err := api.collector.Plan(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "collection_plan_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"targets": targets,
	})
}

func (api API) recentSegments(w http.ResponseWriter, r *http.Request) {
	limit := parseLimit(r, 25, 100)
	segments, err := api.segments.RecentSegments(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "segments_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"segments": segments})
}

func (api API) combineNow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LogType string `json:"log_type"`
		From    string `json:"from"`
		To      string `json:"to"`
		Force   bool   `json:"force"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", "request body must be JSON")
		return
	}
	from, err := parseAPITime(req.From)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_from", err.Error())
		return
	}
	to, err := parseAPITime(req.To)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_to", err.Error())
		return
	}
	result, err := api.combiner.Combine(r.Context(), combiner.Options{
		LogType: req.LogType,
		From:    from,
		To:      to,
		Force:   req.Force,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "combine_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (api API) indexSegment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SegmentPath string `json:"segment_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", "request body must be JSON")
		return
	}
	result, err := api.indexer.IndexSegment(r.Context(), indexer.Options{SegmentPath: req.SegmentPath})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "index_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (api API) runPipeline(w http.ResponseWriter, r *http.Request) {
	if api.pipeline == nil || !api.pipeline.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "pipeline_unavailable", "pipeline requires DATABASE_URL")
		return
	}

	var req struct {
		From        string   `json:"from"`
		To          string   `json:"to"`
		Force       bool     `json:"force"`
		SkipCombine bool     `json:"skip_combine"`
		LogTypes    []string `json:"log_types"`
		MaxSegments int      `json:"max_segments"`
	}
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "bad_json", "request body must be JSON")
			return
		}
	}

	if req.From == "" && req.To == "" {
		result, err := api.pipeline.RunRecent(r.Context(), "api")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "pipeline_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}

	from, err := parseAPITime(req.From)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_from", err.Error())
		return
	}
	to, err := parseAPITime(req.To)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_to", err.Error())
		return
	}
	result, err := api.pipeline.Run(r.Context(), pipeline.Options{
		From:        from,
		To:          to,
		Force:       req.Force,
		SkipCombine: req.SkipCombine,
		LogTypes:    req.LogTypes,
		MaxSegments: req.MaxSegments,
		TriggeredBy: "api",
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "pipeline_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (api API) collectNow(w http.ResponseWriter, r *http.Request) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		_ = api.collector.CollectAll(ctx)
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted": true,
	})
}

func (api API) me(w http.ResponseWriter, r *http.Request) {
	if !api.auth.Enabled() {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
			"auth_required": false,
		})
		return
	}

	cookie, err := r.Cookie(api.auth.CookieName())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "login required")
		return
	}

	user, err := api.auth.UserForToken(r.Context(), cookie.Value)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "login required")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"auth_required": true,
		"user":          user,
	})
}

func (api API) login(w http.ResponseWriter, r *http.Request) {
	if !api.auth.Enabled() {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
			"auth_required": false,
		})
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", "request body must be JSON")
		return
	}

	user, token, err := api.auth.Authenticate(r.Context(), req.Email, req.Password, r.UserAgent())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "email or password is incorrect")
			return
		}
		writeError(w, http.StatusInternalServerError, "login_failed", err.Error())
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     api.auth.CookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   api.auth.SecureCookies(),
		Expires:  time.Now().Add(api.cfg.Auth.SessionTTL),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"user":          user,
	})
}

func (api API) logout(w http.ResponseWriter, r *http.Request) {
	if api.auth.Enabled() {
		if cookie, err := r.Cookie(api.auth.CookieName()); err == nil {
			_ = api.auth.DeleteSession(r.Context(), cookie.Value)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     api.cfg.Auth.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   api.cfg.Auth.SecureCookies,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (api API) listUsers(w http.ResponseWriter, r *http.Request) {
	if !api.auth.Enabled() {
		writeJSON(w, http.StatusOK, map[string]any{"users": []auth.User{}})
		return
	}
	users, err := api.auth.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "users_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (api API) createUser(w http.ResponseWriter, r *http.Request) {
	if !api.auth.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "auth_unavailable", "user management requires DATABASE_URL")
		return
	}
	var req struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", "request body must be JSON")
		return
	}
	user, err := api.auth.CreateUser(r.Context(), req.Email, req.Password, req.DisplayName)
	if err != nil {
		writeError(w, http.StatusBadRequest, "user_create_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": user})
}

func (api API) updateUser(w http.ResponseWriter, r *http.Request) {
	if !api.auth.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "auth_unavailable", "user management requires DATABASE_URL")
		return
	}
	var req struct {
		Email       *string `json:"email"`
		Password    *string `json:"password"`
		DisplayName *string `json:"display_name"`
		IsActive    *bool   `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", "request body must be JSON")
		return
	}
	user, err := api.auth.UpdateUser(r.Context(), chi.URLParam(r, "id"), auth.UpdateUserOptions{
		Email:       req.Email,
		DisplayName: req.DisplayName,
		IsActive:    req.IsActive,
		Password:    req.Password,
	})
	if err != nil {
		writeUserError(w, err, "user_update_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (api API) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !api.auth.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "auth_unavailable", "user management requires DATABASE_URL")
		return
	}
	user, err := api.auth.DeleteUser(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeUserError(w, err, "user_delete_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (api API) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !api.auth.Enabled() {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(api.auth.CookieName())
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "login required")
			return
		}
		if _, err := api.auth.UserForToken(r.Context(), cookie.Value); err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "login required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (api API) authenticatedUser(r *http.Request) (auth.User, error) {
	if !api.auth.Enabled() {
		return auth.User{}, nil
	}
	cookie, err := r.Cookie(api.auth.CookieName())
	if err != nil {
		return auth.User{}, err
	}
	return api.auth.UserForToken(r.Context(), cookie.Value)
}

func writeUserError(w http.ResponseWriter, err error, fallbackCode string) {
	switch {
	case errors.Is(err, auth.ErrUserNotFound):
		writeError(w, http.StatusNotFound, "user_not_found", "user not found")
	case errors.Is(err, auth.ErrLastActiveUser):
		writeError(w, http.StatusConflict, "last_active_user", err.Error())
	default:
		writeError(w, http.StatusBadRequest, fallbackCode, err.Error())
	}
}

func writeReport(w http.ResponseWriter, status int, report reports.Report) {
	report.Input = nil
	writeJSON(w, status, report)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

func parseLimit(r *http.Request, defaultLimit int, maxLimit int) int {
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			if parsed > maxLimit {
				return maxLimit
			}
			return parsed
		}
	}
	return defaultLimit
}

func parseTimeFilters(r *http.Request) (time.Time, time.Time, error) {
	from, err := parseOptionalAPITime(r.URL.Query().Get("from"))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	to, err := parseOptionalAPITime(r.URL.Query().Get("to"))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !from.IsZero() && !to.IsZero() && !to.After(from) {
		return time.Time{}, time.Time{}, errors.New("to must be after from")
	}
	return from, to, nil
}

func parseOptionalAPITime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return parseAPITime(value)
}

func parseAPITime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err == nil {
		return parsed.UTC(), nil
	}
	parsed, err = time.Parse(time.RFC3339, value)
	if err == nil {
		return parsed.UTC(), nil
	}
	return time.Time{}, err
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
