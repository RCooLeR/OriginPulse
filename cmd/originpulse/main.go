package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"originpulse/internal/accessanalysis"
	"originpulse/internal/alerts"
	"originpulse/internal/app"
	"originpulse/internal/archive"
	"originpulse/internal/archivecoverage"
	"originpulse/internal/archiveimport"
	"originpulse/internal/backfill"
	"originpulse/internal/combiner"
	"originpulse/internal/config"
	"originpulse/internal/indexer"
	"originpulse/internal/investigation"
	"originpulse/internal/ipintel"
	"originpulse/internal/pipeline"
	"originpulse/internal/reports"
	"originpulse/internal/retention"
	"originpulse/internal/storageaudit"
)

func main() {
	os.Exit(run())
}

func run() int {
	zerolog.TimeFieldFormat = time.RFC3339Nano

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	command := "server"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}

	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to OriginPulse config file")
	email := fs.String("email", "", "user email for create-user")
	password := fs.String("password", "", "user password for create-user")
	displayName := fs.String("display-name", "", "display name for create-user")
	ipValue := fs.String("ip", "", "IP address for ip-details")
	logType := fs.String("log-type", "", "log type for combine/archive; empty uses command default")
	from := fs.String("from", "", "inclusive RFC3339 start time for combine")
	to := fs.String("to", "", "exclusive RFC3339 end time for combine")
	force := fs.Bool("force", false, "force regeneration where supported")
	segment := fs.String("segment", "", "combined segment path for index")
	logTypes := fs.String("log-types", "", "comma-separated log types for pipeline; empty uses configured collection log types")
	rangeValue := fs.String("range", "24h", "analysis range for alert/report commands")
	siteID := fs.String("site-id", "", "site id for analysis/report commands")
	maxSegments := fs.Int("max-segments", 100, "maximum pending segments to index")
	indexWorkers := fs.Int("index-workers", 0, "parallel pending segments to index; 0 uses config")
	skipCombine := fs.Bool("skip-combine", false, "skip combine phase and only index pending segments")
	dryRun := fs.Bool("dry-run", false, "show retention matches without deleting")
	temporaryImportsOnly := fs.Bool("temporary-imports-only", false, "only expire temporary archive imports during retention")
	batchSize := fs.Int("batch-size", 5000, "event batch size for maintenance commands")
	maxBatches := fs.Int("max-batches", 1, "maximum event batches for maintenance commands; 0 means all")
	noRollups := fs.Bool("no-rollups", false, "skip rollup rebuild/update work for maintenance commands")
	includeSecurity := fs.Bool("include-security", false, "include all security analysis sections")
	includeAdmin := fs.Bool("include-admin", false, "include admin probe analysis")
	includeInjection := fs.Bool("include-injection", false, "include injection probe analysis")
	includeTor := fs.Bool("include-tor", false, "include Tor/source intelligence analysis")
	includeQueryParams := fs.Bool("include-query-params", false, "include query parameter traffic analysis")
	securityOnly := fs.Bool("security-only", false, "only run requested security analysis sections")
	timings := fs.Bool("timings", false, "include maintenance timing output where supported")
	probeCategory := fs.String("probe-category", "", "security probe category filter")
	maxArchiveGroups := fs.Int("max-archive-groups", 25, "maximum archive groups to write")
	removeArchiveSources := fs.Bool("remove-archive-sources", false, "delete hourly combined files after successful archive")
	archiveID := fs.String("archive-id", "", "log archive id for import-archive")
	archivePath := fs.String("archive-path", "", "log archive path for import-archive")
	importReason := fs.String("reason", "", "reason for temporary archive import")
	reportType := fs.String("report-type", "", "report type for generate-report")
	reportID := fs.String("report-id", "", "stored report id")
	alertID := fs.String("alert-id", "", "stored alert id")
	healthURL := fs.String("url", "http://127.0.0.1:8080/health", "healthcheck URL")
	healthTimeout := fs.Duration("timeout", 5*time.Second, "healthcheck timeout")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	if command == "healthcheck" {
		if err := runHealthcheck(ctx, *healthURL, *healthTimeout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}

	if command == "web-push-keys" {
		privateKey, publicKey, err := webpush.GenerateVAPIDKeys()
		if err != nil {
			fmt.Fprintf(os.Stderr, "generate VAPID keys: %v\n", err)
			return 1
		}
		fmt.Printf("ORIGINPULSE_VAPID_PUBLIC_KEY=%s\n", publicKey)
		fmt.Printf("ORIGINPULSE_VAPID_PRIVATE_KEY=%s\n", privateKey)
		fmt.Println("ORIGINPULSE_VAPID_SUBJECT=mailto:originpulse@localhost")
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}

	level, err := zerolog.ParseLevel(cfg.App.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	runtime, err := app.New(ctx, cfg)
	if err != nil {
		log.Error().Err(err).Msg("create runtime")
		return 1
	}
	defer runtime.Close()

	switch command {
	case "server":
		if err := runtime.RunServer(ctx); err != nil {
			log.Error().Err(err).Msg("server stopped with error")
			return 1
		}
	case "collect":
		if err := runtime.CollectOnce(ctx); err != nil {
			log.Error().Err(err).Msg("collection failed")
			return 1
		}
	case "combine":
		fromTime, err := parseCLITime(*from)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -from: %v\n", err)
			return 2
		}
		toTime, err := parseCLITime(*to)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -to: %v\n", err)
			return 2
		}
		result, err := runtime.Combine(ctx, combiner.Options{
			LogType: *logType,
			From:    fromTime,
			To:      toTime,
			Force:   *force,
		})
		if err != nil {
			log.Error().Err(err).Msg("combine failed")
			return 1
		}
		fmt.Printf("segments_written: %d\n", result.SegmentsWritten)
		fmt.Printf("lines_combined: %d\n", result.LinesCombined)
		fmt.Printf("lines_quarantined: %d\n", result.LinesQuarantined)
	case "index":
		result, err := runtime.IndexSegment(ctx, indexer.Options{SegmentPath: *segment, Force: *force})
		if err != nil {
			log.Error().Err(err).Msg("index failed")
			return 1
		}
		fmt.Printf("segment_status: %s\n", result.SegmentStatus)
		fmt.Printf("already_indexed: %t\n", result.AlreadyIndexed)
		fmt.Printf("events_seen: %d\n", result.EventsSeen)
		fmt.Printf("valid_events: %d\n", result.ValidEvents)
		fmt.Printf("invalid_events: %d\n", result.InvalidEvents)
		fmt.Printf("events_stored_before: %d\n", result.EventsStoredBefore)
		fmt.Printf("events_deleted: %d\n", result.EventsDeleted)
		fmt.Printf("events_inserted: %d\n", result.EventsInserted)
		fmt.Printf("log_events_inserted: %d\n", result.LogEventsInserted)
		fmt.Printf("events_conflicted: %d\n", result.EventsConflicted)
		fmt.Printf("events_stored: %d\n", result.EventsStored)
		fmt.Printf("events_skipped: %d\n", result.EventsSkipped)
		fmt.Printf("rollups_updated: %d\n", result.RollupsUpdated)
		fmt.Printf("security_probes: %d\n", result.SecurityProbes)
		fmt.Printf("error_events: %d\n", result.ErrorEvents)
		fmt.Printf("slow_request_events: %d\n", result.SlowRequestEvents)
	case "pipeline":
		var fromTime time.Time
		var toTime time.Time
		if !*skipCombine {
			var err error
			fromTime, err = parseCLITime(*from)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -from: %v\n", err)
				return 2
			}
			toTime, err = parseCLITime(*to)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -to: %v\n", err)
				return 2
			}
		}
		result, err := runtime.RunPipeline(ctx, pipeline.Options{
			From:         fromTime,
			To:           toTime,
			Force:        *force,
			SkipCombine:  *skipCombine,
			LogTypes:     splitCSV(*logTypes),
			MaxSegments:  *maxSegments,
			IndexWorkers: *indexWorkers,
			TriggeredBy:  "cli",
		})
		if err != nil {
			log.Error().Err(err).Msg("pipeline failed")
			return 1
		}
		fmt.Printf("combined_segments: %d\n", result.CombinedSegments)
		fmt.Printf("lines_combined: %d\n", result.LinesCombined)
		fmt.Printf("lines_quarantined: %d\n", result.LinesQuarantined)
		fmt.Printf("indexed_segments: %d\n", result.IndexedSegments)
		fmt.Printf("events_inserted: %d\n", result.EventsInserted)
		fmt.Printf("log_events_inserted: %d\n", result.LogEventsInserted)
		fmt.Printf("events_stored: %d\n", result.EventsStored)
		fmt.Printf("events_skipped: %d\n", result.EventsSkipped)
		fmt.Printf("rollups_updated: %d\n", result.RollupsUpdated)
		fmt.Printf("rollups_repaired: %d\n", result.RollupsRepaired)
		fmt.Printf("rollups_recovered: %d\n", result.RollupsRecovered)
		fmt.Printf("security_probes: %d\n", result.SecurityProbes)
		fmt.Printf("error_events: %d\n", result.ErrorEvents)
		fmt.Printf("slow_request_events: %d\n", result.SlowRequests)
	case "migrate":
		if err := runtime.Migrate(ctx); err != nil {
			log.Error().Err(err).Msg("migration failed")
			return 1
		}
		fmt.Println("migrations: ok")
	case "evaluate-alerts":
		result, err := runtime.EvaluateAlerts(ctx, alerts.Options{Range: *rangeValue, Limit: *maxSegments})
		if err != nil {
			log.Error().Err(err).Msg("alert evaluation failed")
			return 1
		}
		fmt.Printf("range: %s\n", result.Range)
		fmt.Printf("since: %s\n", result.Since.Format(time.RFC3339))
		fmt.Printf("evaluated: %d\n", result.Evaluated)
		fmt.Printf("upserted: %d\n", result.Upserted)
		fmt.Printf("open_alerts: %d\n", len(result.OpenAlerts))
	case "alert-detail":
		if strings.TrimSpace(*alertID) == "" {
			fmt.Fprintln(os.Stderr, "alert-detail requires -alert-id")
			return 2
		}
		result, err := runtime.AlertDetail(ctx, *alertID, *maxSegments)
		if err != nil {
			log.Error().Err(err).Msg("alert detail failed")
			return 1
		}
		fmt.Printf("id: %s\n", result.Alert.ID)
		fmt.Printf("rule: %s\n", result.Alert.RuleKey)
		fmt.Printf("actor: %s/%s\n", result.Alert.ActorType, result.Alert.ActorValue)
		fmt.Printf("requests: %d\n", len(result.Requests))
	case "analyze-access":
		var fromTime time.Time
		var toTime time.Time
		if *from != "" || *to != "" {
			var err error
			fromTime, err = parseCLITime(*from)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -from: %v\n", err)
				return 2
			}
			toTime, err = parseCLITime(*to)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -to: %v\n", err)
				return 2
			}
		}
		result, err := runtime.AnalyzeAccess(ctx, accessanalysis.Options{
			Range:                  *rangeValue,
			SiteID:                 *siteID,
			Limit:                  *maxSegments,
			From:                   fromTime,
			To:                     toTime,
			IncludeSecurity:        *includeSecurity,
			IncludeAdminProbes:     *includeAdmin,
			IncludeInjectionProbes: *includeInjection,
			IncludeTorSources:      *includeTor,
			SecurityOnly:           *securityOnly,
			ProbeCategory:          *probeCategory,
			IncludeTimings:         *timings,
		})
		if err != nil {
			log.Error().Err(err).Msg("access analysis failed")
			return 1
		}
		fmt.Printf("range: %s\n", result.Range)
		fmt.Printf("site_id: %s\n", result.SiteID)
		fmt.Printf("since: %s\n", result.Since.Format(time.RFC3339))
		fmt.Printf("until: %s\n", result.Until.Format(time.RFC3339))
		fmt.Printf("requests: %d\n", result.Totals.Requests)
		fmt.Printf("unique_ips: %d\n", result.Totals.UniqueIPs)
		fmt.Printf("unique_user_agents: %d\n", result.Totals.UniqueUserAgents)
		fmt.Printf("user_agents: %d\n", len(result.UserAgents))
		fmt.Printf("slow_paths: %d\n", len(result.SlowPaths))
		fmt.Printf("admin_probes: %d\n", len(result.AdminProbes))
		fmt.Printf("injection_probes: %d\n", len(result.InjectionProbes))
		fmt.Printf("tor_sources: %d\n", len(result.TorSources))
		fmt.Printf("log_event_totals: %d\n", len(result.LogEventTotals))
		fmt.Printf("log_messages: %d\n", len(result.LogMessages))
		fmt.Printf("log_events: %d\n", len(result.LogEvents))
		fmt.Printf("issues: %d\n", len(result.Issues))
		for _, timing := range result.Timings {
			fmt.Printf("timing_%s_ms: %d\n", timing.Name, timing.DurationMS)
		}
	case "investigate-traffic":
		var fromTime time.Time
		var toTime time.Time
		if *from != "" || *to != "" {
			var err error
			fromTime, err = parseCLITime(*from)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -from: %v\n", err)
				return 2
			}
			toTime, err = parseCLITime(*to)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -to: %v\n", err)
				return 2
			}
		}
		result, err := runtime.InvestigateTraffic(ctx, investigation.Options{
			Range:              *rangeValue,
			SiteID:             *siteID,
			Limit:              *maxSegments,
			From:               fromTime,
			To:                 toTime,
			IncludeQueryParams: *includeQueryParams,
			IncludeTimings:     *timings,
		})
		if err != nil {
			log.Error().Err(err).Msg("traffic investigation failed")
			return 1
		}
		fmt.Printf("range: %s\n", result.Range)
		fmt.Printf("site_id: %s\n", result.SiteID)
		fmt.Printf("since: %s\n", result.Since.Format(time.RFC3339))
		fmt.Printf("until: %s\n", result.Until.Format(time.RFC3339))
		fmt.Printf("top_ips: %d\n", len(result.TopIPs))
		fmt.Printf("top_paths: %d\n", len(result.TopPaths))
		fmt.Printf("recent_errors: %d\n", len(result.RecentErrors))
		fmt.Printf("query_params: %d\n", len(result.QueryParams))
		fmt.Printf("status_breakdown: %d\n", len(result.StatusBreakdown))
		fmt.Printf("timeline: %d\n", len(result.Timeline))
		for _, timing := range result.Timings {
			fmt.Printf("timing_%s_ms: %d\n", timing.Name, timing.DurationMS)
		}
	case "reports-recent":
		result, err := runtime.RecentReports(ctx, *maxSegments, *siteID)
		if err != nil {
			log.Error().Err(err).Msg("recent reports failed")
			return 1
		}
		fmt.Printf("reports: %d\n", len(result))
		for _, item := range result {
			fmt.Printf("%s\t%s\t%s\t%s\tcharts=%d\tdrilldowns=%d\tpreview=%d\n",
				item.ID,
				item.ReportType,
				item.Range,
				item.CreatedAt.Format(time.RFC3339),
				len(item.Charts),
				len(item.Drilldowns),
				len(item.OutputPreview),
			)
		}
	case "generate-report":
		item, err := runtime.GenerateReport(ctx, reports.Options{Range: *rangeValue, SiteID: *siteID, ReportType: *reportType})
		if err != nil {
			log.Error().Err(err).Msg("report generation failed")
			return 1
		}
		_, hasAudit := item.Input["fast_read_audit"].(reports.FastReadAudit)
		fmt.Printf("id: %s\n", item.ID)
		fmt.Printf("type: %s\n", item.ReportType)
		fmt.Printf("range: %s\n", item.Range)
		fmt.Printf("stored: %t\n", item.Stored)
		fmt.Printf("fast_read_audit: %t\n", hasAudit)
		fmt.Printf("charts: %d\n", len(item.Charts))
		fmt.Printf("drilldowns: %d\n", len(item.Drilldowns))
		fmt.Printf("output_bytes: %d\n", len(item.Output))
	case "report-detail":
		if strings.TrimSpace(*reportID) == "" {
			fmt.Fprintln(os.Stderr, "report-detail requires -report-id")
			return 2
		}
		item, err := runtime.ReportDetail(ctx, *reportID)
		if err != nil {
			log.Error().Err(err).Msg("report detail failed")
			return 1
		}
		fmt.Printf("id: %s\n", item.ID)
		fmt.Printf("type: %s\n", item.ReportType)
		fmt.Printf("range: %s\n", item.Range)
		fmt.Printf("summary: %t\n", item.Summary != nil)
		fmt.Printf("charts: %d\n", len(item.Charts))
		fmt.Printf("drilldowns: %d\n", len(item.Drilldowns))
		fmt.Printf("output_bytes: %d\n", len(item.Output))
	case "reports-fast-read-audit":
		result, err := runtime.ReportFastReadAudit(ctx, reports.FastReadAuditOptions{Range: *rangeValue, SiteID: *siteID})
		if err != nil {
			log.Error().Err(err).Msg("report fast-read audit failed")
			return 1
		}
		fmt.Printf("range: %s\n", result.Range)
		fmt.Printf("site_id: %s\n", result.SiteID)
		fmt.Printf("since: %s\n", result.Since.Format(time.RFC3339))
		fmt.Printf("until: %s\n", result.Until.Format(time.RFC3339))
		fmt.Printf("dimension_rollups_ready: %t\n", result.DimensionRollupsReady)
		fmt.Printf("status_rollups_ready: %t\n", result.StatusRollupsReady)
		fmt.Printf("full_range_events: %d\n", result.FullRangeEvents)
		fmt.Printf("minute_edge_events: %d\n", result.MinuteEdgeEvents)
		fmt.Printf("hour_edge_events: %d\n", result.HourEdgeEvents)
		fmt.Printf("unbackfilled_full_hour_events: %d\n", result.UnbackfilledFullHourEvents)
		fmt.Printf("recent_error_fact_rows: %d\n", result.RecentErrorFactRows)
		fmt.Printf("recent_error_raw_gap_rows: %d\n", result.RecentErrorRawGapRows)
		fmt.Printf("security_probe_fact_rows: %d\n", result.SecurityProbeFactRows)
		fmt.Printf("overview_source: %s\n", result.OverviewSource)
		fmt.Printf("access_analysis_source: %s\n", result.AccessAnalysisSource)
		fmt.Printf("traffic_source: %s\n", result.TrafficSource)
		fmt.Printf("recent_errors_source: %s\n", result.RecentErrorsSource)
		fmt.Printf("alerts_source: %s\n", result.AlertsSource)
		fmt.Printf("report_catalog_source: %s\n", result.ReportCatalogSource)
		fmt.Printf("expected_raw_range_aggregations: %t\n", result.ExpectedRawRangeAggregations)
		fmt.Printf("expected_raw_edge_rows: %d\n", result.ExpectedRawEdgeRows)
		fmt.Printf("expected_raw_gap_rows: %d\n", result.ExpectedRawGapRows)
	case "ip-details":
		var fromTime time.Time
		var toTime time.Time
		if *from != "" || *to != "" {
			var err error
			fromTime, err = parseCLITime(*from)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -from: %v\n", err)
				return 2
			}
			toTime, err = parseCLITime(*to)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -to: %v\n", err)
				return 2
			}
		}
		result, err := runtime.IPDetails(ctx, ipintel.DetailOptions{IP: *ipValue, Range: *rangeValue, SiteID: *siteID, Limit: *maxSegments, From: fromTime, To: toTime})
		if err != nil {
			log.Error().Err(err).Msg("IP details failed")
			return 1
		}
		fmt.Printf("ip: %s\n", result.IP)
		fmt.Printf("range: %s\n", result.Range)
		fmt.Printf("requests: %d\n", result.Traffic.Requests)
		fmt.Printf("unique_paths: %d\n", result.Traffic.UniquePaths)
		fmt.Printf("unique_user_agents: %d\n", result.Traffic.UniqueUserAgents)
		fmt.Printf("sites: %d\n", len(result.Sites))
		fmt.Printf("top_paths: %d\n", len(result.TopPaths))
		fmt.Printf("url_hits: %d\n", len(result.URLHits))
		fmt.Printf("recent_requests: %d\n", len(result.RecentRequests))
		fmt.Printf("top_user_agents: %d\n", len(result.TopUserAgents))
	case "refresh-ip-intel":
		result, err := runtime.RefreshIPIntel(ctx, ipintel.Options{Range: *rangeValue, Limit: *maxSegments})
		if err != nil {
			log.Error().Err(err).Msg("IP intelligence refresh failed")
			return 1
		}
		fmt.Printf("range: %s\n", result.Range)
		fmt.Printf("since: %s\n", result.Since.Format(time.RFC3339))
		fmt.Printf("refreshed: %d\n", result.Refreshed)
		fmt.Printf("failed: %d\n", result.Failed)
		fmt.Printf("lookup_failed: %d\n", result.LookupFailed)
		fmt.Printf("geoip_failed: %d\n", result.GeoIPFailed)
		fmt.Printf("reverse_dns_failed: %d\n", result.ReverseDNSFailed)
		fmt.Printf("items: %d\n", len(result.Items))
	case "create-user":
		userPassword := *password
		if userPassword == "" {
			userPassword = os.Getenv("ORIGINPULSE_CREATE_USER_PASSWORD")
		}
		if *email == "" || userPassword == "" {
			fmt.Fprintln(os.Stderr, "create-user requires -email and -password or ORIGINPULSE_CREATE_USER_PASSWORD")
			return 2
		}
		user, err := runtime.CreateUser(ctx, *email, userPassword, *displayName)
		if err != nil {
			log.Error().Err(err).Msg("create user failed")
			return 1
		}
		fmt.Printf("user: %s <%s>\n", user.ID, user.Email)
	case "retention":
		result, err := runtime.RunRetention(ctx, retention.Options{DryRun: *dryRun, TemporaryImportsOnly: *temporaryImportsOnly})
		if err != nil {
			log.Error().Err(err).Msg("retention failed")
			return 1
		}
		fmt.Printf("enabled: %t\n", result.Enabled)
		fmt.Printf("dry_run: %t\n", result.DryRun)
		fmt.Printf("temporary_imports_only: %t\n", result.TemporaryImportsOnly)
		fmt.Printf("raw_file_cutoff: %s\n", result.RawFileCutoff.Format(time.RFC3339))
		fmt.Printf("hot_event_cutoff: %s\n", result.HotEventCutoff.Format(time.RFC3339))
		fmt.Printf("archive_cutoff: %s\n", result.ArchiveCutoff.Format(time.RFC3339))
		fmt.Printf("report_cutoff: %s\n", result.ReportCutoff.Format(time.RFC3339))
		fmt.Printf("temporary_import_cutoff: %s\n", result.TemporaryImportCutoff.Format(time.RFC3339))
		fmt.Printf("raw_file_max_age: %s\n", result.RawFileMaxAge)
		fmt.Printf("hot_event_max_age: %s\n", result.HotEventMaxAge)
		fmt.Printf("archive_max_age: %s\n", result.ArchiveMaxAge)
		fmt.Printf("report_max_age: %s\n", result.ReportMaxAge)
		fmt.Printf("temporary_import_max_age: %s\n", result.TemporaryImportMaxAge)
		fmt.Printf("raw_files_matched: %d\n", result.RawFilesMatched)
		fmt.Printf("raw_bytes_matched: %d\n", result.RawBytesMatched)
		fmt.Printf("combined_segments_matched: %d\n", result.CombinedSegmentsMatched)
		fmt.Printf("access_events_matched: %d\n", result.AccessEventsMatched)
		fmt.Printf("rollups_matched: %d\n", result.RollupsMatched)
		fmt.Printf("reports_matched: %d\n", result.ReportsMatched)
		fmt.Printf("temporary_imports_matched: %d\n", result.TemporaryImportsMatched)
		fmt.Printf("temporary_events_matched: %d\n", result.TemporaryEventsMatched)
		fmt.Printf("temporary_facts_matched: %d\n", result.TemporaryFactsMatched)
		fmt.Printf("archive_files_matched: %d\n", result.ArchiveFilesMatched)
		fmt.Printf("raw_files_deleted: %d\n", result.RawFilesDeleted)
		fmt.Printf("combined_segments_deleted: %d\n", result.CombinedSegmentsDeleted)
		fmt.Printf("access_events_deleted: %d\n", result.AccessEventsDeleted)
		fmt.Printf("rollups_deleted: %d\n", result.RollupsDeleted)
		fmt.Printf("reports_deleted: %d\n", result.ReportsDeleted)
		fmt.Printf("temporary_imports_deleted: %d\n", result.TemporaryImportsDeleted)
		fmt.Printf("temporary_events_deleted: %d\n", result.TemporaryEventsDeleted)
		fmt.Printf("temporary_facts_deleted: %d\n", result.TemporaryFactsDeleted)
		fmt.Printf("archive_files_deleted: %d\n", result.ArchiveFilesDeleted)
		fmt.Printf("rollups_rebuilt: %d\n", result.RollupsRebuilt)
		fmt.Printf("local_files_deleted: %d\n", result.LocalFilesDeleted)
		fmt.Printf("local_file_errors: %d\n", result.LocalFileErrors)
	case "archive-logs":
		result, err := runtime.RunArchive(ctx, archive.Options{DryRun: *dryRun, LogType: *logType, MaxGroups: *maxArchiveGroups, RemoveSources: *removeArchiveSources})
		if err != nil {
			log.Error().Err(err).Msg("archive failed")
			return 1
		}
		fmt.Printf("enabled: %t\n", result.Enabled)
		fmt.Printf("dry_run: %t\n", result.DryRun)
		fmt.Printf("daily_cutoff: %s\n", result.DailyCutoff.Format(time.RFC3339))
		fmt.Printf("weekly_cutoff: %s\n", result.WeeklyCutoff.Format(time.RFC3339))
		fmt.Printf("groups_matched: %d\n", result.GroupsMatched)
		fmt.Printf("archives_written: %d\n", result.ArchivesWritten)
		fmt.Printf("daily_archives_written: %d\n", result.DailyArchivesWritten)
		fmt.Printf("weekly_archives_written: %d\n", result.WeeklyArchivesWritten)
		fmt.Printf("files_archived: %d\n", result.FilesArchived)
		fmt.Printf("source_bytes: %d\n", result.SourceBytes)
		fmt.Printf("compressed_bytes: %d\n", result.CompressedBytes)
		fmt.Printf("source_files_deleted: %d\n", result.SourceFilesDeleted)
		fmt.Printf("source_delete_errors: %d\n", result.SourceDeleteErrors)
		fmt.Printf("skipped_existing: %d\n", result.SkippedExisting)
	case "archive-coverage":
		var fromTime time.Time
		var toTime time.Time
		if *from != "" {
			var err error
			fromTime, err = parseCLITime(*from)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -from: %v\n", err)
				return 2
			}
		}
		if *to != "" {
			var err error
			toTime, err = parseCLITime(*to)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -to: %v\n", err)
				return 2
			}
		}
		result, err := runtime.ArchiveCoverage(ctx, archivecoverage.Options{Range: *rangeValue, From: fromTime, To: toTime})
		if err != nil {
			log.Error().Err(err).Msg("archive coverage failed")
			return 1
		}
		fmt.Printf("range: %s\n", result.Range)
		fmt.Printf("since: %s\n", result.Since.Format(time.RFC3339))
		fmt.Printf("until: %s\n", result.Until.Format(time.RFC3339))
		fmt.Printf("hot_event_cutoff: %s\n", result.HotEventCutoff.Format(time.RFC3339))
		fmt.Printf("requires_archive_import: %t\n", result.RequiresArchiveImport)
		fmt.Printf("already_imported: %t\n", result.AlreadyImported)
		fmt.Printf("import_recommended: %t\n", result.ImportRecommended)
		fmt.Printf("requested_old_seconds: %d\n", result.RequestedOldSeconds)
		fmt.Printf("archive_coverage_ratio: %.4f\n", result.ArchiveCoverageRatio)
		fmt.Printf("temporary_coverage_ratio: %.4f\n", result.TemporaryCoverageRatio)
		fmt.Printf("available_archive_count: %d\n", result.AvailableArchiveCount)
		fmt.Printf("selected_archive_count: %d\n", result.SelectedArchiveCount)
		fmt.Printf("selected_compressed_bytes: %d\n", result.SelectedCompressedBytes)
		for _, item := range result.Archives {
			fmt.Printf("archive: %s %s %s %s %d\n", item.ID, item.Granularity, item.RangeStart.Format(time.RFC3339), item.RangeEnd.Format(time.RFC3339), item.CompressedBytes)
		}
	case "import-archive":
		result, err := runtime.ImportArchive(ctx, archiveimport.Options{ArchiveID: *archiveID, ArchivePath: *archivePath, Reason: *importReason})
		if err != nil {
			log.Error().Err(err).Msg("archive import failed")
			return 1
		}
		fmt.Printf("temporary_import_id: %s\n", result.TemporaryImportID)
		fmt.Printf("archive_id: %s\n", result.ArchiveID)
		fmt.Printf("archive_path: %s\n", result.ArchivePath)
		fmt.Printf("expires_at: %s\n", result.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("range_start: %s\n", result.RangeStart.Format(time.RFC3339))
		fmt.Printf("range_end: %s\n", result.RangeEnd.Format(time.RFC3339))
		fmt.Printf("files_imported: %d\n", result.FilesImported)
		fmt.Printf("events_seen: %d\n", result.EventsSeen)
		fmt.Printf("valid_events: %d\n", result.ValidEvents)
		fmt.Printf("invalid_events: %d\n", result.InvalidEvents)
		fmt.Printf("events_inserted: %d\n", result.EventsInserted)
		fmt.Printf("events_conflicted: %d\n", result.EventsConflicted)
		fmt.Printf("events_skipped: %d\n", result.EventsSkipped)
		fmt.Printf("rollups_updated: %d\n", result.RollupsUpdated)
		fmt.Printf("security_probes: %d\n", result.SecurityProbes)
		fmt.Printf("error_events: %d\n", result.ErrorEvents)
		fmt.Printf("slow_request_events: %d\n", result.SlowRequestEvents)
	case "archive-smoke":
		result, err := runtime.RunArchiveSmoke(ctx, *maxSegments)
		if err != nil {
			log.Error().Err(err).Msg("archive smoke failed")
			return 1
		}
		fmt.Printf("archive_id: %s\n", result.Fixture.ArchiveID)
		fmt.Printf("archive_path: %s\n", result.Fixture.Path)
		fmt.Printf("fixture_lines: %d\n", result.Fixture.Lines)
		fmt.Printf("temporary_import_id: %s\n", result.Import.TemporaryImportID)
		fmt.Printf("events_inserted: %d\n", result.Import.EventsInserted)
		fmt.Printf("temporary_events_before: %d\n", result.TemporaryEventsBefore)
		fmt.Printf("temporary_events_deleted: %d\n", result.Retention.TemporaryEventsDeleted)
		fmt.Printf("temporary_facts_deleted: %d\n", result.Retention.TemporaryFactsDeleted)
		fmt.Printf("temporary_imports_deleted: %d\n", result.Retention.TemporaryImportsDeleted)
		fmt.Printf("temporary_events_after: %d\n", result.TemporaryEventsAfter)
		fmt.Printf("temporary_imports_after: %d\n", result.TemporaryImportsAfter)
		fmt.Printf("rollups_rebuilt: %d\n", result.Retention.RollupsRebuilt)
	case "archive-compact-smoke":
		result, err := runtime.RunArchiveCompactionSmoke(ctx)
		if err != nil {
			log.Error().Err(err).Msg("archive compaction smoke failed")
			return 1
		}
		fmt.Printf("week_start: %s\n", result.Fixture.WeekStart.Format(time.RFC3339))
		fmt.Printf("daily_archives: %d\n", len(result.Fixture.DailyArchiveIDs))
		fmt.Printf("archives_written: %d\n", result.Archive.ArchivesWritten)
		fmt.Printf("weekly_archives_written: %d\n", result.Archive.WeeklyArchivesWritten)
		fmt.Printf("daily_archives_compacted: %d\n", result.Archive.DailyArchivesCompacted)
		fmt.Printf("weekly_archive_id: %s\n", result.WeeklyArchiveID)
		fmt.Printf("weekly_archive_path: %s\n", result.WeeklyArchivePath)
		fmt.Printf("weekly_archive_members: %d\n", result.WeeklyArchiveMembers)
		fmt.Printf("daily_archives_after: %d\n", result.DailyArchivesAfter)
	case "archive-coverage-smoke":
		result, err := runtime.RunArchiveCoverageSmoke(ctx)
		if err != nil {
			log.Error().Err(err).Msg("archive coverage smoke failed")
			return 1
		}
		fmt.Printf("week_start: %s\n", result.Fixture.WeekStart.Format(time.RFC3339))
		fmt.Printf("week_end: %s\n", result.Fixture.WeekEnd.Format(time.RFC3339))
		fmt.Printf("daily_archives: %d\n", len(result.Fixture.DailyArchiveIDs))
		fmt.Printf("archives_written: %d\n", result.Archive.ArchivesWritten)
		fmt.Printf("weekly_archives_written: %d\n", result.Archive.WeeklyArchivesWritten)
		fmt.Printf("coverage_requires_import: %t\n", result.CoverageBeforeImport.RequiresArchiveImport)
		fmt.Printf("coverage_import_recommended: %t\n", result.CoverageBeforeImport.ImportRecommended)
		fmt.Printf("coverage_archive_count: %d\n", result.CoverageBeforeImport.AvailableArchiveCount)
		fmt.Printf("coverage_selected_count: %d\n", result.CoverageBeforeImport.SelectedArchiveCount)
		if len(result.CoverageBeforeImport.Archives) > 0 {
			fmt.Printf("coverage_selected_granularity: %s\n", result.CoverageBeforeImport.Archives[0].Granularity)
			fmt.Printf("coverage_selected_archive_id: %s\n", result.CoverageBeforeImport.Archives[0].ID)
		}
		fmt.Printf("temporary_import_id: %s\n", result.Import.TemporaryImportID)
		fmt.Printf("events_inserted: %d\n", result.Import.EventsInserted)
		fmt.Printf("coverage_already_imported: %t\n", result.CoverageAfterImport.AlreadyImported)
		fmt.Printf("coverage_after_import_recommended: %t\n", result.CoverageAfterImport.ImportRecommended)
		fmt.Printf("temporary_events_deleted: %d\n", result.Retention.TemporaryEventsDeleted)
		fmt.Printf("temporary_facts_deleted: %d\n", result.Retention.TemporaryFactsDeleted)
		fmt.Printf("temporary_imports_deleted: %d\n", result.Retention.TemporaryImportsDeleted)
		fmt.Printf("temporary_events_after: %d\n", result.TemporaryEventsAfter)
		fmt.Printf("temporary_imports_after: %d\n", result.TemporaryImportsAfter)
	case "backfill-dimensions":
		result, err := runtime.RunBackfill(ctx, backfill.Options{
			BatchSize:  *batchSize,
			MaxBatches: *maxBatches,
			Rollups:    !*noRollups,
		})
		if err != nil {
			log.Error().Err(err).Msg("dimension backfill failed")
			return 1
		}
		fmt.Printf("batches: %d\n", result.Batches)
		fmt.Printf("events_processed: %d\n", result.EventsProcessed)
		fmt.Printf("events_remaining: %d\n", result.EventsRemaining)
		fmt.Printf("min_event_id: %d\n", result.MinEventID)
		fmt.Printf("max_event_id: %d\n", result.MaxEventID)
		if !result.RangeStart.IsZero() {
			fmt.Printf("range_start: %s\n", result.RangeStart.Format(time.RFC3339))
			fmt.Printf("range_end: %s\n", result.RangeEnd.Format(time.RFC3339))
		}
		fmt.Printf("ip_rollup_rows: %d\n", result.IPRollupRows)
		fmt.Printf("path_rollup_rows: %d\n", result.PathRollupRows)
		fmt.Printf("user_agent_rollup_rows: %d\n", result.UserAgentRollupRows)
		fmt.Printf("ip_path_rollup_rows: %d\n", result.IPPathRollupRows)
		fmt.Printf("ip_user_agent_rollup_rows: %d\n", result.IPUserAgentRollupRows)
		fmt.Printf("status_rollup_rows: %d\n", result.StatusRollupRows)
		fmt.Printf("site_latency_rows: %d\n", result.SiteLatencyRows)
		fmt.Printf("path_latency_rows: %d\n", result.PathLatencyRows)
		fmt.Printf("error_events: %d\n", result.ErrorEvents)
		fmt.Printf("slow_request_events: %d\n", result.SlowRequestEvents)
		fmt.Printf("user_agents_enriched: %d\n", result.UserAgentsEnriched)
		fmt.Printf("security_probe_rollups: %d\n", result.SecurityProbeRollups)
		fmt.Printf("security_probe_rebuilt: %t\n", result.SecurityProbeRebuilt)
		fmt.Printf("stopped_at_max_batches: %t\n", result.StoppedAtMaxBatches)
	case "rebuild-rollups":
		var fromTime time.Time
		var toTime time.Time
		if *from != "" {
			var err error
			fromTime, err = parseCLITime(*from)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -from: %v\n", err)
				return 2
			}
		}
		if *to != "" {
			var err error
			toTime, err = parseCLITime(*to)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -to: %v\n", err)
				return 2
			}
		}
		start, end, rows, err := runtime.RebuildRollups(ctx, fromTime, toTime)
		if err != nil {
			log.Error().Err(err).Msg("rollup rebuild failed")
			return 1
		}
		fmt.Printf("range_start: %s\n", start.Format(time.RFC3339))
		fmt.Printf("range_end: %s\n", end.Format(time.RFC3339))
		fmt.Printf("rollup_rows_rebuilt: %d\n", rows)
	case "rebuild-status-rollups":
		var fromTime time.Time
		var toTime time.Time
		if *from != "" {
			var err error
			fromTime, err = parseCLITime(*from)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -from: %v\n", err)
				return 2
			}
		}
		if *to != "" {
			var err error
			toTime, err = parseCLITime(*to)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid -to: %v\n", err)
				return 2
			}
		}
		start, end, rows, err := runtime.RebuildStatusRollups(ctx, fromTime, toTime)
		if err != nil {
			log.Error().Err(err).Msg("status rollup rebuild failed")
			return 1
		}
		fmt.Printf("range_start: %s\n", start.Format(time.RFC3339))
		fmt.Printf("range_end: %s\n", end.Format(time.RFC3339))
		fmt.Printf("status_rollup_rows_rebuilt: %d\n", rows)
	case "storage-audit":
		result, err := runtime.StorageAudit(ctx)
		if err != nil {
			log.Error().Err(err).Msg("storage audit failed")
			return 1
		}
		encoded, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Error().Err(err).Msg("encode storage audit")
			return 1
		}
		fmt.Println(string(encoded))
	case "storage-estimate":
		result, err := runtime.StorageAudit(ctx)
		if err != nil {
			log.Error().Err(err).Msg("storage estimate failed")
			return 1
		}
		printProjection := func(label string, item storageaudit.ProjectionScenario) {
			fmt.Printf("%s: %s\n", label, item.Name)
			fmt.Printf("%s_sites: %d\n", label, item.Sites)
			fmt.Printf("%s_events_per_day: %.0f\n", label, item.EventsPerDay)
			fmt.Printf("%s_archive_horizon_requests: %d\n", label, item.ProjectedArchiveHorizonRequests)
			fmt.Printf("%s_active_postgres_bytes: %d\n", label, item.ActivePostgresBytes)
			fmt.Printf("%s_archive_compressed_bytes: %d\n", label, item.ArchiveCompressedBytes)
			fmt.Printf("%s_raw_file_bytes: %d\n", label, item.RawFileBytes)
			fmt.Printf("%s_total_with_archive_bytes: %d\n", label, item.TotalWithArchiveBytes)
		}
		fmt.Printf("observation_days: %.2f\n", result.Projection.ObservationDays)
		fmt.Printf("events_per_day: %.0f\n", result.Projection.EventsPerDay)
		fmt.Printf("bytes_per_event: %.1f\n", result.Projection.BytesPerEvent)
		fmt.Printf("hot_event_days: %.0f\n", result.Projection.HotEventDays)
		fmt.Printf("archive_days: %.0f\n", result.Projection.ArchiveDays)
		fmt.Printf("report_days: %.0f\n", result.Projection.ReportDays)
		printProjection("current", result.Projection.CurrentSites)
		printProjection("twenty_site_blended", result.Projection.TwentySiteBlendedModel)
	case "check-config":
		summary := cfg.CredentialSummary()
		fmt.Printf("config: ok\n")
		fmt.Printf("sites: %d\n", len(cfg.EnabledSites()))
		fmt.Printf("database_configured: %t\n", cfg.DatabaseURL() != "")
		fmt.Printf("machine_token_configured: %t\n", summary.MachineTokenConfigured)
		fmt.Printf("ssh_key_configured: %t\n", summary.SSHKeyConfigured)
		fmt.Printf("retention_enabled: %t\n", cfg.Retention.Enabled)
		fmt.Printf("retention_max_age: %s\n", cfg.Retention.MaxAge)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		return 2
	}

	return 0
}

func runHealthcheck(ctx context.Context, url string, timeout time.Duration) error {
	url = strings.TrimSpace(url)
	if url == "" {
		return fmt.Errorf("healthcheck URL is required")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create healthcheck request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("healthcheck returned %s", resp.Status)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decode healthcheck response: %w", err)
	}
	if ok, _ := body["ok"].(bool); !ok {
		return fmt.Errorf("healthcheck response is not ok")
	}
	if database, _ := body["database"].(map[string]any); database != nil {
		configured, _ := database["configured"].(bool)
		databaseOK, _ := database["ok"].(bool)
		if configured && !databaseOK {
			return fmt.Errorf("healthcheck database ping failed")
		}
	}
	if scheduler, _ := body["scheduler"].(map[string]any); scheduler != nil {
		if failed := numericField(scheduler, "failed_since_start"); failed > 0 {
			return fmt.Errorf("healthcheck scheduler has %.0f failed job(s) since start", failed)
		}
		if boolField(scheduler, "collection_enabled") {
			intervalMS := numericField(scheduler, "collection_interval_ms")
			uptimeSec := numericField(body, "uptime_sec")
			if intervalMS > 0 {
				staleAfter := time.Duration(intervalMS*3) * time.Millisecond
				if time.Duration(uptimeSec)*time.Second > staleAfter {
					finishedAt, ok := stringField(scheduler, "last_cycle_finished_at")
					if !ok {
						return fmt.Errorf("healthcheck scheduler has not completed a cycle within %s", staleAfter)
					}
					parsed, err := time.Parse(time.RFC3339Nano, finishedAt)
					if err != nil {
						return fmt.Errorf("parse scheduler last cycle time: %w", err)
					}
					if age := time.Since(parsed); age > staleAfter {
						return fmt.Errorf("healthcheck scheduler last cycle is stale: %s old", age.Round(time.Second))
					}
				}
			}
		}
	}
	return nil
}

func boolField(values map[string]any, key string) bool {
	value, _ := values[key].(bool)
	return value
}

func numericField(values map[string]any, key string) float64 {
	switch value := values[key].(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case json.Number:
		parsed, _ := value.Float64()
		return parsed
	default:
		return 0
	}
}

func stringField(values map[string]any, key string) (string, bool) {
	value, ok := values[key].(string)
	return value, ok && strings.TrimSpace(value) != ""
}

func parseCLITime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("required")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func defaultConfigPath() string {
	if value := os.Getenv("ORIGINPULSE_CONFIG"); value != "" {
		return value
	}
	return "config.yml"
}
