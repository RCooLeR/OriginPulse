package storageaudit

import (
	"context"
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5"

	"originpulse/internal/config"
	"originpulse/internal/db"
)

type Service struct {
	cfg config.Config
	db  *db.Store
}

type Report struct {
	Enabled          bool             `json:"enabled"`
	GeneratedAt      time.Time        `json:"generated_at"`
	Retention        RetentionSummary `json:"retention"`
	Storage          StorageSummary   `json:"storage"`
	Events           EventSummary     `json:"events"`
	Projection       Projection       `json:"projection"`
	Dimensions       DimensionSummary `json:"dimensions"`
	Facts            FactSummary      `json:"facts"`
	Rollups          RollupSummary    `json:"rollups"`
	Archives         ArchiveSummary   `json:"archives"`
	TemporaryImports TemporarySummary `json:"temporary_imports"`
	Reports          ReportSummary    `json:"reports"`
	Readiness        ReadinessSummary `json:"readiness"`
}

type RetentionSummary struct {
	Enabled               bool      `json:"enabled"`
	RawFileMaxAge         string    `json:"raw_file_max_age"`
	HotEventMaxAge        string    `json:"hot_event_max_age"`
	DailyArchiveAfter     string    `json:"daily_archive_after"`
	WeeklyArchiveAfter    string    `json:"weekly_archive_after"`
	ArchiveMaxAge         string    `json:"archive_max_age"`
	ReportMaxAge          string    `json:"report_max_age"`
	TemporaryImportMaxAge string    `json:"temporary_import_max_age"`
	RawFileCutoff         time.Time `json:"raw_file_cutoff"`
	HotEventCutoff        time.Time `json:"hot_event_cutoff"`
	DailyArchiveCutoff    time.Time `json:"daily_archive_cutoff"`
	WeeklyArchiveCutoff   time.Time `json:"weekly_archive_cutoff"`
	ArchiveCutoff         time.Time `json:"archive_cutoff"`
	ReportCutoff          time.Time `json:"report_cutoff"`
	TemporaryImportCutoff time.Time `json:"temporary_import_cutoff"`
}

type StorageSummary struct {
	DatabaseBytes          int64 `json:"database_bytes"`
	AccessEventsBytes      int64 `json:"access_events_bytes"`
	DimensionsBytes        int64 `json:"dimensions_bytes"`
	RollupsBytes           int64 `json:"rollups_bytes"`
	FactsBytes             int64 `json:"facts_bytes"`
	ReportsBytes           int64 `json:"reports_bytes"`
	ArchivesTableBytes     int64 `json:"archives_table_bytes"`
	RawFilesTableBytes     int64 `json:"raw_files_table_bytes"`
	CombinedSegmentsBytes  int64 `json:"combined_segments_bytes"`
	ArchiveSourceBytes     int64 `json:"archive_source_bytes"`
	ArchiveCompressedBytes int64 `json:"archive_compressed_bytes"`
	EstimatedHotBytes      int64 `json:"estimated_hot_bytes"`
}

type EventSummary struct {
	AccessEvents             int64     `json:"access_events"`
	HotEvents                int64     `json:"hot_events"`
	EventsOlderThanHotCutoff int64     `json:"events_older_than_hot_cutoff"`
	TemporaryEvents          int64     `json:"temporary_events"`
	BackfillRemaining        int64     `json:"backfill_remaining"`
	MinTS                    time.Time `json:"min_ts,omitempty"`
	MaxTS                    time.Time `json:"max_ts,omitempty"`
}

type Projection struct {
	ObservationDays            float64              `json:"observation_days"`
	EventsPerDay               float64              `json:"events_per_day"`
	BytesPerEvent              float64              `json:"bytes_per_event"`
	RawFileBytesPerDay         float64              `json:"raw_file_bytes_per_day"`
	HotEventDays               float64              `json:"hot_event_days"`
	ArchiveDays                float64              `json:"archive_days"`
	ReportDays                 float64              `json:"report_days"`
	CurrentSites               ProjectionScenario   `json:"current_sites"`
	TwentySiteHalfsecondary-siteModel ProjectionScenario   `json:"twenty_site_half_secondary-site_model"`
	SiteRates                  []SiteProjectionRate `json:"site_rates"`
	Assumptions                []string             `json:"assumptions"`
}

type ProjectionScenario struct {
	Name                            string  `json:"name"`
	Sites                           int     `json:"sites"`
	EventsPerDay                    float64 `json:"events_per_day"`
	HotEvents                       int64   `json:"hot_events"`
	HotEventBytes                   int64   `json:"hot_event_bytes"`
	DimensionBytes                  int64   `json:"dimension_bytes"`
	RollupBytes                     int64   `json:"rollup_bytes"`
	FactBytes                       int64   `json:"fact_bytes"`
	ReportBytes                     int64   `json:"report_bytes"`
	RawFileBytes                    int64   `json:"raw_file_bytes"`
	ArchiveCompressedBytes          int64   `json:"archive_compressed_bytes"`
	ActivePostgresBytes             int64   `json:"active_postgres_bytes"`
	TotalWithArchiveBytes           int64   `json:"total_with_archive_bytes"`
	ProjectedDatabaseBytes          int64   `json:"projected_database_bytes"`
	ProjectedArchiveHorizonRequests int64   `json:"projected_archive_horizon_requests"`
}

type SiteProjectionRate struct {
	SiteID       string    `json:"site_id"`
	Events       int64     `json:"events"`
	EventsPerDay float64   `json:"events_per_day"`
	FirstSeen    time.Time `json:"first_seen,omitempty"`
	LastSeen     time.Time `json:"last_seen,omitempty"`
}

type DimensionSummary struct {
	IPs        int64 `json:"ips"`
	Paths      int64 `json:"paths"`
	Queries    int64 `json:"queries"`
	UserAgents int64 `json:"user_agents"`
}

type FactSummary struct {
	SecurityProbes int64 `json:"security_probes"`
	ErrorEvents    int64 `json:"error_events"`
	SlowRequests   int64 `json:"slow_requests"`
}

type RollupSummary struct {
	OneMinute           int64 `json:"one_minute"`
	IPHourly            int64 `json:"ip_hourly"`
	PathHourly          int64 `json:"path_hourly"`
	UserAgentHourly     int64 `json:"user_agent_hourly"`
	IPPathHourly        int64 `json:"ip_path_hourly"`
	IPUserAgentHourly   int64 `json:"ip_user_agent_hourly"`
	StatusHourly        int64 `json:"status_hourly"`
	SiteLatencyHourly   int64 `json:"site_latency_hourly"`
	PathLatencyHourly   int64 `json:"path_latency_hourly"`
	SecurityProbeHourly int64 `json:"security_probe_hourly"`
}

type ArchiveSummary struct {
	RawFiles              int64      `json:"raw_files"`
	RawFileBytes          int64      `json:"raw_file_bytes"`
	CombinedSegments      int64      `json:"combined_segments"`
	IndexedSegments       int64      `json:"indexed_segments"`
	ArchivedSegments      int64      `json:"archived_segments"`
	DeletedSourceSegments int64      `json:"deleted_source_segments"`
	ReadyArchives         int64      `json:"ready_archives"`
	DailyArchives         int64      `json:"daily_archives"`
	WeeklyArchives        int64      `json:"weekly_archives"`
	ExpiredArchives       int64      `json:"expired_archives"`
	PendingDailyGroups    int64      `json:"pending_daily_groups"`
	PendingWeeklyGroups   int64      `json:"pending_weekly_groups"`
	ReadyRangeStart       *time.Time `json:"ready_range_start,omitempty"`
	ReadyRangeEnd         *time.Time `json:"ready_range_end,omitempty"`
}

type TemporarySummary struct {
	ActiveImports  int64 `json:"active_imports"`
	ExpiredImports int64 `json:"expired_imports"`
	ImportedEvents int64 `json:"imported_events"`
	ImportedFacts  int64 `json:"imported_facts"`
}

type ReportSummary struct {
	StoredReports  int64 `json:"stored_reports"`
	ExpiredReports int64 `json:"expired_reports"`
}

type ReadinessSummary struct {
	BackfillReady         bool `json:"backfill_ready"`
	TemporaryClean        bool `json:"temporary_clean"`
	ArchiveQueueEmpty     bool `json:"archive_queue_empty"`
	HotEventsWithinWindow bool `json:"hot_events_within_window"`
}

func NewService(cfg config.Config, store *db.Store) *Service {
	return &Service{cfg: cfg, db: store}
}

func (s *Service) Enabled() bool {
	return s != nil && s.db != nil && s.db.Enabled()
}

func (s *Service) Audit(ctx context.Context) (Report, error) {
	now := time.Now().UTC()
	report := Report{
		Enabled:     s.Enabled(),
		GeneratedAt: now,
		Retention: RetentionSummary{
			Enabled:               s.cfg.Retention.Enabled,
			RawFileMaxAge:         s.cfg.Retention.RawFileMaxAge.String(),
			HotEventMaxAge:        s.cfg.Retention.HotEventMaxAge.String(),
			DailyArchiveAfter:     s.cfg.Retention.DailyArchiveAfter.String(),
			WeeklyArchiveAfter:    s.cfg.Retention.WeeklyArchiveAfter.String(),
			ArchiveMaxAge:         s.cfg.Retention.ArchiveMaxAge.String(),
			ReportMaxAge:          s.cfg.Retention.ReportMaxAge.String(),
			TemporaryImportMaxAge: s.cfg.Retention.TemporaryImportMaxAge.String(),
			RawFileCutoff:         now.Add(-s.cfg.Retention.RawFileMaxAge),
			HotEventCutoff:        now.Add(-s.cfg.Retention.HotEventMaxAge),
			DailyArchiveCutoff:    now.Add(-s.cfg.Retention.DailyArchiveAfter),
			WeeklyArchiveCutoff:   now.Add(-s.cfg.Retention.WeeklyArchiveAfter),
			ArchiveCutoff:         now.Add(-s.cfg.Retention.ArchiveMaxAge),
			ReportCutoff:          now.Add(-s.cfg.Retention.ReportMaxAge),
			TemporaryImportCutoff: now.Add(-s.cfg.Retention.TemporaryImportMaxAge),
		},
	}
	if !s.Enabled() {
		return report, nil
	}

	pool, err := s.db.Pool()
	if err != nil {
		return report, err
	}
	if err := pool.QueryRow(ctx, `SELECT pg_database_size(current_database())::bigint`).Scan(&report.Storage.DatabaseBytes); err != nil {
		return report, err
	}
	report.Storage.AccessEventsBytes, err = relationBytes(ctx, pool, []string{"access_events"})
	if err != nil {
		return report, err
	}
	report.Storage.DimensionsBytes, err = relationBytes(ctx, pool, []string{"dim_ips", "dim_paths", "dim_queries", "dim_user_agents"})
	if err != nil {
		return report, err
	}
	report.Storage.RollupsBytes, err = relationBytes(ctx, pool, []string{"rollup_1m", "rollup_ip_1h", "rollup_path_1h", "rollup_user_agent_1h", "rollup_ip_path_1h", "rollup_ip_user_agent_1h", "rollup_status_1h", "rollup_site_latency_1h", "rollup_path_latency_1h", "rollup_security_probe_1h"})
	if err != nil {
		return report, err
	}
	report.Storage.FactsBytes, err = relationBytes(ctx, pool, []string{"security_probe_events", "error_events", "slow_request_events"})
	if err != nil {
		return report, err
	}
	report.Storage.ReportsBytes, err = relationBytes(ctx, pool, []string{"llm_reports"})
	if err != nil {
		return report, err
	}
	report.Storage.ArchivesTableBytes, err = relationBytes(ctx, pool, []string{"log_archives", "log_archive_segments", "temporary_imports"})
	if err != nil {
		return report, err
	}
	report.Storage.RawFilesTableBytes, err = relationBytes(ctx, pool, []string{"raw_files"})
	if err != nil {
		return report, err
	}
	report.Storage.CombinedSegmentsBytes, err = relationBytes(ctx, pool, []string{"combined_segments"})
	if err != nil {
		return report, err
	}

	if err := report.loadEvents(ctx, pool); err != nil {
		return report, err
	}
	if err := report.loadDimensions(ctx, pool); err != nil {
		return report, err
	}
	if err := report.loadFacts(ctx, pool); err != nil {
		return report, err
	}
	if err := report.loadRollups(ctx, pool); err != nil {
		return report, err
	}
	if err := report.loadArchives(ctx, pool); err != nil {
		return report, err
	}
	if err := report.loadTemporaryImports(ctx, pool); err != nil {
		return report, err
	}
	if err := report.loadReports(ctx, pool); err != nil {
		return report, err
	}
	report.Storage.EstimatedHotBytes = estimatedBytes(report.Events.HotEvents, report.Events.AccessEvents, report.Storage.AccessEventsBytes)
	if err := report.loadProjection(ctx, pool); err != nil {
		return report, err
	}
	report.Readiness = ReadinessSummary{
		BackfillReady:         report.Events.BackfillRemaining == 0,
		TemporaryClean:        report.TemporaryImports.ExpiredImports == 0 && report.TemporaryImports.ImportedEvents == 0 && report.TemporaryImports.ImportedFacts == 0,
		ArchiveQueueEmpty:     report.Archives.PendingDailyGroups == 0 && report.Archives.PendingWeeklyGroups == 0,
		HotEventsWithinWindow: report.Events.EventsOlderThanHotCutoff == 0,
	}
	return report, nil
}

type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (r *Report) loadEvents(ctx context.Context, q queryer) error {
	var minTS, maxTS sql.NullTime
	err := q.QueryRow(ctx, `
SELECT count(*)::bigint,
       count(*) FILTER (WHERE ts >= $1 AND temporary_import_id IS NULL)::bigint,
       count(*) FILTER (WHERE ts < $1 AND temporary_import_id IS NULL)::bigint,
       count(*) FILTER (WHERE temporary_import_id IS NOT NULL)::bigint,
       min(ts),
       max(ts)
FROM access_events`, r.Retention.HotEventCutoff).Scan(
		&r.Events.AccessEvents,
		&r.Events.HotEvents,
		&r.Events.EventsOlderThanHotCutoff,
		&r.Events.TemporaryEvents,
		&minTS,
		&maxTS,
	)
	if err != nil {
		return err
	}
	if minTS.Valid {
		r.Events.MinTS = minTS.Time
	}
	if maxTS.Valid {
		r.Events.MaxTS = maxTS.Time
	}
	return q.QueryRow(ctx, `
SELECT count(*)::bigint
FROM access_events
WHERE (client_ip IS NOT NULL AND ip_id IS NULL)
   OR (path_hash IS NOT NULL AND path_id IS NULL)
   OR (query IS NOT NULL AND query <> '' AND query_id IS NULL)
   OR (user_agent_hash IS NOT NULL AND user_agent_id IS NULL)
   OR rollups_1h_backfilled_at IS NULL
   OR (status >= 400 AND NOT EXISTS (SELECT 1 FROM error_events f WHERE f.event_id = access_events.id))
   OR (request_time_ms >= 1000 AND NOT EXISTS (SELECT 1 FROM slow_request_events f WHERE f.event_id = access_events.id))`).Scan(&r.Events.BackfillRemaining)
}

func (r *Report) loadDimensions(ctx context.Context, q queryer) error {
	return q.QueryRow(ctx, `
SELECT (SELECT count(*)::bigint FROM dim_ips),
       (SELECT count(*)::bigint FROM dim_paths),
       (SELECT count(*)::bigint FROM dim_queries),
       (SELECT count(*)::bigint FROM dim_user_agents)`).Scan(
		&r.Dimensions.IPs,
		&r.Dimensions.Paths,
		&r.Dimensions.Queries,
		&r.Dimensions.UserAgents,
	)
}

func (r *Report) loadFacts(ctx context.Context, q queryer) error {
	return q.QueryRow(ctx, `
SELECT (SELECT count(*)::bigint FROM security_probe_events),
       (SELECT count(*)::bigint FROM error_events),
       (SELECT count(*)::bigint FROM slow_request_events)`).Scan(
		&r.Facts.SecurityProbes,
		&r.Facts.ErrorEvents,
		&r.Facts.SlowRequests,
	)
}

func (r *Report) loadRollups(ctx context.Context, q queryer) error {
	return q.QueryRow(ctx, `
SELECT (SELECT count(*)::bigint FROM rollup_1m),
       (SELECT count(*)::bigint FROM rollup_ip_1h),
       (SELECT count(*)::bigint FROM rollup_path_1h),
       (SELECT count(*)::bigint FROM rollup_user_agent_1h),
       (SELECT count(*)::bigint FROM rollup_ip_path_1h),
       (SELECT count(*)::bigint FROM rollup_ip_user_agent_1h),
       (SELECT count(*)::bigint FROM rollup_status_1h),
       (SELECT count(*)::bigint FROM rollup_site_latency_1h),
       (SELECT count(*)::bigint FROM rollup_path_latency_1h),
       (SELECT count(*)::bigint FROM rollup_security_probe_1h)`).Scan(
		&r.Rollups.OneMinute,
		&r.Rollups.IPHourly,
		&r.Rollups.PathHourly,
		&r.Rollups.UserAgentHourly,
		&r.Rollups.IPPathHourly,
		&r.Rollups.IPUserAgentHourly,
		&r.Rollups.StatusHourly,
		&r.Rollups.SiteLatencyHourly,
		&r.Rollups.PathLatencyHourly,
		&r.Rollups.SecurityProbeHourly,
	)
}

func (r *Report) loadArchives(ctx context.Context, q queryer) error {
	var start, end sql.NullTime
	err := q.QueryRow(ctx, `
SELECT (SELECT count(*)::bigint FROM raw_files),
       (SELECT coalesce(sum(remote_size), 0)::bigint FROM raw_files),
       (SELECT count(*)::bigint FROM combined_segments),
       (SELECT count(*)::bigint FROM combined_segments WHERE status = 'indexed'),
       (SELECT count(*)::bigint FROM combined_segments WHERE archive_id IS NOT NULL),
       (SELECT count(*)::bigint FROM combined_segments WHERE source_deleted_at IS NOT NULL),
       (SELECT count(*)::bigint FROM log_archives WHERE status = 'ready'),
       (SELECT count(*)::bigint FROM log_archives WHERE status = 'ready' AND granularity = 'daily'),
       (SELECT count(*)::bigint FROM log_archives WHERE status = 'ready' AND granularity = 'weekly'),
       (SELECT count(*)::bigint FROM log_archives WHERE status = 'ready' AND (expires_at < now() OR range_end < $1)),
       (SELECT coalesce(sum(source_bytes), 0)::bigint FROM log_archives WHERE status = 'ready'),
       (SELECT coalesce(sum(compressed_bytes), 0)::bigint FROM log_archives WHERE status = 'ready'),
       (SELECT min(range_start) FROM log_archives WHERE status = 'ready'),
       (SELECT max(range_end) FROM log_archives WHERE status = 'ready')`, r.Retention.ArchiveCutoff).Scan(
		&r.Archives.RawFiles,
		&r.Archives.RawFileBytes,
		&r.Archives.CombinedSegments,
		&r.Archives.IndexedSegments,
		&r.Archives.ArchivedSegments,
		&r.Archives.DeletedSourceSegments,
		&r.Archives.ReadyArchives,
		&r.Archives.DailyArchives,
		&r.Archives.WeeklyArchives,
		&r.Archives.ExpiredArchives,
		&r.Storage.ArchiveSourceBytes,
		&r.Storage.ArchiveCompressedBytes,
		&start,
		&end,
	)
	if err != nil {
		return err
	}
	if start.Valid {
		readyRangeStart := start.Time
		r.Archives.ReadyRangeStart = &readyRangeStart
	}
	if end.Valid {
		readyRangeEnd := end.Time
		r.Archives.ReadyRangeEnd = &readyRangeEnd
	}
	if err := q.QueryRow(ctx, archiveQueueSQL("daily"), r.Retention.DailyArchiveCutoff, r.Retention.WeeklyArchiveCutoff).Scan(&r.Archives.PendingDailyGroups); err != nil {
		return err
	}
	if err := q.QueryRow(ctx, `
WITH candidates AS (
  SELECT date_trunc('week', bucket_start) AS range_start
  FROM combined_segments
  WHERE log_type = 'nginx-access'
    AND bucket_end < $1
    AND status = 'indexed'
    AND source_deleted_at IS NULL
  GROUP BY 1
  UNION
  SELECT date_trunc('week', range_start) AS range_start
  FROM log_archives
  WHERE log_type = 'nginx-access'
    AND granularity = 'daily'
    AND status = 'ready'
    AND range_end < $1
  GROUP BY 1
)
SELECT count(*)::bigint
FROM candidates c
WHERE NOT EXISTS (
  SELECT 1 FROM log_archives a
  WHERE a.log_type = 'nginx-access'
    AND a.granularity = 'weekly'
    AND a.range_start = c.range_start
    AND a.status = 'ready'
)`, r.Retention.WeeklyArchiveCutoff).Scan(&r.Archives.PendingWeeklyGroups); err != nil {
		return err
	}
	return nil
}

func archiveQueueSQL(granularity string) string {
	if granularity == "weekly" {
		return `
WITH candidates AS (
  SELECT date_trunc('week', bucket_start) AS range_start
  FROM combined_segments
  WHERE log_type = 'nginx-access'
    AND bucket_end < $1
    AND status = 'indexed'
    AND source_deleted_at IS NULL
  GROUP BY 1
)
SELECT count(*)::bigint
FROM candidates c
WHERE NOT EXISTS (
  SELECT 1 FROM log_archives a
  WHERE a.log_type = 'nginx-access'
    AND a.granularity = 'weekly'
    AND a.range_start = c.range_start
    AND a.status = 'ready'
)`
	}
	return `
WITH candidates AS (
  SELECT date_trunc('day', bucket_start) AS range_start
  FROM combined_segments
  WHERE log_type = 'nginx-access'
    AND bucket_end < $1
    AND ($2::timestamptz IS NULL OR bucket_end >= $2)
    AND status = 'indexed'
    AND source_deleted_at IS NULL
  GROUP BY 1
)
SELECT count(*)::bigint
FROM candidates c
WHERE NOT EXISTS (
  SELECT 1 FROM log_archives a
  WHERE a.log_type = 'nginx-access'
    AND a.granularity = 'daily'
    AND a.range_start = c.range_start
    AND a.status = 'ready'
)`
}

func (r *Report) loadTemporaryImports(ctx context.Context, q queryer) error {
	return q.QueryRow(ctx, `
SELECT (SELECT count(*)::bigint FROM temporary_imports WHERE status = 'imported' AND expires_at >= now()),
       (SELECT count(*)::bigint FROM temporary_imports WHERE expires_at < now() OR imported_at < $1),
       (SELECT count(*)::bigint FROM access_events WHERE temporary_import_id IS NOT NULL),
       (
         (SELECT count(*) FROM security_probe_events WHERE temporary_import_id IS NOT NULL) +
         (SELECT count(*) FROM error_events WHERE temporary_import_id IS NOT NULL) +
         (SELECT count(*) FROM slow_request_events WHERE temporary_import_id IS NOT NULL)
       )::bigint`, r.Retention.TemporaryImportCutoff).Scan(
		&r.TemporaryImports.ActiveImports,
		&r.TemporaryImports.ExpiredImports,
		&r.TemporaryImports.ImportedEvents,
		&r.TemporaryImports.ImportedFacts,
	)
}

func (r *Report) loadReports(ctx context.Context, q queryer) error {
	return q.QueryRow(ctx, `
SELECT count(*)::bigint,
       count(*) FILTER (WHERE created_at < $1)::bigint
FROM llm_reports`, r.Retention.ReportCutoff).Scan(&r.Reports.StoredReports, &r.Reports.ExpiredReports)
}

func (r *Report) loadProjection(ctx context.Context, q queryer) error {
	r.Projection.HotEventDays = durationDays(r.Retention.HotEventCutoff, r.GeneratedAt)
	r.Projection.ArchiveDays = durationDays(r.Retention.ArchiveCutoff, r.GeneratedAt)
	r.Projection.ReportDays = durationDays(r.Retention.ReportCutoff, r.GeneratedAt)
	if !r.Events.MinTS.IsZero() && r.Events.MaxTS.After(r.Events.MinTS) {
		r.Projection.ObservationDays = r.Events.MaxTS.Sub(r.Events.MinTS).Hours() / 24
	}
	if r.Projection.ObservationDays <= 0 {
		r.Projection.ObservationDays = 1
	}
	if r.Events.AccessEvents > 0 {
		r.Projection.EventsPerDay = float64(r.Events.AccessEvents) / r.Projection.ObservationDays
		r.Projection.BytesPerEvent = float64(r.Storage.AccessEventsBytes) / float64(r.Events.AccessEvents)
	}
	r.Projection.RawFileBytesPerDay = float64(r.Archives.RawFileBytes) / r.Projection.ObservationDays
	r.Projection.SiteRates = []SiteProjectionRate{}
	if rowsQueryer, ok := q.(interface {
		Query(context.Context, string, ...any) (pgx.Rows, error)
	}); ok {
		rows, err := rowsQueryer.Query(ctx, `
SELECT site_id,
       count(*)::bigint,
       min(ts),
       max(ts)
FROM access_events
GROUP BY site_id
ORDER BY count(*) DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item SiteProjectionRate
			if err := rows.Scan(&item.SiteID, &item.Events, &item.FirstSeen, &item.LastSeen); err != nil {
				return err
			}
			days := item.LastSeen.Sub(item.FirstSeen).Hours() / 24
			if days <= 0 {
				days = r.Projection.ObservationDays
			}
			if days <= 0 {
				days = 1
			}
			item.EventsPerDay = float64(item.Events) / days
			r.Projection.SiteRates = append(r.Projection.SiteRates, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}

	r.Projection.Assumptions = []string{
		"Projection uses the current measured database density and configured retention windows.",
		"Dimensions, rollups, and fact bytes are projected over the archive retention horizon because they remain online after hot access_events expire.",
		"Raw downloaded files are projected only over raw_file_max_age.",
		"Combined archive bytes use observed archive compression when available, otherwise a conservative 25% of raw source bytes.",
		"Twenty-site model uses measured example-like and secondary-site-like rates, plus 16 smaller sites at half the measured secondary-site-like rate.",
	}
	currentSites := len(r.Projection.SiteRates)
	if currentSites == 0 && r.Events.AccessEvents > 0 {
		currentSites = 1
	}
	r.Projection.CurrentSites = r.projectScenario("current configured sites", currentSites, r.Projection.EventsPerDay)
	r.Projection.TwentySiteHalfsecondary-siteModel = r.projectScenario("20 sites: 2 example-like, 2 secondary-site-like, 16 half-secondary-site", 20, r.twentySiteEventsPerDay())
	return nil
}

func (r Report) twentySiteEventsPerDay() float64 {
	if len(r.Projection.SiteRates) == 0 {
		return r.Projection.EventsPerDay
	}
	exampleRate := r.Projection.SiteRates[0].EventsPerDay
	secondary-siteRate := exampleRate
	if len(r.Projection.SiteRates) > 1 {
		secondary-siteRate = r.Projection.SiteRates[1].EventsPerDay
	}
	return 2*exampleRate + 2*secondary-siteRate + 16*(secondary-siteRate*0.5)
}

func (r Report) projectScenario(name string, sites int, eventsPerDay float64) ProjectionScenario {
	scale := 0.0
	if r.Projection.EventsPerDay > 0 {
		scale = eventsPerDay / r.Projection.EventsPerDay
	}
	observedDays := r.Projection.ObservationDays
	if observedDays <= 0 {
		observedDays = 1
	}
	hotDays := r.Projection.HotEventDays
	archiveDays := r.Projection.ArchiveDays
	reportDays := r.Projection.ReportDays
	rawDays := durationDays(r.Retention.RawFileCutoff, r.GeneratedAt)
	archiveCompressionRatio := 0.25
	if r.Storage.ArchiveSourceBytes > 0 && r.Storage.ArchiveCompressedBytes > 0 {
		archiveCompressionRatio = float64(r.Storage.ArchiveCompressedBytes) / float64(r.Storage.ArchiveSourceBytes)
	}

	hotEvents := int64(eventsPerDay * hotDays)
	hotEventBytes := int64(float64(hotEvents) * r.Projection.BytesPerEvent)
	dimensionBytes := scaledHorizonBytes(r.Storage.DimensionsBytes, scale, archiveDays, observedDays)
	rollupBytes := scaledHorizonBytes(r.Storage.RollupsBytes, scale, archiveDays, observedDays)
	factBytes := scaledHorizonBytes(r.Storage.FactsBytes, scale, archiveDays, observedDays)
	reportBytes := scaledHorizonBytes(r.Storage.ReportsBytes, scale, reportDays, observedDays)
	rawBytes := int64(r.Projection.RawFileBytesPerDay * rawDays * scale)
	archiveBytes := int64(r.Projection.RawFileBytesPerDay * archiveDays * scale * archiveCompressionRatio)
	activePostgres := hotEventBytes + dimensionBytes + rollupBytes + factBytes + reportBytes + r.Storage.ArchivesTableBytes + r.Storage.RawFilesTableBytes + r.Storage.CombinedSegmentsBytes
	return ProjectionScenario{
		Name:                            name,
		Sites:                           sites,
		EventsPerDay:                    eventsPerDay,
		HotEvents:                       hotEvents,
		HotEventBytes:                   hotEventBytes,
		DimensionBytes:                  dimensionBytes,
		RollupBytes:                     rollupBytes,
		FactBytes:                       factBytes,
		ReportBytes:                     reportBytes,
		RawFileBytes:                    rawBytes,
		ArchiveCompressedBytes:          archiveBytes,
		ActivePostgresBytes:             activePostgres,
		ProjectedDatabaseBytes:          activePostgres,
		TotalWithArchiveBytes:           activePostgres + rawBytes + archiveBytes,
		ProjectedArchiveHorizonRequests: int64(eventsPerDay * archiveDays),
	}
}

func relationBytes(ctx context.Context, q queryer, tables []string) (int64, error) {
	total := int64(0)
	for _, table := range tables {
		var bytes int64
		if err := q.QueryRow(ctx, `SELECT coalesce(pg_total_relation_size(to_regclass($1)), 0)::bigint`, table).Scan(&bytes); err != nil {
			return 0, err
		}
		total += bytes
	}
	return total, nil
}

func estimatedBytes(part int64, total int64, totalBytes int64) int64 {
	if part <= 0 || total <= 0 || totalBytes <= 0 {
		return 0
	}
	return int64(float64(totalBytes) * (float64(part) / float64(total)))
}

func durationDays(start time.Time, end time.Time) float64 {
	if start.IsZero() || end.IsZero() || !end.After(start) {
		return 0
	}
	return end.Sub(start).Hours() / 24
}

func scaledHorizonBytes(observedBytes int64, scale float64, horizonDays float64, observedDays float64) int64 {
	if observedBytes <= 0 || scale <= 0 || horizonDays <= 0 || observedDays <= 0 {
		return 0
	}
	return int64(float64(observedBytes) * scale * (horizonDays / observedDays))
}
