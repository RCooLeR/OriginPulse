package reports

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/db"
	"originpulse/internal/rollups"
)

type FastReadAuditOptions struct {
	Range  string
	SiteID string
	Now    time.Time
}

type FastReadAudit struct {
	Range                        string    `json:"range"`
	SiteID                       string    `json:"site_id,omitempty"`
	Since                        time.Time `json:"since"`
	Until                        time.Time `json:"until"`
	FullMinuteStart              time.Time `json:"full_minute_start"`
	FullMinuteEnd                time.Time `json:"full_minute_end"`
	FullHourStart                time.Time `json:"full_hour_start"`
	FullHourEnd                  time.Time `json:"full_hour_end"`
	DimensionRollupsReady        bool      `json:"dimension_rollups_ready"`
	StatusRollupsReady           bool      `json:"status_rollups_ready"`
	FullRangeEvents              int64     `json:"full_range_events"`
	MinuteEdgeEvents             int64     `json:"minute_edge_events"`
	HourEdgeEvents               int64     `json:"hour_edge_events"`
	UnbackfilledFullHourEvents   int64     `json:"unbackfilled_full_hour_events"`
	RecentErrorFactRows          int64     `json:"recent_error_fact_rows"`
	RecentErrorRawGapRows        int64     `json:"recent_error_raw_gap_rows"`
	SecurityProbeFactRows        int64     `json:"security_probe_fact_rows"`
	OverviewSource               string    `json:"overview_source"`
	AccessAnalysisSource         string    `json:"access_analysis_source"`
	TrafficSource                string    `json:"traffic_source"`
	RecentErrorsSource           string    `json:"recent_errors_source"`
	AlertsSource                 string    `json:"alerts_source"`
	ReportCatalogSource          string    `json:"report_catalog_source"`
	ExpectedRawRangeAggregations bool      `json:"expected_raw_range_aggregations"`
	ExpectedRawEdgeRows          int64     `json:"expected_raw_edge_rows"`
	ExpectedRawGapRows           int64     `json:"expected_raw_gap_rows"`
}

func (s *Service) FastReadAudit(ctx context.Context, opts FastReadAuditOptions) (FastReadAudit, error) {
	if s == nil || s.db == nil || !s.db.Enabled() {
		return FastReadAudit{}, db.ErrUnavailable
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	duration, label := parseRange(opts.Range)
	since := now.Add(-duration)
	until := now
	siteID := strings.TrimSpace(opts.SiteID)

	pool, err := s.db.Pool()
	if err != nil {
		return FastReadAudit{}, err
	}
	fullMinuteStart, fullMinuteEnd, _ := rollups.FullMinuteRange(since, until)
	fullHourStart, fullHourEnd, _ := rollups.FullHourRange(since, until)
	audit := FastReadAudit{
		Range:               label,
		SiteID:              siteID,
		Since:               since,
		Until:               until,
		FullMinuteStart:     fullMinuteStart,
		FullMinuteEnd:       fullMinuteEnd,
		FullHourStart:       fullHourStart,
		FullHourEnd:         fullHourEnd,
		RecentErrorsSource:  "error_events + raw_gap_rows",
		AlertsSource:        "alerts table + fact detail on demand",
		ReportCatalogSource: "llm_reports serialized rows",
	}
	if err := populateFastReadAudit(ctx, pool, &audit); err != nil {
		return audit, err
	}
	audit.OverviewSource = "rollup_1m + minute edge events"
	if audit.RecentErrorRawGapRows > 0 {
		audit.RecentErrorsSource = "error_events + raw_gap_rows"
	} else {
		audit.RecentErrorsSource = "error_events"
	}
	if audit.DimensionRollupsReady {
		audit.AccessAnalysisSource = "dimension rollups + fact tables + hour edge events"
		audit.TrafficSource = "dimension/status rollups + fact tables + hour edge events"
	} else {
		audit.AccessAnalysisSource = "raw access_events fallback"
		audit.TrafficSource = "raw access_events fallback"
	}
	if !audit.StatusRollupsReady {
		audit.TrafficSource += " + raw status fallback"
	}
	audit.ExpectedRawRangeAggregations = !audit.DimensionRollupsReady || !audit.StatusRollupsReady
	if audit.DimensionRollupsReady {
		audit.ExpectedRawEdgeRows = maxInt64(audit.MinuteEdgeEvents, audit.HourEdgeEvents)
	} else {
		audit.ExpectedRawEdgeRows = audit.FullRangeEvents
	}
	audit.ExpectedRawGapRows = audit.RecentErrorRawGapRows
	return audit, nil
}

func populateFastReadAudit(ctx context.Context, pool *pgxpool.Pool, audit *FastReadAudit) error {
	var err error
	audit.DimensionRollupsReady, err = rollups.DimensionRollupsReady(ctx, pool, audit.Since, audit.Until, audit.SiteID)
	if err != nil {
		return err
	}
	audit.StatusRollupsReady = false
	if audit.DimensionRollupsReady {
		audit.StatusRollupsReady, err = rollups.StatusRollupsReady(ctx, pool, audit.Since, audit.Until, audit.SiteID)
		if err != nil {
			return err
		}
	}
	audit.FullRangeEvents, err = countEventsFromMinuteRollups(ctx, pool, audit)
	if err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)::bigint
FROM access_events
WHERE ts >= $1 AND ts < $2
  AND ($3 = '' OR site_id = $3)
  AND (ts < $4 OR ts >= $5)`, audit.Since, audit.Until, audit.SiteID, audit.FullMinuteStart, audit.FullMinuteEnd).Scan(&audit.MinuteEdgeEvents); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)::bigint
FROM access_events
WHERE ts >= $1 AND ts < $2
  AND ($3 = '' OR site_id = $3)
  AND (ts < $4 OR ts >= $5)`, audit.Since, audit.Until, audit.SiteID, audit.FullHourStart, audit.FullHourEnd).Scan(&audit.HourEdgeEvents); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)::bigint
FROM access_events
WHERE ts >= $1 AND ts < $2
  AND ($3 = '' OR site_id = $3)
  AND rollups_1h_backfilled_at IS NULL`, audit.FullHourStart, audit.FullHourEnd, audit.SiteID).Scan(&audit.UnbackfilledFullHourEvents); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)::bigint
FROM error_events
WHERE ts >= $1 AND ts < $2
  AND ($3 = '' OR site_id = $3)`, audit.Since, audit.Until, audit.SiteID).Scan(&audit.RecentErrorFactRows); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)::bigint
FROM access_events e
WHERE e.ts >= $1 AND e.ts < $2
  AND ($3 = '' OR e.site_id = $3)
  AND e.status >= 400
  AND NOT EXISTS (SELECT 1 FROM error_events f WHERE f.event_id = e.id)`, audit.Since, audit.Until, audit.SiteID).Scan(&audit.RecentErrorRawGapRows); err != nil {
		return err
	}
	return pool.QueryRow(ctx, `
SELECT count(*)::bigint
FROM security_probe_events
WHERE ts >= $1 AND ts < $2
  AND ($3 = '' OR site_id = $3)`, audit.Since, audit.Until, audit.SiteID).Scan(&audit.SecurityProbeFactRows)
}

func countEventsFromMinuteRollups(ctx context.Context, pool *pgxpool.Pool, audit *FastReadAudit) (int64, error) {
	var count int64
	err := pool.QueryRow(ctx, `
WITH rollup_rows AS (
  SELECT coalesce(sum(requests), 0)::bigint AS requests
  FROM rollup_1m
  WHERE bucket_ts >= $4 AND bucket_ts < $5
    AND ($3 = '' OR site_id = $3)
),
edge_rows AS (
  SELECT count(*)::bigint AS requests
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND (ts < $4 OR ts >= $5)
)
SELECT
  (SELECT requests FROM rollup_rows) +
  (SELECT requests FROM edge_rows)`, audit.Since, audit.Until, audit.SiteID, audit.FullMinuteStart, audit.FullMinuteEnd).Scan(&count)
	return count, err
}

func maxInt64(a int64, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
