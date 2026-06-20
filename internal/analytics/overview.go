package analytics

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/db"
	"originpulse/internal/rollups"
)

type Options struct {
	Range  string
	SiteID string
	From   time.Time
	To     time.Time
}

type Overview struct {
	Range             string    `json:"range"`
	SiteID            string    `json:"site_id,omitempty"`
	Since             time.Time `json:"since"`
	Until             time.Time `json:"until"`
	Requests          int64     `json:"requests"`
	RequestsPerMinute float64   `json:"requests_per_minute"`
	UniqueIPs         int64     `json:"unique_ips"`
	Status4xxRate     float64   `json:"status_4xx_rate"`
	Status5xxRate     float64   `json:"status_5xx_rate"`
	TopSite           *TopSite  `json:"top_site,omitempty"`
	TopIP             *TopIP    `json:"top_ip,omitempty"`
}

type TopSite struct {
	SiteID   string `json:"site_id"`
	Requests int64  `json:"requests"`
}

type TopIP struct {
	IP       string `json:"ip"`
	Requests int64  `json:"requests"`
}

type overviewCounts struct {
	Requests         int64
	Status2xx        int64
	Status3xx        int64
	Status4xx        int64
	Status5xx        int64
	BytesSent        int64
	RequestTimeCount int64
	RequestTimeSumMS int64
	SlowRequests     int64
}

type Service struct {
	db *db.Store
}

func NewService(store *db.Store) *Service {
	return &Service{db: store}
}

func (s *Service) Enabled() bool {
	return s != nil && s.db != nil && s.db.Enabled()
}

func (s *Service) DashboardOverview(ctx context.Context, rangeLabel string) (Overview, error) {
	return s.DashboardOverviewFor(ctx, Options{Range: rangeLabel})
}

func (s *Service) DashboardOverviewFor(ctx context.Context, opts Options) (Overview, error) {
	now := time.Now().UTC()
	since, until, label, err := resolveWindow(now, opts.Range, opts.From, opts.To)
	overview := Overview{
		Range:  label,
		SiteID: strings.TrimSpace(opts.SiteID),
		Since:  since,
		Until:  until,
	}
	if err != nil {
		return overview, err
	}
	if !s.Enabled() {
		return overview, nil
	}

	pool, err := s.db.Pool()
	if err != nil {
		return overview, err
	}
	duration := until.Sub(since)

	counts, err := overviewCountsFromMinuteRollups(ctx, pool, since, until, overview.SiteID)
	if err != nil {
		return overview, err
	}
	overview.Requests = counts.Requests
	rollupsReady, err := rollups.DimensionRollupsReady(ctx, pool, since, until, overview.SiteID)
	if err != nil {
		return overview, err
	}
	if rollupsReady {
		uniqueIPs, err := uniqueIPsFromRollups(ctx, pool, since, until, overview.SiteID)
		if err != nil {
			return overview, err
		}
		overview.UniqueIPs = uniqueIPs
	} else if err := pool.QueryRow(ctx, `
SELECT count(DISTINCT client_ip)::bigint
FROM access_events
WHERE ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3) AND client_ip IS NOT NULL`,
		since, until, overview.SiteID,
	).Scan(&overview.UniqueIPs); err != nil {
		return overview, err
	}

	if duration.Minutes() > 0 {
		overview.RequestsPerMinute = float64(overview.Requests) / duration.Minutes()
	}
	if overview.Requests > 0 {
		overview.Status4xxRate = float64(counts.Status4xx) / float64(overview.Requests)
		overview.Status5xxRate = float64(counts.Status5xx) / float64(overview.Requests)
	}

	topSite, err := topSiteFromMinuteRollups(ctx, pool, since, until, overview.SiteID)
	if err == nil {
		overview.TopSite = &topSite
	}

	var topIP TopIP
	if rollupsReady {
		topIP, err := topIPFromRollups(ctx, pool, since, until, overview.SiteID)
		if err == nil {
			overview.TopIP = &topIP
		}
	} else if err := pool.QueryRow(ctx, `
SELECT host(client_ip), count(*)::bigint
FROM access_events
WHERE ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3) AND client_ip IS NOT NULL
GROUP BY client_ip
ORDER BY count(*) DESC
LIMIT 1`, since, until, overview.SiteID).Scan(&topIP.IP, &topIP.Requests); err == nil {
		overview.TopIP = &topIP
	}

	return overview, nil
}

func overviewCountsFromMinuteRollups(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, siteID string) (overviewCounts, error) {
	fullStart, fullEnd, _ := rollups.FullMinuteRange(since, until)
	var counts overviewCounts
	err := pool.QueryRow(ctx, `
WITH rollup_rows AS (
  SELECT coalesce(sum(requests), 0)::bigint AS requests,
         coalesce(sum(status_2xx), 0)::bigint AS status_2xx,
         coalesce(sum(status_3xx), 0)::bigint AS status_3xx,
         coalesce(sum(status_4xx), 0)::bigint AS status_4xx,
         coalesce(sum(status_5xx), 0)::bigint AS status_5xx,
         coalesce(sum(bytes_sent), 0)::bigint AS bytes_sent,
         coalesce(sum(request_time_count), 0)::bigint AS request_time_count,
         coalesce(sum(request_time_sum_ms), 0)::bigint AS request_time_sum_ms,
         coalesce(sum(slow_requests), 0)::bigint AS slow_requests
  FROM rollup_1m
  WHERE bucket_ts >= $4 AND bucket_ts < $5
    AND ($3 = '' OR site_id = $3)
),
edge_rows AS (
  SELECT count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 200 AND status < 300)::bigint AS status_2xx,
         count(*) FILTER (WHERE status >= 300 AND status < 400)::bigint AS status_3xx,
         count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
         coalesce(sum(bytes_sent), 0)::bigint AS bytes_sent,
         count(*) FILTER (WHERE request_time_ms IS NOT NULL)::bigint AS request_time_count,
         coalesce(sum(request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::bigint AS request_time_sum_ms,
         count(*) FILTER (WHERE request_time_ms >= 1000)::bigint AS slow_requests
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND (ts < $4 OR ts >= $5)
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
)
SELECT coalesce(sum(requests), 0)::bigint,
       coalesce(sum(status_2xx), 0)::bigint,
       coalesce(sum(status_3xx), 0)::bigint,
       coalesce(sum(status_4xx), 0)::bigint,
       coalesce(sum(status_5xx), 0)::bigint,
       coalesce(sum(bytes_sent), 0)::bigint,
       coalesce(sum(request_time_count), 0)::bigint,
       coalesce(sum(request_time_sum_ms), 0)::bigint,
       coalesce(sum(slow_requests), 0)::bigint
FROM combined`, since, until, siteID, fullStart, fullEnd).Scan(
		&counts.Requests,
		&counts.Status2xx,
		&counts.Status3xx,
		&counts.Status4xx,
		&counts.Status5xx,
		&counts.BytesSent,
		&counts.RequestTimeCount,
		&counts.RequestTimeSumMS,
		&counts.SlowRequests,
	)
	return counts, err
}

func topSiteFromMinuteRollups(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, siteID string) (TopSite, error) {
	fullStart, fullEnd, _ := rollups.FullMinuteRange(since, until)
	var topSite TopSite
	err := pool.QueryRow(ctx, `
WITH rollup_rows AS (
  SELECT site_id, sum(requests)::bigint AS requests
  FROM rollup_1m
  WHERE bucket_ts >= $4 AND bucket_ts < $5
    AND ($3 = '' OR site_id = $3)
  GROUP BY site_id
),
edge_rows AS (
  SELECT site_id, count(*)::bigint AS requests
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND (ts < $4 OR ts >= $5)
  GROUP BY site_id
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
)
SELECT site_id, sum(requests)::bigint
FROM combined
GROUP BY site_id
ORDER BY sum(requests) DESC
LIMIT 1`, since, until, siteID, fullStart, fullEnd).Scan(&topSite.SiteID, &topSite.Requests)
	return topSite, err
}

func uniqueIPsFromRollups(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, siteID string) (int64, error) {
	fullStart, fullEnd, _ := rollups.FullHourRange(since, until)
	var count int64
	err := pool.QueryRow(ctx, `
WITH rollup_ips AS (
  SELECT DISTINCT ip_id
  FROM rollup_ip_1h
  WHERE bucket_ts >= $4 AND bucket_ts < $5
    AND ($3 = '' OR site_id = $3)
),
edge_ips AS (
  SELECT DISTINCT ip_id
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND client_ip IS NOT NULL
    AND (ts < $4 OR ts >= $5)
    AND ip_id IS NOT NULL
),
edge_raw_ips AS (
  SELECT DISTINCT client_ip
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND client_ip IS NOT NULL
    AND ip_id IS NULL
    AND (ts < $4 OR ts >= $5)
),
combined_ids AS (
  SELECT ip_id FROM rollup_ips
  UNION
  SELECT ip_id FROM edge_ips
)
SELECT
  (SELECT count(*)::bigint FROM combined_ids) +
  (SELECT count(*)::bigint FROM edge_raw_ips raw
   WHERE NOT EXISTS (
     SELECT 1
     FROM dim_ips d
     JOIN combined_ids c ON c.ip_id = d.id
     WHERE d.ip = raw.client_ip
   ))`, since, until, siteID, fullStart, fullEnd).Scan(&count)
	return count, err
}

func topIPFromRollups(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, siteID string) (TopIP, error) {
	fullStart, fullEnd, _ := rollups.FullHourRange(since, until)
	var topIP TopIP
	err := pool.QueryRow(ctx, `
WITH rollup_rows AS (
  SELECT d.ip, sum(r.requests)::bigint AS requests
  FROM rollup_ip_1h r
  JOIN dim_ips d ON d.id = r.ip_id
  WHERE r.bucket_ts >= $4 AND r.bucket_ts < $5
    AND ($3 = '' OR r.site_id = $3)
  GROUP BY d.ip
),
edge_rows AS (
  SELECT client_ip AS ip, count(*)::bigint AS requests
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND client_ip IS NOT NULL
    AND (ts < $4 OR ts >= $5)
  GROUP BY client_ip
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
)
SELECT host(ip), sum(requests)::bigint
FROM combined
GROUP BY ip
ORDER BY sum(requests) DESC
LIMIT 1`, since, until, siteID, fullStart, fullEnd).Scan(&topIP.IP, &topIP.Requests)
	return topIP, err
}

func resolveWindow(now time.Time, rangeValue string, from time.Time, to time.Time) (time.Time, time.Time, string, error) {
	duration, label := parseRange(rangeValue)
	since := now.Add(-duration)
	until := now
	if !from.IsZero() || !to.IsZero() {
		label = "custom"
	}
	if !from.IsZero() {
		since = from.UTC()
	}
	if !to.IsZero() {
		until = to.UTC()
	}
	if !until.After(since) {
		return since, until, label, errors.New("to must be after from")
	}
	return since, until, label, nil
}

func parseRange(value string) (time.Duration, string) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "15m":
		return 15 * time.Minute, "15m"
	case "6h":
		return 6 * time.Hour, "6h"
	case "24h", "daily", "day":
		return 24 * time.Hour, "24h"
	case "7d", "weekly", "week":
		return 7 * 24 * time.Hour, "7d"
	case "30d", "monthly", "month":
		return 30 * 24 * time.Hour, "30d"
	case "90d", "quarterly", "quarter":
		return 90 * 24 * time.Hour, "90d"
	case "365d", "annual", "yearly", "year", "1y":
		return 365 * 24 * time.Hour, "365d"
	case "1h", "":
		return time.Hour, "1h"
	default:
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed, value
		}
		return time.Hour, "1h"
	}
}
