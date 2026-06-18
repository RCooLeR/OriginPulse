package analytics

import (
	"context"
	"errors"
	"strings"
	"time"

	"originpulse/internal/db"
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

	var status2xx, status3xx, status4xx, status5xx int64
	var bytesSent int64
	if err := pool.QueryRow(ctx, `
SELECT coalesce(sum(requests), 0),
       coalesce(sum(status_2xx), 0),
       coalesce(sum(status_3xx), 0),
       coalesce(sum(status_4xx), 0),
       coalesce(sum(status_5xx), 0),
       coalesce(sum(bytes_sent), 0)
FROM rollup_1m
WHERE bucket_ts >= $1 AND bucket_ts < $2 AND ($3 = '' OR site_id = $3)`,
		since, until, overview.SiteID,
	).Scan(&overview.Requests, &status2xx, &status3xx, &status4xx, &status5xx, &bytesSent); err != nil {
		return overview, err
	}
	if err := pool.QueryRow(ctx, `
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
		overview.Status4xxRate = float64(status4xx) / float64(overview.Requests)
		overview.Status5xxRate = float64(status5xx) / float64(overview.Requests)
	}

	var topSite TopSite
	if err := pool.QueryRow(ctx, `
SELECT site_id, sum(requests)::bigint
FROM rollup_1m
WHERE bucket_ts >= $1 AND bucket_ts < $2 AND ($3 = '' OR site_id = $3)
GROUP BY site_id
ORDER BY sum(requests) DESC
LIMIT 1`, since, until, overview.SiteID).Scan(&topSite.SiteID, &topSite.Requests); err == nil {
		overview.TopSite = &topSite
	}

	var topIP TopIP
	if err := pool.QueryRow(ctx, `
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
