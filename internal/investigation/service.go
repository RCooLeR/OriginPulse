package investigation

import (
	"context"
	"errors"
	"strings"
	"time"

	"originpulse/internal/db"
)

type Options struct {
	Range  string
	Limit  int
	SiteID string
	From   time.Time
	To     time.Time
}

type Traffic struct {
	Range           string           `json:"range"`
	SiteID          string           `json:"site_id,omitempty"`
	Since           time.Time        `json:"since"`
	Until           time.Time        `json:"until"`
	GeneratedAt     time.Time        `json:"generated_at"`
	TopIPs          []IPSummary      `json:"top_ips"`
	TopPaths        []PathSummary    `json:"top_paths"`
	RecentErrors    []EventSummary   `json:"recent_errors"`
	StatusBreakdown []StatusSummary  `json:"status_breakdown"`
	Timeline        []TimelineBucket `json:"timeline"`
	DatabaseEnabled bool             `json:"database_enabled"`
}

type IPSummary struct {
	IP         string    `json:"ip"`
	Requests   int64     `json:"requests"`
	Status4xx  int64     `json:"status_4xx"`
	Status5xx  int64     `json:"status_5xx"`
	BytesSent  int64     `json:"bytes_sent"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	RiskScore  *int      `json:"risk_score,omitempty"`
	ActorType  string    `json:"actor_type,omitempty"`
	KnownActor string    `json:"known_actor,omitempty"`
	ReverseDNS string    `json:"reverse_dns,omitempty"`
}

type PathSummary struct {
	Path      string `json:"path"`
	Requests  int64  `json:"requests"`
	Status4xx int64  `json:"status_4xx"`
	Status5xx int64  `json:"status_5xx"`
	BytesSent int64  `json:"bytes_sent"`
}

type EventSummary struct {
	TS          time.Time `json:"ts"`
	SiteID      string    `json:"site_id"`
	Env         string    `json:"env"`
	ClientIP    string    `json:"client_ip,omitempty"`
	Method      string    `json:"method,omitempty"`
	Path        string    `json:"path,omitempty"`
	Query       string    `json:"query,omitempty"`
	Status      int       `json:"status,omitempty"`
	BytesSent   int64     `json:"bytes_sent,omitempty"`
	Referer     string    `json:"referer,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	ContainerID string    `json:"container_id,omitempty"`
}

type StatusSummary struct {
	Status   int   `json:"status"`
	Requests int64 `json:"requests"`
}

type TimelineBucket struct {
	BucketTS  time.Time `json:"bucket_ts"`
	Requests  int64     `json:"requests"`
	Status4xx int64     `json:"status_4xx"`
	Status5xx int64     `json:"status_5xx"`
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

func (s *Service) Traffic(ctx context.Context, opts Options) (Traffic, error) {
	limit := normalizeLimit(opts.Limit)
	now := time.Now().UTC()
	since, until, label, err := resolveWindow(now, opts.Range, opts.From, opts.To)
	out := Traffic{
		Range:           label,
		SiteID:          strings.TrimSpace(opts.SiteID),
		Since:           since,
		Until:           until,
		GeneratedAt:     now,
		TopIPs:          []IPSummary{},
		TopPaths:        []PathSummary{},
		RecentErrors:    []EventSummary{},
		StatusBreakdown: []StatusSummary{},
		Timeline:        []TimelineBucket{},
		DatabaseEnabled: s.Enabled(),
	}
	if err != nil {
		return out, err
	}
	if !s.Enabled() {
		return out, nil
	}

	pool, err := s.db.Pool()
	if err != nil {
		return out, err
	}

	ipRows, err := pool.Query(ctx, `
SELECT host(e.client_ip),
       count(*)::bigint AS requests,
       count(*) FILTER (WHERE e.status >= 400 AND e.status < 500)::bigint AS status_4xx,
       count(*) FILTER (WHERE e.status >= 500 AND e.status < 600)::bigint AS status_5xx,
       coalesce(sum(e.bytes_sent), 0)::bigint AS bytes_sent,
       min(e.ts),
       max(e.ts),
       coalesce(ii.risk_score, -1),
       coalesce(ii.actor_type, ''),
       coalesce(ii.known_actor, ''),
       coalesce(ii.reverse_dns, '')
FROM access_events e
LEFT JOIN ip_intel ii ON ii.ip = e.client_ip
WHERE e.ts >= $1 AND e.ts < $2 AND ($3 = '' OR e.site_id = $3) AND e.client_ip IS NOT NULL
GROUP BY e.client_ip, ii.risk_score, ii.actor_type, ii.known_actor, ii.reverse_dns
ORDER BY requests DESC
LIMIT $4`, out.Since, out.Until, out.SiteID, limit)
	if err != nil {
		return out, err
	}
	defer ipRows.Close()
	for ipRows.Next() {
		var item IPSummary
		var riskScore int
		if err := ipRows.Scan(
			&item.IP,
			&item.Requests,
			&item.Status4xx,
			&item.Status5xx,
			&item.BytesSent,
			&item.FirstSeen,
			&item.LastSeen,
			&riskScore,
			&item.ActorType,
			&item.KnownActor,
			&item.ReverseDNS,
		); err != nil {
			return out, err
		}
		if riskScore >= 0 {
			item.RiskScore = &riskScore
		}
		out.TopIPs = append(out.TopIPs, item)
	}
	if err := ipRows.Err(); err != nil {
		return out, err
	}

	pathRows, err := pool.Query(ctx, `
SELECT coalesce(path, '') AS path,
       count(*)::bigint AS requests,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
       coalesce(sum(bytes_sent), 0)::bigint AS bytes_sent
FROM access_events
WHERE ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3)
GROUP BY path
ORDER BY requests DESC
LIMIT $4`, out.Since, out.Until, out.SiteID, limit)
	if err != nil {
		return out, err
	}
	defer pathRows.Close()
	for pathRows.Next() {
		var item PathSummary
		if err := pathRows.Scan(&item.Path, &item.Requests, &item.Status4xx, &item.Status5xx, &item.BytesSent); err != nil {
			return out, err
		}
		out.TopPaths = append(out.TopPaths, item)
	}
	if err := pathRows.Err(); err != nil {
		return out, err
	}

	errorRows, err := pool.Query(ctx, `
SELECT ts,
       site_id,
       env,
       coalesce(container_id, ''),
       coalesce(host(client_ip), ''),
       coalesce(method, ''),
       coalesce(path, ''),
       coalesce(query, ''),
       coalesce(status, 0),
       coalesce(bytes_sent, 0),
       coalesce(referer, ''),
       left(coalesce(user_agent, ''), 300)
FROM access_events
WHERE ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3) AND status >= 400
ORDER BY ts DESC
LIMIT $4`, out.Since, out.Until, out.SiteID, limit)
	if err != nil {
		return out, err
	}
	defer errorRows.Close()
	for errorRows.Next() {
		var item EventSummary
		if err := errorRows.Scan(
			&item.TS,
			&item.SiteID,
			&item.Env,
			&item.ContainerID,
			&item.ClientIP,
			&item.Method,
			&item.Path,
			&item.Query,
			&item.Status,
			&item.BytesSent,
			&item.Referer,
			&item.UserAgent,
		); err != nil {
			return out, err
		}
		out.RecentErrors = append(out.RecentErrors, item)
	}
	if err := errorRows.Err(); err != nil {
		return out, err
	}

	statusRows, err := pool.Query(ctx, `
SELECT coalesce(status, 0), count(*)::bigint
FROM access_events
WHERE ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3)
GROUP BY status
ORDER BY count(*) DESC, status
LIMIT 16`, out.Since, out.Until, out.SiteID)
	if err != nil {
		return out, err
	}
	defer statusRows.Close()
	for statusRows.Next() {
		var item StatusSummary
		if err := statusRows.Scan(&item.Status, &item.Requests); err != nil {
			return out, err
		}
		out.StatusBreakdown = append(out.StatusBreakdown, item)
	}
	if err := statusRows.Err(); err != nil {
		return out, err
	}

	bucketSeconds := timelineBucketSeconds(out.Until.Sub(out.Since))
	timelineRows, err := pool.Query(ctx, `
SELECT to_timestamp(floor(extract(epoch FROM bucket_ts) / $4::double precision) * $4::double precision) AS bucket_ts,
       sum(requests)::bigint,
       sum(status_4xx)::bigint,
       sum(status_5xx)::bigint
FROM rollup_1m
WHERE bucket_ts >= $1 AND bucket_ts < $2 AND ($3 = '' OR site_id = $3)
GROUP BY 1
ORDER BY 1 DESC
LIMIT 180`, out.Since, out.Until, out.SiteID, bucketSeconds)
	if err != nil {
		return out, err
	}
	defer timelineRows.Close()
	for timelineRows.Next() {
		var item TimelineBucket
		if err := timelineRows.Scan(&item.BucketTS, &item.Requests, &item.Status4xx, &item.Status5xx); err != nil {
			return out, err
		}
		out.Timeline = append(out.Timeline, item)
	}
	if err := timelineRows.Err(); err != nil {
		return out, err
	}

	return out, nil
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 10
	}
	if limit > 100 {
		return 100
	}
	return limit
}

func timelineBucketSeconds(duration time.Duration) int {
	switch {
	case duration <= 3*time.Hour:
		return 60
	case duration <= 12*time.Hour:
		return 5 * 60
	case duration <= 3*24*time.Hour:
		return 15 * 60
	case duration <= 14*24*time.Hour:
		return 60 * 60
	default:
		return 24 * 60 * 60
	}
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
