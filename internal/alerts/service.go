package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/db"
	"originpulse/internal/rollups"
)

var ErrNotFound = errors.New("alert not found")

const (
	RecentMaxLimit = 500
	DetailMaxLimit = 500
)

type Options struct {
	Range string
	Limit int
}

type Result struct {
	Range      string    `json:"range"`
	Since      time.Time `json:"since"`
	Evaluated  int       `json:"evaluated"`
	Upserted   int       `json:"upserted"`
	OpenAlerts []Alert   `json:"open_alerts"`
}

type Alert struct {
	ID          string         `json:"id"`
	RuleKey     string         `json:"rule_key"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	Status      string         `json:"status"`
	SiteID      string         `json:"site_id,omitempty"`
	Env         string         `json:"env,omitempty"`
	ActorType   string         `json:"actor_type,omitempty"`
	ActorValue  string         `json:"actor_value,omitempty"`
	Score       int            `json:"score,omitempty"`
	Summary     string         `json:"summary,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
	FirstSeenAt time.Time      `json:"first_seen_at"`
	LastSeenAt  time.Time      `json:"last_seen_at"`
	CreatedAt   time.Time      `json:"created_at"`
}

type Detail struct {
	Alert    Alert     `json:"alert"`
	Requests []Request `json:"requests"`
}

type Request struct {
	Timestamp time.Time `json:"ts"`
	SiteID    string    `json:"site_id"`
	Env       string    `json:"env"`
	Method    string    `json:"method,omitempty"`
	Path      string    `json:"path"`
	Query     string    `json:"query,omitempty"`
	Status    int       `json:"status"`
	BytesSent int64     `json:"bytes_sent,omitempty"`
	ClientIP  string    `json:"client_ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Referer   string    `json:"referer,omitempty"`
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

func (s *Service) Open(ctx context.Context, limit int) ([]Alert, error) {
	if !s.Enabled() {
		return []Alert{}, nil
	}
	limit = normalizeRecentLimit(limit)

	pool, err := s.db.Pool()
	if err != nil {
		return nil, err
	}

	rows, err := pool.Query(ctx, `
SELECT id::text,
       rule_key,
       title,
       severity,
       status,
       coalesce(site_id, ''),
       coalesce(env, ''),
       coalesce(actor_type, ''),
       coalesce(actor_value, ''),
       coalesce(score, 0),
       coalesce(summary, ''),
       details::text,
       first_seen_at,
       last_seen_at,
       created_at
FROM alerts
WHERE status = 'open'
ORDER BY last_seen_at DESC, created_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	alerts := make([]Alert, 0, limit)
	for rows.Next() {
		item, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, item)
	}
	return alerts, rows.Err()
}

func (s *Service) Get(ctx context.Context, id string, limit int) (Detail, error) {
	if !s.Enabled() {
		return Detail{}, ErrNotFound
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return Detail{}, ErrNotFound
	}
	limit = normalizeDetailLimit(limit)
	pool, err := s.db.Pool()
	if err != nil {
		return Detail{}, err
	}

	row := pool.QueryRow(ctx, `
SELECT id::text,
       rule_key,
       title,
       severity,
       status,
       coalesce(site_id, ''),
       coalesce(env, ''),
       coalesce(actor_type, ''),
       coalesce(actor_value, ''),
       coalesce(score, 0),
       coalesce(summary, ''),
       details::text,
       first_seen_at,
       last_seen_at,
       created_at
FROM alerts
WHERE id = $1::uuid`, id)
	alert, err := scanAlert(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Detail{}, ErrNotFound
	}
	if err != nil {
		return Detail{}, err
	}
	requests, err := loadAlertRequests(ctx, pool, alert, limit)
	if err != nil {
		return Detail{}, err
	}
	return Detail{Alert: alert, Requests: requests}, nil
}

func (s *Service) Evaluate(ctx context.Context, opts Options) (Result, error) {
	duration, label := parseRange(opts.Range)
	limit := normalizeLimit(opts.Limit)
	now := time.Now().UTC()
	result := Result{
		Range:      label,
		Since:      now.Add(-duration),
		OpenAlerts: []Alert{},
	}
	if !s.Enabled() {
		return result, nil
	}

	pool, err := s.db.Pool()
	if err != nil {
		return result, err
	}
	until := now

	rollupsReady, err := rollups.DimensionRollupsReady(ctx, pool, result.Since, until, "")
	if err != nil {
		return result, err
	}

	ipCandidates, err := loadIPCandidates(ctx, pool, result.Since, until, limit, rollupsReady)
	if err != nil {
		return result, err
	}
	for _, candidate := range ipCandidates {
		result.Evaluated++
		if candidate.Status5xx >= 10 && ratio(candidate.Status5xx, candidate.Requests) >= 0.10 {
			if err := s.upsertCandidate(ctx, candidate, "ip_5xx_burst"); err != nil {
				return result, err
			}
			result.Upserted++
			continue
		}
		if candidate.Status4xx >= 100 && ratio(candidate.Status4xx, candidate.Requests) >= 0.50 {
			if err := s.upsertCandidate(ctx, candidate, "ip_4xx_scan"); err != nil {
				return result, err
			}
			result.Upserted++
		}
	}

	pathCandidates, err := loadPathCandidates(ctx, pool, result.Since, until, limit, rollupsReady)
	if err != nil {
		return result, err
	}
	for _, candidate := range pathCandidates {
		result.Evaluated++
		if candidate.Status5xx >= 5 && ratio(candidate.Status5xx, candidate.Requests) >= 0.20 {
			if err := s.upsertCandidate(ctx, candidate, "path_5xx_hotspot"); err != nil {
				return result, err
			}
			result.Upserted++
		}
	}

	result.OpenAlerts, err = s.Open(ctx, 25)
	return result, err
}

func loadIPCandidates(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, limit int, rollupsReady bool) ([]actorCandidate, error) {
	if rollupsReady {
		return loadIPCandidatesFromRollups(ctx, pool, since, until, limit)
	}
	return loadIPCandidatesFromRaw(ctx, pool, since, until, limit)
}

func loadIPCandidatesFromRaw(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, limit int) ([]actorCandidate, error) {
	rows, err := pool.Query(ctx, `
SELECT site_id,
       env,
       host(client_ip),
       count(*)::bigint AS requests,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
       min(ts),
       max(ts)
FROM access_events
WHERE ts >= $1 AND ts < $3 AND client_ip IS NOT NULL
GROUP BY site_id, env, client_ip
HAVING count(*) >= 50
ORDER BY count(*) DESC
LIMIT $2`, since, limit, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	candidates := make([]actorCandidate, 0, limit)
	for rows.Next() {
		var candidate actorCandidate
		if err := rows.Scan(
			&candidate.SiteID,
			&candidate.Env,
			&candidate.ActorValue,
			&candidate.Requests,
			&candidate.Status4xx,
			&candidate.Status5xx,
			&candidate.FirstSeen,
			&candidate.LastSeen,
		); err != nil {
			return nil, err
		}
		candidate.ActorType = "ip"
		candidates = append(candidates, candidate)
	}
	return candidates, rows.Err()
}

func loadIPCandidatesFromRollups(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, limit int) ([]actorCandidate, error) {
	fullStart, fullEnd, _ := rollups.FullHourRange(since, until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT r.site_id,
         r.env,
         d.ip,
         sum(r.requests)::bigint AS requests,
         sum(r.status_4xx)::bigint AS status_4xx,
         sum(r.status_5xx)::bigint AS status_5xx,
         min(r.first_seen_at) AS first_seen_at,
         max(r.last_seen_at) AS last_seen_at
  FROM rollup_ip_1h r
  JOIN dim_ips d ON d.id = r.ip_id
  WHERE r.bucket_ts >= $3 AND r.bucket_ts < $4
  GROUP BY r.site_id, r.env, d.ip
),
edge_rows AS (
  SELECT site_id,
         env,
         client_ip AS ip,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND client_ip IS NOT NULL
    AND (ts < $3 OR ts >= $4)
  GROUP BY site_id, env, client_ip
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
),
grouped AS (
  SELECT site_id,
         env,
         ip,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx,
         min(first_seen_at) AS first_seen_at,
         max(last_seen_at) AS last_seen_at
  FROM combined
  GROUP BY site_id, env, ip
)
SELECT site_id,
       env,
       host(ip),
       requests,
       status_4xx,
       status_5xx,
       first_seen_at,
       last_seen_at
FROM grouped
WHERE requests >= 50
ORDER BY requests DESC
LIMIT $5`, since, until, fullStart, fullEnd, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	candidates := make([]actorCandidate, 0, limit)
	for rows.Next() {
		var candidate actorCandidate
		if err := rows.Scan(
			&candidate.SiteID,
			&candidate.Env,
			&candidate.ActorValue,
			&candidate.Requests,
			&candidate.Status4xx,
			&candidate.Status5xx,
			&candidate.FirstSeen,
			&candidate.LastSeen,
		); err != nil {
			return nil, err
		}
		candidate.ActorType = "ip"
		candidates = append(candidates, candidate)
	}
	return candidates, rows.Err()
}

func loadPathCandidates(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, limit int, rollupsReady bool) ([]actorCandidate, error) {
	if rollupsReady {
		return loadPathCandidatesFromRollups(ctx, pool, since, until, limit)
	}
	return loadPathCandidatesFromRaw(ctx, pool, since, until, limit)
}

func loadPathCandidatesFromRaw(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, limit int) ([]actorCandidate, error) {
	rows, err := pool.Query(ctx, `
SELECT site_id,
       env,
       coalesce(path, ''),
       count(*)::bigint AS requests,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
       min(ts),
       max(ts)
FROM access_events
WHERE ts >= $1 AND ts < $3
GROUP BY site_id, env, path
HAVING count(*) >= 30
ORDER BY count(*) DESC
LIMIT $2`, since, limit, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	candidates := make([]actorCandidate, 0, limit)
	for rows.Next() {
		var candidate actorCandidate
		if err := rows.Scan(
			&candidate.SiteID,
			&candidate.Env,
			&candidate.ActorValue,
			&candidate.Requests,
			&candidate.Status5xx,
			&candidate.FirstSeen,
			&candidate.LastSeen,
		); err != nil {
			return nil, err
		}
		candidate.ActorType = "path"
		candidates = append(candidates, candidate)
	}
	return candidates, rows.Err()
}

func loadPathCandidatesFromRollups(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, limit int) ([]actorCandidate, error) {
	fullStart, fullEnd, _ := rollups.FullHourRange(since, until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT r.site_id,
         r.env,
         d.path,
         sum(r.requests)::bigint AS requests,
         sum(r.status_5xx)::bigint AS status_5xx,
         min(r.first_seen_at) AS first_seen_at,
         max(r.last_seen_at) AS last_seen_at
  FROM rollup_path_1h r
  JOIN dim_paths d ON d.id = r.path_id
  WHERE r.bucket_ts >= $3 AND r.bucket_ts < $4
  GROUP BY r.site_id, r.env, d.path
),
edge_rows AS (
  SELECT site_id,
         env,
         coalesce(path, '') AS path,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND (ts < $3 OR ts >= $4)
  GROUP BY site_id, env, coalesce(path, '')
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
),
grouped AS (
  SELECT site_id,
         env,
         path,
         sum(requests)::bigint AS requests,
         sum(status_5xx)::bigint AS status_5xx,
         min(first_seen_at) AS first_seen_at,
         max(last_seen_at) AS last_seen_at
  FROM combined
  GROUP BY site_id, env, path
)
SELECT site_id,
       env,
       path,
       requests,
       status_5xx,
       first_seen_at,
       last_seen_at
FROM grouped
WHERE requests >= 30
ORDER BY requests DESC
LIMIT $5`, since, until, fullStart, fullEnd, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	candidates := make([]actorCandidate, 0, limit)
	for rows.Next() {
		var candidate actorCandidate
		if err := rows.Scan(
			&candidate.SiteID,
			&candidate.Env,
			&candidate.ActorValue,
			&candidate.Requests,
			&candidate.Status5xx,
			&candidate.FirstSeen,
			&candidate.LastSeen,
		); err != nil {
			return nil, err
		}
		candidate.ActorType = "path"
		candidates = append(candidates, candidate)
	}
	return candidates, rows.Err()
}

type actorCandidate struct {
	SiteID     string
	Env        string
	ActorType  string
	ActorValue string
	Requests   int64
	Status4xx  int64
	Status5xx  int64
	FirstSeen  time.Time
	LastSeen   time.Time
}

func (s *Service) upsertCandidate(ctx context.Context, candidate actorCandidate, ruleKey string) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}

	title, summary, score := describe(candidate, ruleKey)
	severity := severityFor(score)
	details := map[string]any{
		"requests":   candidate.Requests,
		"status_4xx": candidate.Status4xx,
		"status_5xx": candidate.Status5xx,
		"range":      map[string]string{"first_seen": candidate.FirstSeen.Format(time.RFC3339), "last_seen": candidate.LastSeen.Format(time.RFC3339)},
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return err
	}

	var existingID string
	err = pool.QueryRow(ctx, `
SELECT id::text
FROM alerts
WHERE status = 'open'
  AND rule_key = $1
  AND site_id = $2
  AND env = $3
  AND actor_type = $4
  AND actor_value = $5
ORDER BY created_at DESC
LIMIT 1`,
		ruleKey,
		candidate.SiteID,
		candidate.Env,
		candidate.ActorType,
		candidate.ActorValue,
	).Scan(&existingID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	if existingID != "" {
		_, err = pool.Exec(ctx, `
UPDATE alerts
SET title = $2,
    severity = $3,
    score = $4,
    summary = $5,
    details = $6::jsonb,
    first_seen_at = LEAST(first_seen_at, $7),
    last_seen_at = GREATEST(last_seen_at, $8)
WHERE id = $1`,
			existingID,
			title,
			severity,
			score,
			summary,
			string(detailsJSON),
			candidate.FirstSeen,
			candidate.LastSeen,
		)
		return err
	}

	_, err = pool.Exec(ctx, `
INSERT INTO alerts (
  rule_key, title, severity, status, site_id, env, actor_type, actor_value,
  score, summary, details, first_seen_at, last_seen_at
) VALUES (
  $1, $2, $3, 'open', $4, $5, $6, $7,
  $8, $9, $10::jsonb, $11, $12
)`,
		ruleKey,
		title,
		severity,
		candidate.SiteID,
		candidate.Env,
		candidate.ActorType,
		candidate.ActorValue,
		score,
		summary,
		string(detailsJSON),
		candidate.FirstSeen,
		candidate.LastSeen,
	)
	return err
}

type alertScanner interface {
	Scan(dest ...any) error
}

func scanAlert(row alertScanner) (Alert, error) {
	var item Alert
	var detailsRaw string
	if err := row.Scan(
		&item.ID,
		&item.RuleKey,
		&item.Title,
		&item.Severity,
		&item.Status,
		&item.SiteID,
		&item.Env,
		&item.ActorType,
		&item.ActorValue,
		&item.Score,
		&item.Summary,
		&detailsRaw,
		&item.FirstSeenAt,
		&item.LastSeenAt,
		&item.CreatedAt,
	); err != nil {
		return Alert{}, err
	}
	if detailsRaw != "" {
		_ = json.Unmarshal([]byte(detailsRaw), &item.Details)
	}
	return item, nil
}

func loadAlertRequests(ctx context.Context, pool *pgxpool.Pool, alert Alert, limit int) ([]Request, error) {
	statusMin, statusMax := alertStatusRange(alert.RuleKey)
	if alert.ActorType == "ip" && alert.ActorValue != "" {
		return loadAlertRequestsForIP(ctx, pool, alert, statusMin, statusMax, limit)
	}
	if alert.ActorType == "path" && alert.ActorValue != "" {
		return loadAlertRequestsForPath(ctx, pool, alert, statusMin, statusMax, limit)
	}
	return []Request{}, nil
}

func loadAlertRequestsForIP(ctx context.Context, pool *pgxpool.Pool, alert Alert, statusMin int, statusMax int, limit int) ([]Request, error) {
	rows, err := pool.Query(ctx, `
SELECT f.ts,
       f.site_id,
       f.env,
       coalesce(f.method, ''),
       coalesce(p.path, ''),
       coalesce(q.query, ''),
       f.status,
       coalesce(f.bytes_sent, 0)::bigint,
       coalesce(host(f.client_ip), ''),
       left(coalesce(ua.user_agent, ''), 300),
       coalesce(f.referer, '')
FROM error_events f
LEFT JOIN dim_paths p ON p.id = f.path_id
LEFT JOIN dim_queries q ON q.id = f.query_id
LEFT JOIN dim_user_agents ua ON ua.id = f.user_agent_id
WHERE f.client_ip = $1::inet
  AND f.ts >= $2 AND f.ts <= $3
  AND ($4 = '' OR f.site_id = $4)
  AND ($5 = '' OR f.env = $5)
  AND f.status >= $6 AND f.status < $7
ORDER BY f.ts DESC
LIMIT $8`, alert.ActorValue, alert.FirstSeenAt, alert.LastSeenAt, alert.SiteID, alert.Env, statusMin, statusMax, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlertRequests(rows)
}

func loadAlertRequestsForPath(ctx context.Context, pool *pgxpool.Pool, alert Alert, statusMin int, statusMax int, limit int) ([]Request, error) {
	rows, err := pool.Query(ctx, `
SELECT f.ts,
       f.site_id,
       f.env,
       coalesce(f.method, ''),
       coalesce(p.path, ''),
       coalesce(q.query, ''),
       f.status,
       coalesce(f.bytes_sent, 0)::bigint,
       coalesce(host(f.client_ip), ''),
       left(coalesce(ua.user_agent, ''), 300),
       coalesce(f.referer, '')
FROM error_events f
JOIN dim_paths p ON p.id = f.path_id
LEFT JOIN dim_queries q ON q.id = f.query_id
LEFT JOIN dim_user_agents ua ON ua.id = f.user_agent_id
WHERE p.path = $1
  AND f.ts >= $2 AND f.ts <= $3
  AND ($4 = '' OR f.site_id = $4)
  AND ($5 = '' OR f.env = $5)
  AND f.status >= $6 AND f.status < $7
ORDER BY f.ts DESC
LIMIT $8`, alert.ActorValue, alert.FirstSeenAt, alert.LastSeenAt, alert.SiteID, alert.Env, statusMin, statusMax, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlertRequests(rows)
}

func scanAlertRequests(rows pgx.Rows) ([]Request, error) {
	requests := []Request{}
	for rows.Next() {
		var item Request
		if err := rows.Scan(
			&item.Timestamp,
			&item.SiteID,
			&item.Env,
			&item.Method,
			&item.Path,
			&item.Query,
			&item.Status,
			&item.BytesSent,
			&item.ClientIP,
			&item.UserAgent,
			&item.Referer,
		); err != nil {
			return nil, err
		}
		requests = append(requests, item)
	}
	return requests, rows.Err()
}

func alertStatusRange(ruleKey string) (int, int) {
	if strings.Contains(ruleKey, "5xx") {
		return 500, 600
	}
	if strings.Contains(ruleKey, "4xx") {
		return 400, 500
	}
	return 400, 600
}

func describe(candidate actorCandidate, ruleKey string) (string, string, int) {
	switch ruleKey {
	case "ip_5xx_burst":
		rate := ratio(candidate.Status5xx, candidate.Requests)
		score := int(rate*70) + int(min(candidate.Status5xx/10, 30))
		return "High 5xx rate from IP",
			fmt.Sprintf("%s generated %d server errors across %d requests", candidate.ActorValue, candidate.Status5xx, candidate.Requests),
			clamp(score, 35, 100)
	case "ip_4xx_scan":
		rate := ratio(candidate.Status4xx, candidate.Requests)
		score := int(rate*60) + int(min(candidate.Status4xx/50, 30))
		return "High 4xx volume from IP",
			fmt.Sprintf("%s generated %d client errors across %d requests", candidate.ActorValue, candidate.Status4xx, candidate.Requests),
			clamp(score, 25, 90)
	case "path_5xx_hotspot":
		rate := ratio(candidate.Status5xx, candidate.Requests)
		score := int(rate*80) + int(min(candidate.Status5xx/5, 20))
		return "Path 5xx hotspot",
			fmt.Sprintf("%s returned %d server errors across %d requests", candidate.ActorValue, candidate.Status5xx, candidate.Requests),
			clamp(score, 30, 95)
	default:
		return "Traffic anomaly",
			fmt.Sprintf("%s %s matched %s", candidate.ActorType, candidate.ActorValue, ruleKey),
			25
	}
}

func severityFor(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

func ratio(part int64, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) / float64(total)
}

func min(a int64, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func clamp(value int, low int, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 500 {
		return 500
	}
	return limit
}

func normalizeRecentLimit(limit int) int {
	if limit <= 0 {
		return 25
	}
	if limit > RecentMaxLimit {
		return RecentMaxLimit
	}
	return limit
}

func normalizeDetailLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > DetailMaxLimit {
		return DetailMaxLimit
	}
	return limit
}

func parseRange(value string) (time.Duration, string) {
	switch value {
	case "15m":
		return 15 * time.Minute, "15m"
	case "6h":
		return 6 * time.Hour, "6h"
	case "24h":
		return 24 * time.Hour, "24h"
	case "7d":
		return 7 * 24 * time.Hour, "7d"
	case "1h", "":
		return time.Hour, "1h"
	default:
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed, value
		}
		return time.Hour, "1h"
	}
}
