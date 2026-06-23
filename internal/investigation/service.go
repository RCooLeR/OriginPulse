package investigation

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/db"
	"originpulse/internal/rollups"
)

type Options struct {
	Range              string
	Limit              int
	SiteID             string
	From               time.Time
	To                 time.Time
	IncludeQueryParams bool
	IncludeTimings     bool
}

const DetailMaxLimit = 500

type Traffic struct {
	Range           string              `json:"range"`
	SiteID          string              `json:"site_id,omitempty"`
	Since           time.Time           `json:"since"`
	Until           time.Time           `json:"until"`
	GeneratedAt     time.Time           `json:"generated_at"`
	TopIPs          []IPSummary         `json:"top_ips"`
	TopPaths        []PathSummary       `json:"top_paths"`
	RecentErrors    []EventSummary      `json:"recent_errors"`
	QueryParams     []QueryParamSummary `json:"query_params"`
	StatusBreakdown []StatusSummary     `json:"status_breakdown"`
	Timeline        []TimelineBucket    `json:"timeline"`
	Timings         []Timing            `json:"timings,omitempty"`
	DatabaseEnabled bool                `json:"database_enabled"`
}

type Timing struct {
	Name       string `json:"name"`
	DurationMS int64  `json:"duration_ms"`
}

type IPSummary struct {
	IP               string    `json:"ip"`
	Requests         int64     `json:"requests"`
	Status4xx        int64     `json:"status_4xx"`
	Status5xx        int64     `json:"status_5xx"`
	BytesSent        int64     `json:"bytes_sent"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	RiskScore        *int      `json:"risk_score,omitempty"`
	ActorType        string    `json:"actor_type,omitempty"`
	KnownActor       string    `json:"known_actor,omitempty"`
	ReverseDNS       string    `json:"reverse_dns,omitempty"`
	VerifiedActor    bool      `json:"verified_actor"`
	VerifiedSource   bool      `json:"verified_source"`
	ProviderVerified bool      `json:"provider_verified"`
	ProviderID       string    `json:"provider_id,omitempty"`
	ProviderName     string    `json:"provider_name,omitempty"`
	ProviderSource   string    `json:"provider_source_url,omitempty"`
	ProviderRange    string    `json:"provider_range,omitempty"`
	ManualLabel      string    `json:"manual_label,omitempty"`
	ManualAction     string    `json:"manual_action,omitempty"`
}

type PathSummary struct {
	Path      string `json:"path"`
	Requests  int64  `json:"requests"`
	Status4xx int64  `json:"status_4xx"`
	Status5xx int64  `json:"status_5xx"`
	BytesSent int64  `json:"bytes_sent"`
}

type QueryParamSummary struct {
	SiteID           string    `json:"site_id"`
	Env              string    `json:"env"`
	Family           string    `json:"family"`
	Param            string    `json:"param"`
	Requests         int64     `json:"requests"`
	DistinctValues   int64     `json:"distinct_values"`
	Status4xx        int64     `json:"status_4xx"`
	Status5xx        int64     `json:"status_5xx"`
	SlowRequests     int64     `json:"slow_requests"`
	UniqueIPs        int64     `json:"unique_ips"`
	UniqueUserAgents int64     `json:"unique_user_agents"`
	UniquePaths      int64     `json:"unique_paths"`
	AvgRequestTimeMS float64   `json:"avg_request_time_ms"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	ExamplePath      string    `json:"example_path,omitempty"`
	ExampleQuery     string    `json:"example_query,omitempty"`
	ExampleValue     string    `json:"example_value,omitempty"`
}

type EventSummary struct {
	TS               time.Time `json:"ts"`
	SiteID           string    `json:"site_id"`
	Env              string    `json:"env"`
	ClientIP         string    `json:"client_ip,omitempty"`
	Method           string    `json:"method,omitempty"`
	Path             string    `json:"path,omitempty"`
	Query            string    `json:"query,omitempty"`
	Status           int       `json:"status,omitempty"`
	BytesSent        int64     `json:"bytes_sent,omitempty"`
	Referer          string    `json:"referer,omitempty"`
	UserAgent        string    `json:"user_agent,omitempty"`
	ContainerID      string    `json:"container_id,omitempty"`
	KnownActor       string    `json:"known_actor,omitempty"`
	ActorType        string    `json:"actor_type,omitempty"`
	VerifiedActor    bool      `json:"verified_actor"`
	VerifiedSource   bool      `json:"verified_source"`
	ProviderVerified bool      `json:"provider_verified"`
	ProviderID       string    `json:"provider_id,omitempty"`
	ProviderName     string    `json:"provider_name,omitempty"`
	ProviderSource   string    `json:"provider_source_url,omitempty"`
	ProviderRange    string    `json:"provider_range,omitempty"`
	ManualLabel      string    `json:"manual_label,omitempty"`
	ManualAction     string    `json:"manual_action,omitempty"`
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
		QueryParams:     []QueryParamSummary{},
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

	recordTiming := func(name string, started time.Time) {
		if !opts.IncludeTimings {
			return
		}
		out.Timings = append(out.Timings, Timing{Name: name, DurationMS: time.Since(started).Milliseconds()})
	}
	timed := func(name string, fn func() error) error {
		started := time.Now()
		err := fn()
		recordTiming(name, started)
		return err
	}

	started := time.Now()
	rollupsReady, err := rollups.DimensionRollupsReady(ctx, pool, out.Since, out.Until, out.SiteID)
	recordTiming("dimension_rollups_ready", started)
	if err != nil {
		return out, err
	}
	if rollupsReady {
		if err := timed("top_ips_rollups", func() error { return loadTopIPsFromRollups(ctx, pool, &out, limit) }); err != nil {
			return out, err
		}
		if err := timed("top_paths_rollups", func() error { return loadTopPathsFromRollups(ctx, pool, &out, limit) }); err != nil {
			return out, err
		}
	} else {
		if err := timed("top_ips_raw", func() error { return loadTopIPsFromRaw(ctx, pool, &out, limit) }); err != nil {
			return out, err
		}
		if err := timed("top_paths_raw", func() error { return loadTopPathsFromRaw(ctx, pool, &out, limit) }); err != nil {
			return out, err
		}
	}

	if err := timed("recent_errors", func() error { return loadRecentErrorsFromFacts(ctx, pool, &out, limit) }); err != nil {
		return out, err
	}
	if opts.IncludeQueryParams {
		queryParamReady := false
		if rollupsReady {
			started := time.Now()
			queryParamReady, err = queryParamRollupCoverageReady(ctx, pool, out.Since, out.Until, out.SiteID)
			recordTiming("query_param_rollups_ready", started)
			if err != nil {
				return out, err
			}
		}
		if queryParamReady {
			if err := timed("query_params_rollups", func() error { return loadQueryParamsFromRollups(ctx, pool, &out, limit) }); err != nil {
				return out, err
			}
		} else if err := timed("query_params_raw", func() error { return loadQueryParamsFromRaw(ctx, pool, &out, limit) }); err != nil {
			return out, err
		}
	}

	statusRollupsReady := false
	if rollupsReady {
		started := time.Now()
		statusRollupsReady, err = rollups.StatusRollupsReady(ctx, pool, out.Since, out.Until, out.SiteID)
		recordTiming("status_rollups_ready", started)
		if err != nil {
			return out, err
		}
	}
	if statusRollupsReady {
		if err := timed("status_breakdown_rollups", func() error { return loadStatusBreakdownFromRollups(ctx, pool, &out) }); err != nil {
			return out, err
		}
	} else if err := timed("status_breakdown_raw", func() error { return loadStatusBreakdownFromRaw(ctx, pool, &out) }); err != nil {
		return out, err
	}

	bucketSeconds := timelineBucketSeconds(out.Until.Sub(out.Since))
	started = time.Now()
	timelineRows, err := pool.Query(ctx, `
WITH buckets AS (
  SELECT to_timestamp(floor(extract(epoch FROM bucket_ts) / $4::double precision) * $4::double precision) AS bucket_ts,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx
  FROM rollup_1m
  WHERE bucket_ts >= $1 AND bucket_ts < $2 AND ($3 = '' OR site_id = $3)
  GROUP BY 1
  ORDER BY 1 DESC
  LIMIT 180
)
SELECT bucket_ts,
       requests,
       status_4xx,
       status_5xx
FROM buckets
ORDER BY bucket_ts ASC`, out.Since, out.Until, out.SiteID, bucketSeconds)
	if err != nil {
		recordTiming("timeline", started)
		return out, err
	}
	defer timelineRows.Close()
	for timelineRows.Next() {
		var item TimelineBucket
		if err := timelineRows.Scan(&item.BucketTS, &item.Requests, &item.Status4xx, &item.Status5xx); err != nil {
			recordTiming("timeline", started)
			return out, err
		}
		out.Timeline = append(out.Timeline, item)
	}
	if err := timelineRows.Err(); err != nil {
		recordTiming("timeline", started)
		return out, err
	}
	recordTiming("timeline", started)

	return out, nil
}

func loadRecentErrorsFromFacts(ctx context.Context, pool *pgxpool.Pool, out *Traffic, limit int) error {
	rows, err := pool.Query(ctx, `
WITH fact_rows AS (
  SELECT f.ts,
         f.site_id,
         f.env,
         coalesce(f.container_id, '') AS container_id,
         coalesce(host(f.client_ip), '') AS client_ip,
         coalesce(f.method, '') AS method,
         coalesce(p.path, '') AS path,
         coalesce(q.query, '') AS query,
         f.status,
         coalesce(f.bytes_sent, 0) AS bytes_sent,
         coalesce(f.referer, '') AS referer,
         left(coalesce(ua.user_agent, ''), 300) AS user_agent,
         coalesce(ii.known_actor, '') AS known_actor,
         coalesce(ii.actor_type, '') AS actor_type,
         coalesce(ii.verified_actor, false) AS verified_actor,
         (coalesce(ii.manual_action, '') IN ('allowlisted', 'verified') OR (coalesce(ii.manual_action, '') <> 'suspicious' AND lower(coalesce(ii.actor_type, '')) NOT IN ('', 'datacenter', 'unknown', 'tor') AND (coalesce(ii.verified_actor, false) OR (coalesce(ii.forward_confirmed, false) AND nullif(ii.known_actor, '') IS NOT NULL)))) AS verified_source,
         coalesce(ii.provider_verified, false) AS provider_verified,
         coalesce(ii.provider_id, '') AS provider_id,
         coalesce(ii.provider_name, '') AS provider_name,
         coalesce(ii.provider_source_url, '') AS provider_source_url,
         coalesce(ii.provider_range::text, '') AS provider_range,
         coalesce(ii.manual_label, '') AS manual_label,
         coalesce(ii.manual_action, '') AS manual_action
  FROM error_events f
  LEFT JOIN dim_paths p ON p.id = f.path_id
  LEFT JOIN dim_queries q ON q.id = f.query_id
  LEFT JOIN dim_user_agents ua ON ua.id = f.user_agent_id
  LEFT JOIN ip_intel ii ON ii.ip = f.client_ip
  WHERE f.ts >= $1 AND f.ts < $2 AND ($3 = '' OR f.site_id = $3)
),
raw_gap_rows AS (
  SELECT e.ts,
         e.site_id,
         e.env,
         coalesce(e.container_id, '') AS container_id,
         coalesce(host(e.client_ip), '') AS client_ip,
         coalesce(e.method, '') AS method,
         coalesce(e.path, '') AS path,
         coalesce(e.query, '') AS query,
         coalesce(e.status, 0) AS status,
         coalesce(e.bytes_sent, 0) AS bytes_sent,
         coalesce(e.referer, '') AS referer,
         left(coalesce(e.user_agent, ''), 300) AS user_agent,
         coalesce(ii.known_actor, '') AS known_actor,
         coalesce(ii.actor_type, '') AS actor_type,
         coalesce(ii.verified_actor, false) AS verified_actor,
         (coalesce(ii.manual_action, '') IN ('allowlisted', 'verified') OR (coalesce(ii.manual_action, '') <> 'suspicious' AND lower(coalesce(ii.actor_type, '')) NOT IN ('', 'datacenter', 'unknown', 'tor') AND (coalesce(ii.verified_actor, false) OR (coalesce(ii.forward_confirmed, false) AND nullif(ii.known_actor, '') IS NOT NULL)))) AS verified_source,
         coalesce(ii.provider_verified, false) AS provider_verified,
         coalesce(ii.provider_id, '') AS provider_id,
         coalesce(ii.provider_name, '') AS provider_name,
         coalesce(ii.provider_source_url, '') AS provider_source_url,
         coalesce(ii.provider_range::text, '') AS provider_range,
         coalesce(ii.manual_label, '') AS manual_label,
         coalesce(ii.manual_action, '') AS manual_action
  FROM access_events e
  LEFT JOIN ip_intel ii ON ii.ip = e.client_ip
  WHERE e.ts >= $1 AND e.ts < $2
    AND ($3 = '' OR e.site_id = $3)
    AND e.status >= 400
    AND NOT EXISTS (SELECT 1 FROM error_events f WHERE f.event_id = e.id)
),
combined AS (
  SELECT * FROM fact_rows
  UNION ALL
  SELECT * FROM raw_gap_rows
)
SELECT ts,
       site_id,
       env,
       container_id,
       client_ip,
       method,
       path,
       query,
       status,
       bytes_sent,
       referer,
       user_agent,
       known_actor,
       actor_type,
       verified_actor,
       verified_source,
       provider_verified,
       provider_id,
       provider_name,
       provider_source_url,
       provider_range,
       manual_label,
       manual_action
FROM combined
ORDER BY ts DESC
LIMIT $4`, out.Since, out.Until, out.SiteID, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item EventSummary
		if err := rows.Scan(
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
			&item.KnownActor,
			&item.ActorType,
			&item.VerifiedActor,
			&item.VerifiedSource,
			&item.ProviderVerified,
			&item.ProviderID,
			&item.ProviderName,
			&item.ProviderSource,
			&item.ProviderRange,
			&item.ManualLabel,
			&item.ManualAction,
		); err != nil {
			return err
		}
		out.RecentErrors = append(out.RecentErrors, item)
	}
	return rows.Err()
}

func loadStatusBreakdownFromRaw(ctx context.Context, pool *pgxpool.Pool, out *Traffic) error {
	statusRows, err := pool.Query(ctx, `
SELECT coalesce(status, 0), count(*)::bigint
FROM access_events
WHERE ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3)
GROUP BY status
ORDER BY count(*) DESC, status
LIMIT 16`, out.Since, out.Until, out.SiteID)
	if err != nil {
		return err
	}
	defer statusRows.Close()
	for statusRows.Next() {
		var item StatusSummary
		if err := statusRows.Scan(&item.Status, &item.Requests); err != nil {
			return err
		}
		out.StatusBreakdown = append(out.StatusBreakdown, item)
	}
	return statusRows.Err()
}

func loadStatusBreakdownFromRollups(ctx context.Context, pool *pgxpool.Pool, out *Traffic) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(out.Since, out.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT status, sum(requests)::bigint AS requests
  FROM rollup_status_1h
  WHERE bucket_ts >= $4 AND bucket_ts < $5
    AND ($3 = '' OR site_id = $3)
  GROUP BY status
),
edge_rows AS (
  SELECT coalesce(status, 0) AS status, count(*)::bigint AS requests
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND (ts < $4 OR ts >= $5)
  GROUP BY coalesce(status, 0)
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
)
SELECT status, sum(requests)::bigint
FROM combined
GROUP BY status
ORDER BY sum(requests) DESC, status
LIMIT 16`, out.Since, out.Until, out.SiteID, fullStart, fullEnd)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item StatusSummary
		if err := rows.Scan(&item.Status, &item.Requests); err != nil {
			return err
		}
		out.StatusBreakdown = append(out.StatusBreakdown, item)
	}
	return rows.Err()
}

func loadTopIPsFromRaw(ctx context.Context, pool *pgxpool.Pool, out *Traffic, limit int) error {
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
       coalesce(ii.reverse_dns, ''),
       coalesce(ii.verified_actor, false),
       coalesce(ii.forward_confirmed, false),
       coalesce(ii.provider_verified, false),
       coalesce(ii.provider_id, ''),
       coalesce(ii.provider_name, ''),
       coalesce(ii.provider_source_url, ''),
       coalesce(ii.provider_range::text, ''),
       coalesce(ii.manual_label, ''),
       coalesce(ii.manual_action, '')
FROM access_events e
LEFT JOIN ip_intel ii ON ii.ip = e.client_ip
WHERE e.ts >= $1 AND e.ts < $2 AND ($3 = '' OR e.site_id = $3) AND e.client_ip IS NOT NULL
GROUP BY e.client_ip, ii.risk_score, ii.actor_type, ii.known_actor, ii.reverse_dns, ii.verified_actor, ii.forward_confirmed, ii.provider_verified, ii.provider_id, ii.provider_name, ii.provider_source_url, ii.provider_range, ii.manual_label, ii.manual_action
ORDER BY requests DESC
LIMIT $4`, out.Since, out.Until, out.SiteID, limit)
	if err != nil {
		return err
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
			&item.VerifiedActor,
			&item.VerifiedSource,
			&item.ProviderVerified,
			&item.ProviderID,
			&item.ProviderName,
			&item.ProviderSource,
			&item.ProviderRange,
			&item.ManualLabel,
			&item.ManualAction,
		); err != nil {
			return err
		}
		if riskScore >= 0 {
			item.RiskScore = &riskScore
		}
		item.VerifiedSource = verifiedSource(item.KnownActor, item.ActorType, item.ManualAction, item.VerifiedSource, item.VerifiedActor)
		out.TopIPs = append(out.TopIPs, item)
	}
	return ipRows.Err()
}

func loadTopPathsFromRaw(ctx context.Context, pool *pgxpool.Pool, out *Traffic, limit int) error {
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
		return err
	}
	defer pathRows.Close()
	for pathRows.Next() {
		var item PathSummary
		if err := pathRows.Scan(&item.Path, &item.Requests, &item.Status4xx, &item.Status5xx, &item.BytesSent); err != nil {
			return err
		}
		out.TopPaths = append(out.TopPaths, item)
	}
	return pathRows.Err()
}

func loadQueryParamsFromRaw(ctx context.Context, pool *pgxpool.Pool, out *Traffic, limit int) error {
	rows, err := pool.Query(ctx, `
WITH query_pairs AS (
  SELECT e.ts,
         e.site_id,
         e.env,
         e.status,
         e.request_time_ms,
         e.client_ip,
         e.user_agent_id,
         e.path_id,
         coalesce(p.path, '') AS path,
         q.query,
         lower(ltrim(split_part(pair.value, '=', 1), '?')) AS param,
         CASE WHEN strpos(pair.value, '=') > 0 THEN substr(pair.value, strpos(pair.value, '=') + 1) ELSE '' END AS param_value
  FROM access_events e
  JOIN LATERAL (
    SELECT query
    FROM dim_queries
    WHERE id = e.query_id
  ) q ON true
  LEFT JOIN dim_paths p ON p.id = e.path_id
  CROSS JOIN LATERAL unnest(string_to_array(q.query, '&')) AS pair(value)
  WHERE e.ts >= $1
    AND e.ts < $2
    AND ($3 = '' OR e.site_id = $3)
    AND e.query_id IS NOT NULL
),
classified AS (
  SELECT *,
         CASE
           WHEN param = 'srsltid' THEN 'srsltid'
           WHEN param LIKE 'utm\_%' ESCAPE '\' THEN 'utm'
           WHEN param IN ('gclid', 'fbclid', 'msclkid', 'dclid', 'gad_source', 'gbraid', 'wbraid', 'gad_campaignid') THEN 'click-id'
           WHEN param IN ('campaign', 'cid', 'x-campaign') THEN 'campaign'
           WHEN param LIKE 'wpv\_%' ESCAPE '\' THEN 'wpv'
           ELSE 'other'
         END AS family
  FROM query_pairs
  WHERE param <> ''
)
SELECT site_id,
       env,
       family,
       param,
       count(*)::bigint AS requests,
       count(DISTINCT param_value)::bigint AS distinct_values,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
       count(*) FILTER (WHERE request_time_ms >= 1000)::bigint AS slow_requests,
       count(DISTINCT client_ip)::bigint AS unique_ips,
       count(DISTINCT user_agent_id)::bigint AS unique_user_agents,
       count(DISTINCT path_id)::bigint AS unique_paths,
       coalesce(avg(request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::double precision AS avg_request_time_ms,
       min(ts) AS first_seen,
       max(ts) AS last_seen,
       coalesce((array_agg(path ORDER BY ts DESC))[1], '') AS example_path,
       coalesce((array_agg(query ORDER BY ts DESC))[1], '') AS example_query,
       coalesce((array_agg(param_value ORDER BY ts DESC))[1], '') AS example_value
FROM classified
GROUP BY site_id, env, family, param
ORDER BY status_5xx DESC, slow_requests DESC, requests DESC, site_id, env, family, param
LIMIT $4`, out.Since, out.Until, out.SiteID, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item QueryParamSummary
		if err := rows.Scan(
			&item.SiteID,
			&item.Env,
			&item.Family,
			&item.Param,
			&item.Requests,
			&item.DistinctValues,
			&item.Status4xx,
			&item.Status5xx,
			&item.SlowRequests,
			&item.UniqueIPs,
			&item.UniqueUserAgents,
			&item.UniquePaths,
			&item.AvgRequestTimeMS,
			&item.FirstSeen,
			&item.LastSeen,
			&item.ExamplePath,
			&item.ExampleQuery,
			&item.ExampleValue,
		); err != nil {
			return err
		}
		out.QueryParams = append(out.QueryParams, item)
	}
	return rows.Err()
}

func queryParamRollupCoverageReady(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, siteID string) (bool, error) {
	fullStart, fullEnd, ok := rollups.FullHourRange(since, until)
	if !ok {
		return false, nil
	}
	var missing bool
	err := pool.QueryRow(ctx, `
WITH event_hours AS (
  SELECT DISTINCT date_trunc('hour', ts) AS bucket_ts, site_id, env
  FROM access_events
  WHERE ts >= $1
    AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND query_id IS NOT NULL
),
rollup_hours AS (
  SELECT DISTINCT bucket_ts, site_id, env
  FROM rollup_query_param_1h
  WHERE bucket_ts >= $1
    AND bucket_ts < $2
    AND ($3 = '' OR site_id = $3)
)
SELECT EXISTS (
  SELECT 1
  FROM event_hours e
  LEFT JOIN rollup_hours r ON r.bucket_ts = e.bucket_ts AND r.site_id = e.site_id AND r.env = e.env
  WHERE r.bucket_ts IS NULL
  LIMIT 1
)`, fullStart, fullEnd, siteID).Scan(&missing)
	return !missing, err
}

func loadQueryParamsFromRollups(ctx context.Context, pool *pgxpool.Pool, out *Traffic, limit int) error {
	fullStart, fullEnd, ok := rollups.FullHourRange(out.Since, out.Until)
	if !ok {
		return loadQueryParamsFromRaw(ctx, pool, out, limit)
	}
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT site_id,
         env,
         family,
         param,
         param_value,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx,
         sum(slow_requests)::bigint AS slow_requests,
         sum(unique_ips)::bigint AS unique_ips,
         sum(unique_user_agents)::bigint AS unique_user_agents,
         sum(unique_paths)::bigint AS unique_paths,
         sum(request_time_count)::bigint AS request_time_count,
         sum(request_time_sum_ms)::bigint AS request_time_sum_ms,
         min(first_seen_at) AS first_seen,
         max(last_seen_at) AS last_seen,
         coalesce((array_agg(example_path ORDER BY last_seen_at DESC))[1], '') AS example_path,
         coalesce((array_agg(example_query ORDER BY last_seen_at DESC))[1], '') AS example_query
  FROM rollup_query_param_1h
  WHERE bucket_ts >= $5
    AND bucket_ts < $6
    AND ($3 = '' OR site_id = $3)
  GROUP BY site_id, env, family, param, param_value
),
edge_pairs AS (
  SELECT e.ts,
         e.site_id,
         e.env,
         e.status,
         e.request_time_ms,
         e.client_ip,
         e.user_agent_id,
         e.path_id,
         coalesce(p.path, '') AS path,
         q.query,
         lower(ltrim(split_part(pair.value, '=', 1), '?')) AS param,
         CASE WHEN strpos(pair.value, '=') > 0 THEN substr(pair.value, strpos(pair.value, '=') + 1) ELSE '' END AS param_value
  FROM access_events e
  JOIN LATERAL (
    SELECT query
    FROM dim_queries
    WHERE id = e.query_id
  ) q ON true
  LEFT JOIN dim_paths p ON p.id = e.path_id
  CROSS JOIN LATERAL unnest(string_to_array(q.query, '&')) AS pair(value)
  WHERE e.ts >= $1
    AND e.ts < $2
    AND ($3 = '' OR e.site_id = $3)
    AND e.query_id IS NOT NULL
    AND (e.ts < $5 OR e.ts >= $6)
),
edge_classified AS (
  SELECT *,
         CASE
           WHEN param = 'srsltid' THEN 'srsltid'
           WHEN param LIKE 'utm\_%' ESCAPE '\' THEN 'utm'
           WHEN param IN ('gclid', 'fbclid', 'msclkid', 'dclid', 'gad_source', 'gbraid', 'wbraid', 'gad_campaignid') THEN 'click-id'
           WHEN param IN ('campaign', 'cid', 'x-campaign') THEN 'campaign'
           WHEN param LIKE 'wpv\_%' ESCAPE '\' THEN 'wpv'
           ELSE 'other'
         END AS family
  FROM edge_pairs
  WHERE param <> ''
),
edge_rows AS (
  SELECT site_id,
         env,
         family,
         param,
         param_value,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
         count(*) FILTER (WHERE request_time_ms >= 1000)::bigint AS slow_requests,
         count(DISTINCT client_ip)::bigint AS unique_ips,
         count(DISTINCT user_agent_id)::bigint AS unique_user_agents,
         count(DISTINCT path_id)::bigint AS unique_paths,
         count(*) FILTER (WHERE request_time_ms IS NOT NULL)::bigint AS request_time_count,
         coalesce(sum(request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::bigint AS request_time_sum_ms,
         min(ts) AS first_seen,
         max(ts) AS last_seen,
         coalesce((array_agg(path ORDER BY ts DESC))[1], '') AS example_path,
         coalesce((array_agg(query ORDER BY ts DESC))[1], '') AS example_query
  FROM edge_classified
  GROUP BY site_id, env, family, param, param_value
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
),
grouped AS (
  SELECT site_id,
         env,
         family,
         param,
         param_value,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx,
         sum(slow_requests)::bigint AS slow_requests,
         sum(unique_ips)::bigint AS unique_ips,
         sum(unique_user_agents)::bigint AS unique_user_agents,
         sum(unique_paths)::bigint AS unique_paths,
         sum(request_time_count)::bigint AS request_time_count,
         sum(request_time_sum_ms)::bigint AS request_time_sum_ms,
         min(first_seen) AS first_seen,
         max(last_seen) AS last_seen,
         coalesce((array_agg(example_path ORDER BY last_seen DESC))[1], '') AS example_path,
         coalesce((array_agg(example_query ORDER BY last_seen DESC))[1], '') AS example_query
  FROM combined
  GROUP BY site_id, env, family, param, param_value
)
SELECT site_id,
       env,
       family,
       param,
       sum(requests)::bigint AS requests,
       count(DISTINCT param_value)::bigint AS distinct_values,
       sum(status_4xx)::bigint AS status_4xx,
       sum(status_5xx)::bigint AS status_5xx,
       sum(slow_requests)::bigint AS slow_requests,
       sum(unique_ips)::bigint AS unique_ips,
       sum(unique_user_agents)::bigint AS unique_user_agents,
       sum(unique_paths)::bigint AS unique_paths,
       CASE WHEN sum(request_time_count) > 0 THEN (sum(request_time_sum_ms)::double precision / sum(request_time_count)::double precision) ELSE 0 END AS avg_request_time_ms,
       min(first_seen) AS first_seen,
       max(last_seen) AS last_seen,
       coalesce((array_agg(example_path ORDER BY last_seen DESC))[1], '') AS example_path,
       coalesce((array_agg(example_query ORDER BY last_seen DESC))[1], '') AS example_query,
       coalesce((array_agg(param_value ORDER BY last_seen DESC))[1], '') AS example_value
FROM grouped
GROUP BY site_id, env, family, param
ORDER BY sum(status_5xx) DESC, sum(slow_requests) DESC, sum(requests) DESC, site_id, env, family, param
LIMIT $4`, out.Since, out.Until, out.SiteID, limit, fullStart, fullEnd)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item QueryParamSummary
		if err := rows.Scan(
			&item.SiteID,
			&item.Env,
			&item.Family,
			&item.Param,
			&item.Requests,
			&item.DistinctValues,
			&item.Status4xx,
			&item.Status5xx,
			&item.SlowRequests,
			&item.UniqueIPs,
			&item.UniqueUserAgents,
			&item.UniquePaths,
			&item.AvgRequestTimeMS,
			&item.FirstSeen,
			&item.LastSeen,
			&item.ExamplePath,
			&item.ExampleQuery,
			&item.ExampleValue,
		); err != nil {
			return err
		}
		out.QueryParams = append(out.QueryParams, item)
	}
	return rows.Err()
}

func loadTopIPsFromRollups(ctx context.Context, pool *pgxpool.Pool, out *Traffic, limit int) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(out.Since, out.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT d.ip,
         sum(r.requests)::bigint AS requests,
         sum(r.status_4xx)::bigint AS status_4xx,
         sum(r.status_5xx)::bigint AS status_5xx,
         sum(r.bytes_sent)::bigint AS bytes_sent,
         min(r.first_seen_at) AS first_seen_at,
         max(r.last_seen_at) AS last_seen_at
  FROM rollup_ip_1h r
  JOIN dim_ips d ON d.id = r.ip_id
  WHERE r.bucket_ts >= $5 AND r.bucket_ts < $6
    AND ($3 = '' OR r.site_id = $3)
  GROUP BY d.ip
),
edge_rows AS (
  SELECT e.client_ip AS ip,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE e.status >= 400 AND e.status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE e.status >= 500 AND e.status < 600)::bigint AS status_5xx,
         coalesce(sum(e.bytes_sent), 0)::bigint AS bytes_sent,
         min(e.ts) AS first_seen_at,
         max(e.ts) AS last_seen_at
  FROM access_events e
  WHERE e.ts >= $1 AND e.ts < $2
    AND ($3 = '' OR e.site_id = $3)
    AND e.client_ip IS NOT NULL
    AND (e.ts < $5 OR e.ts >= $6)
  GROUP BY e.client_ip
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
),
grouped AS (
  SELECT ip,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx,
         sum(bytes_sent)::bigint AS bytes_sent,
         min(first_seen_at) AS first_seen_at,
         max(last_seen_at) AS last_seen_at
  FROM combined
  GROUP BY ip
)
SELECT host(g.ip),
       g.requests,
       g.status_4xx,
       g.status_5xx,
       g.bytes_sent,
       g.first_seen_at,
       g.last_seen_at,
       coalesce(ii.risk_score, -1),
       coalesce(ii.actor_type, ''),
       coalesce(ii.known_actor, ''),
       coalesce(ii.reverse_dns, ''),
       coalesce(ii.verified_actor, false),
       coalesce(ii.forward_confirmed, false),
       coalesce(ii.provider_verified, false),
       coalesce(ii.provider_id, ''),
       coalesce(ii.provider_name, ''),
       coalesce(ii.provider_source_url, ''),
       coalesce(ii.provider_range::text, ''),
       coalesce(ii.manual_label, ''),
       coalesce(ii.manual_action, '')
FROM grouped g
LEFT JOIN ip_intel ii ON ii.ip = g.ip
ORDER BY g.requests DESC
LIMIT $4`, out.Since, out.Until, out.SiteID, limit, fullStart, fullEnd)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item IPSummary
		var riskScore int
		if err := rows.Scan(
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
			&item.VerifiedActor,
			&item.VerifiedSource,
			&item.ProviderVerified,
			&item.ProviderID,
			&item.ProviderName,
			&item.ProviderSource,
			&item.ProviderRange,
			&item.ManualLabel,
			&item.ManualAction,
		); err != nil {
			return err
		}
		if riskScore >= 0 {
			item.RiskScore = &riskScore
		}
		item.VerifiedSource = verifiedSource(item.KnownActor, item.ActorType, item.ManualAction, item.VerifiedSource, item.VerifiedActor)
		out.TopIPs = append(out.TopIPs, item)
	}
	return rows.Err()
}

func loadTopPathsFromRollups(ctx context.Context, pool *pgxpool.Pool, out *Traffic, limit int) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(out.Since, out.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT d.path,
         sum(r.requests)::bigint AS requests,
         sum(r.status_4xx)::bigint AS status_4xx,
         sum(r.status_5xx)::bigint AS status_5xx,
         sum(r.bytes_sent)::bigint AS bytes_sent
  FROM rollup_path_1h r
  JOIN dim_paths d ON d.id = r.path_id
  WHERE r.bucket_ts >= $5 AND r.bucket_ts < $6
    AND ($3 = '' OR r.site_id = $3)
  GROUP BY d.path
),
edge_rows AS (
  SELECT coalesce(path, '') AS path,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
         coalesce(sum(bytes_sent), 0)::bigint AS bytes_sent
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND (ts < $5 OR ts >= $6)
  GROUP BY coalesce(path, '')
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
)
SELECT path,
       sum(requests)::bigint AS requests,
       sum(status_4xx)::bigint AS status_4xx,
       sum(status_5xx)::bigint AS status_5xx,
       sum(bytes_sent)::bigint AS bytes_sent
FROM combined
GROUP BY path
ORDER BY requests DESC
LIMIT $4`, out.Since, out.Until, out.SiteID, limit, fullStart, fullEnd)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item PathSummary
		if err := rows.Scan(&item.Path, &item.Requests, &item.Status4xx, &item.Status5xx, &item.BytesSent); err != nil {
			return err
		}
		out.TopPaths = append(out.TopPaths, item)
	}
	return rows.Err()
}

func verifiedSource(knownActor string, actorType string, manualAction string, forwardConfirmed bool, verifiedActor bool) bool {
	action := strings.ToLower(strings.TrimSpace(manualAction))
	if action == "suspicious" {
		return false
	}
	if action == "allowlisted" || action == "verified" {
		return true
	}
	if !trustedActorType(actorType) {
		return false
	}
	if verifiedActor {
		return true
	}
	actor := strings.ToLower(strings.TrimSpace(knownActor))
	return forwardConfirmed && actor != "" && actor != "tor exit"
}

func trustedActorType(actorType string) bool {
	switch strings.ToLower(strings.TrimSpace(actorType)) {
	case "cloud", "datacenter", "edge", "hosting", "vps", "unknown", "tor", "":
		return false
	default:
		return true
	}
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 10
	}
	if limit > DetailMaxLimit {
		return DetailMaxLimit
	}
	return limit
}

func normalizeOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

func timelineBucketSeconds(duration time.Duration) int {
	seconds := 60
	switch {
	case duration <= 3*time.Hour:
		seconds = 60
	case duration <= 12*time.Hour:
		seconds = 5 * 60
	case duration <= 3*24*time.Hour:
		seconds = 15 * 60
	case duration <= 14*24*time.Hour:
		seconds = 60 * 60
	default:
		seconds = 24 * 60 * 60
	}
	const maxTimelinePoints = 180
	if duration > 0 && int(duration.Seconds())/seconds > maxTimelinePoints {
		seconds = niceTimelineBucketSeconds(duration, maxTimelinePoints)
	}
	return seconds
}

func niceTimelineBucketSeconds(duration time.Duration, maxPoints int) int {
	if maxPoints <= 0 {
		maxPoints = 180
	}
	minSeconds := int(math.Ceil(duration.Seconds() / float64(maxPoints)))
	niceBuckets := []int{
		60,
		2 * 60,
		5 * 60,
		10 * 60,
		15 * 60,
		30 * 60,
		60 * 60,
		2 * 60 * 60,
		3 * 60 * 60,
		6 * 60 * 60,
		12 * 60 * 60,
		24 * 60 * 60,
		2 * 24 * 60 * 60,
		3 * 24 * 60 * 60,
		7 * 24 * 60 * 60,
		14 * 24 * 60 * 60,
		30 * 24 * 60 * 60,
	}
	for _, bucket := range niceBuckets {
		if bucket >= minSeconds {
			return bucket
		}
	}
	return niceBuckets[len(niceBuckets)-1]
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
	case "30m":
		return 30 * time.Minute, "30m"
	case "3h":
		return 3 * time.Hour, "3h"
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
