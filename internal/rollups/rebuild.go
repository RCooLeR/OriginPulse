package rollups

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func DimensionRollupsReady(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, siteID string) (bool, error) {
	start, end, ok := FullHourRange(since, until)
	if !ok {
		return true, nil
	}
	var hasUnmarked bool
	err := pool.QueryRow(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND rollups_1h_backfilled_at IS NULL
  LIMIT 1
)`, start, end, siteID).Scan(&hasUnmarked)
	return !hasUnmarked, err
}

func StatusRollupsReady(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, siteID string) (bool, error) {
	start, end, ok := FullHourRange(since, until)
	if !ok {
		return true, nil
	}
	var minuteRequests int64
	var statusRequests int64
	err := pool.QueryRow(ctx, `
SELECT
  (SELECT coalesce(sum(requests), 0)::bigint
   FROM rollup_1m
   WHERE bucket_ts >= $1 AND bucket_ts < $2 AND ($3 = '' OR site_id = $3)),
  (SELECT coalesce(sum(requests), 0)::bigint
   FROM rollup_status_1h
   WHERE bucket_ts >= $1 AND bucket_ts < $2 AND ($3 = '' OR site_id = $3))`, start, end, siteID).Scan(&minuteRequests, &statusRequests)
	if err != nil {
		return false, err
	}
	if minuteRequests == 0 {
		return true, nil
	}
	return statusRequests == minuteRequests, nil
}

func FullHourRange(since time.Time, until time.Time) (time.Time, time.Time, bool) {
	start := since.UTC().Truncate(time.Hour)
	if !start.Equal(since.UTC()) {
		start = start.Add(time.Hour)
	}
	end := until.UTC().Truncate(time.Hour)
	return start, end, end.After(start)
}

func FullMinuteRange(since time.Time, until time.Time) (time.Time, time.Time, bool) {
	start := since.UTC().Truncate(time.Minute)
	if !start.Equal(since.UTC()) {
		start = start.Add(time.Minute)
	}
	end := until.UTC().Truncate(time.Minute)
	return start, end, end.After(start)
}

func Rebuild(ctx context.Context, pool *pgxpool.Pool, start time.Time, end time.Time) (int, error) {
	if !end.After(start) {
		return 0, nil
	}
	for _, table := range []string{"rollup_1m", "rollup_ip_1h", "rollup_path_1h", "rollup_user_agent_1h", "rollup_ip_path_1h", "rollup_ip_user_agent_1h", "rollup_status_1h", "rollup_site_latency_1h", "rollup_path_latency_1h", "rollup_security_probe_1h", "rollup_query_param_1h"} {
		if _, err := pool.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE bucket_ts >= $1 AND bucket_ts < $2`, table), start, end); err != nil {
			return 0, err
		}
	}

	count, err := insertReturningCount(ctx, pool, `
WITH grouped AS (
  SELECT date_trunc('minute', ts) AS bucket_ts,
         site_id,
         env,
         count(*) AS requests,
         count(*) FILTER (WHERE status >= 200 AND status < 300) AS status_2xx,
         count(*) FILTER (WHERE status >= 300 AND status < 400) AS status_3xx,
         count(*) FILTER (WHERE status >= 400 AND status < 500) AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600) AS status_5xx,
         count(DISTINCT client_ip) AS unique_ips,
         coalesce(sum(bytes_sent), 0) AS bytes_sent,
         count(*) FILTER (WHERE request_time_ms IS NOT NULL) AS request_time_count,
         coalesce(sum(request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0) AS request_time_sum_ms,
         count(*) FILTER (WHERE request_time_ms >= 1000) AS slow_requests,
         count(*) FILTER (WHERE coalesce(user_agent, '') = '') AS empty_user_agents
  FROM access_events
  WHERE ts >= $1 AND ts < $2
  GROUP BY 1, 2, 3
)
INSERT INTO rollup_1m (
  bucket_ts, site_id, env, requests, status_2xx, status_3xx, status_4xx, status_5xx, unique_ips, bytes_sent,
  request_time_count, request_time_sum_ms, slow_requests, empty_user_agents
)
SELECT bucket_ts, site_id, env, requests, status_2xx, status_3xx, status_4xx, status_5xx, unique_ips, bytes_sent,
       request_time_count, request_time_sum_ms, slow_requests, empty_user_agents
FROM grouped
ON CONFLICT (bucket_ts, site_id, env) DO UPDATE
SET requests = EXCLUDED.requests,
    status_2xx = EXCLUDED.status_2xx,
    status_3xx = EXCLUDED.status_3xx,
    status_4xx = EXCLUDED.status_4xx,
    status_5xx = EXCLUDED.status_5xx,
    unique_ips = EXCLUDED.unique_ips,
    bytes_sent = EXCLUDED.bytes_sent,
    request_time_count = EXCLUDED.request_time_count,
    request_time_sum_ms = EXCLUDED.request_time_sum_ms,
    slow_requests = EXCLUDED.slow_requests,
    empty_user_agents = EXCLUDED.empty_user_agents
RETURNING 1`, start, end)
	if err != nil {
		return 0, err
	}

	for _, spec := range []string{ipRollupSQL, pathRollupSQL, userAgentRollupSQL, ipPathRollupSQL, ipUserAgentRollupSQL, statusRollupSQL, siteLatencyRollupSQL, pathLatencyRollupSQL, securityProbeRollupSQL, queryParamRollupSQL} {
		inserted, err := insertReturningCount(ctx, pool, spec, start, end)
		if err != nil {
			return 0, err
		}
		count += inserted
	}

	return count, nil
}

func RebuildStatus(ctx context.Context, pool *pgxpool.Pool, start time.Time, end time.Time) (int, error) {
	if !end.After(start) {
		return 0, nil
	}
	if _, err := pool.Exec(ctx, `DELETE FROM rollup_status_1h WHERE bucket_ts >= $1 AND bucket_ts < $2`, start, end); err != nil {
		return 0, err
	}
	return insertReturningCount(ctx, pool, statusRollupSQL, start, end)
}

func insertReturningCount(ctx context.Context, pool *pgxpool.Pool, query string, args ...any) (int, error) {
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		count++
	}
	return count, rows.Err()
}

const ipRollupSQL = `
WITH grouped AS (
  SELECT date_trunc('hour', ts) AS bucket_ts,
         site_id,
         env,
         ip_id,
         count(*) AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500) AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600) AS status_5xx,
         coalesce(sum(bytes_sent), 0) AS bytes_sent,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM access_events
  WHERE ts >= $1 AND ts < $2 AND ip_id IS NOT NULL
  GROUP BY 1, 2, 3, 4
)
INSERT INTO rollup_ip_1h (
  bucket_ts, site_id, env, ip_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, ip_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, ip_id) DO UPDATE
SET requests = EXCLUDED.requests,
    status_4xx = EXCLUDED.status_4xx,
    status_5xx = EXCLUDED.status_5xx,
    bytes_sent = EXCLUDED.bytes_sent,
    first_seen_at = EXCLUDED.first_seen_at,
    last_seen_at = EXCLUDED.last_seen_at
RETURNING 1`

const queryParamFamilyCase = `
CASE
  WHEN param = 'srsltid' THEN 'srsltid'
  WHEN param LIKE 'utm\_%' ESCAPE '\' THEN 'utm'
  WHEN param IN ('gclid', 'fbclid', 'msclkid', 'dclid', 'gad_source', 'gbraid', 'wbraid', 'gad_campaignid') THEN 'click-id'
  WHEN param IN ('campaign', 'cid', 'x-campaign') THEN 'campaign'
  WHEN param LIKE 'wpv\_%' ESCAPE '\' THEN 'wpv'
  ELSE 'other'
END`

const queryParamRollupSQL = `
WITH query_pairs AS (
  SELECT date_trunc('hour', e.ts) AS bucket_ts,
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
         CASE WHEN strpos(pair.value, '=') > 0 THEN substr(pair.value, strpos(pair.value, '=') + 1) ELSE '' END AS param_value,
         e.ts
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
    AND e.query_id IS NOT NULL
),
classified AS (
  SELECT *,
         ` + queryParamFamilyCase + ` AS family
  FROM query_pairs
  WHERE param <> ''
),
grouped AS (
  SELECT bucket_ts,
         site_id,
         env,
         family,
         param,
         param_value,
         count(*) AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500) AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600) AS status_5xx,
         count(*) FILTER (WHERE request_time_ms >= 1000) AS slow_requests,
         count(DISTINCT client_ip) AS unique_ips,
         count(DISTINCT user_agent_id) AS unique_user_agents,
         count(DISTINCT path_id) AS unique_paths,
         count(*) FILTER (WHERE request_time_ms IS NOT NULL) AS request_time_count,
         coalesce(sum(request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0) AS request_time_sum_ms,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at,
         coalesce((array_agg(path ORDER BY ts DESC))[1], '') AS example_path,
         coalesce((array_agg(query ORDER BY ts DESC))[1], '') AS example_query
  FROM classified
  GROUP BY 1, 2, 3, 4, 5, 6
)
INSERT INTO rollup_query_param_1h (
  bucket_ts, site_id, env, family, param, param_value, requests, status_4xx, status_5xx, slow_requests,
  unique_ips, unique_user_agents, unique_paths, request_time_count, request_time_sum_ms, first_seen_at, last_seen_at,
  example_path, example_query
)
SELECT bucket_ts, site_id, env, family, param, param_value, requests, status_4xx, status_5xx, slow_requests,
       unique_ips, unique_user_agents, unique_paths, request_time_count, request_time_sum_ms, first_seen_at, last_seen_at,
       example_path, example_query
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, family, param, param_value) DO UPDATE
SET requests = EXCLUDED.requests,
    status_4xx = EXCLUDED.status_4xx,
    status_5xx = EXCLUDED.status_5xx,
    slow_requests = EXCLUDED.slow_requests,
    unique_ips = EXCLUDED.unique_ips,
    unique_user_agents = EXCLUDED.unique_user_agents,
    unique_paths = EXCLUDED.unique_paths,
    request_time_count = EXCLUDED.request_time_count,
    request_time_sum_ms = EXCLUDED.request_time_sum_ms,
    first_seen_at = EXCLUDED.first_seen_at,
    last_seen_at = EXCLUDED.last_seen_at,
    example_path = EXCLUDED.example_path,
    example_query = EXCLUDED.example_query
RETURNING 1`

const pathRollupSQL = `
WITH grouped AS (
  SELECT date_trunc('hour', ts) AS bucket_ts,
         site_id,
         env,
         path_id,
         count(*) AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500) AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600) AS status_5xx,
         coalesce(sum(bytes_sent), 0) AS bytes_sent,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM access_events
  WHERE ts >= $1 AND ts < $2 AND path_id IS NOT NULL
  GROUP BY 1, 2, 3, 4
)
INSERT INTO rollup_path_1h (
  bucket_ts, site_id, env, path_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, path_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, path_id) DO UPDATE
SET requests = EXCLUDED.requests,
    status_4xx = EXCLUDED.status_4xx,
    status_5xx = EXCLUDED.status_5xx,
    bytes_sent = EXCLUDED.bytes_sent,
    first_seen_at = EXCLUDED.first_seen_at,
    last_seen_at = EXCLUDED.last_seen_at
RETURNING 1`

const userAgentRollupSQL = `
WITH grouped AS (
  SELECT date_trunc('hour', ts) AS bucket_ts,
         site_id,
         env,
         user_agent_id,
         count(*) AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500) AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600) AS status_5xx,
         coalesce(sum(bytes_sent), 0) AS bytes_sent,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM access_events
  WHERE ts >= $1 AND ts < $2 AND user_agent_id IS NOT NULL
  GROUP BY 1, 2, 3, 4
)
INSERT INTO rollup_user_agent_1h (
  bucket_ts, site_id, env, user_agent_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, user_agent_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, user_agent_id) DO UPDATE
SET requests = EXCLUDED.requests,
    status_4xx = EXCLUDED.status_4xx,
    status_5xx = EXCLUDED.status_5xx,
    bytes_sent = EXCLUDED.bytes_sent,
    first_seen_at = EXCLUDED.first_seen_at,
    last_seen_at = EXCLUDED.last_seen_at
RETURNING 1`

const ipPathRollupSQL = `
WITH grouped AS (
  SELECT date_trunc('hour', ts) AS bucket_ts,
         site_id,
         env,
         ip_id,
         path_id,
         count(*) AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500) AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600) AS status_5xx,
         coalesce(sum(bytes_sent), 0) AS bytes_sent,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ip_id IS NOT NULL
    AND path_id IS NOT NULL
  GROUP BY 1, 2, 3, 4, 5
)
INSERT INTO rollup_ip_path_1h (
  bucket_ts, site_id, env, ip_id, path_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, ip_id, path_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, ip_id, path_id) DO UPDATE
SET requests = EXCLUDED.requests,
    status_4xx = EXCLUDED.status_4xx,
    status_5xx = EXCLUDED.status_5xx,
    bytes_sent = EXCLUDED.bytes_sent,
    first_seen_at = EXCLUDED.first_seen_at,
    last_seen_at = EXCLUDED.last_seen_at
RETURNING 1`

const ipUserAgentRollupSQL = `
WITH grouped AS (
  SELECT date_trunc('hour', ts) AS bucket_ts,
         site_id,
         env,
         ip_id,
         user_agent_id,
         count(*) AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500) AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600) AS status_5xx,
         coalesce(sum(bytes_sent), 0) AS bytes_sent,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ip_id IS NOT NULL
    AND user_agent_id IS NOT NULL
  GROUP BY 1, 2, 3, 4, 5
)
INSERT INTO rollup_ip_user_agent_1h (
  bucket_ts, site_id, env, ip_id, user_agent_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, ip_id, user_agent_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, ip_id, user_agent_id) DO UPDATE
SET requests = EXCLUDED.requests,
    status_4xx = EXCLUDED.status_4xx,
    status_5xx = EXCLUDED.status_5xx,
    bytes_sent = EXCLUDED.bytes_sent,
    first_seen_at = EXCLUDED.first_seen_at,
    last_seen_at = EXCLUDED.last_seen_at
RETURNING 1`

const statusRollupSQL = `
WITH grouped AS (
  SELECT date_trunc('hour', ts) AS bucket_ts,
         site_id,
         env,
         coalesce(status, 0) AS status,
         count(*) AS requests,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM access_events
  WHERE ts >= $1 AND ts < $2
  GROUP BY 1, 2, 3, 4
)
INSERT INTO rollup_status_1h (
  bucket_ts, site_id, env, status, requests, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, status, requests, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, status) DO UPDATE
SET requests = EXCLUDED.requests,
    first_seen_at = EXCLUDED.first_seen_at,
    last_seen_at = EXCLUDED.last_seen_at
RETURNING 1`

const latencyBucketCase = `
CASE
  WHEN request_time_ms <= 50 THEN 50
  WHEN request_time_ms <= 100 THEN 100
  WHEN request_time_ms <= 200 THEN 200
  WHEN request_time_ms <= 300 THEN 300
  WHEN request_time_ms <= 500 THEN 500
  WHEN request_time_ms <= 750 THEN 750
  WHEN request_time_ms <= 1000 THEN 1000
  WHEN request_time_ms <= 1500 THEN 1500
  WHEN request_time_ms <= 2000 THEN 2000
  WHEN request_time_ms <= 3000 THEN 3000
  WHEN request_time_ms <= 5000 THEN 5000
  WHEN request_time_ms <= 10000 THEN 10000
  WHEN request_time_ms <= 30000 THEN 30000
  WHEN request_time_ms <= 60000 THEN 60000
  ELSE 2147483647
END`

const siteLatencyRollupSQL = `
WITH bucketed AS (
  SELECT date_trunc('hour', ts) AS bucket_ts,
         site_id,
         env,
         ` + latencyBucketCase + ` AS bucket_le_ms
  FROM access_events
  WHERE ts >= $1 AND ts < $2 AND request_time_ms IS NOT NULL
),
grouped AS (
  SELECT bucket_ts,
         site_id,
         env,
         bucket_le_ms,
         count(*) AS requests
  FROM bucketed
  GROUP BY 1, 2, 3, 4
)
INSERT INTO rollup_site_latency_1h (
  bucket_ts, site_id, env, bucket_le_ms, requests
)
SELECT bucket_ts, site_id, env, bucket_le_ms, requests
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, bucket_le_ms) DO UPDATE
SET requests = EXCLUDED.requests
RETURNING 1`

const pathLatencyRollupSQL = `
WITH bucketed AS (
  SELECT date_trunc('hour', ts) AS bucket_ts,
         site_id,
         env,
         path_id,
         ` + latencyBucketCase + ` AS bucket_le_ms,
         status,
         request_time_ms,
         ts
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND request_time_ms IS NOT NULL
    AND path_id IS NOT NULL
),
grouped AS (
  SELECT bucket_ts,
         site_id,
         env,
         path_id,
         bucket_le_ms,
         count(*) AS requests,
         count(*) FILTER (WHERE status >= 500 AND status < 600) AS status_5xx,
         coalesce(sum(request_time_ms), 0) AS request_time_sum_ms,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM bucketed
  GROUP BY 1, 2, 3, 4, 5
)
INSERT INTO rollup_path_latency_1h (
  bucket_ts, site_id, env, path_id, bucket_le_ms, requests, status_5xx, request_time_sum_ms, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, path_id, bucket_le_ms, requests, status_5xx, request_time_sum_ms, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, path_id, bucket_le_ms) DO UPDATE
SET requests = EXCLUDED.requests,
    status_5xx = EXCLUDED.status_5xx,
    request_time_sum_ms = EXCLUDED.request_time_sum_ms,
    first_seen_at = EXCLUDED.first_seen_at,
    last_seen_at = EXCLUDED.last_seen_at
RETURNING 1`

const securityProbeRollupSQL = `
WITH grouped AS (
  SELECT date_trunc('hour', ts) AS bucket_ts,
         site_id,
         env,
         family,
         category,
         rule_key,
         count(*) AS events,
         count(DISTINCT client_ip) AS unique_ips,
         count(*) FILTER (WHERE status >= 400 AND status < 500) AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600) AS status_5xx,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM security_probe_events
  WHERE ts >= $1 AND ts < $2
  GROUP BY 1, 2, 3, 4, 5, 6
)
INSERT INTO rollup_security_probe_1h (
  bucket_ts, site_id, env, family, category, rule_key, events, unique_ips, status_4xx, status_5xx, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, family, category, rule_key, events, unique_ips, status_4xx, status_5xx, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, family, category, rule_key) DO UPDATE
SET events = EXCLUDED.events,
    unique_ips = EXCLUDED.unique_ips,
    status_4xx = EXCLUDED.status_4xx,
    status_5xx = EXCLUDED.status_5xx,
    first_seen_at = EXCLUDED.first_seen_at,
    last_seen_at = EXCLUDED.last_seen_at
RETURNING 1`
