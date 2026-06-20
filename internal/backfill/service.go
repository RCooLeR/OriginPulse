package backfill

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/db"
	"originpulse/internal/useragent"
)

const backfillLockKey int64 = 7720004

type Options struct {
	BatchSize  int  `json:"batch_size"`
	MaxBatches int  `json:"max_batches"`
	Rollups    bool `json:"rollups"`
}

type Result struct {
	Batches               int       `json:"batches"`
	EventsProcessed       int64     `json:"events_processed"`
	EventsRemaining       int64     `json:"events_remaining"`
	MinEventID            int64     `json:"min_event_id,omitempty"`
	MaxEventID            int64     `json:"max_event_id,omitempty"`
	RangeStart            time.Time `json:"range_start,omitempty"`
	RangeEnd              time.Time `json:"range_end,omitempty"`
	IPRollupRows          int64     `json:"ip_rollup_rows"`
	PathRollupRows        int64     `json:"path_rollup_rows"`
	UserAgentRollupRows   int64     `json:"user_agent_rollup_rows"`
	IPPathRollupRows      int64     `json:"ip_path_rollup_rows"`
	IPUserAgentRollupRows int64     `json:"ip_user_agent_rollup_rows"`
	StatusRollupRows      int64     `json:"status_rollup_rows"`
	SiteLatencyRows       int64     `json:"site_latency_rows"`
	PathLatencyRows       int64     `json:"path_latency_rows"`
	ErrorEvents           int64     `json:"error_events"`
	SlowRequestEvents     int64     `json:"slow_request_events"`
	UserAgentsEnriched    int64     `json:"user_agents_enriched"`
	SecurityProbeRollups  int64     `json:"security_probe_rollups"`
	SecurityProbeRebuilt  bool      `json:"security_probe_rebuilt"`
	StoppedAtMaxBatches   bool      `json:"stopped_at_max_batches"`
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

func (s *Service) Run(ctx context.Context, opts Options) (Result, error) {
	if !s.Enabled() {
		return Result{}, db.ErrUnavailable
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 5000
	}
	if opts.BatchSize > 50000 {
		opts.BatchSize = 50000
	}

	var result Result
	err := s.db.WithAdvisoryLock(ctx, backfillLockKey, func(ctx context.Context) error {
		pool, err := s.db.Pool()
		if err != nil {
			return err
		}
		if opts.Rollups {
			securityRows, err := rebuildSecurityProbeRollups(ctx, pool)
			if err != nil {
				return err
			}
			result.SecurityProbeRollups = securityRows
			result.SecurityProbeRebuilt = true
		}
		enriched, err := enrichMissingUserAgents(ctx, pool, opts.BatchSize)
		if err != nil {
			return err
		}
		result.UserAgentsEnriched = enriched
		for {
			if opts.MaxBatches > 0 && result.Batches >= opts.MaxBatches {
				result.StoppedAtMaxBatches = true
				break
			}
			batch, err := s.runBatch(ctx, pool, opts)
			if err != nil {
				return err
			}
			if batch.EventsProcessed == 0 {
				break
			}
			result.Batches++
			result.EventsProcessed += batch.EventsProcessed
			result.IPRollupRows += batch.IPRollupRows
			result.PathRollupRows += batch.PathRollupRows
			result.UserAgentRollupRows += batch.UserAgentRollupRows
			result.IPPathRollupRows += batch.IPPathRollupRows
			result.IPUserAgentRollupRows += batch.IPUserAgentRollupRows
			result.StatusRollupRows += batch.StatusRollupRows
			result.SiteLatencyRows += batch.SiteLatencyRows
			result.PathLatencyRows += batch.PathLatencyRows
			result.ErrorEvents += batch.ErrorEvents
			result.SlowRequestEvents += batch.SlowRequestEvents
			mergeRange(&result, batch)
		}
		enriched, err = enrichMissingUserAgents(ctx, pool, opts.BatchSize)
		if err != nil {
			return err
		}
		result.UserAgentsEnriched += enriched
		remaining, err := countRemaining(ctx, pool)
		if err != nil {
			return err
		}
		result.EventsRemaining = remaining
		return nil
	})
	return result, err
}

func enrichMissingUserAgents(ctx context.Context, pool *pgxpool.Pool, batchSize int) (int64, error) {
	if batchSize <= 0 {
		batchSize = 5000
	}
	rows, err := pool.Query(ctx, `
SELECT id, user_agent, request_count
FROM dim_user_agents
WHERE coalesce(family, '') = ''
   OR risk_score IS NULL
   OR coalesce(actor_type, '') = ''
   OR coalesce(device_family, '') = ''
   OR (actor_type = 'browser' AND coalesce(browser_family, '') = '')
ORDER BY last_seen_at DESC
LIMIT $1`, batchSize)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	updates := make([][]any, 0, batchSize)
	for rows.Next() {
		var id int64
		var sample string
		var requests int64
		if err := rows.Scan(&id, &sample, &requests); err != nil {
			return 0, err
		}
		analysis := useragent.Analyze(sample, requests)
		updates = append(updates, []any{
			id,
			analysis.Family,
			analysis.BrowserFamily,
			analysis.BrowserVersion,
			analysis.OSFamily,
			analysis.OSVersion,
			analysis.DeviceFamily,
			analysis.ActorType,
			analysis.KnownActor,
			analysis.IsBot,
			analysis.IsTool,
			analysis.RiskScore,
		})
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(updates) == 0 {
		return 0, nil
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = tx.Rollback(context.Background())
	}()
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE backfill_user_agent_enrichment (
  id bigint NOT NULL,
  family text,
  browser_family text,
  browser_version text,
  os_family text,
  os_version text,
  device_family text,
  actor_type text,
  known_actor text,
  is_bot boolean NOT NULL,
  is_tool boolean NOT NULL,
  risk_score integer
) ON COMMIT DROP`); err != nil {
		return 0, err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"backfill_user_agent_enrichment"}, []string{
		"id", "family", "browser_family", "browser_version", "os_family", "os_version", "device_family",
		"actor_type", "known_actor", "is_bot", "is_tool", "risk_score",
	}, pgx.CopyFromRows(updates)); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `
UPDATE dim_user_agents d
SET family = nullif(e.family, ''),
    browser_family = nullif(e.browser_family, ''),
    browser_version = nullif(e.browser_version, ''),
    os_family = nullif(e.os_family, ''),
    os_version = nullif(e.os_version, ''),
    device_family = nullif(e.device_family, ''),
    actor_type = nullif(e.actor_type, ''),
    known_actor = nullif(e.known_actor, ''),
    is_bot = e.is_bot,
    is_tool = e.is_tool,
    risk_score = e.risk_score
FROM backfill_user_agent_enrichment e
WHERE d.id = e.id`)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Service) runBatch(ctx context.Context, pool *pgxpool.Pool, opts Options) (Result, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		_ = tx.Rollback(context.Background())
	}()

	if _, err := tx.Exec(ctx, `
CREATE TEMP TABLE backfill_event_batch ON COMMIT DROP AS
SELECT id
FROM access_events
WHERE (client_ip IS NOT NULL AND ip_id IS NULL)
   OR (path_hash IS NOT NULL AND path_id IS NULL)
   OR (query IS NOT NULL AND query <> '' AND query_id IS NULL)
   OR (user_agent_hash IS NOT NULL AND user_agent_id IS NULL)
   OR rollups_1h_backfilled_at IS NULL
   OR (status >= 400 AND NOT EXISTS (SELECT 1 FROM error_events f WHERE f.event_id = access_events.id))
   OR (request_time_ms >= 1000 AND NOT EXISTS (SELECT 1 FROM slow_request_events f WHERE f.event_id = access_events.id))
ORDER BY id
LIMIT $1`, opts.BatchSize); err != nil {
		return Result{}, err
	}
	if _, err := tx.Exec(ctx, `CREATE UNIQUE INDEX ON backfill_event_batch (id)`); err != nil {
		return Result{}, err
	}

	var result Result
	err = tx.QueryRow(ctx, `
SELECT count(*)::bigint
FROM access_events e
JOIN backfill_event_batch b ON b.id = e.id`).Scan(&result.EventsProcessed)
	if err != nil {
		return Result{}, err
	}
	if result.EventsProcessed == 0 {
		if err := tx.Commit(ctx); err != nil {
			return Result{}, err
		}
		return result, nil
	}
	err = tx.QueryRow(ctx, `
SELECT min(e.id)::bigint,
       max(e.id)::bigint,
       min(e.ts),
       max(e.ts)
FROM access_events e
JOIN backfill_event_batch b ON b.id = e.id`).Scan(
		&result.MinEventID,
		&result.MaxEventID,
		&result.RangeStart,
		&result.RangeEnd,
	)
	if err != nil {
		return Result{}, err
	}

	for _, statement := range []string{
		`
INSERT INTO dim_ips (ip, first_seen_at, last_seen_at, request_count)
SELECT e.client_ip, min(e.ts), max(e.ts), count(*)
FROM access_events e
JOIN backfill_event_batch b ON b.id = e.id
WHERE e.client_ip IS NOT NULL
  AND e.ip_id IS NULL
GROUP BY e.client_ip
ON CONFLICT (ip) DO UPDATE SET
  first_seen_at = LEAST(dim_ips.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at = GREATEST(dim_ips.last_seen_at, EXCLUDED.last_seen_at),
  request_count = dim_ips.request_count + EXCLUDED.request_count`,
		`
INSERT INTO dim_paths (path, path_hash, first_seen_at, last_seen_at, request_count)
SELECT e.path, e.path_hash, min(e.ts), max(e.ts), count(*)
FROM access_events e
JOIN backfill_event_batch b ON b.id = e.id
WHERE e.path IS NOT NULL
  AND e.path_hash IS NOT NULL
  AND e.path_id IS NULL
GROUP BY e.path, e.path_hash
ON CONFLICT (path_hash) DO UPDATE SET
  path = EXCLUDED.path,
  first_seen_at = LEAST(dim_paths.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at = GREATEST(dim_paths.last_seen_at, EXCLUDED.last_seen_at),
  request_count = dim_paths.request_count + EXCLUDED.request_count`,
		`
INSERT INTO dim_queries (query, query_hash, first_seen_at, last_seen_at, request_count)
SELECT e.query, digest(e.query, 'sha256'), min(e.ts), max(e.ts), count(*)
FROM access_events e
JOIN backfill_event_batch b ON b.id = e.id
WHERE e.query IS NOT NULL
  AND e.query <> ''
  AND e.query_id IS NULL
GROUP BY e.query
ON CONFLICT (query_hash) DO UPDATE SET
  query = EXCLUDED.query,
  first_seen_at = LEAST(dim_queries.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at = GREATEST(dim_queries.last_seen_at, EXCLUDED.last_seen_at),
  request_count = dim_queries.request_count + EXCLUDED.request_count`,
		`
INSERT INTO dim_user_agents (user_agent, user_agent_hash, first_seen_at, last_seen_at, request_count)
SELECT e.user_agent, e.user_agent_hash, min(e.ts), max(e.ts), count(*)
FROM access_events e
JOIN backfill_event_batch b ON b.id = e.id
WHERE e.user_agent IS NOT NULL
  AND e.user_agent_hash IS NOT NULL
  AND e.user_agent_id IS NULL
GROUP BY e.user_agent, e.user_agent_hash
ON CONFLICT (user_agent_hash) DO UPDATE SET
  user_agent = EXCLUDED.user_agent,
  first_seen_at = LEAST(dim_user_agents.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at = GREATEST(dim_user_agents.last_seen_at, EXCLUDED.last_seen_at),
  request_count = dim_user_agents.request_count + EXCLUDED.request_count`,
		`
UPDATE access_events e
SET ip_id = d.id
FROM backfill_event_batch b, dim_ips d
WHERE e.id = b.id
  AND e.ip_id IS NULL
  AND e.client_ip = d.ip`,
		`
UPDATE access_events e
SET path_id = d.id
FROM backfill_event_batch b, dim_paths d
WHERE e.id = b.id
  AND e.path_id IS NULL
  AND e.path_hash = d.path_hash`,
		`
UPDATE access_events e
SET query_id = d.id
FROM backfill_event_batch b, dim_queries d
WHERE e.id = b.id
  AND e.query_id IS NULL
  AND e.query IS NOT NULL
  AND e.query <> ''
  AND digest(e.query, 'sha256') = d.query_hash`,
		`
UPDATE access_events e
SET user_agent_id = d.id
FROM backfill_event_batch b, dim_user_agents d
WHERE e.id = b.id
  AND e.user_agent_id IS NULL
  AND e.user_agent_hash = d.user_agent_hash`,
	} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return Result{}, err
		}
	}

	if opts.Rollups {
		result.IPRollupRows, err = upsertBatchRollup(ctx, tx, ipRollupSQL)
		if err != nil {
			return Result{}, err
		}
		result.PathRollupRows, err = upsertBatchRollup(ctx, tx, pathRollupSQL)
		if err != nil {
			return Result{}, err
		}
		result.UserAgentRollupRows, err = upsertBatchRollup(ctx, tx, userAgentRollupSQL)
		if err != nil {
			return Result{}, err
		}
		result.IPPathRollupRows, err = upsertBatchRollup(ctx, tx, ipPathRollupSQL)
		if err != nil {
			return Result{}, err
		}
		result.IPUserAgentRollupRows, err = upsertBatchRollup(ctx, tx, ipUserAgentRollupSQL)
		if err != nil {
			return Result{}, err
		}
		result.StatusRollupRows, err = upsertBatchRollup(ctx, tx, statusRollupSQL)
		if err != nil {
			return Result{}, err
		}
		result.SiteLatencyRows, err = upsertBatchRollup(ctx, tx, siteLatencyRollupSQL)
		if err != nil {
			return Result{}, err
		}
		result.PathLatencyRows, err = upsertBatchRollup(ctx, tx, pathLatencyRollupSQL)
		if err != nil {
			return Result{}, err
		}
		if _, err := tx.Exec(ctx, `
UPDATE access_events e
SET rollups_1h_backfilled_at = now()
FROM backfill_event_batch b
WHERE e.id = b.id
  AND e.rollups_1h_backfilled_at IS NULL`); err != nil {
			return Result{}, err
		}
	}
	result.ErrorEvents, err = upsertBatchRollup(ctx, tx, errorFactSQL)
	if err != nil {
		return Result{}, err
	}
	result.SlowRequestEvents, err = upsertBatchRollup(ctx, tx, slowRequestFactSQL)
	if err != nil {
		return Result{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Result{}, err
	}
	return result, nil
}

func countRemaining(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var count int64
	err := pool.QueryRow(ctx, `
SELECT count(*)::bigint
FROM access_events
WHERE (client_ip IS NOT NULL AND ip_id IS NULL)
   OR (path_hash IS NOT NULL AND path_id IS NULL)
   OR (query IS NOT NULL AND query <> '' AND query_id IS NULL)
   OR (user_agent_hash IS NOT NULL AND user_agent_id IS NULL)
   OR rollups_1h_backfilled_at IS NULL
   OR (status >= 400 AND NOT EXISTS (SELECT 1 FROM error_events f WHERE f.event_id = access_events.id))
   OR (request_time_ms >= 1000 AND NOT EXISTS (SELECT 1 FROM slow_request_events f WHERE f.event_id = access_events.id))`).Scan(&count)
	return count, err
}

func mergeRange(total *Result, batch Result) {
	if batch.MinEventID != 0 && (total.MinEventID == 0 || batch.MinEventID < total.MinEventID) {
		total.MinEventID = batch.MinEventID
	}
	if batch.MaxEventID > total.MaxEventID {
		total.MaxEventID = batch.MaxEventID
	}
	if !batch.RangeStart.IsZero() && (total.RangeStart.IsZero() || batch.RangeStart.Before(total.RangeStart)) {
		total.RangeStart = batch.RangeStart
	}
	if !batch.RangeEnd.IsZero() && batch.RangeEnd.After(total.RangeEnd) {
		total.RangeEnd = batch.RangeEnd
	}
}

func upsertBatchRollup(ctx context.Context, tx pgx.Tx, statement string) (int64, error) {
	rows, err := tx.Query(ctx, statement)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var count int64
	for rows.Next() {
		count++
	}
	return count, rows.Err()
}

func rebuildSecurityProbeRollups(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = tx.Rollback(context.Background())
	}()

	if _, err := tx.Exec(ctx, `TRUNCATE rollup_security_probe_1h`); err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, securityProbeRollupSQL)
	if err != nil {
		return 0, err
	}
	var count int64
	for rows.Next() {
		count++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}

const ipRollupSQL = `
WITH grouped AS (
  SELECT date_trunc('hour', e.ts) AS bucket_ts,
         e.site_id,
         e.env,
         e.ip_id,
         count(*) AS requests,
         count(*) FILTER (WHERE e.status >= 400 AND e.status < 500) AS status_4xx,
         count(*) FILTER (WHERE e.status >= 500 AND e.status < 600) AS status_5xx,
         coalesce(sum(e.bytes_sent), 0) AS bytes_sent,
         min(e.ts) AS first_seen_at,
         max(e.ts) AS last_seen_at
  FROM access_events e
  JOIN backfill_event_batch b ON b.id = e.id
  WHERE e.rollups_1h_backfilled_at IS NULL
    AND e.ip_id IS NOT NULL
  GROUP BY 1, 2, 3, 4
)
INSERT INTO rollup_ip_1h (
  bucket_ts, site_id, env, ip_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, ip_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, ip_id) DO UPDATE
SET requests = rollup_ip_1h.requests + EXCLUDED.requests,
    status_4xx = rollup_ip_1h.status_4xx + EXCLUDED.status_4xx,
    status_5xx = rollup_ip_1h.status_5xx + EXCLUDED.status_5xx,
    bytes_sent = rollup_ip_1h.bytes_sent + EXCLUDED.bytes_sent,
    first_seen_at = LEAST(rollup_ip_1h.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at = GREATEST(rollup_ip_1h.last_seen_at, EXCLUDED.last_seen_at)
RETURNING 1`

const pathRollupSQL = `
WITH grouped AS (
  SELECT date_trunc('hour', e.ts) AS bucket_ts,
         e.site_id,
         e.env,
         e.path_id,
         count(*) AS requests,
         count(*) FILTER (WHERE e.status >= 400 AND e.status < 500) AS status_4xx,
         count(*) FILTER (WHERE e.status >= 500 AND e.status < 600) AS status_5xx,
         coalesce(sum(e.bytes_sent), 0) AS bytes_sent,
         min(e.ts) AS first_seen_at,
         max(e.ts) AS last_seen_at
  FROM access_events e
  JOIN backfill_event_batch b ON b.id = e.id
  WHERE e.rollups_1h_backfilled_at IS NULL
    AND e.path_id IS NOT NULL
  GROUP BY 1, 2, 3, 4
)
INSERT INTO rollup_path_1h (
  bucket_ts, site_id, env, path_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, path_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, path_id) DO UPDATE
SET requests = rollup_path_1h.requests + EXCLUDED.requests,
    status_4xx = rollup_path_1h.status_4xx + EXCLUDED.status_4xx,
    status_5xx = rollup_path_1h.status_5xx + EXCLUDED.status_5xx,
    bytes_sent = rollup_path_1h.bytes_sent + EXCLUDED.bytes_sent,
    first_seen_at = LEAST(rollup_path_1h.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at = GREATEST(rollup_path_1h.last_seen_at, EXCLUDED.last_seen_at)
RETURNING 1`

const userAgentRollupSQL = `
WITH grouped AS (
  SELECT date_trunc('hour', e.ts) AS bucket_ts,
         e.site_id,
         e.env,
         e.user_agent_id,
         count(*) AS requests,
         count(*) FILTER (WHERE e.status >= 400 AND e.status < 500) AS status_4xx,
         count(*) FILTER (WHERE e.status >= 500 AND e.status < 600) AS status_5xx,
         coalesce(sum(e.bytes_sent), 0) AS bytes_sent,
         min(e.ts) AS first_seen_at,
         max(e.ts) AS last_seen_at
  FROM access_events e
  JOIN backfill_event_batch b ON b.id = e.id
  WHERE e.rollups_1h_backfilled_at IS NULL
    AND e.user_agent_id IS NOT NULL
  GROUP BY 1, 2, 3, 4
)
INSERT INTO rollup_user_agent_1h (
  bucket_ts, site_id, env, user_agent_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, user_agent_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, user_agent_id) DO UPDATE
SET requests = rollup_user_agent_1h.requests + EXCLUDED.requests,
    status_4xx = rollup_user_agent_1h.status_4xx + EXCLUDED.status_4xx,
    status_5xx = rollup_user_agent_1h.status_5xx + EXCLUDED.status_5xx,
    bytes_sent = rollup_user_agent_1h.bytes_sent + EXCLUDED.bytes_sent,
    first_seen_at = LEAST(rollup_user_agent_1h.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at = GREATEST(rollup_user_agent_1h.last_seen_at, EXCLUDED.last_seen_at)
RETURNING 1`

const ipPathRollupSQL = `
WITH grouped AS (
  SELECT date_trunc('hour', e.ts) AS bucket_ts,
         e.site_id,
         e.env,
         e.ip_id,
         e.path_id,
         count(*) AS requests,
         count(*) FILTER (WHERE e.status >= 400 AND e.status < 500) AS status_4xx,
         count(*) FILTER (WHERE e.status >= 500 AND e.status < 600) AS status_5xx,
         coalesce(sum(e.bytes_sent), 0) AS bytes_sent,
         min(e.ts) AS first_seen_at,
         max(e.ts) AS last_seen_at
  FROM access_events e
  JOIN backfill_event_batch b ON b.id = e.id
  WHERE e.rollups_1h_backfilled_at IS NULL
    AND e.ip_id IS NOT NULL
    AND e.path_id IS NOT NULL
  GROUP BY 1, 2, 3, 4, 5
)
INSERT INTO rollup_ip_path_1h (
  bucket_ts, site_id, env, ip_id, path_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, ip_id, path_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, ip_id, path_id) DO UPDATE
SET requests = rollup_ip_path_1h.requests + EXCLUDED.requests,
    status_4xx = rollup_ip_path_1h.status_4xx + EXCLUDED.status_4xx,
    status_5xx = rollup_ip_path_1h.status_5xx + EXCLUDED.status_5xx,
    bytes_sent = rollup_ip_path_1h.bytes_sent + EXCLUDED.bytes_sent,
    first_seen_at = LEAST(rollup_ip_path_1h.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at = GREATEST(rollup_ip_path_1h.last_seen_at, EXCLUDED.last_seen_at)
RETURNING 1`

const ipUserAgentRollupSQL = `
WITH grouped AS (
  SELECT date_trunc('hour', e.ts) AS bucket_ts,
         e.site_id,
         e.env,
         e.ip_id,
         e.user_agent_id,
         count(*) AS requests,
         count(*) FILTER (WHERE e.status >= 400 AND e.status < 500) AS status_4xx,
         count(*) FILTER (WHERE e.status >= 500 AND e.status < 600) AS status_5xx,
         coalesce(sum(e.bytes_sent), 0) AS bytes_sent,
         min(e.ts) AS first_seen_at,
         max(e.ts) AS last_seen_at
  FROM access_events e
  JOIN backfill_event_batch b ON b.id = e.id
  WHERE e.rollups_1h_backfilled_at IS NULL
    AND e.ip_id IS NOT NULL
    AND e.user_agent_id IS NOT NULL
  GROUP BY 1, 2, 3, 4, 5
)
INSERT INTO rollup_ip_user_agent_1h (
  bucket_ts, site_id, env, ip_id, user_agent_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, ip_id, user_agent_id, requests, status_4xx, status_5xx, bytes_sent, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, ip_id, user_agent_id) DO UPDATE
SET requests = rollup_ip_user_agent_1h.requests + EXCLUDED.requests,
    status_4xx = rollup_ip_user_agent_1h.status_4xx + EXCLUDED.status_4xx,
    status_5xx = rollup_ip_user_agent_1h.status_5xx + EXCLUDED.status_5xx,
    bytes_sent = rollup_ip_user_agent_1h.bytes_sent + EXCLUDED.bytes_sent,
    first_seen_at = LEAST(rollup_ip_user_agent_1h.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at = GREATEST(rollup_ip_user_agent_1h.last_seen_at, EXCLUDED.last_seen_at)
RETURNING 1`

const statusRollupSQL = `
WITH grouped AS (
  SELECT date_trunc('hour', e.ts) AS bucket_ts,
         e.site_id,
         e.env,
         coalesce(e.status, 0) AS status,
         count(*) AS requests,
         min(e.ts) AS first_seen_at,
         max(e.ts) AS last_seen_at
  FROM access_events e
  JOIN backfill_event_batch b ON b.id = e.id
  WHERE e.rollups_1h_backfilled_at IS NULL
  GROUP BY 1, 2, 3, 4
)
INSERT INTO rollup_status_1h (
  bucket_ts, site_id, env, status, requests, first_seen_at, last_seen_at
)
SELECT bucket_ts, site_id, env, status, requests, first_seen_at, last_seen_at
FROM grouped
ON CONFLICT (bucket_ts, site_id, env, status) DO UPDATE
SET requests = rollup_status_1h.requests + EXCLUDED.requests,
    first_seen_at = LEAST(rollup_status_1h.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at = GREATEST(rollup_status_1h.last_seen_at, EXCLUDED.last_seen_at)
RETURNING 1`

const latencyBucketCase = `
CASE
  WHEN e.request_time_ms <= 50 THEN 50
  WHEN e.request_time_ms <= 100 THEN 100
  WHEN e.request_time_ms <= 200 THEN 200
  WHEN e.request_time_ms <= 300 THEN 300
  WHEN e.request_time_ms <= 500 THEN 500
  WHEN e.request_time_ms <= 750 THEN 750
  WHEN e.request_time_ms <= 1000 THEN 1000
  WHEN e.request_time_ms <= 1500 THEN 1500
  WHEN e.request_time_ms <= 2000 THEN 2000
  WHEN e.request_time_ms <= 3000 THEN 3000
  WHEN e.request_time_ms <= 5000 THEN 5000
  WHEN e.request_time_ms <= 10000 THEN 10000
  WHEN e.request_time_ms <= 30000 THEN 30000
  WHEN e.request_time_ms <= 60000 THEN 60000
  ELSE 2147483647
END`

const siteLatencyRollupSQL = `
WITH bucketed AS (
  SELECT date_trunc('hour', e.ts) AS bucket_ts,
         e.site_id,
         e.env,
         ` + latencyBucketCase + ` AS bucket_le_ms
  FROM access_events e
  JOIN backfill_event_batch b ON b.id = e.id
  WHERE e.rollups_1h_backfilled_at IS NULL
    AND e.request_time_ms IS NOT NULL
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
SET requests = rollup_site_latency_1h.requests + EXCLUDED.requests
RETURNING 1`

const pathLatencyRollupSQL = `
WITH bucketed AS (
  SELECT date_trunc('hour', e.ts) AS bucket_ts,
         e.site_id,
         e.env,
         e.path_id,
         ` + latencyBucketCase + ` AS bucket_le_ms,
         e.status,
         e.request_time_ms,
         e.ts
  FROM access_events e
  JOIN backfill_event_batch b ON b.id = e.id
  WHERE e.rollups_1h_backfilled_at IS NULL
    AND e.request_time_ms IS NOT NULL
    AND e.path_id IS NOT NULL
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
SET requests = rollup_path_latency_1h.requests + EXCLUDED.requests,
    status_5xx = rollup_path_latency_1h.status_5xx + EXCLUDED.status_5xx,
    request_time_sum_ms = rollup_path_latency_1h.request_time_sum_ms + EXCLUDED.request_time_sum_ms,
    first_seen_at = LEAST(rollup_path_latency_1h.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at = GREATEST(rollup_path_latency_1h.last_seen_at, EXCLUDED.last_seen_at)
RETURNING 1`

const errorFactSQL = `
INSERT INTO error_events (
  event_id, ts, site_id, env, container_id, client_ip, method,
  path_id, query_id, user_agent_id, status, bytes_sent, referer,
  segment_id, segment_line_no, temporary_import_id
)
SELECT e.id,
       e.ts,
       e.site_id,
       e.env,
       e.container_id,
       e.client_ip,
       e.method,
       e.path_id,
       e.query_id,
       e.user_agent_id,
       e.status,
       e.bytes_sent,
       e.referer,
       e.segment_id,
       e.segment_line_no,
       e.temporary_import_id
FROM access_events e
JOIN backfill_event_batch b ON b.id = e.id
WHERE e.status >= 400
ON CONFLICT (event_id) DO NOTHING
RETURNING 1`

const slowRequestFactSQL = `
INSERT INTO slow_request_events (
  event_id, ts, site_id, env, container_id, client_ip, method,
  path_id, query_id, user_agent_id, status, request_time_ms, upstream_time_ms,
  segment_id, segment_line_no, temporary_import_id
)
SELECT e.id,
       e.ts,
       e.site_id,
       e.env,
       e.container_id,
       e.client_ip,
       e.method,
       e.path_id,
       e.query_id,
       e.user_agent_id,
       e.status,
       e.request_time_ms,
       e.upstream_time_ms,
       e.segment_id,
       e.segment_line_no,
       e.temporary_import_id
FROM access_events e
JOIN backfill_event_batch b ON b.id = e.id
WHERE e.request_time_ms >= 1000
ON CONFLICT (event_id) DO NOTHING
RETURNING 1`

const securityProbeRollupSQL = `
INSERT INTO rollup_security_probe_1h (
  bucket_ts, site_id, env, family, category, rule_key, events, unique_ips, status_4xx, status_5xx, first_seen_at, last_seen_at
)
SELECT date_trunc('hour', ts), site_id, env, family, category, rule_key,
       count(*),
       count(DISTINCT client_ip),
       count(*) FILTER (WHERE status >= 400 AND status < 500),
       count(*) FILTER (WHERE status >= 500 AND status < 600),
       min(ts),
       max(ts)
FROM security_probe_events
GROUP BY 1, 2, 3, 4, 5, 6
ON CONFLICT (bucket_ts, site_id, env, family, category, rule_key) DO UPDATE
SET events = EXCLUDED.events,
    unique_ips = EXCLUDED.unique_ips,
    status_4xx = EXCLUDED.status_4xx,
    status_5xx = EXCLUDED.status_5xx,
    first_seen_at = EXCLUDED.first_seen_at,
    last_seen_at = EXCLUDED.last_seen_at
RETURNING 1`
