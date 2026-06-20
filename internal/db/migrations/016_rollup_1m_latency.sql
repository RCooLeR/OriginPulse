ALTER TABLE rollup_1m ADD COLUMN IF NOT EXISTS request_time_count bigint NOT NULL DEFAULT 0;
ALTER TABLE rollup_1m ADD COLUMN IF NOT EXISTS request_time_sum_ms bigint NOT NULL DEFAULT 0;
ALTER TABLE rollup_1m ADD COLUMN IF NOT EXISTS slow_requests bigint NOT NULL DEFAULT 0;

WITH grouped AS (
  SELECT date_trunc('minute', ts) AS bucket_ts,
         site_id,
         env,
         count(*) FILTER (WHERE request_time_ms IS NOT NULL)::bigint AS request_time_count,
         coalesce(sum(request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::bigint AS request_time_sum_ms,
         count(*) FILTER (WHERE request_time_ms >= 1000)::bigint AS slow_requests
  FROM access_events
  GROUP BY 1, 2, 3
)
UPDATE rollup_1m r
SET request_time_count = g.request_time_count,
    request_time_sum_ms = g.request_time_sum_ms,
    slow_requests = g.slow_requests
FROM grouped g
WHERE r.bucket_ts = g.bucket_ts
  AND r.site_id = g.site_id
  AND r.env = g.env;
