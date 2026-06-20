ALTER TABLE rollup_1m ADD COLUMN IF NOT EXISTS empty_user_agents bigint NOT NULL DEFAULT 0;

WITH grouped AS (
  SELECT date_trunc('minute', ts) AS bucket_ts,
         site_id,
         env,
         count(*) FILTER (WHERE coalesce(user_agent, '') = '')::bigint AS empty_user_agents
  FROM access_events
  GROUP BY 1, 2, 3
)
UPDATE rollup_1m r
SET empty_user_agents = g.empty_user_agents
FROM grouped g
WHERE r.bucket_ts = g.bucket_ts
  AND r.site_id = g.site_id
  AND r.env = g.env;
