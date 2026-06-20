CREATE TABLE IF NOT EXISTS rollup_status_1h (
  bucket_ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  status int NOT NULL,
  requests bigint NOT NULL DEFAULT 0,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  PRIMARY KEY (bucket_ts, site_id, env, status)
);

CREATE INDEX IF NOT EXISTS rollup_status_1h_site_bucket_requests_idx ON rollup_status_1h (site_id, bucket_ts DESC, requests DESC);

TRUNCATE rollup_ip_1h, rollup_path_1h, rollup_user_agent_1h, rollup_status_1h;

UPDATE access_events
SET rollups_1h_backfilled_at = NULL
WHERE rollups_1h_backfilled_at IS NOT NULL;
