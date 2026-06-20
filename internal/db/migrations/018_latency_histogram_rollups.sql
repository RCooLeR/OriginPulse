CREATE TABLE IF NOT EXISTS rollup_site_latency_1h (
  bucket_ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  bucket_le_ms int NOT NULL,
  requests bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket_ts, site_id, env, bucket_le_ms)
);

CREATE TABLE IF NOT EXISTS rollup_path_latency_1h (
  bucket_ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  path_id bigint NOT NULL REFERENCES dim_paths(id),
  bucket_le_ms int NOT NULL,
  requests bigint NOT NULL DEFAULT 0,
  status_5xx bigint NOT NULL DEFAULT 0,
  request_time_sum_ms bigint NOT NULL DEFAULT 0,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  PRIMARY KEY (bucket_ts, site_id, env, path_id, bucket_le_ms)
);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'rollup_path_latency_1h_path_id_fkey') THEN
    ALTER TABLE rollup_path_latency_1h
      ADD CONSTRAINT rollup_path_latency_1h_path_id_fkey FOREIGN KEY (path_id) REFERENCES dim_paths(id);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS rollup_site_latency_1h_site_bucket_idx ON rollup_site_latency_1h (site_id, bucket_ts DESC, bucket_le_ms);
CREATE INDEX IF NOT EXISTS rollup_path_latency_1h_site_bucket_requests_idx ON rollup_path_latency_1h (site_id, bucket_ts DESC, requests DESC);

TRUNCATE rollup_ip_1h, rollup_path_1h, rollup_user_agent_1h, rollup_status_1h, rollup_site_latency_1h, rollup_path_latency_1h;

UPDATE access_events
SET rollups_1h_backfilled_at = NULL
WHERE rollups_1h_backfilled_at IS NOT NULL;
