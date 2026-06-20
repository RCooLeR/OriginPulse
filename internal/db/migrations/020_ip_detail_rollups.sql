CREATE TABLE IF NOT EXISTS rollup_ip_path_1h (
  bucket_ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  ip_id bigint NOT NULL REFERENCES dim_ips(id),
  path_id bigint NOT NULL REFERENCES dim_paths(id),
  requests bigint NOT NULL DEFAULT 0,
  status_4xx bigint NOT NULL DEFAULT 0,
  status_5xx bigint NOT NULL DEFAULT 0,
  bytes_sent bigint NOT NULL DEFAULT 0,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  PRIMARY KEY (bucket_ts, site_id, env, ip_id, path_id)
);

CREATE TABLE IF NOT EXISTS rollup_ip_user_agent_1h (
  bucket_ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  ip_id bigint NOT NULL REFERENCES dim_ips(id),
  user_agent_id bigint NOT NULL REFERENCES dim_user_agents(id),
  requests bigint NOT NULL DEFAULT 0,
  status_4xx bigint NOT NULL DEFAULT 0,
  status_5xx bigint NOT NULL DEFAULT 0,
  bytes_sent bigint NOT NULL DEFAULT 0,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  PRIMARY KEY (bucket_ts, site_id, env, ip_id, user_agent_id)
);

CREATE INDEX IF NOT EXISTS rollup_ip_path_1h_ip_bucket_requests_idx
  ON rollup_ip_path_1h (ip_id, bucket_ts DESC, requests DESC);
CREATE INDEX IF NOT EXISTS rollup_ip_path_1h_site_bucket_requests_idx
  ON rollup_ip_path_1h (site_id, bucket_ts DESC, requests DESC);
CREATE INDEX IF NOT EXISTS rollup_ip_user_agent_1h_ip_bucket_requests_idx
  ON rollup_ip_user_agent_1h (ip_id, bucket_ts DESC, requests DESC);
CREATE INDEX IF NOT EXISTS rollup_ip_user_agent_1h_site_bucket_requests_idx
  ON rollup_ip_user_agent_1h (site_id, bucket_ts DESC, requests DESC);

TRUNCATE rollup_ip_path_1h, rollup_ip_user_agent_1h;

UPDATE access_events
SET rollups_1h_backfilled_at = NULL
WHERE rollups_1h_backfilled_at IS NOT NULL;
