CREATE TABLE IF NOT EXISTS rollup_query_param_1h (
  bucket_ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  family text NOT NULL,
  param text NOT NULL,
  param_value text NOT NULL,
  param_value_hash text NOT NULL,
  requests bigint NOT NULL DEFAULT 0,
  status_4xx bigint NOT NULL DEFAULT 0,
  status_5xx bigint NOT NULL DEFAULT 0,
  slow_requests bigint NOT NULL DEFAULT 0,
  unique_ips bigint NOT NULL DEFAULT 0,
  unique_user_agents bigint NOT NULL DEFAULT 0,
  unique_paths bigint NOT NULL DEFAULT 0,
  request_time_count bigint NOT NULL DEFAULT 0,
  request_time_sum_ms bigint NOT NULL DEFAULT 0,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  example_path text NOT NULL DEFAULT '',
  example_query text NOT NULL DEFAULT '',
  PRIMARY KEY (bucket_ts, site_id, env, family, param, param_value_hash)
);

CREATE INDEX IF NOT EXISTS rollup_query_param_1h_site_bucket_requests_idx
  ON rollup_query_param_1h (site_id, bucket_ts DESC, requests DESC);

CREATE INDEX IF NOT EXISTS rollup_query_param_1h_family_bucket_errors_idx
  ON rollup_query_param_1h (family, param, bucket_ts DESC, status_5xx DESC);
