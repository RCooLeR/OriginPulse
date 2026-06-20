CREATE TABLE IF NOT EXISTS rollup_ip_1h (
  bucket_ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  ip_id bigint NOT NULL REFERENCES dim_ips(id),
  requests bigint NOT NULL DEFAULT 0,
  status_4xx bigint NOT NULL DEFAULT 0,
  status_5xx bigint NOT NULL DEFAULT 0,
  bytes_sent bigint NOT NULL DEFAULT 0,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  PRIMARY KEY (bucket_ts, site_id, env, ip_id)
);

CREATE TABLE IF NOT EXISTS rollup_path_1h (
  bucket_ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  path_id bigint NOT NULL REFERENCES dim_paths(id),
  requests bigint NOT NULL DEFAULT 0,
  status_4xx bigint NOT NULL DEFAULT 0,
  status_5xx bigint NOT NULL DEFAULT 0,
  bytes_sent bigint NOT NULL DEFAULT 0,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  PRIMARY KEY (bucket_ts, site_id, env, path_id)
);

CREATE TABLE IF NOT EXISTS rollup_user_agent_1h (
  bucket_ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  user_agent_id bigint NOT NULL REFERENCES dim_user_agents(id),
  requests bigint NOT NULL DEFAULT 0,
  status_4xx bigint NOT NULL DEFAULT 0,
  status_5xx bigint NOT NULL DEFAULT 0,
  bytes_sent bigint NOT NULL DEFAULT 0,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  PRIMARY KEY (bucket_ts, site_id, env, user_agent_id)
);

CREATE TABLE IF NOT EXISTS rollup_security_probe_1h (
  bucket_ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  family text NOT NULL,
  category text NOT NULL,
  rule_key text NOT NULL,
  events bigint NOT NULL DEFAULT 0,
  unique_ips bigint NOT NULL DEFAULT 0,
  status_4xx bigint NOT NULL DEFAULT 0,
  status_5xx bigint NOT NULL DEFAULT 0,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  PRIMARY KEY (bucket_ts, site_id, env, family, category, rule_key)
);

CREATE INDEX IF NOT EXISTS rollup_ip_1h_site_bucket_requests_idx ON rollup_ip_1h (site_id, bucket_ts DESC, requests DESC);
CREATE INDEX IF NOT EXISTS rollup_path_1h_site_bucket_requests_idx ON rollup_path_1h (site_id, bucket_ts DESC, requests DESC);
CREATE INDEX IF NOT EXISTS rollup_user_agent_1h_site_bucket_requests_idx ON rollup_user_agent_1h (site_id, bucket_ts DESC, requests DESC);
CREATE INDEX IF NOT EXISTS rollup_security_probe_1h_site_bucket_events_idx ON rollup_security_probe_1h (site_id, bucket_ts DESC, events DESC);
