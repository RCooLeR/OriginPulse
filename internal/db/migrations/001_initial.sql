CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email citext NOT NULL UNIQUE,
  password_hash text NOT NULL,
  display_name text,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz
);

CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  user_agent text,
  ip inet,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS sites (
  id text PRIMARY KEY,
  name text NOT NULL,
  pantheon_site_id text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  tags text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS site_envs (
  site_id text NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  env text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  PRIMARY KEY (site_id, env)
);

CREATE TABLE IF NOT EXISTS raw_files (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  container_id text NOT NULL,
  log_type text NOT NULL,
  remote_path text NOT NULL,
  remote_size bigint,
  remote_mtime timestamptz,
  local_path text NOT NULL,
  sha256 text,
  status text NOT NULL,
  error text,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  downloaded_at timestamptz,
  UNIQUE(site_id, env, container_id, remote_path)
);

CREATE INDEX IF NOT EXISTS raw_files_status_idx ON raw_files (status, downloaded_at DESC);
CREATE INDEX IF NOT EXISTS raw_files_site_env_idx ON raw_files (site_id, env, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS combined_segments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  log_type text NOT NULL,
  bucket_start timestamptz NOT NULL,
  bucket_end timestamptz NOT NULL,
  path text NOT NULL,
  sha256 text,
  line_count bigint NOT NULL DEFAULT 0,
  min_ts timestamptz,
  max_ts timestamptz,
  status text NOT NULL,
  version int NOT NULL DEFAULT 1,
  generated_at timestamptz NOT NULL DEFAULT now(),
  indexed_at timestamptz,
  UNIQUE(log_type, bucket_start)
);

CREATE TABLE IF NOT EXISTS access_events (
  id bigserial PRIMARY KEY,
  ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  container_id text NOT NULL,
  client_ip inet,
  method text,
  scheme text,
  host text,
  path text,
  path_hash bytea,
  query text,
  status int,
  bytes_sent bigint,
  referer text,
  user_agent text,
  user_agent_hash bytea,
  request_time_ms int,
  upstream_time_ms int,
  fingerprint bytea NOT NULL,
  segment_id uuid REFERENCES combined_segments(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS access_events_ts_idx ON access_events (ts);
CREATE INDEX IF NOT EXISTS access_events_site_ts_idx ON access_events (site_id, ts);
CREATE INDEX IF NOT EXISTS access_events_ip_ts_idx ON access_events (client_ip, ts);
CREATE INDEX IF NOT EXISTS access_events_status_ts_idx ON access_events (status, ts);
CREATE UNIQUE INDEX IF NOT EXISTS access_events_fingerprint_ts_idx ON access_events (fingerprint, ts);

CREATE TABLE IF NOT EXISTS rollup_1m (
  bucket_ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  requests bigint NOT NULL DEFAULT 0,
  status_2xx bigint NOT NULL DEFAULT 0,
  status_3xx bigint NOT NULL DEFAULT 0,
  status_4xx bigint NOT NULL DEFAULT 0,
  status_5xx bigint NOT NULL DEFAULT 0,
  unique_ips bigint NOT NULL DEFAULT 0,
  bytes_sent bigint NOT NULL DEFAULT 0,
  top_ip inet,
  top_ip_requests bigint,
  top_path text,
  top_path_requests bigint,
  PRIMARY KEY (bucket_ts, site_id, env)
);

CREATE TABLE IF NOT EXISTS ip_intel (
  ip inet PRIMARY KEY,
  asn bigint,
  asn_org text,
  network cidr,
  country_code text,
  reverse_dns text,
  forward_confirmed boolean,
  known_actor text,
  actor_type text,
  verified_actor boolean NOT NULL DEFAULT false,
  is_tor_exit boolean NOT NULL DEFAULT false,
  is_datacenter boolean,
  manual_label text,
  manual_action text,
  risk_score int,
  source jsonb NOT NULL DEFAULT '{}',
  refreshed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_key text NOT NULL,
  title text NOT NULL,
  severity text NOT NULL,
  status text NOT NULL DEFAULT 'open',
  site_id text REFERENCES sites(id),
  env text,
  actor_type text,
  actor_value text,
  score int,
  summary text,
  details jsonb NOT NULL DEFAULT '{}',
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  acknowledged_at timestamptz,
  resolved_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS alerts_status_idx ON alerts (status, severity, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS llm_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  report_type text NOT NULL,
  range_start timestamptz NOT NULL,
  range_end timestamptz NOT NULL,
  site_id text REFERENCES sites(id),
  prompt_hash text,
  model text NOT NULL,
  input jsonb NOT NULL,
  output text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  type text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  payload jsonb NOT NULL,
  attempts int NOT NULL DEFAULT 0,
  run_after timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz,
  locked_by text,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS jobs_ready_idx ON jobs (status, run_after);
