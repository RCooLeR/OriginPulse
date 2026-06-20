CREATE TABLE IF NOT EXISTS error_events (
  event_id bigint PRIMARY KEY REFERENCES access_events(id) ON DELETE CASCADE,
  ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  container_id text,
  client_ip inet,
  method text,
  path_id bigint REFERENCES dim_paths(id),
  query_id bigint REFERENCES dim_queries(id),
  user_agent_id bigint REFERENCES dim_user_agents(id),
  status int NOT NULL,
  bytes_sent bigint,
  referer text,
  segment_id uuid REFERENCES combined_segments(id) ON DELETE SET NULL,
  segment_line_no bigint,
  temporary_import_id uuid REFERENCES temporary_imports(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS error_events_ts_idx ON error_events (ts DESC);
CREATE INDEX IF NOT EXISTS error_events_site_ts_idx ON error_events (site_id, ts DESC);
CREATE INDEX IF NOT EXISTS error_events_status_ts_idx ON error_events (status, ts DESC);
CREATE INDEX IF NOT EXISTS error_events_ip_ts_idx ON error_events (client_ip, ts DESC);
CREATE INDEX IF NOT EXISTS error_events_temporary_import_idx ON error_events (temporary_import_id) WHERE temporary_import_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS slow_request_events (
  event_id bigint PRIMARY KEY REFERENCES access_events(id) ON DELETE CASCADE,
  ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  container_id text,
  client_ip inet,
  method text,
  path_id bigint REFERENCES dim_paths(id),
  query_id bigint REFERENCES dim_queries(id),
  user_agent_id bigint REFERENCES dim_user_agents(id),
  status int,
  request_time_ms int NOT NULL,
  upstream_time_ms int,
  segment_id uuid REFERENCES combined_segments(id) ON DELETE SET NULL,
  segment_line_no bigint,
  temporary_import_id uuid REFERENCES temporary_imports(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS slow_request_events_ts_idx ON slow_request_events (ts DESC);
CREATE INDEX IF NOT EXISTS slow_request_events_site_ts_idx ON slow_request_events (site_id, ts DESC);
CREATE INDEX IF NOT EXISTS slow_request_events_path_ts_idx ON slow_request_events (path_id, ts DESC);
CREATE INDEX IF NOT EXISTS slow_request_events_request_time_idx ON slow_request_events (request_time_ms DESC, ts DESC);
CREATE INDEX IF NOT EXISTS slow_request_events_temporary_import_idx ON slow_request_events (temporary_import_id) WHERE temporary_import_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS access_events_error_fact_backfill_idx
  ON access_events (id)
  WHERE status >= 400;

CREATE INDEX IF NOT EXISTS access_events_slow_fact_backfill_idx
  ON access_events (id)
  WHERE request_time_ms >= 1000;
