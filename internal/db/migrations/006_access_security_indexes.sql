CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS access_events_path_trgm_idx
  ON access_events USING gin (lower(coalesce(path, '')) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS access_events_query_trgm_idx
  ON access_events USING gin (lower(coalesce(query, '')) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS access_events_method_path_ts_idx
  ON access_events (method, path, ts DESC);

CREATE INDEX IF NOT EXISTS ip_intel_tor_exit_idx
  ON ip_intel (is_tor_exit, ip)
  WHERE is_tor_exit;
