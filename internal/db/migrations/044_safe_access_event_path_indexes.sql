DROP INDEX IF EXISTS access_events_method_path_ts_idx;

CREATE INDEX IF NOT EXISTS access_events_method_path_hash_ts_idx
  ON access_events (method, path_hash, ts DESC)
  WHERE path_hash IS NOT NULL;
