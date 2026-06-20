CREATE INDEX IF NOT EXISTS error_events_path_status_ts_idx
  ON error_events (path_id, status, ts DESC)
  WHERE path_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS error_events_ip_status_ts_idx
  ON error_events (client_ip, status, ts DESC)
  WHERE client_ip IS NOT NULL;
