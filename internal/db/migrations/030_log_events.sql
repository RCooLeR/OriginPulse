CREATE TABLE IF NOT EXISTS log_events (
  id bigserial PRIMARY KEY,
  ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  container_id text NOT NULL,
  log_type text NOT NULL,
  severity text,
  message text NOT NULL,
  raw text NOT NULL,
  fingerprint bytea NOT NULL,
  segment_id uuid REFERENCES combined_segments(id) ON DELETE SET NULL,
  segment_line_no bigint,
  raw_file_id uuid REFERENCES raw_files(id) ON DELETE SET NULL,
  raw_line_no bigint,
  temporary_import_id uuid REFERENCES temporary_imports(id) ON DELETE SET NULL,
  imported_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (fingerprint, ts)
);

CREATE INDEX IF NOT EXISTS log_events_type_ts_idx ON log_events (log_type, ts DESC);
CREATE INDEX IF NOT EXISTS log_events_site_type_ts_idx ON log_events (site_id, log_type, ts DESC);
CREATE INDEX IF NOT EXISTS log_events_severity_ts_idx ON log_events (severity, ts DESC) WHERE severity IS NOT NULL;
CREATE INDEX IF NOT EXISTS log_events_segment_idx ON log_events (segment_id) WHERE segment_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS log_events_temporary_import_idx ON log_events (temporary_import_id) WHERE temporary_import_id IS NOT NULL;
