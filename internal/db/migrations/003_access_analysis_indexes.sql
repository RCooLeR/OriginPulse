CREATE INDEX IF NOT EXISTS access_events_user_agent_hash_ts_idx ON access_events (user_agent_hash, ts DESC);
CREATE INDEX IF NOT EXISTS access_events_path_hash_ts_idx ON access_events (path_hash, ts DESC);
CREATE INDEX IF NOT EXISTS access_events_site_status_ts_idx ON access_events (site_id, status, ts DESC);
CREATE INDEX IF NOT EXISTS access_events_request_time_ts_idx ON access_events (request_time_ms, ts DESC) WHERE request_time_ms IS NOT NULL;
CREATE INDEX IF NOT EXISTS access_events_segment_id_idx ON access_events (segment_id);
CREATE INDEX IF NOT EXISTS combined_segments_bucket_end_idx ON combined_segments (bucket_end);
CREATE INDEX IF NOT EXISTS raw_files_log_type_mtime_idx ON raw_files (log_type, remote_mtime);
