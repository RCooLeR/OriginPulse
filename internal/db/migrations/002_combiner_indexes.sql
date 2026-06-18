CREATE INDEX IF NOT EXISTS raw_files_status_idx ON raw_files (status, downloaded_at DESC);
CREATE INDEX IF NOT EXISTS raw_files_site_env_idx ON raw_files (site_id, env, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS combined_segments_status_idx ON combined_segments (status, bucket_start DESC);
