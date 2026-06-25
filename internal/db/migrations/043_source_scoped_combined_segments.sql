ALTER TABLE combined_segments ADD COLUMN IF NOT EXISTS site_id text;
ALTER TABLE combined_segments ADD COLUMN IF NOT EXISTS env text;
ALTER TABLE combined_segments ADD COLUMN IF NOT EXISTS container_id text;

ALTER TABLE raw_files ADD COLUMN IF NOT EXISTS combined_at timestamptz;
ALTER TABLE raw_files ADD COLUMN IF NOT EXISTS combined_sha256 text;
ALTER TABLE raw_files ADD COLUMN IF NOT EXISTS combined_line_count bigint NOT NULL DEFAULT 0;

UPDATE combined_segments
SET site_id = coalesce(nullif(site_id, ''), '__legacy__'),
    env = coalesce(nullif(env, ''), '__legacy__'),
    container_id = coalesce(nullif(container_id, ''), '__legacy__')
WHERE site_id IS NULL OR env IS NULL OR container_id IS NULL
   OR site_id = '' OR env = '' OR container_id = '';

ALTER TABLE combined_segments ALTER COLUMN site_id SET DEFAULT '__legacy__';
ALTER TABLE combined_segments ALTER COLUMN env SET DEFAULT '__legacy__';
ALTER TABLE combined_segments ALTER COLUMN container_id SET DEFAULT '__legacy__';
ALTER TABLE combined_segments ALTER COLUMN site_id SET NOT NULL;
ALTER TABLE combined_segments ALTER COLUMN env SET NOT NULL;
ALTER TABLE combined_segments ALTER COLUMN container_id SET NOT NULL;

ALTER TABLE combined_segments DROP CONSTRAINT IF EXISTS combined_segments_log_type_bucket_start_key;

CREATE UNIQUE INDEX IF NOT EXISTS combined_segments_source_bucket_key
  ON combined_segments (site_id, env, container_id, log_type, bucket_start);

CREATE INDEX IF NOT EXISTS combined_segments_source_status_idx
  ON combined_segments (status, bucket_start DESC, site_id, env, container_id);

CREATE INDEX IF NOT EXISTS combined_segments_source_bucket_end_idx
  ON combined_segments (site_id, env, container_id, log_type, bucket_end);

CREATE INDEX IF NOT EXISTS raw_files_downloaded_activity_idx
  ON raw_files (log_type, greatest(coalesce(remote_mtime, '-infinity'::timestamptz), coalesce(downloaded_at, '-infinity'::timestamptz)) DESC)
  WHERE status = 'downloaded';

CREATE INDEX IF NOT EXISTS raw_files_combine_backlog_idx
  ON raw_files (log_type, downloaded_at DESC)
  WHERE status = 'downloaded'
    AND (combined_at IS NULL OR combined_sha256 IS DISTINCT FROM sha256);
