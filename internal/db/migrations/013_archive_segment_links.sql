ALTER TABLE combined_segments ADD COLUMN IF NOT EXISTS archive_id uuid REFERENCES log_archives(id) ON DELETE SET NULL;
ALTER TABLE combined_segments ADD COLUMN IF NOT EXISTS archived_at timestamptz;
ALTER TABLE combined_segments ADD COLUMN IF NOT EXISTS source_deleted_at timestamptz;

CREATE TABLE IF NOT EXISTS log_archive_segments (
  archive_id uuid NOT NULL REFERENCES log_archives(id) ON DELETE CASCADE,
  segment_id uuid NOT NULL REFERENCES combined_segments(id) ON DELETE CASCADE,
  original_path text NOT NULL,
  bucket_start timestamptz NOT NULL,
  bucket_end timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (archive_id, segment_id)
);

CREATE INDEX IF NOT EXISTS combined_segments_archive_idx ON combined_segments (archive_id, archived_at);
CREATE INDEX IF NOT EXISTS combined_segments_source_deleted_idx ON combined_segments (source_deleted_at) WHERE source_deleted_at IS NOT NULL;
