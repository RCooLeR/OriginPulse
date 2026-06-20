ALTER TABLE temporary_imports ADD COLUMN IF NOT EXISTS source_file_count int NOT NULL DEFAULT 0;
ALTER TABLE temporary_imports ADD COLUMN IF NOT EXISTS imported_event_count bigint NOT NULL DEFAULT 0;
ALTER TABLE temporary_imports ADD COLUMN IF NOT EXISTS conflicted_event_count bigint NOT NULL DEFAULT 0;
ALTER TABLE temporary_imports ADD COLUMN IF NOT EXISTS invalid_event_count bigint NOT NULL DEFAULT 0;
ALTER TABLE temporary_imports ADD COLUMN IF NOT EXISTS security_probe_count bigint NOT NULL DEFAULT 0;
ALTER TABLE temporary_imports ADD COLUMN IF NOT EXISTS last_error text;

CREATE INDEX IF NOT EXISTS temporary_imports_status_idx ON temporary_imports (status, imported_at DESC);
