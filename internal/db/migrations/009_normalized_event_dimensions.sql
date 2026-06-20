CREATE TABLE IF NOT EXISTS dim_ips (
  id bigserial PRIMARY KEY,
  ip inet NOT NULL UNIQUE,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  request_count bigint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dim_paths (
  id bigserial PRIMARY KEY,
  path text NOT NULL,
  path_hash bytea NOT NULL UNIQUE,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  request_count bigint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dim_queries (
  id bigserial PRIMARY KEY,
  query text NOT NULL,
  query_hash bytea NOT NULL UNIQUE,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  request_count bigint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dim_user_agents (
  id bigserial PRIMARY KEY,
  user_agent text NOT NULL,
  user_agent_hash bytea NOT NULL UNIQUE,
  browser_family text,
  browser_version text,
  os_family text,
  os_version text,
  device_family text,
  actor_type text,
  known_actor text,
  is_bot boolean NOT NULL DEFAULT false,
  is_tool boolean NOT NULL DEFAULT false,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  request_count bigint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS log_archives (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  log_type text NOT NULL,
  granularity text NOT NULL CHECK (granularity IN ('daily', 'weekly', 'monthly')),
  range_start timestamptz NOT NULL,
  range_end timestamptz NOT NULL,
  path text NOT NULL,
  sha256 text,
  source_file_count int NOT NULL DEFAULT 0,
  source_bytes bigint NOT NULL DEFAULT 0,
  compressed_bytes bigint NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'ready',
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (log_type, granularity, range_start)
);

CREATE TABLE IF NOT EXISTS temporary_imports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reason text,
  range_start timestamptz NOT NULL,
  range_end timestamptz NOT NULL,
  archive_paths text[] NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'imported',
  imported_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

ALTER TABLE access_events ADD COLUMN IF NOT EXISTS ip_id bigint;
ALTER TABLE access_events ADD COLUMN IF NOT EXISTS path_id bigint;
ALTER TABLE access_events ADD COLUMN IF NOT EXISTS query_id bigint;
ALTER TABLE access_events ADD COLUMN IF NOT EXISTS user_agent_id bigint;
ALTER TABLE access_events ADD COLUMN IF NOT EXISTS segment_line_no bigint;
ALTER TABLE access_events ADD COLUMN IF NOT EXISTS raw_file_id uuid;
ALTER TABLE access_events ADD COLUMN IF NOT EXISTS raw_line_no bigint;
ALTER TABLE access_events ADD COLUMN IF NOT EXISTS temporary_import_id uuid;
ALTER TABLE access_events ADD COLUMN IF NOT EXISTS imported_until timestamptz;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'access_events_ip_id_fkey') THEN
    ALTER TABLE access_events ADD CONSTRAINT access_events_ip_id_fkey FOREIGN KEY (ip_id) REFERENCES dim_ips(id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'access_events_path_id_fkey') THEN
    ALTER TABLE access_events ADD CONSTRAINT access_events_path_id_fkey FOREIGN KEY (path_id) REFERENCES dim_paths(id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'access_events_query_id_fkey') THEN
    ALTER TABLE access_events ADD CONSTRAINT access_events_query_id_fkey FOREIGN KEY (query_id) REFERENCES dim_queries(id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'access_events_user_agent_id_fkey') THEN
    ALTER TABLE access_events ADD CONSTRAINT access_events_user_agent_id_fkey FOREIGN KEY (user_agent_id) REFERENCES dim_user_agents(id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'access_events_raw_file_id_fkey') THEN
    ALTER TABLE access_events ADD CONSTRAINT access_events_raw_file_id_fkey FOREIGN KEY (raw_file_id) REFERENCES raw_files(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'access_events_temporary_import_id_fkey') THEN
    ALTER TABLE access_events ADD CONSTRAINT access_events_temporary_import_id_fkey FOREIGN KEY (temporary_import_id) REFERENCES temporary_imports(id) ON DELETE SET NULL;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS dim_ips_last_seen_idx ON dim_ips (last_seen_at DESC);
CREATE INDEX IF NOT EXISTS dim_paths_last_seen_idx ON dim_paths (last_seen_at DESC);
CREATE INDEX IF NOT EXISTS dim_queries_last_seen_idx ON dim_queries (last_seen_at DESC);
CREATE INDEX IF NOT EXISTS dim_user_agents_last_seen_idx ON dim_user_agents (last_seen_at DESC);
CREATE INDEX IF NOT EXISTS dim_user_agents_actor_idx ON dim_user_agents (actor_type, known_actor);

CREATE INDEX IF NOT EXISTS log_archives_range_idx ON log_archives (log_type, granularity, range_start, range_end);
CREATE INDEX IF NOT EXISTS log_archives_expires_idx ON log_archives (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS temporary_imports_expires_idx ON temporary_imports (expires_at);

CREATE INDEX IF NOT EXISTS access_events_ip_id_ts_idx ON access_events (ip_id, ts DESC);
CREATE INDEX IF NOT EXISTS access_events_path_id_ts_idx ON access_events (path_id, ts DESC);
CREATE INDEX IF NOT EXISTS access_events_query_id_ts_idx ON access_events (query_id, ts DESC);
CREATE INDEX IF NOT EXISTS access_events_user_agent_id_ts_idx ON access_events (user_agent_id, ts DESC);
CREATE INDEX IF NOT EXISTS access_events_temporary_import_id_idx ON access_events (temporary_import_id);
CREATE INDEX IF NOT EXISTS access_events_imported_until_idx ON access_events (imported_until) WHERE imported_until IS NOT NULL;
