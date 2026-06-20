ALTER TABLE access_events ADD COLUMN IF NOT EXISTS rollups_1h_backfilled_at timestamptz;

CREATE INDEX IF NOT EXISTS access_events_dimension_backfill_idx
  ON access_events (id)
  WHERE (client_ip IS NOT NULL AND ip_id IS NULL)
     OR (path_hash IS NOT NULL AND path_id IS NULL)
     OR (query IS NOT NULL AND query <> '' AND query_id IS NULL)
     OR (user_agent_hash IS NOT NULL AND user_agent_id IS NULL)
     OR rollups_1h_backfilled_at IS NULL;

CREATE INDEX IF NOT EXISTS access_events_rollup_backfill_ts_idx
  ON access_events (ts, site_id, env)
  WHERE rollups_1h_backfilled_at IS NULL;
