DROP INDEX IF EXISTS access_events_rollup_backfill_ts_idx;

CREATE INDEX IF NOT EXISTS access_events_rollup_backfill_ts_idx
  ON access_events (ts, site_id, env)
  WHERE rollups_1h_backfilled_at IS NULL;
