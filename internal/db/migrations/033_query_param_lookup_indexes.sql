CREATE INDEX IF NOT EXISTS access_events_query_ts_idx
  ON access_events (ts DESC, query_id)
  WHERE query_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS access_events_site_query_ts_idx
  ON access_events (site_id, ts DESC, query_id)
  WHERE query_id IS NOT NULL;
