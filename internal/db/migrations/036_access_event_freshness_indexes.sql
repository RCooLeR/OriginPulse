CREATE INDEX IF NOT EXISTS access_events_created_at_idx
  ON access_events (created_at DESC);
