CREATE TABLE IF NOT EXISTS job_runs (
  id text PRIMARY KEY,
  type text NOT NULL,
  status text NOT NULL,
  message text,
  meta jsonb NOT NULL DEFAULT '{}'::jsonb,
  started_at timestamptz NOT NULL,
  finished_at timestamptz,
  duration_ms bigint NOT NULL DEFAULT 0,
  last_error text,
  triggered_by text
);

CREATE INDEX IF NOT EXISTS job_runs_started_at_idx ON job_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS job_runs_status_idx ON job_runs (status, started_at DESC);
