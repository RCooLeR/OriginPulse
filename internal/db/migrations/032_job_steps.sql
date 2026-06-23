CREATE TABLE IF NOT EXISTS job_steps (
  id bigserial PRIMARY KEY,
  job_id text NOT NULL REFERENCES job_runs(id) ON DELETE CASCADE,
  name text NOT NULL,
  status text NOT NULL DEFAULT 'running',
  message text,
  meta jsonb NOT NULL DEFAULT '{}'::jsonb,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  duration_ms bigint NOT NULL DEFAULT 0,
  last_error text
);

CREATE INDEX IF NOT EXISTS job_steps_started_at_idx ON job_steps (started_at DESC);
CREATE INDEX IF NOT EXISTS job_steps_job_id_idx ON job_steps (job_id, started_at);
CREATE INDEX IF NOT EXISTS job_steps_status_idx ON job_steps (status, started_at DESC);
