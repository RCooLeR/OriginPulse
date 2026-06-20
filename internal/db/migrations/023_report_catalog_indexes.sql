CREATE INDEX IF NOT EXISTS llm_reports_site_created_idx
  ON llm_reports (site_id, created_at DESC);

CREATE INDEX IF NOT EXISTS llm_reports_type_created_idx
  ON llm_reports (report_type, created_at DESC);
