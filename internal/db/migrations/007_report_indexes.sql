CREATE INDEX IF NOT EXISTS llm_reports_type_created_idx ON llm_reports (report_type, created_at DESC);
CREATE INDEX IF NOT EXISTS llm_reports_site_type_created_idx ON llm_reports (site_id, report_type, created_at DESC);
CREATE INDEX IF NOT EXISTS llm_reports_range_end_idx ON llm_reports (range_end DESC);
