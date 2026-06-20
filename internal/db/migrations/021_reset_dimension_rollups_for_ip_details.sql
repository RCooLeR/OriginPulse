TRUNCATE
  rollup_ip_1h,
  rollup_path_1h,
  rollup_user_agent_1h,
  rollup_ip_path_1h,
  rollup_ip_user_agent_1h,
  rollup_status_1h,
  rollup_site_latency_1h,
  rollup_path_latency_1h,
  rollup_security_probe_1h;

UPDATE access_events
SET rollups_1h_backfilled_at = NULL
WHERE rollups_1h_backfilled_at IS NOT NULL;
