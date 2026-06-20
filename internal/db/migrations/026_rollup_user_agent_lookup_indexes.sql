CREATE INDEX IF NOT EXISTS rollup_ip_user_agent_1h_user_agent_bucket_requests_idx
  ON rollup_ip_user_agent_1h (user_agent_id, bucket_ts DESC, requests DESC);

CREATE INDEX IF NOT EXISTS rollup_user_agent_1h_user_agent_bucket_requests_idx
  ON rollup_user_agent_1h (user_agent_id, bucket_ts DESC, requests DESC);
