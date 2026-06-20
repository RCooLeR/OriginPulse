CREATE INDEX IF NOT EXISTS security_probe_events_family_site_ip_ts_idx
  ON security_probe_events (family, site_id, client_ip, ts DESC)
  WHERE client_ip IS NOT NULL;

CREATE INDEX IF NOT EXISTS security_probe_events_family_ip_ts_idx
  ON security_probe_events (family, client_ip, ts DESC)
  WHERE client_ip IS NOT NULL;
