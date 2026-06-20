WITH encoded_tautology_events AS (
  SELECT id,
         ts,
         site_id,
         env,
         client_ip,
         method,
         path,
         query,
         status,
         segment_id,
         temporary_import_id,
         lower(coalesce(path, '') || '?' || coalesce(query, '')) AS target
  FROM access_events
  WHERE client_ip IS NOT NULL
    AND (
      lower(coalesce(path, '') || '?' || coalesce(query, '')) LIKE '%+or+1=1%' OR
      lower(coalesce(path, '') || '?' || coalesce(query, '')) LIKE '%+and+1=1%' OR
      lower(coalesce(path, '') || '?' || coalesce(query, '')) LIKE '%20or%201=1%' OR
      lower(coalesce(path, '') || '?' || coalesce(query, '')) LIKE '%20or%201%3d1%' OR
      lower(coalesce(path, '') || '?' || coalesce(query, '')) LIKE '%20and%201=1%' OR
      lower(coalesce(path, '') || '?' || coalesce(query, '')) LIKE '%20and%201%3d1%' OR
      lower(coalesce(path, '') || '?' || coalesce(query, '')) LIKE '%09or%091=1%' OR
      lower(coalesce(path, '') || '?' || coalesce(query, '')) LIKE '%09or%091%3d1%' OR
      lower(coalesce(path, '') || '?' || coalesce(query, '')) LIKE '%09and%091=1%' OR
      lower(coalesce(path, '') || '?' || coalesce(query, '')) LIKE '%09and%091%3d1%'
    )
)
INSERT INTO security_probe_events (
  event_id, family, category, rule_key, match_reason, ts, site_id, env,
  client_ip, method, path, query, status, segment_id, temporary_import_id
)
SELECT id, 'injection', 'sql_injection', 'probe_sql_injection', 'tautology',
       ts, site_id, env, client_ip, nullif(method, ''), nullif(path, ''),
       nullif(query, ''), status, segment_id, temporary_import_id
FROM encoded_tautology_events
ON CONFLICT (event_id, family, category) DO NOTHING;
