UPDATE job_runs
SET meta = jsonb_set(meta, '{files_seen}', to_jsonb((meta->>'files_seen')::bigint), false)
WHERE type = 'collect_site_env'
  AND jsonb_typeof(meta->'files_seen') = 'string'
  AND meta->>'files_seen' ~ '^[0-9]+$';

UPDATE job_runs
SET meta = jsonb_set(meta, '{files_downloaded}', to_jsonb((meta->>'files_downloaded')::bigint), false)
WHERE type = 'collect_site_env'
  AND jsonb_typeof(meta->'files_downloaded') = 'string'
  AND meta->>'files_downloaded' ~ '^[0-9]+$';

UPDATE job_runs
SET meta = jsonb_set(meta, '{files_skipped}', to_jsonb((meta->>'files_skipped')::bigint), false)
WHERE type = 'collect_site_env'
  AND jsonb_typeof(meta->'files_skipped') = 'string'
  AND meta->>'files_skipped' ~ '^[0-9]+$';

UPDATE job_runs
SET meta = jsonb_set(meta, '{bytes_downloaded}', to_jsonb((meta->>'bytes_downloaded')::bigint), false)
WHERE type = 'collect_site_env'
  AND jsonb_typeof(meta->'bytes_downloaded') = 'string'
  AND meta->>'bytes_downloaded' ~ '^[0-9]+$';

UPDATE job_runs
SET meta = jsonb_set(meta, '{servers_attempted}', to_jsonb((meta->>'servers_attempted')::bigint), false)
WHERE type = 'collect_site_env'
  AND jsonb_typeof(meta->'servers_attempted') = 'string'
  AND meta->>'servers_attempted' ~ '^[0-9]+$';

UPDATE job_runs
SET meta = jsonb_set(meta, '{servers_succeeded}', to_jsonb((meta->>'servers_succeeded')::bigint), false)
WHERE type = 'collect_site_env'
  AND jsonb_typeof(meta->'servers_succeeded') = 'string'
  AND meta->>'servers_succeeded' ~ '^[0-9]+$';

UPDATE job_runs
SET meta = jsonb_set(meta, '{server_failures}', to_jsonb((meta->>'server_failures')::bigint), false)
WHERE type = 'collect_site_env'
  AND jsonb_typeof(meta->'server_failures') = 'string'
  AND meta->>'server_failures' ~ '^[0-9]+$';
