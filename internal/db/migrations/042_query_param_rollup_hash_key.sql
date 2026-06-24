ALTER TABLE rollup_query_param_1h
  ADD COLUMN IF NOT EXISTS param_value_hash text;

UPDATE rollup_query_param_1h
SET param_value_hash = md5(param_value)
WHERE param_value_hash IS NULL OR param_value_hash = '';

ALTER TABLE rollup_query_param_1h
  ALTER COLUMN param_value_hash SET NOT NULL;

ALTER TABLE rollup_query_param_1h
  DROP CONSTRAINT IF EXISTS rollup_query_param_1h_pkey;

ALTER TABLE rollup_query_param_1h
  ADD PRIMARY KEY (bucket_ts, site_id, env, family, param, param_value_hash);
