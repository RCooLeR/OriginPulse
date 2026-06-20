CREATE TABLE IF NOT EXISTS security_probe_events (
  id bigserial PRIMARY KEY,
  event_id bigint NOT NULL REFERENCES access_events(id) ON DELETE CASCADE,
  family text NOT NULL,
  category text NOT NULL,
  rule_key text NOT NULL,
  match_reason text,
  ts timestamptz NOT NULL,
  site_id text NOT NULL REFERENCES sites(id),
  env text NOT NULL,
  client_ip inet,
  method text,
  path text,
  query text,
  status int,
  segment_id uuid REFERENCES combined_segments(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (event_id, family, category)
);

CREATE INDEX IF NOT EXISTS security_probe_events_ts_idx
  ON security_probe_events (ts DESC);

CREATE INDEX IF NOT EXISTS security_probe_events_family_ts_idx
  ON security_probe_events (family, ts DESC);

CREATE INDEX IF NOT EXISTS security_probe_events_category_ts_idx
  ON security_probe_events (category, ts DESC);

CREATE INDEX IF NOT EXISTS security_probe_events_site_ts_idx
  ON security_probe_events (site_id, ts DESC);

CREATE INDEX IF NOT EXISTS security_probe_events_ip_ts_idx
  ON security_probe_events (client_ip, ts DESC);

CREATE INDEX IF NOT EXISTS security_probe_events_segment_idx
  ON security_probe_events (segment_id);

WITH base AS (
  SELECT id,
         ts,
         site_id,
         env,
         client_ip,
         upper(coalesce(method, '')) AS method_norm,
         coalesce(method, '') AS method,
         coalesce(path, '') AS path,
         lower(coalesce(path, '')) AS path_norm,
         coalesce(query, '') AS query,
         lower(coalesce(query, '')) AS query_norm,
         lower(coalesce(path, '') || '?' || coalesce(query, '')) AS target,
         status,
         segment_id
  FROM access_events
  WHERE client_ip IS NOT NULL
),
admin_flagged AS (
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
         CASE
           WHEN path_norm LIKE '%phpmyadmin%' OR path_norm LIKE '%/pma%' OR path_norm LIKE '%adminer%' OR path_norm LIKE '%/xmlrpc.php%' OR path_norm LIKE '%/wp-admin/install.php%' OR path_norm LIKE '%/wp-admin/setup-config.php%' THEN 'admin_tool'
           WHEN target LIKE '%lostpassword%' OR target LIKE '%lost-password%' OR target LIKE '%retrievepassword%' OR target LIKE '%resetpass%' OR target LIKE '%forgot_password%' OR target LIKE '%forgot-password%' OR target LIKE '%passwordreset%' OR target LIKE '%reset_password%' OR target LIKE '%request-password-reset%' OR path_norm LIKE '/password/reset%' OR path_norm LIKE '/password/email%' OR path_norm LIKE '/reset-password%' OR path_norm LIKE '/forgot-password%' OR path_norm LIKE '/account/reset%' THEN 'password_reset'
           WHEN method_norm = 'POST' AND (path_norm = '/wp-login.php' OR path_norm LIKE '%/login%' OR path_norm LIKE '%/user/login%' OR path_norm LIKE '%/site/login%' OR path_norm LIKE '%/s/login%' OR target LIKE '%controller=adminlogin%' OR target LIKE '%submitlogin%' OR target LIKE '%adminlogin%') THEN 'admin_login'
           WHEN path_norm LIKE '%/wp-login.php%' OR path_norm LIKE '%/wp-admin%' OR path_norm LIKE '%/administrator%' OR path_norm LIKE '%/admin%' OR path_norm LIKE '%/login%' OR path_norm LIKE '%/user/login%' OR path_norm LIKE '%/backend%' OR path_norm LIKE '%/manager%' THEN 'admin_path'
           ELSE ''
         END AS category
  FROM base
  WHERE (path_norm LIKE '%phpmyadmin%' OR path_norm LIKE '%/pma%' OR path_norm LIKE '%adminer%' OR path_norm LIKE '%/xmlrpc.php%' OR path_norm LIKE '%/wp-admin/install.php%' OR path_norm LIKE '%/wp-admin/setup-config.php%' OR
         target LIKE '%lostpassword%' OR target LIKE '%lost-password%' OR target LIKE '%retrievepassword%' OR target LIKE '%resetpass%' OR target LIKE '%forgot_password%' OR target LIKE '%forgot-password%' OR target LIKE '%passwordreset%' OR target LIKE '%reset_password%' OR target LIKE '%request-password-reset%' OR path_norm LIKE '/password/reset%' OR path_norm LIKE '/password/email%' OR path_norm LIKE '/reset-password%' OR path_norm LIKE '/forgot-password%' OR path_norm LIKE '/account/reset%' OR
         path_norm LIKE '%/wp-login.php%' OR path_norm LIKE '%/wp-admin%' OR path_norm LIKE '%/administrator%' OR path_norm LIKE '%/admin%' OR path_norm LIKE '%/login%' OR path_norm LIKE '%/user/login%' OR path_norm LIKE '%/backend%' OR path_norm LIKE '%/manager%' OR
         target LIKE '%controller=adminlogin%' OR target LIKE '%submitlogin%' OR target LIKE '%adminlogin%')
    AND NOT (path_norm ~ '^/[a-z]{2}(-[a-z]{2})?/api/restapi/' AND coalesce(status, 0) < 500)
    AND NOT (path_norm LIKE '%/wp-admin/admin-ajax.php' AND coalesce(status, 0) >= 200 AND coalesce(status, 0) < 400)
),
injection_candidates AS MATERIALIZED (
  SELECT *
  FROM base
  WHERE (path_norm LIKE '%.env%' OR query_norm LIKE '%.env%' OR
         path_norm LIKE '%wp-config.php%' OR query_norm LIKE '%wp-config.php%' OR
         path_norm LIKE '%composer.json%' OR query_norm LIKE '%composer.json%' OR
         path_norm LIKE '%composer.lock%' OR query_norm LIKE '%composer.lock%' OR
         path_norm LIKE '%id_rsa%' OR query_norm LIKE '%id_rsa%' OR
         path_norm LIKE '%.git/%' OR query_norm LIKE '%.git/%' OR
         path_norm LIKE '%union%' OR query_norm LIKE '%union%' OR
         path_norm LIKE '%select%' OR query_norm LIKE '%select%' OR
         path_norm LIKE '%information_schema%' OR query_norm LIKE '%information_schema%' OR
         path_norm LIKE '%sleep(%' OR query_norm LIKE '%sleep(%' OR
         path_norm LIKE '%benchmark(%' OR query_norm LIKE '%benchmark(%' OR
         path_norm LIKE '%extractvalue(%' OR query_norm LIKE '%extractvalue(%' OR
         path_norm LIKE '%updatexml(%' OR query_norm LIKE '%updatexml(%' OR
         path_norm LIKE '%concat(%' OR query_norm LIKE '%concat(%' OR
         path_norm LIKE '% or 1=1%' OR query_norm LIKE '% or 1=1%' OR
         path_norm LIKE '% and 1=1%' OR query_norm LIKE '% and 1=1%' OR
         path_norm LIKE '%+or+1%3d%' OR query_norm LIKE '%+or+1%3d%' OR
         path_norm LIKE '%+and+1%3d%' OR query_norm LIKE '%+and+1%3d%' OR
         path_norm LIKE '%--%' OR query_norm LIKE '%--%' OR
         path_norm LIKE '%/*%' OR query_norm LIKE '%/*%' OR
         path_norm LIKE '%2d%2d%' OR query_norm LIKE '%2d%2d%' OR
         path_norm LIKE '%2f%2a%' OR query_norm LIKE '%2f%2a%' OR
         path_norm LIKE '%<script%' OR query_norm LIKE '%<script%' OR
         path_norm LIKE '%3cscript%' OR query_norm LIKE '%3cscript%' OR
         path_norm LIKE '%javascript:%' OR query_norm LIKE '%javascript:%' OR
         path_norm LIKE '%onerror=%' OR query_norm LIKE '%onerror=%' OR
         path_norm LIKE '%onload=%' OR query_norm LIKE '%onload=%' OR
         path_norm LIKE '%alert(%' OR query_norm LIKE '%alert(%' OR
         path_norm LIKE '%/etc/passwd%' OR query_norm LIKE '%/etc/passwd%' OR
         path_norm LIKE '%proc/self/environ%' OR query_norm LIKE '%proc/self/environ%' OR
         path_norm LIKE '%boot.ini%' OR query_norm LIKE '%boot.ini%' OR
         path_norm LIKE '%..%' OR query_norm LIKE '%..%' OR
         path_norm LIKE '%2e%2e%' OR query_norm LIKE '%2e%2e%')
),
injection_flagged AS (
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
         CASE
           WHEN (target LIKE '%union%select%' OR
                 (target LIKE '%;select%' OR target LIKE '%3bselect%' OR target ~ '(^|[^a-z0-9_])select(%20|\+|[[:space:]])+[^&]{0,240}(%20|\+|[[:space:]])+from([^a-z0-9_]|$)') OR
                 target LIKE '%information_schema%' OR target LIKE '%sleep(%' OR target LIKE '%benchmark(%' OR target LIKE '%extractvalue(%' OR target LIKE '%updatexml(%' OR target LIKE '%concat(%' OR
                 target LIKE '% or 1=1%' OR target LIKE '% and 1=1%' OR target LIKE '%+or+1%3d%' OR target LIKE '%+and+1%3d%' OR
                 position('%25%27%20or%20' in target) > 0 OR position('%27%20or%20' in target) > 0 OR position('%27+or+' in target) > 0 OR
                  ((target LIKE '%--%' OR position('%2d%2d' in target) > 0 OR target LIKE '%/*%' OR position('%2f%2a' in target) > 0 OR position('%2f**' in target) > 0) AND
                  (target LIKE '%select%' OR target LIKE '%union%' OR target LIKE '%information_schema%' OR target LIKE '%concat(%' OR target LIKE '%sleep(%' OR target LIKE '%benchmark(%' OR target LIKE '%extractvalue(%' OR target LIKE '%updatexml(%'))) THEN 'sql_injection'
           WHEN target LIKE '%<script%' OR target LIKE '%3cscript%' OR target LIKE '%javascript:%' OR target LIKE '%onerror=%' OR target LIKE '%onload=%' OR target LIKE '%alert(%' THEN 'xss'
           WHEN path_norm LIKE '/.env%' OR target LIKE '%/.env%' OR target LIKE '%wp-config.php%' OR target LIKE '%composer.json%' OR target LIKE '%composer.lock%' OR target LIKE '%id_rsa%' OR target LIKE '%/.git/%' THEN 'secret_file'
           WHEN (target ~ '(^|[^.])(\.\.(/|%2f|%5c)|%2e%2e(/|%2f|%5c))' OR target LIKE '%/etc/passwd%' OR target LIKE '%proc/self/environ%' OR target LIKE '%boot.ini%') THEN 'path_traversal'
           ELSE ''
         END AS category,
         CASE
           WHEN target LIKE '%union%select%' THEN 'union_select'
           WHEN (target LIKE '%;select%' OR target LIKE '%3bselect%' OR target ~ '(^|[^a-z0-9_])select(%20|\+|[[:space:]])+[^&]{0,240}(%20|\+|[[:space:]])+from([^a-z0-9_]|$)') THEN 'select_from'
           WHEN target LIKE '%information_schema%' THEN 'information_schema'
           WHEN target LIKE '%sleep(%' OR target LIKE '%benchmark(%' THEN 'time_delay_function'
           WHEN target LIKE '%extractvalue(%' OR target LIKE '%updatexml(%' OR target LIKE '%concat(%' THEN 'sql_function'
           WHEN target LIKE '% or 1=1%' OR target LIKE '% and 1=1%' OR target LIKE '%+or+1%3d%' OR target LIKE '%+and+1%3d%' OR position('%25%27%20or%20' in target) > 0 OR position('%27%20or%20' in target) > 0 OR position('%27+or+' in target) > 0 THEN 'tautology'
           WHEN (target LIKE '%--%' OR position('%2d%2d' in target) > 0 OR target LIKE '%/*%' OR position('%2f%2a' in target) > 0 OR position('%2f**' in target) > 0) AND (target LIKE '%select%' OR target LIKE '%union%' OR target LIKE '%information_schema%' OR target LIKE '%concat(%' OR target LIKE '%sleep(%' OR target LIKE '%benchmark(%' OR target LIKE '%extractvalue(%' OR target LIKE '%updatexml(%') THEN 'sql_comment_with_keyword'
           WHEN target LIKE '%<script%' OR target LIKE '%3cscript%' THEN 'script_tag'
           WHEN target LIKE '%javascript:%' OR target LIKE '%onerror=%' OR target LIKE '%onload=%' OR target LIKE '%alert(%' THEN 'xss_payload'
           WHEN path_norm LIKE '/.env%' OR target LIKE '%/.env%' OR target LIKE '%wp-config.php%' OR target LIKE '%composer.json%' OR target LIKE '%composer.lock%' OR target LIKE '%id_rsa%' OR target LIKE '%/.git/%' THEN 'secret_file'
           WHEN (target ~ '(^|[^.])(\.\.(/|%2f|%5c)|%2e%2e(/|%2f|%5c))' OR target LIKE '%/etc/passwd%' OR target LIKE '%proc/self/environ%' OR target LIKE '%boot.ini%') THEN 'path_traversal'
           ELSE ''
         END AS match_reason
  FROM injection_candidates
)
INSERT INTO security_probe_events (
  event_id, family, category, rule_key, match_reason, ts, site_id, env,
  client_ip, method, path, query, status, segment_id
)
SELECT id, 'admin', category, 'admin_' || category, '', ts, site_id, env,
       client_ip, nullif(method, ''), nullif(path, ''), nullif(query, ''), status, segment_id
FROM admin_flagged
WHERE category <> ''
UNION ALL
SELECT id, 'injection', category, 'probe_' || category, match_reason, ts, site_id, env,
       client_ip, nullif(method, ''), nullif(path, ''), nullif(query, ''), status, segment_id
FROM injection_flagged
WHERE category <> ''
ON CONFLICT (event_id, family, category) DO NOTHING;
