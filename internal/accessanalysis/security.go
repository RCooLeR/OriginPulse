package accessanalysis

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/rollups"
)

type AccessProbeSummary struct {
	Category    string         `json:"category"`
	RuleKey     string         `json:"rule_key"`
	SiteID      string         `json:"site_id"`
	Env         string         `json:"env"`
	IP          string         `json:"ip"`
	Method      string         `json:"method"`
	Path        string         `json:"path"`
	SampleQuery string         `json:"sample_query,omitempty"`
	MatchReason string         `json:"match_reason,omitempty"`
	Requests    int64          `json:"requests"`
	TotalIPHits int64          `json:"total_ip_hits"`
	Status4xx   int64          `json:"status_4xx"`
	Status5xx   int64          `json:"status_5xx"`
	RiskScore   int            `json:"risk_score"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	Evidence    map[string]any `json:"evidence,omitempty"`
}

type TorSourceSummary struct {
	IP               string    `json:"ip"`
	SiteID           string    `json:"site_id"`
	Env              string    `json:"env"`
	Requests         int64     `json:"requests"`
	AdminRequests    int64     `json:"admin_requests"`
	Status4xx        int64     `json:"status_4xx"`
	Status5xx        int64     `json:"status_5xx"`
	ReverseDNS       string    `json:"reverse_dns,omitempty"`
	KnownActor       string    `json:"known_actor,omitempty"`
	ActorType        string    `json:"actor_type,omitempty"`
	RiskScore        int       `json:"risk_score"`
	ForwardConfirmed bool      `json:"forward_confirmed"`
	VerifiedActor    bool      `json:"verified_actor"`
	VerifiedSource   bool      `json:"verified_source"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
}

const adminProbeCategorySQL = `
CASE
  WHEN path_norm LIKE '%phpmyadmin%' OR path_norm LIKE '%/pma%' OR path_norm LIKE '%adminer%' OR path_norm LIKE '%/xmlrpc.php%' OR path_norm LIKE '%/wp-admin/install.php%' OR path_norm LIKE '%/wp-admin/setup-config.php%' THEN 'admin_tool'
  WHEN target LIKE '%lostpassword%' OR target LIKE '%lost-password%' OR target LIKE '%retrievepassword%' OR target LIKE '%resetpass%' OR target LIKE '%forgot_password%' OR target LIKE '%forgot-password%' OR target LIKE '%passwordreset%' OR target LIKE '%reset_password%' OR target LIKE '%request-password-reset%' OR path_norm LIKE '/password/reset%' OR path_norm LIKE '/password/email%' OR path_norm LIKE '/reset-password%' OR path_norm LIKE '/forgot-password%' OR path_norm LIKE '/account/reset%' THEN 'password_reset'
  WHEN method_norm = 'POST' AND (path_norm = '/wp-login.php' OR path_norm LIKE '%/login%' OR path_norm LIKE '%/user/login%' OR path_norm LIKE '%/site/login%' OR path_norm LIKE '%/s/login%' OR target LIKE '%controller=adminlogin%' OR target LIKE '%submitlogin%' OR target LIKE '%adminlogin%') THEN 'admin_login'
  WHEN path_norm LIKE '%/wp-login.php%' OR path_norm LIKE '%/wp-admin%' OR path_norm LIKE '%/administrator%' OR path_norm LIKE '%/admin%' OR path_norm LIKE '%/login%' OR path_norm LIKE '%/user/login%' OR path_norm LIKE '%/backend%' OR path_norm LIKE '%/manager%' THEN 'admin_path'
  ELSE ''
END`

const adminPathPredicateSQL = `
(path_norm LIKE '%phpmyadmin%' OR path_norm LIKE '%/pma%' OR path_norm LIKE '%adminer%' OR path_norm LIKE '%/xmlrpc.php%' OR path_norm LIKE '%/wp-admin/install.php%' OR path_norm LIKE '%/wp-admin/setup-config.php%' OR
 target LIKE '%lostpassword%' OR target LIKE '%lost-password%' OR target LIKE '%retrievepassword%' OR target LIKE '%resetpass%' OR target LIKE '%forgot_password%' OR target LIKE '%forgot-password%' OR target LIKE '%passwordreset%' OR target LIKE '%reset_password%' OR target LIKE '%request-password-reset%' OR path_norm LIKE '/password/reset%' OR path_norm LIKE '/password/email%' OR path_norm LIKE '/reset-password%' OR path_norm LIKE '/forgot-password%' OR path_norm LIKE '/account/reset%' OR
 path_norm LIKE '%/wp-login.php%' OR path_norm LIKE '%/wp-admin%' OR path_norm LIKE '%/administrator%' OR path_norm LIKE '%/admin%' OR path_norm LIKE '%/login%' OR path_norm LIKE '%/user/login%' OR path_norm LIKE '%/backend%' OR path_norm LIKE '%/manager%' OR
 target LIKE '%controller=adminlogin%' OR target LIKE '%submitlogin%' OR target LIKE '%adminlogin%')`

const injectionProbeCategorySQL = `
CASE
  WHEN ` + sqlInjectionPredicateSQL + ` THEN 'sql_injection'
  WHEN target LIKE '%<script%' OR target LIKE '%3cscript%' OR target LIKE '%javascript:%' OR target LIKE '%onerror=%' OR target LIKE '%onload=%' OR target LIKE '%alert(%' THEN 'xss'
  WHEN path_norm LIKE '/.env%' OR target LIKE '%/.env%' OR target LIKE '%wp-config.php%' OR target LIKE '%composer.json%' OR target LIKE '%composer.lock%' OR target LIKE '%id_rsa%' OR target LIKE '%/.git/%' THEN 'secret_file'
  WHEN ` + pathTraversalPredicateSQL + ` THEN 'path_traversal'
  ELSE ''
END`

const injectionProbeReasonSQL = `
CASE
  WHEN target LIKE '%union%select%' THEN 'union_select'
  WHEN ` + sqlSelectStatementPredicateSQL + ` THEN 'select_from'
  WHEN target LIKE '%information_schema%' THEN 'information_schema'
  WHEN target LIKE '%sleep(%' OR target LIKE '%benchmark(%' THEN 'time_delay_function'
  WHEN target LIKE '%extractvalue(%' OR target LIKE '%updatexml(%' OR target LIKE '%concat(%' THEN 'sql_function'
  WHEN target LIKE '% or 1=1%' OR target LIKE '% and 1=1%' OR target LIKE '%+or+1%3d%' OR target LIKE '%+and+1%3d%' OR position('%25%27%20or%20' in target) > 0 OR position('%27%20or%20' in target) > 0 OR position('%27+or+' in target) > 0 THEN 'tautology'
  WHEN (target LIKE '%--%' OR position('%2d%2d' in target) > 0 OR target LIKE '%/*%' OR position('%2f%2a' in target) > 0 OR position('%2f**' in target) > 0) AND (target LIKE '%select%' OR target LIKE '%union%' OR target LIKE '%information_schema%' OR target LIKE '%concat(%' OR target LIKE '%sleep(%' OR target LIKE '%benchmark(%' OR target LIKE '%extractvalue(%' OR target LIKE '%updatexml(%') THEN 'sql_comment_with_keyword'
  WHEN target LIKE '%<script%' OR target LIKE '%3cscript%' THEN 'script_tag'
  WHEN target LIKE '%javascript:%' OR target LIKE '%onerror=%' OR target LIKE '%onload=%' OR target LIKE '%alert(%' THEN 'xss_payload'
  WHEN path_norm LIKE '/.env%' OR target LIKE '%/.env%' OR target LIKE '%wp-config.php%' OR target LIKE '%composer.json%' OR target LIKE '%composer.lock%' OR target LIKE '%id_rsa%' OR target LIKE '%/.git/%' THEN 'secret_file'
  WHEN ` + pathTraversalPredicateSQL + ` THEN 'path_traversal'
  ELSE ''
END`

const sqlInjectionPredicateSQL = `
(target LIKE '%union%select%' OR
 ` + sqlSelectStatementPredicateSQL + ` OR
 target LIKE '%information_schema%' OR
 target LIKE '%sleep(%' OR
 target LIKE '%benchmark(%' OR
 target LIKE '%extractvalue(%' OR
 target LIKE '%updatexml(%' OR
 target LIKE '%concat(%' OR
 target LIKE '% or 1=1%' OR
 target LIKE '% and 1=1%' OR
 target LIKE '%+or+1%3d%' OR
 target LIKE '%+and+1%3d%' OR
 target LIKE '%+or+1=1%' OR
 target LIKE '%+and+1=1%' OR
 target LIKE '%20or%201=1%' OR
 target LIKE '%20or%201%3d1%' OR
 target LIKE '%20and%201=1%' OR
 target LIKE '%20and%201%3d1%' OR
 target LIKE '%09or%091=1%' OR
 target LIKE '%09or%091%3d1%' OR
 target LIKE '%09and%091=1%' OR
 target LIKE '%09and%091%3d1%' OR
 position('%25%27%20or%20' in target) > 0 OR
 position('%27%20or%20' in target) > 0 OR
 position('%27+or+' in target) > 0 OR
 ((target LIKE '%--%' OR position('%2d%2d' in target) > 0 OR target LIKE '%/*%' OR position('%2f%2a' in target) > 0 OR position('%2f**' in target) > 0) AND
  (target LIKE '%select%' OR target LIKE '%union%' OR target LIKE '%information_schema%' OR target LIKE '%concat(%' OR target LIKE '%sleep(%' OR target LIKE '%benchmark(%' OR target LIKE '%extractvalue(%' OR target LIKE '%updatexml(%')))`

const sqlSelectFromRegex = `(^|[^a-z0-9_])select(%20|\+|[[:space:]])+[^&]{0,240}(%20|\+|[[:space:]])+from([^a-z0-9_]|$)`

const sqlSelectStatementPredicateSQL = `
(target LIKE '%;select%' OR target LIKE '%3bselect%' OR target ~ '` + sqlSelectFromRegex + `')`

const injectionPathPredicateSQL = `
(` + sqlInjectionPredicateSQL + ` OR
 target LIKE '%<script%' OR target LIKE '%3cscript%' OR target LIKE '%javascript:%' OR target LIKE '%onerror=%' OR target LIKE '%onload=%' OR target LIKE '%alert(%' OR
 path_norm LIKE '/.env%' OR target LIKE '%/.env%' OR target LIKE '%wp-config.php%' OR target LIKE '%composer.json%' OR target LIKE '%composer.lock%' OR target LIKE '%id_rsa%' OR target LIKE '%/.git/%' OR
 ` + pathTraversalPredicateSQL + `)`

const injectionCandidatePredicateSQL = `
(path_norm LIKE '%.env%' OR query_norm LIKE '%.env%' OR
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
 path_norm LIKE '%+or+1=1%' OR query_norm LIKE '%+or+1=1%' OR
 path_norm LIKE '%+and+1=1%' OR query_norm LIKE '%+and+1=1%' OR
 path_norm LIKE '%20or%201=1%' OR query_norm LIKE '%20or%201=1%' OR
 path_norm LIKE '%20or%201%3d1%' OR query_norm LIKE '%20or%201%3d1%' OR
 path_norm LIKE '%20and%201=1%' OR query_norm LIKE '%20and%201=1%' OR
 path_norm LIKE '%20and%201%3d1%' OR query_norm LIKE '%20and%201%3d1%' OR
 path_norm LIKE '%09or%091=1%' OR query_norm LIKE '%09or%091=1%' OR
 path_norm LIKE '%09or%091%3d1%' OR query_norm LIKE '%09or%091%3d1%' OR
 path_norm LIKE '%09and%091=1%' OR query_norm LIKE '%09and%091=1%' OR
 path_norm LIKE '%09and%091%3d1%' OR query_norm LIKE '%09and%091%3d1%' OR
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
 path_norm LIKE '%2e%2e%' OR query_norm LIKE '%2e%2e%')`

const pathTraversalRegex = `(^|[^.])(\.\.(/|%2f|%5c)|%2e%2e(/|%2f|%5c))`

const pathTraversalPredicateSQL = `
(target ~ '` + pathTraversalRegex + `' OR target LIKE '%/etc/passwd%' OR target LIKE '%proc/self/environ%' OR target LIKE '%boot.ini%')`

func (s *Service) loadAdminProbes(ctx context.Context, report *Report, limit int) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	rows, err := pool.Query(ctx, `
WITH base AS (
  SELECT site_id,
         env,
         client_ip,
         coalesce(method, '') AS method,
         coalesce(path, '') AS path,
         coalesce(query, '') AS query,
         category,
         status,
         ts
  FROM security_probe_events
  WHERE family = 'admin'
    AND ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3) AND client_ip IS NOT NULL
),
ip_totals AS (
  SELECT client_ip, count(*)::bigint AS total_ip_hits
  FROM base
  GROUP BY client_ip
)
SELECT category,
       base.site_id,
       base.env,
       host(base.client_ip),
       base.method,
       base.path,
       coalesce(left(max(nullif(base.query, '')), 240), ''),
       count(*)::bigint,
       max(t.total_ip_hits)::bigint,
       count(*) FILTER (WHERE base.status >= 400 AND base.status < 500)::bigint,
       count(*) FILTER (WHERE base.status >= 500 AND base.status < 600)::bigint,
       min(base.ts),
       max(base.ts)
FROM base
JOIN ip_totals t ON t.client_ip = base.client_ip
WHERE base.category <> ''
GROUP BY base.category, base.site_id, base.env, base.client_ip, base.method, base.path
ORDER BY count(*) DESC, max(base.ts) DESC
LIMIT $4`, report.Since, report.Until, report.SiteID, limit)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item AccessProbeSummary
		if err := rows.Scan(
			&item.Category,
			&item.SiteID,
			&item.Env,
			&item.IP,
			&item.Method,
			&item.Path,
			&item.SampleQuery,
			&item.Requests,
			&item.TotalIPHits,
			&item.Status4xx,
			&item.Status5xx,
			&item.FirstSeen,
			&item.LastSeen,
		); err != nil {
			return err
		}
		item.RuleKey = "admin_" + item.Category
		item.RiskScore = adminProbeScore(item)
		item.Evidence = probeEvidence(item)
		report.AdminProbes = append(report.AdminProbes, item)
	}
	return rows.Err()
}

func (s *Service) loadInjectionProbes(ctx context.Context, report *Report, limit int, categoryFilter string) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	rows, err := pool.Query(ctx, `
WITH base AS (
  SELECT site_id,
         env,
         client_ip,
         coalesce(method, '') AS method,
         coalesce(path, '') AS path,
         coalesce(query, '') AS query,
         category,
         coalesce(match_reason, '') AS match_reason,
         status,
         ts
  FROM security_probe_events
  WHERE family = 'injection'
    AND ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3)
    AND ($4 = '' OR category = $4)
    AND client_ip IS NOT NULL
),
ip_totals AS (
  SELECT client_ip, count(*)::bigint AS total_ip_hits
  FROM base
  GROUP BY client_ip
)
SELECT category,
       base.site_id,
       base.env,
       host(base.client_ip),
       base.method,
       base.path,
       coalesce(left(max(nullif(base.query, '')), 240), ''),
       max(base.match_reason),
       count(*)::bigint,
       max(t.total_ip_hits)::bigint,
       count(*) FILTER (WHERE base.status >= 400 AND base.status < 500)::bigint,
       count(*) FILTER (WHERE base.status >= 500 AND base.status < 600)::bigint,
       min(base.ts),
       max(base.ts)
FROM base
JOIN ip_totals t ON t.client_ip = base.client_ip
WHERE base.category <> ''
GROUP BY base.category, base.site_id, base.env, base.client_ip, base.method, base.path
ORDER BY count(*) DESC, max(base.ts) DESC
LIMIT $5`, report.Since, report.Until, report.SiteID, strings.TrimSpace(categoryFilter), limit)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item AccessProbeSummary
		if err := rows.Scan(
			&item.Category,
			&item.SiteID,
			&item.Env,
			&item.IP,
			&item.Method,
			&item.Path,
			&item.SampleQuery,
			&item.MatchReason,
			&item.Requests,
			&item.TotalIPHits,
			&item.Status4xx,
			&item.Status5xx,
			&item.FirstSeen,
			&item.LastSeen,
		); err != nil {
			return err
		}
		item.RuleKey = "probe_" + item.Category
		item.RiskScore = injectionProbeScore(item)
		item.Evidence = probeEvidence(item)
		report.InjectionProbes = append(report.InjectionProbes, item)
	}
	return rows.Err()
}

func (s *Service) loadTorSources(ctx context.Context, report *Report, limit int, rollupsReady bool) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	if rollupsReady {
		return loadTorSourcesFromRollups(ctx, pool, report, limit)
	}
	return loadTorSourcesFromRaw(ctx, pool, report, limit)
}

func loadTorSourcesFromRaw(ctx context.Context, pool *pgxpool.Pool, report *Report, limit int) error {
	query := fmt.Sprintf(`
WITH base AS (
  SELECT e.site_id,
         e.env,
         e.client_ip,
         lower(coalesce(e.path, '')) AS path_norm,
         lower(coalesce(e.path, '') || '?' || coalesce(e.query, '')) AS target,
         e.status,
         e.ts,
         coalesce(ii.reverse_dns, '') AS reverse_dns,
         coalesce(ii.known_actor, '') AS known_actor,
         coalesce(ii.actor_type, '') AS actor_type,
         coalesce(ii.risk_score, 80) AS risk_score,
         coalesce(ii.forward_confirmed, false) AS forward_confirmed,
         coalesce(ii.verified_actor, false) AS verified_actor
  FROM access_events e
  JOIN ip_intel ii ON ii.ip = e.client_ip
  WHERE e.ts >= $1 AND e.ts < $2 AND ($3 = '' OR e.site_id = $3)
    AND (coalesce(ii.is_tor_exit, false) OR lower(coalesce(ii.known_actor, '')) = 'tor exit' OR lower(coalesce(ii.actor_type, '')) = 'tor')
)
SELECT host(client_ip),
       site_id,
       env,
       count(*)::bigint,
       count(*) FILTER (WHERE %s)::bigint,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint,
       min(reverse_dns),
       min(known_actor),
       min(actor_type),
       max(risk_score),
       bool_or(forward_confirmed),
       bool_or(verified_actor),
       min(ts),
       max(ts)
FROM base
GROUP BY client_ip, site_id, env
ORDER BY count(*) FILTER (WHERE %s) DESC, count(*) DESC, max(ts) DESC
LIMIT $4`, adminPathPredicateSQL, adminPathPredicateSQL)
	rows, err := pool.Query(ctx, query, report.Since, report.Until, report.SiteID, limit)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item TorSourceSummary
		if err := rows.Scan(
			&item.IP,
			&item.SiteID,
			&item.Env,
			&item.Requests,
			&item.AdminRequests,
			&item.Status4xx,
			&item.Status5xx,
			&item.ReverseDNS,
			&item.KnownActor,
			&item.ActorType,
			&item.RiskScore,
			&item.ForwardConfirmed,
			&item.VerifiedActor,
			&item.FirstSeen,
			&item.LastSeen,
		); err != nil {
			return err
		}
		item.VerifiedSource = item.ForwardConfirmed || item.VerifiedActor
		if item.KnownActor == "" {
			item.KnownActor = "Tor exit"
		}
		if item.ActorType == "" {
			item.ActorType = "tor"
		}
		report.TorSources = append(report.TorSources, item)
	}
	return rows.Err()
}

func loadTorSourcesFromRollups(ctx context.Context, pool *pgxpool.Pool, report *Report, limit int) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(report.Since, report.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT r.site_id,
         r.env,
         d.ip AS client_ip,
         sum(r.requests)::bigint AS requests,
         sum(r.status_4xx)::bigint AS status_4xx,
         sum(r.status_5xx)::bigint AS status_5xx,
         min(r.first_seen_at) AS first_seen_at,
         max(r.last_seen_at) AS last_seen_at
  FROM rollup_ip_1h r
  JOIN dim_ips d ON d.id = r.ip_id
  WHERE r.bucket_ts >= $4 AND r.bucket_ts < $5
    AND ($3 = '' OR r.site_id = $3)
  GROUP BY r.site_id, r.env, d.ip
),
edge_rows AS (
  SELECT site_id,
         env,
         client_ip,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND client_ip IS NOT NULL
    AND (ts < $4 OR ts >= $5)
  GROUP BY site_id, env, client_ip
),
traffic AS (
  SELECT site_id,
         env,
         client_ip,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx,
         min(first_seen_at) AS first_seen_at,
         max(last_seen_at) AS last_seen_at
  FROM (
    SELECT * FROM rollup_rows
    UNION ALL
    SELECT * FROM edge_rows
  ) rows
  GROUP BY site_id, env, client_ip
),
admin_probe_hits AS (
  SELECT site_id,
         env,
         client_ip,
         count(*)::bigint AS admin_requests
  FROM security_probe_events
  WHERE family = 'admin'
    AND ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND client_ip IS NOT NULL
  GROUP BY site_id, env, client_ip
)
SELECT host(t.client_ip),
       t.site_id,
       t.env,
       t.requests,
       coalesce(a.admin_requests, 0)::bigint,
       t.status_4xx,
       t.status_5xx,
       coalesce(ii.reverse_dns, ''),
       coalesce(ii.known_actor, ''),
       coalesce(ii.actor_type, ''),
       coalesce(ii.risk_score, 80),
       coalesce(ii.forward_confirmed, false),
       coalesce(ii.verified_actor, false),
       t.first_seen_at,
       t.last_seen_at
FROM traffic t
JOIN ip_intel ii ON ii.ip = t.client_ip
LEFT JOIN admin_probe_hits a ON a.site_id = t.site_id AND a.env = t.env AND a.client_ip = t.client_ip
WHERE coalesce(ii.is_tor_exit, false)
   OR lower(coalesce(ii.known_actor, '')) = 'tor exit'
   OR lower(coalesce(ii.actor_type, '')) = 'tor'
ORDER BY coalesce(a.admin_requests, 0) DESC, t.requests DESC, t.last_seen_at DESC
LIMIT $6`, report.Since, report.Until, report.SiteID, fullStart, fullEnd, limit)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item TorSourceSummary
		if err := rows.Scan(
			&item.IP,
			&item.SiteID,
			&item.Env,
			&item.Requests,
			&item.AdminRequests,
			&item.Status4xx,
			&item.Status5xx,
			&item.ReverseDNS,
			&item.KnownActor,
			&item.ActorType,
			&item.RiskScore,
			&item.ForwardConfirmed,
			&item.VerifiedActor,
			&item.FirstSeen,
			&item.LastSeen,
		); err != nil {
			return err
		}
		item.VerifiedSource = item.ForwardConfirmed || item.VerifiedActor
		if item.KnownActor == "" {
			item.KnownActor = "Tor exit"
		}
		if item.ActorType == "" {
			item.ActorType = "tor"
		}
		report.TorSources = append(report.TorSources, item)
	}
	return rows.Err()
}

func adminProbeIssues(probes []AccessProbeSummary) []Issue {
	issues := []Issue{}
	for _, probe := range probes {
		score := adminProbeScore(probe)
		if probe.Category == "admin_path" && probe.Requests < 10 && probe.Status4xx < 5 {
			continue
		}
		issues = append(issues, probeIssue(probe, score, adminProbeTitle(probe.Category), adminProbeSummary(probe)))
	}
	return issues
}

func injectionProbeIssues(probes []AccessProbeSummary) []Issue {
	issues := []Issue{}
	for _, probe := range probes {
		score := injectionProbeScore(probe)
		issues = append(issues, probeIssue(probe, score, injectionProbeTitle(probe.Category), injectionProbeSummary(probe)))
	}
	return issues
}

func torSourceIssues(sources []TorSourceSummary) []Issue {
	issues := []Issue{}
	for _, source := range sources {
		if source.AdminRequests == 0 && source.Requests < 10 {
			continue
		}
		score := 50 + int(min(source.Requests/25, 20))
		title := "Tor exit traffic observed"
		summary := fmt.Sprintf("%s made %d requests to %s", source.IP, source.Requests, source.SiteID)
		events := source.Requests
		if source.AdminRequests > 0 {
			score = clamp(70+int(min(source.AdminRequests*5, 20)), 70, 95)
			title = "Tor exit request to admin surface"
			summary = fmt.Sprintf("%s made %d admin-path requests to %s", source.IP, source.AdminRequests, source.SiteID)
			events = source.AdminRequests
		}
		issues = append(issues, Issue{
			RuleKey:    "tor_exit_traffic",
			Severity:   severityFor(score),
			Title:      title,
			Summary:    summary,
			SiteID:     source.SiteID,
			Env:        source.Env,
			ActorType:  "ip",
			ActorValue: source.IP,
			Score:      score,
			Requests:   source.Requests,
			Events:     events,
			Rate:       ratio(events, source.Requests),
			FirstSeen:  source.FirstSeen,
			LastSeen:   source.LastSeen,
			Evidence: map[string]any{
				"admin_requests":  source.AdminRequests,
				"reverse_dns":     source.ReverseDNS,
				"known_actor":     source.KnownActor,
				"verified_source": source.VerifiedSource,
			},
		})
	}
	return issues
}

func probeIssue(probe AccessProbeSummary, score int, title string, summary string) Issue {
	return Issue{
		RuleKey:    probe.RuleKey,
		Severity:   severityFor(score),
		Title:      title,
		Summary:    summary,
		SiteID:     probe.SiteID,
		Env:        probe.Env,
		ActorType:  "ip",
		ActorValue: probe.IP,
		Score:      score,
		Requests:   probe.Requests,
		Events:     probe.Requests,
		Rate:       ratio(probe.Status4xx+probe.Status5xx, probe.Requests),
		FirstSeen:  probe.FirstSeen,
		LastSeen:   probe.LastSeen,
		Evidence:   probeEvidence(probe),
	}
}

func adminProbeScore(probe AccessProbeSummary) int {
	base := 35
	switch probe.Category {
	case "admin_tool":
		base = 58
	case "admin_login":
		base = 62
	case "password_reset":
		base = 55
	case "admin_path":
		base = 42
	}
	if strings.EqualFold(probe.Method, "POST") {
		base += 8
	}
	base += int(min(probe.Requests/3, 16))
	base += int(min((probe.Status4xx+probe.Status5xx)/2, 12))
	return clamp(base, 30, 92)
}

func injectionProbeScore(probe AccessProbeSummary) int {
	base := 55
	switch probe.Category {
	case "sql_injection":
		base = 70
	case "xss":
		base = 64
	case "path_traversal":
		base = 68
	case "secret_file":
		base = 60
	}
	base += int(min(probe.Requests/4, 10))
	if probe.Status5xx > 0 {
		base += 4
	}
	return clamp(base, 35, 90)
}

func adminProbeTitle(category string) string {
	switch category {
	case "admin_tool":
		return "Admin tool probe"
	case "admin_login":
		return "Admin login probe"
	case "password_reset":
		return "Password reset probe"
	case "admin_path":
		return "Admin path scan"
	default:
		return "Admin probe"
	}
}

func injectionProbeTitle(category string) string {
	switch category {
	case "sql_injection":
		return "SQL injection pattern"
	case "xss":
		return "XSS payload pattern"
	case "path_traversal":
		return "Directory traversal attempt"
	case "secret_file":
		return "Sensitive file request"
	default:
		return "Suspicious request pattern"
	}
}

func adminProbeSummary(probe AccessProbeSummary) string {
	return fmt.Sprintf("%s made %d %s request(s) to %s", probe.IP, probe.Requests, adminProbeCategoryLabel(probe.Category), displayProbePath(probe))
}

func injectionProbeSummary(probe AccessProbeSummary) string {
	return fmt.Sprintf("%s made %d %s request(s) to %s", probe.IP, probe.Requests, injectionProbeCategoryLabel(probe.Category), displayProbePath(probe))
}

func adminProbeCategoryLabel(category string) string {
	switch category {
	case "admin_tool":
		return "admin-tool"
	case "admin_login":
		return "admin-login"
	case "password_reset":
		return "password-reset"
	case "admin_path":
		return "admin-path"
	default:
		return "admin"
	}
}

func injectionProbeCategoryLabel(category string) string {
	switch category {
	case "sql_injection":
		return "SQL injection"
	case "xss":
		return "XSS"
	case "path_traversal":
		return "directory traversal"
	case "secret_file":
		return "sensitive-file"
	default:
		return "suspicious-pattern"
	}
}

func displayProbePath(probe AccessProbeSummary) string {
	path := strings.TrimSpace(probe.Path)
	if path == "" {
		path = "/"
	}
	method := strings.TrimSpace(probe.Method)
	if method == "" {
		return path
	}
	return method + " " + path
}

func probeEvidence(probe AccessProbeSummary) map[string]any {
	return map[string]any{
		"category":      probe.Category,
		"method":        probe.Method,
		"path":          probe.Path,
		"sample_query":  probe.SampleQuery,
		"match_reason":  probe.MatchReason,
		"total_ip_hits": probe.TotalIPHits,
		"status_4xx":    probe.Status4xx,
		"status_5xx":    probe.Status5xx,
	}
}
