package investigation

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrSecuritySignalRequired = errors.New("security signal kind, category, path, or ip is required")

type SecuritySignalOptions struct {
	Kind                 string
	Category             string
	RuleKey              string
	SiteID               string
	Env                  string
	IP                   string
	Method               string
	Path                 string
	Range                string
	Limit                int
	RelatedIPOffset      int
	RelatedRequestOffset int
	From                 time.Time
	To                   time.Time
}

type SecuritySignalDetail struct {
	Range                 string               `json:"range"`
	SiteID                string               `json:"site_id,omitempty"`
	Since                 time.Time            `json:"since"`
	Until                 time.Time            `json:"until"`
	GeneratedAt           time.Time            `json:"generated_at"`
	DatabaseEnabled       bool                 `json:"database_enabled"`
	Signal                SecuritySignalRecord `json:"signal"`
	RelatedIPs            []IPSummary          `json:"related_ips"`
	RelatedIPsTotal       int                  `json:"related_ips_total"`
	RelatedIPsLimit       int                  `json:"related_ips_limit"`
	RelatedIPsOffset      int                  `json:"related_ips_offset"`
	RelatedRequests       []EventSummary       `json:"related_requests"`
	RelatedRequestsTotal  int                  `json:"related_requests_total"`
	RelatedRequestsLimit  int                  `json:"related_requests_limit"`
	RelatedRequestsOffset int                  `json:"related_requests_offset"`
	Source                string               `json:"source"`
}

type SecuritySignalRecord struct {
	Title       string    `json:"title,omitempty"`
	Kind        string    `json:"kind,omitempty"`
	Category    string    `json:"category,omitempty"`
	RuleKey     string    `json:"rule_key,omitempty"`
	SiteID      string    `json:"site_id,omitempty"`
	Env         string    `json:"env,omitempty"`
	IP          string    `json:"ip,omitempty"`
	Method      string    `json:"method,omitempty"`
	Path        string    `json:"path,omitempty"`
	SampleQuery string    `json:"sample_query,omitempty"`
	MatchReason string    `json:"match_reason,omitempty"`
	Requests    int64     `json:"requests"`
	TotalIPHits int64     `json:"total_ip_hits"`
	Status4xx   int64     `json:"status_4xx"`
	Status5xx   int64     `json:"status_5xx"`
	RiskScore   int       `json:"risk_score"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
}

func (s *Service) SecuritySignalDetails(ctx context.Context, opts SecuritySignalOptions) (SecuritySignalDetail, error) {
	limit := normalizeLimit(opts.Limit)
	relatedIPOffset := normalizeOffset(opts.RelatedIPOffset)
	relatedRequestOffset := normalizeOffset(opts.RelatedRequestOffset)
	now := time.Now().UTC()
	since, until, label, err := resolveWindow(now, opts.Range, opts.From, opts.To)
	kind := normalizeSecurityKind(opts.Kind)
	out := SecuritySignalDetail{
		Range:           label,
		SiteID:          strings.TrimSpace(opts.SiteID),
		Since:           since,
		Until:           until,
		GeneratedAt:     now,
		DatabaseEnabled: s.Enabled(),
		Signal: SecuritySignalRecord{
			Kind:     kind,
			Category: strings.TrimSpace(opts.Category),
			RuleKey:  strings.TrimSpace(opts.RuleKey),
			SiteID:   strings.TrimSpace(opts.SiteID),
			Env:      strings.TrimSpace(opts.Env),
			IP:       strings.TrimSpace(opts.IP),
			Method:   strings.TrimSpace(opts.Method),
			Path:     strings.TrimSpace(opts.Path),
		},
		RelatedIPs:            []IPSummary{},
		RelatedIPsLimit:       limit,
		RelatedIPsOffset:      relatedIPOffset,
		RelatedRequests:       []EventSummary{},
		RelatedRequestsLimit:  limit,
		RelatedRequestsOffset: relatedRequestOffset,
	}
	if err != nil {
		return out, err
	}
	if kind == "" && out.Signal.Category == "" && out.Signal.RuleKey == "" && out.Signal.IP == "" && out.Signal.Path == "" {
		return out, ErrSecuritySignalRequired
	}
	if !s.Enabled() {
		return out, nil
	}

	pool, err := s.db.Pool()
	if err != nil {
		return out, err
	}
	if kind == "tor" {
		out.Source = "access_events+ip_intel"
		if err := loadTorSignalSummary(ctx, pool, &out); err != nil {
			return out, err
		}
		if err := loadTorSignalIPs(ctx, pool, &out, limit, relatedIPOffset); err != nil {
			return out, err
		}
		if err := loadTorSignalRequests(ctx, pool, &out, limit, relatedRequestOffset); err != nil {
			return out, err
		}
		return out, nil
	}

	out.Source = "security_probe_events"
	if err := loadProbeSignalSummary(ctx, pool, &out); err != nil {
		return out, err
	}
	if err := loadProbeSignalIPs(ctx, pool, &out, limit, relatedIPOffset); err != nil {
		return out, err
	}
	if err := loadProbeSignalRequests(ctx, pool, &out, limit, relatedRequestOffset); err != nil {
		return out, err
	}
	return out, nil
}

func loadProbeSignalSummary(ctx context.Context, pool *pgxpool.Pool, out *SecuritySignalDetail) error {
	return pool.QueryRow(ctx, `
WITH filtered AS (
  SELECT *
  FROM security_probe_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR family = $3)
    AND ($4 = '' OR category = $4 OR rule_key = $4)
    AND ($5 = '' OR site_id = $5)
    AND ($6 = '' OR env = $6)
    AND ($7 = '' OR host(client_ip) = $7)
    AND ($8 = '' OR coalesce(method, '') = $8)
    AND ($9 = '' OR coalesce(path, '') = $9)
),
ip_totals AS (
  SELECT client_ip, count(*)::bigint AS requests
  FROM filtered
  WHERE client_ip IS NOT NULL
  GROUP BY client_ip
)
SELECT coalesce(max(f.family), $3),
       coalesce(max(f.category), $4),
       coalesce(max(f.rule_key), ''),
       coalesce(max(f.site_id), $5),
       coalesce(max(f.env), $6),
       coalesce(max(host(f.client_ip)), $7),
       coalesce(max(f.method), $8),
       coalesce(max(f.path), $9),
       coalesce(left(max(nullif(f.query, '')), 240), ''),
       coalesce(max(f.match_reason), ''),
       count(*)::bigint,
       coalesce(max(ip_totals.requests), count(*))::bigint,
       count(*) FILTER (WHERE f.status >= 400 AND f.status < 500)::bigint,
       count(*) FILTER (WHERE f.status >= 500 AND f.status < 600)::bigint,
       coalesce(min(f.ts), $1),
       coalesce(max(f.ts), $1)
FROM filtered f
LEFT JOIN ip_totals ON ip_totals.client_ip = f.client_ip`, out.Since, out.Until, out.Signal.Kind, firstNonEmpty(out.Signal.Category, out.Signal.RuleKey), out.Signal.SiteID, out.Signal.Env, out.Signal.IP, out.Signal.Method, out.Signal.Path).Scan(
		&out.Signal.Kind,
		&out.Signal.Category,
		&out.Signal.RuleKey,
		&out.Signal.SiteID,
		&out.Signal.Env,
		&out.Signal.IP,
		&out.Signal.Method,
		&out.Signal.Path,
		&out.Signal.SampleQuery,
		&out.Signal.MatchReason,
		&out.Signal.Requests,
		&out.Signal.TotalIPHits,
		&out.Signal.Status4xx,
		&out.Signal.Status5xx,
		&out.Signal.FirstSeen,
		&out.Signal.LastSeen,
	)
}

func loadProbeSignalIPs(ctx context.Context, pool *pgxpool.Pool, out *SecuritySignalDetail, limit int, offset int) error {
	rows, err := pool.Query(ctx, `
SELECT host(f.client_ip),
       count(*)::bigint AS requests,
       count(*) FILTER (WHERE f.status >= 400 AND f.status < 500)::bigint AS status_4xx,
       count(*) FILTER (WHERE f.status >= 500 AND f.status < 600)::bigint AS status_5xx,
       coalesce(sum(e.bytes_sent), 0)::bigint AS bytes_sent,
       min(f.ts),
       max(f.ts),
       coalesce(ii.risk_score, -1),
       coalesce(ii.actor_type, ''),
       coalesce(ii.known_actor, ''),
       coalesce(ii.reverse_dns, ''),
       count(*) OVER()::int
FROM security_probe_events f
LEFT JOIN access_events e ON e.id = f.event_id
LEFT JOIN ip_intel ii ON ii.ip = f.client_ip
WHERE f.ts >= $1 AND f.ts < $2
  AND ($3 = '' OR f.family = $3)
  AND ($4 = '' OR f.category = $4 OR f.rule_key = $4)
  AND ($5 = '' OR f.site_id = $5)
  AND ($6 = '' OR f.env = $6)
  AND ($7 = '' OR host(f.client_ip) = $7)
  AND ($8 = '' OR coalesce(f.method, '') = $8)
  AND ($9 = '' OR coalesce(f.path, '') = $9)
  AND f.client_ip IS NOT NULL
GROUP BY f.client_ip, ii.risk_score, ii.actor_type, ii.known_actor, ii.reverse_dns
ORDER BY count(*) DESC, max(f.ts) DESC
LIMIT $10 OFFSET $11`, out.Since, out.Until, out.Signal.Kind, firstNonEmpty(out.Signal.Category, out.Signal.RuleKey), out.Signal.SiteID, out.Signal.Env, out.Signal.IP, out.Signal.Method, out.Signal.Path, limit, offset)
	if err != nil {
		return err
	}
	defer rows.Close()
	return scanUserAgentIPRowsWithTotal(rows, &out.RelatedIPs, &out.RelatedIPsTotal)
}

func loadProbeSignalRequests(ctx context.Context, pool *pgxpool.Pool, out *SecuritySignalDetail, limit int, offset int) error {
	rows, err := pool.Query(ctx, `
SELECT f.ts,
       f.site_id,
       f.env,
       coalesce(host(f.client_ip), ''),
       coalesce(f.method, ''),
       coalesce(f.path, ''),
       coalesce(f.query, ''),
       coalesce(f.status, 0),
       coalesce(e.bytes_sent, 0),
       coalesce(e.referer, ''),
       left(coalesce(e.user_agent, ''), 300),
       coalesce(e.container_id, ''),
       count(*) OVER()::int
FROM security_probe_events f
LEFT JOIN access_events e ON e.id = f.event_id
WHERE f.ts >= $1 AND f.ts < $2
  AND ($3 = '' OR f.family = $3)
  AND ($4 = '' OR f.category = $4 OR f.rule_key = $4)
  AND ($5 = '' OR f.site_id = $5)
  AND ($6 = '' OR f.env = $6)
  AND ($7 = '' OR host(f.client_ip) = $7)
  AND ($8 = '' OR coalesce(f.method, '') = $8)
  AND ($9 = '' OR coalesce(f.path, '') = $9)
ORDER BY f.ts DESC
LIMIT $10 OFFSET $11`, out.Since, out.Until, out.Signal.Kind, firstNonEmpty(out.Signal.Category, out.Signal.RuleKey), out.Signal.SiteID, out.Signal.Env, out.Signal.IP, out.Signal.Method, out.Signal.Path, limit, offset)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item EventSummary
		var rowTotal int
		if err := rows.Scan(&item.TS, &item.SiteID, &item.Env, &item.ClientIP, &item.Method, &item.Path, &item.Query, &item.Status, &item.BytesSent, &item.Referer, &item.UserAgent, &item.ContainerID, &rowTotal); err != nil {
			return err
		}
		if rowTotal > out.RelatedRequestsTotal {
			out.RelatedRequestsTotal = rowTotal
		}
		out.RelatedRequests = append(out.RelatedRequests, item)
	}
	return rows.Err()
}

func loadTorSignalSummary(ctx context.Context, pool *pgxpool.Pool, out *SecuritySignalDetail) error {
	out.Signal.Kind = "tor"
	out.Signal.Category = firstNonEmpty(out.Signal.Category, "tor_exit")
	out.Signal.RuleKey = firstNonEmpty(out.Signal.RuleKey, "tor_exit_source")
	out.Signal.Title = "Tor source"
	out.Signal.RiskScore = 70
	return pool.QueryRow(ctx, `
SELECT coalesce(max(e.site_id), $3),
       coalesce(max(e.env), $4),
       coalesce(max(host(e.client_ip)), $5),
       count(*)::bigint,
       count(*) FILTER (WHERE e.status >= 400 AND e.status < 500)::bigint,
       count(*) FILTER (WHERE e.status >= 500 AND e.status < 600)::bigint,
       coalesce(min(e.ts), $1),
       coalesce(max(e.ts), $1),
       coalesce(max(ii.risk_score), 70)
FROM access_events e
JOIN ip_intel ii ON ii.ip = e.client_ip
WHERE e.ts >= $1 AND e.ts < $2
  AND coalesce(ii.is_tor_exit, false)
  AND ($3 = '' OR e.site_id = $3)
  AND ($4 = '' OR e.env = $4)
  AND ($5 = '' OR host(e.client_ip) = $5)`, out.Since, out.Until, out.Signal.SiteID, out.Signal.Env, out.Signal.IP).Scan(&out.Signal.SiteID, &out.Signal.Env, &out.Signal.IP, &out.Signal.Requests, &out.Signal.Status4xx, &out.Signal.Status5xx, &out.Signal.FirstSeen, &out.Signal.LastSeen, &out.Signal.RiskScore)
}

func loadTorSignalIPs(ctx context.Context, pool *pgxpool.Pool, out *SecuritySignalDetail, limit int, offset int) error {
	rows, err := pool.Query(ctx, `
SELECT host(e.client_ip),
       count(*)::bigint,
       count(*) FILTER (WHERE e.status >= 400 AND e.status < 500)::bigint,
       count(*) FILTER (WHERE e.status >= 500 AND e.status < 600)::bigint,
       coalesce(sum(e.bytes_sent), 0)::bigint,
       min(e.ts),
       max(e.ts),
       coalesce(ii.risk_score, 70),
       coalesce(ii.actor_type, 'tor'),
       coalesce(ii.known_actor, ''),
       coalesce(ii.reverse_dns, ''),
       count(*) OVER()::int
FROM access_events e
JOIN ip_intel ii ON ii.ip = e.client_ip
WHERE e.ts >= $1 AND e.ts < $2
  AND coalesce(ii.is_tor_exit, false)
  AND ($3 = '' OR e.site_id = $3)
  AND ($4 = '' OR e.env = $4)
  AND ($5 = '' OR host(e.client_ip) = $5)
GROUP BY e.client_ip, ii.risk_score, ii.actor_type, ii.known_actor, ii.reverse_dns
ORDER BY count(*) DESC, max(e.ts) DESC
LIMIT $6 OFFSET $7`, out.Since, out.Until, out.Signal.SiteID, out.Signal.Env, out.Signal.IP, limit, offset)
	if err != nil {
		return err
	}
	defer rows.Close()
	return scanUserAgentIPRowsWithTotal(rows, &out.RelatedIPs, &out.RelatedIPsTotal)
}

func loadTorSignalRequests(ctx context.Context, pool *pgxpool.Pool, out *SecuritySignalDetail, limit int, offset int) error {
	rows, err := pool.Query(ctx, `
SELECT e.ts,
       e.site_id,
       e.env,
       coalesce(host(e.client_ip), ''),
       coalesce(e.method, ''),
       coalesce(e.path, ''),
       coalesce(e.query, ''),
       coalesce(e.status, 0),
       coalesce(e.bytes_sent, 0),
       coalesce(e.referer, ''),
       left(coalesce(e.user_agent, ''), 300),
       coalesce(e.container_id, ''),
       count(*) OVER()::int
FROM access_events e
JOIN ip_intel ii ON ii.ip = e.client_ip
WHERE e.ts >= $1 AND e.ts < $2
  AND coalesce(ii.is_tor_exit, false)
  AND ($3 = '' OR e.site_id = $3)
  AND ($4 = '' OR e.env = $4)
  AND ($5 = '' OR host(e.client_ip) = $5)
ORDER BY e.ts DESC
LIMIT $6 OFFSET $7`, out.Since, out.Until, out.Signal.SiteID, out.Signal.Env, out.Signal.IP, limit, offset)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item EventSummary
		var rowTotal int
		if err := rows.Scan(&item.TS, &item.SiteID, &item.Env, &item.ClientIP, &item.Method, &item.Path, &item.Query, &item.Status, &item.BytesSent, &item.Referer, &item.UserAgent, &item.ContainerID, &rowTotal); err != nil {
			return err
		}
		if rowTotal > out.RelatedRequestsTotal {
			out.RelatedRequestsTotal = rowTotal
		}
		out.RelatedRequests = append(out.RelatedRequests, item)
	}
	return rows.Err()
}

func normalizeSecurityKind(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "admin", "injection", "tor":
		return value
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
