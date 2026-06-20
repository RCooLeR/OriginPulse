package investigation

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/rollups"
	"originpulse/internal/useragent"
)

var ErrUserAgentRequired = errors.New("user agent id or sample is required")

type UserAgentOptions struct {
	ID            int64
	Sample        string
	Range         string
	Limit         int
	SiteID        string
	TopIPOffset   int
	TopPathOffset int
	RequestOffset int
	From          time.Time
	To            time.Time
}

type UserAgentDetail struct {
	Range           string           `json:"range"`
	SiteID          string           `json:"site_id,omitempty"`
	Since           time.Time        `json:"since"`
	Until           time.Time        `json:"until"`
	GeneratedAt     time.Time        `json:"generated_at"`
	DatabaseEnabled bool             `json:"database_enabled"`
	UserAgent       UserAgentRecord  `json:"user_agent"`
	Traffic         UserAgentTraffic `json:"traffic"`
	TopIPs          []IPSummary      `json:"top_ips"`
	TopIPsTotal     int              `json:"top_ips_total"`
	TopIPsLimit     int              `json:"top_ips_limit"`
	TopIPsOffset    int              `json:"top_ips_offset"`
	TopPaths        []PathSummary    `json:"top_paths"`
	TopPathsTotal   int              `json:"top_paths_total"`
	TopPathsLimit   int              `json:"top_paths_limit"`
	TopPathsOffset  int              `json:"top_paths_offset"`
	RecentRequests  []EventSummary   `json:"recent_requests"`
	RequestsTotal   int              `json:"requests_total"`
	RequestsLimit   int              `json:"requests_limit"`
	RequestsOffset  int              `json:"requests_offset"`
	Source          string           `json:"source"`
}

type UserAgentRecord struct {
	ID             int64     `json:"id,omitempty"`
	Sample         string    `json:"sample"`
	Family         string    `json:"family,omitempty"`
	BrowserFamily  string    `json:"browser_family,omitempty"`
	BrowserVersion string    `json:"browser_version,omitempty"`
	OSFamily       string    `json:"os_family,omitempty"`
	OSVersion      string    `json:"os_version,omitempty"`
	DeviceFamily   string    `json:"device_family,omitempty"`
	ActorType      string    `json:"actor_type,omitempty"`
	KnownActor     string    `json:"known_actor,omitempty"`
	IsBot          bool      `json:"is_bot"`
	IsTool         bool      `json:"is_tool"`
	RequestCount   int64     `json:"request_count,omitempty"`
	FirstSeen      time.Time `json:"first_seen,omitempty"`
	LastSeen       time.Time `json:"last_seen,omitempty"`
}

type UserAgentTraffic struct {
	Requests  int64     `json:"requests"`
	Status4xx int64     `json:"status_4xx"`
	Status5xx int64     `json:"status_5xx"`
	BytesSent int64     `json:"bytes_sent"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

func (s *Service) UserAgentDetails(ctx context.Context, opts UserAgentOptions) (UserAgentDetail, error) {
	limit := normalizeLimit(opts.Limit)
	topIPOffset := normalizeOffset(opts.TopIPOffset)
	topPathOffset := normalizeOffset(opts.TopPathOffset)
	requestOffset := normalizeOffset(opts.RequestOffset)
	now := time.Now().UTC()
	since, until, label, err := resolveWindow(now, opts.Range, opts.From, opts.To)
	sample := strings.TrimSpace(opts.Sample)
	out := UserAgentDetail{
		Range:           label,
		SiteID:          strings.TrimSpace(opts.SiteID),
		Since:           since,
		Until:           until,
		GeneratedAt:     now,
		DatabaseEnabled: s.Enabled(),
		UserAgent:       UserAgentRecord{ID: opts.ID, Sample: sample},
		TopIPs:          []IPSummary{},
		TopIPsLimit:     limit,
		TopIPsOffset:    topIPOffset,
		TopPaths:        []PathSummary{},
		TopPathsLimit:   limit,
		TopPathsOffset:  topPathOffset,
		RecentRequests:  []EventSummary{},
		RequestsLimit:   limit,
		RequestsOffset:  requestOffset,
	}
	if err != nil {
		return out, err
	}
	if opts.ID <= 0 && sample == "" {
		return out, ErrUserAgentRequired
	}
	if !s.Enabled() {
		return out, nil
	}

	pool, err := s.db.Pool()
	if err != nil {
		return out, err
	}
	if err := loadUserAgentRecord(ctx, pool, &out, opts.ID, sample); err != nil {
		return out, err
	}
	rollupsReady, err := rollups.DimensionRollupsReady(ctx, pool, out.Since, out.Until, out.SiteID)
	if err != nil {
		return out, err
	}
	if rollupsReady && out.UserAgent.ID > 0 {
		out.Source = "rollups+events"
		if err := loadUserAgentTrafficFromRollups(ctx, pool, &out); err != nil {
			return out, err
		}
		if err := loadUserAgentTopIPsFromRollups(ctx, pool, &out, limit, topIPOffset); err != nil {
			return out, err
		}
	} else {
		out.Source = "events"
		if err := loadUserAgentTrafficFromRaw(ctx, pool, &out); err != nil {
			return out, err
		}
		if err := loadUserAgentTopIPsFromRaw(ctx, pool, &out, limit, topIPOffset); err != nil {
			return out, err
		}
	}
	if err := loadUserAgentTopPathsFromRaw(ctx, pool, &out, limit, topPathOffset); err != nil {
		return out, err
	}
	if err := loadUserAgentRecentRequests(ctx, pool, &out, limit, requestOffset); err != nil {
		return out, err
	}
	return out, nil
}

func loadUserAgentRecord(ctx context.Context, pool *pgxpool.Pool, out *UserAgentDetail, id int64, sample string) error {
	row := pool.QueryRow(ctx, `
SELECT id,
       user_agent,
       coalesce(browser_family, ''),
       coalesce(browser_version, ''),
       coalesce(os_family, ''),
       coalesce(os_version, ''),
       coalesce(device_family, ''),
       coalesce(actor_type, ''),
       coalesce(known_actor, ''),
       is_bot,
       is_tool,
       request_count,
       first_seen_at,
       last_seen_at
FROM dim_user_agents
WHERE ($1::bigint > 0 AND id = $1)
   OR ($2 <> '' AND (user_agent = $2 OR left(user_agent, 300) = $2))
ORDER BY CASE
  WHEN $1::bigint > 0 AND id = $1 THEN 0
  WHEN user_agent = $2 THEN 1
  ELSE 2
END,
request_count DESC
LIMIT 1`, id, sample)
	err := row.Scan(
		&out.UserAgent.ID,
		&out.UserAgent.Sample,
		&out.UserAgent.BrowserFamily,
		&out.UserAgent.BrowserVersion,
		&out.UserAgent.OSFamily,
		&out.UserAgent.OSVersion,
		&out.UserAgent.DeviceFamily,
		&out.UserAgent.ActorType,
		&out.UserAgent.KnownActor,
		&out.UserAgent.IsBot,
		&out.UserAgent.IsTool,
		&out.UserAgent.RequestCount,
		&out.UserAgent.FirstSeen,
		&out.UserAgent.LastSeen,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		analysis := useragent.Analyze(sample, 0)
		out.UserAgent.Sample = sample
		out.UserAgent.Family = analysis.Family
		out.UserAgent.BrowserFamily = analysis.BrowserFamily
		out.UserAgent.BrowserVersion = analysis.BrowserVersion
		out.UserAgent.OSFamily = analysis.OSFamily
		out.UserAgent.OSVersion = analysis.OSVersion
		out.UserAgent.DeviceFamily = analysis.DeviceFamily
		out.UserAgent.ActorType = analysis.ActorType
		out.UserAgent.KnownActor = analysis.KnownActor
		out.UserAgent.IsBot = analysis.IsBot
		out.UserAgent.IsTool = analysis.IsTool
		return nil
	}
	if err != nil {
		return err
	}
	analysis := useragent.Analyze(out.UserAgent.Sample, 0)
	out.UserAgent.Family = analysis.Family
	if out.UserAgent.BrowserFamily == "" {
		out.UserAgent.BrowserFamily = analysis.BrowserFamily
	}
	if out.UserAgent.BrowserVersion == "" {
		out.UserAgent.BrowserVersion = analysis.BrowserVersion
	}
	if out.UserAgent.OSFamily == "" {
		out.UserAgent.OSFamily = analysis.OSFamily
	}
	if out.UserAgent.OSVersion == "" {
		out.UserAgent.OSVersion = analysis.OSVersion
	}
	if out.UserAgent.DeviceFamily == "" {
		out.UserAgent.DeviceFamily = analysis.DeviceFamily
	}
	if out.UserAgent.ActorType == "" {
		out.UserAgent.ActorType = analysis.ActorType
	}
	if out.UserAgent.KnownActor == "" {
		out.UserAgent.KnownActor = analysis.KnownActor
	}
	out.UserAgent.IsBot = out.UserAgent.IsBot || analysis.IsBot
	out.UserAgent.IsTool = out.UserAgent.IsTool || analysis.IsTool
	return nil
}

func loadUserAgentTrafficFromRaw(ctx context.Context, pool *pgxpool.Pool, out *UserAgentDetail) error {
	return pool.QueryRow(ctx, `
SELECT count(*)::bigint,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint,
       coalesce(sum(bytes_sent), 0)::bigint,
       coalesce(min(ts), $1),
       coalesce(max(ts), $1)
FROM access_events
WHERE ts >= $1 AND ts < $2
  AND ($3 = '' OR site_id = $3)
  AND (($4::bigint > 0 AND user_agent_id = $4) OR ($5 <> '' AND left(coalesce(user_agent, ''), 300) = $5))`,
		out.Since, out.Until, out.SiteID, out.UserAgent.ID, out.UserAgent.Sample,
	).Scan(&out.Traffic.Requests, &out.Traffic.Status4xx, &out.Traffic.Status5xx, &out.Traffic.BytesSent, &out.Traffic.FirstSeen, &out.Traffic.LastSeen)
}

func loadUserAgentTrafficFromRollups(ctx context.Context, pool *pgxpool.Pool, out *UserAgentDetail) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(out.Since, out.Until)
	return pool.QueryRow(ctx, `
WITH rollup_rows AS (
  SELECT sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx,
         sum(bytes_sent)::bigint AS bytes_sent,
         min(first_seen_at) AS first_seen_at,
         max(last_seen_at) AS last_seen_at
  FROM rollup_user_agent_1h
  WHERE user_agent_id = $4
    AND bucket_ts >= $6 AND bucket_ts < $7
    AND ($3 = '' OR site_id = $3)
),
edge_rows AS (
  SELECT count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
         coalesce(sum(bytes_sent), 0)::bigint AS bytes_sent,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND (user_agent_id = $4 OR ($5 <> '' AND left(coalesce(user_agent, ''), 300) = $5))
    AND (ts < $6 OR ts >= $7)
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
)
SELECT coalesce(sum(requests), 0)::bigint,
       coalesce(sum(status_4xx), 0)::bigint,
       coalesce(sum(status_5xx), 0)::bigint,
       coalesce(sum(bytes_sent), 0)::bigint,
       coalesce(min(first_seen_at), $1),
       coalesce(max(last_seen_at), $1)
FROM combined`, out.Since, out.Until, out.SiteID, out.UserAgent.ID, out.UserAgent.Sample, fullStart, fullEnd,
	).Scan(&out.Traffic.Requests, &out.Traffic.Status4xx, &out.Traffic.Status5xx, &out.Traffic.BytesSent, &out.Traffic.FirstSeen, &out.Traffic.LastSeen)
}

func loadUserAgentTopIPsFromRaw(ctx context.Context, pool *pgxpool.Pool, out *UserAgentDetail, limit int, offset int) error {
	rows, err := pool.Query(ctx, `
SELECT host(e.client_ip),
       count(*)::bigint,
       count(*) FILTER (WHERE e.status >= 400 AND e.status < 500)::bigint,
       count(*) FILTER (WHERE e.status >= 500 AND e.status < 600)::bigint,
       coalesce(sum(e.bytes_sent), 0)::bigint,
       min(e.ts),
       max(e.ts),
       coalesce(ii.risk_score, -1),
       coalesce(ii.actor_type, ''),
       coalesce(ii.known_actor, ''),
       coalesce(ii.reverse_dns, ''),
       count(*) OVER()::int
FROM access_events e
LEFT JOIN ip_intel ii ON ii.ip = e.client_ip
WHERE e.ts >= $1 AND e.ts < $2
  AND ($3 = '' OR e.site_id = $3)
  AND e.client_ip IS NOT NULL
  AND (($4::bigint > 0 AND e.user_agent_id = $4) OR ($5 <> '' AND left(coalesce(e.user_agent, ''), 300) = $5))
GROUP BY e.client_ip, ii.risk_score, ii.actor_type, ii.known_actor, ii.reverse_dns
ORDER BY count(*) DESC
LIMIT $6 OFFSET $7`, out.Since, out.Until, out.SiteID, out.UserAgent.ID, out.UserAgent.Sample, limit, offset)
	if err != nil {
		return err
	}
	defer rows.Close()
	return scanUserAgentIPRowsWithTotal(rows, &out.TopIPs, &out.TopIPsTotal)
}

func loadUserAgentTopIPsFromRollups(ctx context.Context, pool *pgxpool.Pool, out *UserAgentDetail, limit int, offset int) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(out.Since, out.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT d.ip,
         sum(r.requests)::bigint AS requests,
         sum(r.status_4xx)::bigint AS status_4xx,
         sum(r.status_5xx)::bigint AS status_5xx,
         sum(r.bytes_sent)::bigint AS bytes_sent,
         min(r.first_seen_at) AS first_seen_at,
         max(r.last_seen_at) AS last_seen_at
  FROM rollup_ip_user_agent_1h r
  JOIN dim_ips d ON d.id = r.ip_id
  WHERE r.user_agent_id = $4
    AND r.bucket_ts >= $6 AND r.bucket_ts < $7
    AND ($3 = '' OR r.site_id = $3)
  GROUP BY d.ip
),
edge_rows AS (
  SELECT e.client_ip AS ip,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE e.status >= 400 AND e.status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE e.status >= 500 AND e.status < 600)::bigint AS status_5xx,
         coalesce(sum(e.bytes_sent), 0)::bigint AS bytes_sent,
         min(e.ts) AS first_seen_at,
         max(e.ts) AS last_seen_at
  FROM access_events e
  WHERE e.ts >= $1 AND e.ts < $2
    AND ($3 = '' OR e.site_id = $3)
    AND e.client_ip IS NOT NULL
    AND (e.user_agent_id = $4 OR ($5 <> '' AND left(coalesce(e.user_agent, ''), 300) = $5))
    AND (e.ts < $6 OR e.ts >= $7)
  GROUP BY e.client_ip
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
),
grouped AS (
  SELECT ip,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx,
         sum(bytes_sent)::bigint AS bytes_sent,
         min(first_seen_at) AS first_seen_at,
         max(last_seen_at) AS last_seen_at
  FROM combined
  GROUP BY ip
)
SELECT host(g.ip),
       g.requests,
       g.status_4xx,
       g.status_5xx,
       g.bytes_sent,
       g.first_seen_at,
       g.last_seen_at,
       coalesce(ii.risk_score, -1),
       coalesce(ii.actor_type, ''),
       coalesce(ii.known_actor, ''),
       coalesce(ii.reverse_dns, ''),
       count(*) OVER()::int
FROM grouped g
LEFT JOIN ip_intel ii ON ii.ip = g.ip
ORDER BY g.requests DESC
LIMIT $8 OFFSET $9`, out.Since, out.Until, out.SiteID, out.UserAgent.ID, out.UserAgent.Sample, fullStart, fullEnd, limit, offset)
	if err != nil {
		return err
	}
	defer rows.Close()
	return scanUserAgentIPRowsWithTotal(rows, &out.TopIPs, &out.TopIPsTotal)
}

func scanUserAgentIPRowsWithTotal(rows pgx.Rows, out *[]IPSummary, total *int) error {
	for rows.Next() {
		var item IPSummary
		var riskScore int
		var rowTotal int
		if err := rows.Scan(&item.IP, &item.Requests, &item.Status4xx, &item.Status5xx, &item.BytesSent, &item.FirstSeen, &item.LastSeen, &riskScore, &item.ActorType, &item.KnownActor, &item.ReverseDNS, &rowTotal); err != nil {
			return err
		}
		if rowTotal > *total {
			*total = rowTotal
		}
		if riskScore >= 0 {
			item.RiskScore = &riskScore
		}
		*out = append(*out, item)
	}
	return rows.Err()
}

func scanUserAgentIPRows(rows pgx.Rows, out *[]IPSummary) error {
	for rows.Next() {
		var item IPSummary
		var riskScore int
		if err := rows.Scan(&item.IP, &item.Requests, &item.Status4xx, &item.Status5xx, &item.BytesSent, &item.FirstSeen, &item.LastSeen, &riskScore, &item.ActorType, &item.KnownActor, &item.ReverseDNS); err != nil {
			return err
		}
		if riskScore >= 0 {
			item.RiskScore = &riskScore
		}
		*out = append(*out, item)
	}
	return rows.Err()
}

func loadUserAgentTopPathsFromRaw(ctx context.Context, pool *pgxpool.Pool, out *UserAgentDetail, limit int, offset int) error {
	rows, err := pool.Query(ctx, `
SELECT coalesce(path, '') AS path,
       count(*)::bigint,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint,
       coalesce(sum(bytes_sent), 0)::bigint,
       count(*) OVER()::int
FROM access_events
WHERE ts >= $1 AND ts < $2
  AND ($3 = '' OR site_id = $3)
  AND (($4::bigint > 0 AND user_agent_id = $4) OR ($5 <> '' AND left(coalesce(user_agent, ''), 300) = $5))
GROUP BY coalesce(path, '')
ORDER BY count(*) DESC
LIMIT $6 OFFSET $7`, out.Since, out.Until, out.SiteID, out.UserAgent.ID, out.UserAgent.Sample, limit, offset)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item PathSummary
		var rowTotal int
		if err := rows.Scan(&item.Path, &item.Requests, &item.Status4xx, &item.Status5xx, &item.BytesSent, &rowTotal); err != nil {
			return err
		}
		if rowTotal > out.TopPathsTotal {
			out.TopPathsTotal = rowTotal
		}
		out.TopPaths = append(out.TopPaths, item)
	}
	return rows.Err()
}

func loadUserAgentRecentRequests(ctx context.Context, pool *pgxpool.Pool, out *UserAgentDetail, limit int, offset int) error {
	rows, err := pool.Query(ctx, `
SELECT ts,
       site_id,
       env,
       coalesce(host(client_ip), ''),
       coalesce(method, ''),
       coalesce(path, ''),
       coalesce(query, ''),
       coalesce(status, 0),
       coalesce(bytes_sent, 0),
       coalesce(referer, ''),
       left(coalesce(user_agent, ''), 300),
       coalesce(container_id, ''),
       count(*) OVER()::int
FROM access_events
WHERE ts >= $1 AND ts < $2
  AND ($3 = '' OR site_id = $3)
  AND (($4::bigint > 0 AND user_agent_id = $4) OR ($5 <> '' AND left(coalesce(user_agent, ''), 300) = $5))
ORDER BY ts DESC
LIMIT $6 OFFSET $7`, out.Since, out.Until, out.SiteID, out.UserAgent.ID, out.UserAgent.Sample, limit, offset)
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
		if rowTotal > out.RequestsTotal {
			out.RequestsTotal = rowTotal
		}
		out.RecentRequests = append(out.RecentRequests, item)
	}
	return rows.Err()
}
