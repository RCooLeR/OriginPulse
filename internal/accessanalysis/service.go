package accessanalysis

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/db"
	"originpulse/internal/rollups"
	"originpulse/internal/useragent"
)

type Options struct {
	Range                  string    `json:"range"`
	Limit                  int       `json:"limit"`
	SiteID                 string    `json:"site_id"`
	From                   time.Time `json:"from"`
	To                     time.Time `json:"to"`
	IncludeSecurity        bool      `json:"include_security"`
	IncludeAdminProbes     bool      `json:"include_admin"`
	IncludeInjectionProbes bool      `json:"include_injection"`
	IncludeTorSources      bool      `json:"include_tor"`
	SecurityOnly           bool      `json:"security_only"`
	ProbeCategory          string    `json:"probe_category"`
	IncludeTimings         bool      `json:"include_timings"`
}

const ResultMaxLimit = 500

type Report struct {
	Range           string               `json:"range"`
	SiteID          string               `json:"site_id,omitempty"`
	Since           time.Time            `json:"since"`
	Until           time.Time            `json:"until"`
	GeneratedAt     time.Time            `json:"generated_at"`
	DatabaseEnabled bool                 `json:"database_enabled"`
	Totals          Totals               `json:"totals"`
	Sites           []SiteSummary        `json:"sites"`
	Issues          []Issue              `json:"issues"`
	SourceIPs       []SourceIPSummary    `json:"source_ips"`
	UserAgents      []UserAgentSummary   `json:"user_agents"`
	SlowPaths       []SlowPathSummary    `json:"slow_paths"`
	AdminProbes     []AccessProbeSummary `json:"admin_probes"`
	InjectionProbes []AccessProbeSummary `json:"injection_probes"`
	TorSources      []TorSourceSummary   `json:"tor_sources"`
	StatusBreakdown []StatusSummary      `json:"status_breakdown"`
	Timings         []Timing             `json:"timings,omitempty"`
}

type Timing struct {
	Name       string `json:"name"`
	DurationMS int64  `json:"duration_ms"`
}

type Totals struct {
	Requests          int64   `json:"requests"`
	UniqueIPs         int64   `json:"unique_ips"`
	UniqueUserAgents  int64   `json:"unique_user_agents"`
	Status4xx         int64   `json:"status_4xx"`
	Status5xx         int64   `json:"status_5xx"`
	EmptyUserAgents   int64   `json:"empty_user_agents"`
	SlowRequests      int64   `json:"slow_requests"`
	BytesSent         int64   `json:"bytes_sent"`
	AvgRequestTimeMS  float64 `json:"avg_request_time_ms"`
	P95RequestTimeMS  float64 `json:"p95_request_time_ms"`
	Status4xxRate     float64 `json:"status_4xx_rate"`
	Status5xxRate     float64 `json:"status_5xx_rate"`
	SlowRequestsRate  float64 `json:"slow_requests_rate"`
	EmptyUserAgentPct float64 `json:"empty_user_agent_pct"`
}

type SiteSummary struct {
	SiteID           string    `json:"site_id"`
	Env              string    `json:"env"`
	Requests         int64     `json:"requests"`
	UniqueIPs        int64     `json:"unique_ips"`
	Status4xx        int64     `json:"status_4xx"`
	Status5xx        int64     `json:"status_5xx"`
	Status4xxRate    float64   `json:"status_4xx_rate"`
	Status5xxRate    float64   `json:"status_5xx_rate"`
	AvgRequestTimeMS float64   `json:"avg_request_time_ms"`
	P95RequestTimeMS float64   `json:"p95_request_time_ms"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
}

type Issue struct {
	RuleKey    string         `json:"rule_key"`
	Severity   string         `json:"severity"`
	Title      string         `json:"title"`
	Summary    string         `json:"summary"`
	SiteID     string         `json:"site_id,omitempty"`
	Env        string         `json:"env,omitempty"`
	ActorType  string         `json:"actor_type,omitempty"`
	ActorValue string         `json:"actor_value,omitempty"`
	Score      int            `json:"score"`
	Requests   int64          `json:"requests"`
	Events     int64          `json:"events"`
	Rate       float64        `json:"rate"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	Evidence   map[string]any `json:"evidence,omitempty"`
}

type SourceIPSummary struct {
	IP               string    `json:"ip"`
	Requests         int64     `json:"requests"`
	Status4xx        int64     `json:"status_4xx"`
	Status5xx        int64     `json:"status_5xx"`
	BytesSent        int64     `json:"bytes_sent"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	ReverseDNS       string    `json:"reverse_dns,omitempty"`
	ASN              int64     `json:"asn,omitempty"`
	ASNOrg           string    `json:"asn_org,omitempty"`
	Network          string    `json:"network,omitempty"`
	CountryCode      string    `json:"country_code,omitempty"`
	KnownActor       string    `json:"known_actor,omitempty"`
	ActorType        string    `json:"actor_type,omitempty"`
	RiskScore        *int      `json:"risk_score,omitempty"`
	ForwardConfirmed bool      `json:"forward_confirmed"`
	VerifiedActor    bool      `json:"verified_actor"`
	VerifiedSource   bool      `json:"verified_source"`
	IsTorExit        bool      `json:"is_tor_exit"`
	ManualLabel      string    `json:"manual_label,omitempty"`
	ManualAction     string    `json:"manual_action,omitempty"`
}

type UserAgentSummary struct {
	Sample           string    `json:"sample"`
	Family           string    `json:"family"`
	BrowserFamily    string    `json:"browser_family,omitempty"`
	BrowserVersion   string    `json:"browser_version,omitempty"`
	OSFamily         string    `json:"os_family,omitempty"`
	OSVersion        string    `json:"os_version,omitempty"`
	DeviceFamily     string    `json:"device_family,omitempty"`
	ActorType        string    `json:"actor_type"`
	KnownActor       string    `json:"known_actor,omitempty"`
	IsBot            bool      `json:"is_bot"`
	IsTool           bool      `json:"is_tool"`
	Requests         int64     `json:"requests"`
	UniqueIPs        int64     `json:"unique_ips"`
	Status4xx        int64     `json:"status_4xx"`
	Status5xx        int64     `json:"status_5xx"`
	Status4xxRate    float64   `json:"status_4xx_rate"`
	Status5xxRate    float64   `json:"status_5xx_rate"`
	RiskScore        int       `json:"risk_score"`
	VerifiedIPs      int64     `json:"verified_ips"`
	VerifiedRequests int64     `json:"verified_requests"`
	VerifiedSource   bool      `json:"verified_source"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
}

type SlowPathSummary struct {
	SiteID           string    `json:"site_id"`
	Env              string    `json:"env"`
	Path             string    `json:"path"`
	Requests         int64     `json:"requests"`
	AvgRequestTimeMS float64   `json:"avg_request_time_ms"`
	P95RequestTimeMS float64   `json:"p95_request_time_ms"`
	Status5xx        int64     `json:"status_5xx"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
}

type StatusSummary struct {
	Status   int   `json:"status"`
	Requests int64 `json:"requests"`
}

type aggregateCounts struct {
	Requests         int64
	Status4xx        int64
	Status5xx        int64
	BytesSent        int64
	RequestTimeCount int64
	RequestTimeSumMS int64
	SlowRequests     int64
	EmptyUserAgents  int64
}

type Service struct {
	db *db.Store
}

func NewService(store *db.Store) *Service {
	return &Service{db: store}
}

func (s *Service) Enabled() bool {
	return s != nil && s.db != nil && s.db.Enabled()
}

func (s *Service) Analyze(ctx context.Context, opts Options) (Report, error) {
	limit := normalizeLimit(opts.Limit)
	now := time.Now().UTC()
	since, until, label, err := resolveWindow(now, opts.Range, opts.From, opts.To)
	report := Report{
		Range:           label,
		SiteID:          strings.TrimSpace(opts.SiteID),
		Since:           since,
		Until:           until,
		GeneratedAt:     now,
		DatabaseEnabled: s.Enabled(),
		Sites:           []SiteSummary{},
		Issues:          []Issue{},
		SourceIPs:       []SourceIPSummary{},
		UserAgents:      []UserAgentSummary{},
		SlowPaths:       []SlowPathSummary{},
		AdminProbes:     []AccessProbeSummary{},
		InjectionProbes: []AccessProbeSummary{},
		TorSources:      []TorSourceSummary{},
		StatusBreakdown: []StatusSummary{},
	}
	if err != nil {
		return report, err
	}
	if !s.Enabled() {
		return report, nil
	}

	pool, err := s.db.Pool()
	if err != nil {
		return report, err
	}

	recordTiming := func(name string, started time.Time) {
		if opts.IncludeTimings {
			report.Timings = append(report.Timings, Timing{Name: name, DurationMS: time.Since(started).Milliseconds()})
		}
	}
	timed := func(name string, fn func() error) error {
		started := time.Now()
		err := fn()
		recordTiming(name, started)
		return err
	}

	includeAdminProbes := opts.IncludeSecurity || opts.IncludeAdminProbes
	includeInjectionProbes := opts.IncludeSecurity || opts.IncludeInjectionProbes
	includeTorSources := opts.IncludeSecurity || opts.IncludeTorSources
	if opts.SecurityOnly {
		rollupsReady := false
		if includeTorSources {
			started := time.Now()
			rollupsReady, err = rollups.DimensionRollupsReady(ctx, pool, report.Since, report.Until, report.SiteID)
			recordTiming("dimension_rollups_ready", started)
			if err != nil {
				return report, err
			}
		}
		if includeAdminProbes {
			if err := timed("admin_probes", func() error { return s.loadAdminProbes(ctx, &report, limit) }); err != nil {
				return report, err
			}
			report.Issues = append(report.Issues, adminProbeIssues(report.AdminProbes)...)
		}
		if includeInjectionProbes {
			if err := timed("injection_probes", func() error { return s.loadInjectionProbes(ctx, &report, limit, opts.ProbeCategory) }); err != nil {
				return report, err
			}
			report.Issues = append(report.Issues, injectionProbeIssues(report.InjectionProbes)...)
		}
		if includeTorSources {
			if err := timed("tor_sources", func() error { return s.loadTorSources(ctx, &report, limit, rollupsReady) }); err != nil {
				return report, err
			}
			report.Issues = append(report.Issues, torSourceIssues(report.TorSources)...)
		}
		sortIssues(report.Issues)
		return report, nil
	}

	started := time.Now()
	rollupsReady, err := rollups.DimensionRollupsReady(ctx, pool, report.Since, report.Until, report.SiteID)
	recordTiming("dimension_rollups_ready", started)
	if err != nil {
		return report, err
	}

	if err := timed("totals", func() error { return loadTotals(ctx, pool, &report, rollupsReady) }); err != nil {
		return report, err
	}
	report.Totals.Status4xxRate = ratio(report.Totals.Status4xx, report.Totals.Requests)
	report.Totals.Status5xxRate = ratio(report.Totals.Status5xx, report.Totals.Requests)
	report.Totals.SlowRequestsRate = ratio(report.Totals.SlowRequests, report.Totals.Requests)
	report.Totals.EmptyUserAgentPct = ratio(report.Totals.EmptyUserAgents, report.Totals.Requests)

	if err := timed("sites", func() error { return s.loadSites(ctx, &report, rollupsReady) }); err != nil {
		return report, err
	}
	if err := timed("source_ips", func() error { return s.loadSourceIPs(ctx, &report, limit, rollupsReady) }); err != nil {
		return report, err
	}
	if err := timed("user_agents", func() error { return s.loadUserAgents(ctx, &report, limit, rollupsReady) }); err != nil {
		return report, err
	}
	if err := timed("slow_paths", func() error { return s.loadSlowPaths(ctx, &report, limit, rollupsReady) }); err != nil {
		return report, err
	}
	if includeAdminProbes {
		if err := timed("admin_probes", func() error { return s.loadAdminProbes(ctx, &report, limit) }); err != nil {
			return report, err
		}
	}
	if includeInjectionProbes {
		if err := timed("injection_probes", func() error { return s.loadInjectionProbes(ctx, &report, limit, opts.ProbeCategory) }); err != nil {
			return report, err
		}
	}
	if includeTorSources {
		if err := timed("tor_sources", func() error { return s.loadTorSources(ctx, &report, limit, rollupsReady) }); err != nil {
			return report, err
		}
	}
	statusRollupsReady := false
	if rollupsReady {
		started := time.Now()
		statusRollupsReady, err = rollups.StatusRollupsReady(ctx, pool, report.Since, report.Until, report.SiteID)
		recordTiming("status_rollups_ready", started)
		if err != nil {
			return report, err
		}
	}
	if err := timed("status_breakdown", func() error { return s.loadStatusBreakdown(ctx, &report, statusRollupsReady) }); err != nil {
		return report, err
	}
	if err := timed("detect_issues", func() error { return s.detectIssues(ctx, &report, limit, rollupsReady) }); err != nil {
		return report, err
	}
	started = time.Now()
	sortIssues(report.Issues)
	recordTiming("sort_issues", started)

	return report, nil
}

func loadTotals(ctx context.Context, pool *pgxpool.Pool, report *Report, rollupsReady bool) error {
	counts, err := aggregateCountsFromMinuteRollups(ctx, pool, report.Since, report.Until, report.SiteID)
	if err != nil {
		return err
	}
	report.Totals.Requests = counts.Requests
	report.Totals.Status4xx = counts.Status4xx
	report.Totals.Status5xx = counts.Status5xx
	report.Totals.EmptyUserAgents = counts.EmptyUserAgents
	report.Totals.SlowRequests = counts.SlowRequests
	report.Totals.BytesSent = counts.BytesSent
	if counts.RequestTimeCount > 0 {
		report.Totals.AvgRequestTimeMS = float64(counts.RequestTimeSumMS) / float64(counts.RequestTimeCount)
	}

	if rollupsReady {
		report.Totals.UniqueIPs, err = uniqueIPsFromRollups(ctx, pool, report.Since, report.Until, report.SiteID)
		if err != nil {
			return err
		}
		report.Totals.UniqueUserAgents, err = uniqueUserAgentsFromRollups(ctx, pool, report.Since, report.Until, report.SiteID)
		if err != nil {
			return err
		}
	} else if err := pool.QueryRow(ctx, `
SELECT count(DISTINCT client_ip)::bigint,
       count(DISTINCT user_agent_hash)::bigint
FROM access_events
WHERE ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3)`, report.Since, report.Until, report.SiteID).Scan(
		&report.Totals.UniqueIPs,
		&report.Totals.UniqueUserAgents,
	); err != nil {
		return err
	}

	if rollupsReady {
		report.Totals.P95RequestTimeMS, err = p95FromSiteLatencyRollups(ctx, pool, report.Since, report.Until, report.SiteID)
		return err
	}
	return pool.QueryRow(ctx, `
SELECT coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::float8
FROM access_events
WHERE ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3)`, report.Since, report.Until, report.SiteID).Scan(&report.Totals.P95RequestTimeMS)
}

func p95FromSiteLatencyRollups(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, siteID string) (float64, error) {
	fullStart, fullEnd, _ := rollups.FullHourRange(since, until)
	var p95 float64
	err := pool.QueryRow(ctx, `
WITH rollup_rows AS (
  SELECT bucket_le_ms, sum(requests)::bigint AS requests
  FROM rollup_site_latency_1h
  WHERE bucket_ts >= $4 AND bucket_ts < $5
    AND ($3 = '' OR site_id = $3)
  GROUP BY bucket_le_ms
),
edge_bucketed AS (
  SELECT CASE
           WHEN request_time_ms <= 50 THEN 50
           WHEN request_time_ms <= 100 THEN 100
           WHEN request_time_ms <= 200 THEN 200
           WHEN request_time_ms <= 300 THEN 300
           WHEN request_time_ms <= 500 THEN 500
           WHEN request_time_ms <= 750 THEN 750
           WHEN request_time_ms <= 1000 THEN 1000
           WHEN request_time_ms <= 1500 THEN 1500
           WHEN request_time_ms <= 2000 THEN 2000
           WHEN request_time_ms <= 3000 THEN 3000
           WHEN request_time_ms <= 5000 THEN 5000
           WHEN request_time_ms <= 10000 THEN 10000
           WHEN request_time_ms <= 30000 THEN 30000
           WHEN request_time_ms <= 60000 THEN 60000
           ELSE 2147483647
         END AS bucket_le_ms
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND request_time_ms IS NOT NULL
    AND (ts < $4 OR ts >= $5)
),
edge_rows AS (
  SELECT bucket_le_ms, count(*)::bigint AS requests
  FROM edge_bucketed
  GROUP BY bucket_le_ms
),
hist AS (
  SELECT bucket_le_ms, sum(requests)::bigint AS requests
  FROM (
    SELECT * FROM rollup_rows
    UNION ALL
    SELECT * FROM edge_rows
  ) rows
  GROUP BY bucket_le_ms
),
ranked AS (
  SELECT bucket_le_ms,
         sum(requests) OVER (ORDER BY bucket_le_ms) AS cumulative,
         sum(requests) OVER () AS total
  FROM hist
)
SELECT coalesce(min(bucket_le_ms) FILTER (WHERE cumulative >= ceil(total * 0.95)), 0)::float8
FROM ranked`, since, until, siteID, fullStart, fullEnd).Scan(&p95)
	return p95, err
}

func aggregateCountsFromMinuteRollups(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, siteID string) (aggregateCounts, error) {
	fullStart, fullEnd, _ := rollups.FullMinuteRange(since, until)
	var counts aggregateCounts
	err := pool.QueryRow(ctx, `
WITH rollup_rows AS (
  SELECT coalesce(sum(requests), 0)::bigint AS requests,
         coalesce(sum(status_4xx), 0)::bigint AS status_4xx,
         coalesce(sum(status_5xx), 0)::bigint AS status_5xx,
         coalesce(sum(bytes_sent), 0)::bigint AS bytes_sent,
         coalesce(sum(request_time_count), 0)::bigint AS request_time_count,
         coalesce(sum(request_time_sum_ms), 0)::bigint AS request_time_sum_ms,
         coalesce(sum(slow_requests), 0)::bigint AS slow_requests,
         coalesce(sum(empty_user_agents), 0)::bigint AS empty_user_agents
  FROM rollup_1m
  WHERE bucket_ts >= $4 AND bucket_ts < $5
    AND ($3 = '' OR site_id = $3)
),
edge_rows AS (
  SELECT count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
         coalesce(sum(bytes_sent), 0)::bigint AS bytes_sent,
         count(*) FILTER (WHERE request_time_ms IS NOT NULL)::bigint AS request_time_count,
         coalesce(sum(request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::bigint AS request_time_sum_ms,
         count(*) FILTER (WHERE request_time_ms >= 1000)::bigint AS slow_requests,
         count(*) FILTER (WHERE coalesce(user_agent, '') = '')::bigint AS empty_user_agents
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND (ts < $4 OR ts >= $5)
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
       coalesce(sum(request_time_count), 0)::bigint,
       coalesce(sum(request_time_sum_ms), 0)::bigint,
       coalesce(sum(slow_requests), 0)::bigint,
       coalesce(sum(empty_user_agents), 0)::bigint
FROM combined`, since, until, siteID, fullStart, fullEnd).Scan(
		&counts.Requests,
		&counts.Status4xx,
		&counts.Status5xx,
		&counts.BytesSent,
		&counts.RequestTimeCount,
		&counts.RequestTimeSumMS,
		&counts.SlowRequests,
		&counts.EmptyUserAgents,
	)
	return counts, err
}

func uniqueIPsFromRollups(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, siteID string) (int64, error) {
	fullStart, fullEnd, _ := rollups.FullHourRange(since, until)
	var count int64
	err := pool.QueryRow(ctx, `
WITH rollup_ips AS (
  SELECT DISTINCT ip_id
  FROM rollup_ip_1h
  WHERE bucket_ts >= $4 AND bucket_ts < $5
    AND ($3 = '' OR site_id = $3)
),
edge_ips AS (
  SELECT DISTINCT coalesce(e.ip_id, d.id) AS ip_id,
         CASE WHEN coalesce(e.ip_id, d.id) IS NULL THEN e.client_ip ELSE NULL END AS raw_ip
  FROM access_events e
  LEFT JOIN dim_ips d ON d.ip = e.client_ip
  WHERE e.ts >= $1 AND e.ts < $2
    AND ($3 = '' OR e.site_id = $3)
    AND e.client_ip IS NOT NULL
    AND (e.ts < $4 OR e.ts >= $5)
),
combined AS (
  SELECT ip_id, NULL::inet AS raw_ip FROM rollup_ips
  UNION
  SELECT ip_id, raw_ip FROM edge_ips
)
SELECT count(DISTINCT coalesce(ip_id::text, host(raw_ip)))::bigint
FROM combined`, since, until, siteID, fullStart, fullEnd).Scan(&count)
	return count, err
}

func uniqueUserAgentsFromRollups(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, siteID string) (int64, error) {
	fullStart, fullEnd, _ := rollups.FullHourRange(since, until)
	var count int64
	err := pool.QueryRow(ctx, `
WITH rollup_agents AS (
  SELECT DISTINCT user_agent_id
  FROM rollup_user_agent_1h
  WHERE bucket_ts >= $4 AND bucket_ts < $5
    AND ($3 = '' OR site_id = $3)
),
edge_agents AS (
  SELECT DISTINCT coalesce(e.user_agent_id, d.id) AS user_agent_id,
         CASE WHEN coalesce(e.user_agent_id, d.id) IS NULL THEN encode(e.user_agent_hash, 'hex') ELSE NULL END AS raw_hash
  FROM access_events e
  LEFT JOIN dim_user_agents d ON d.user_agent_hash = e.user_agent_hash
  WHERE e.ts >= $1 AND e.ts < $2
    AND ($3 = '' OR e.site_id = $3)
    AND e.user_agent_hash IS NOT NULL
    AND (e.ts < $4 OR e.ts >= $5)
),
combined AS (
  SELECT user_agent_id, NULL::text AS raw_hash FROM rollup_agents
  UNION
  SELECT user_agent_id, raw_hash FROM edge_agents
)
SELECT count(DISTINCT coalesce(user_agent_id::text, raw_hash))::bigint
FROM combined`, since, until, siteID, fullStart, fullEnd).Scan(&count)
	return count, err
}

func (s *Service) loadSites(ctx context.Context, report *Report, rollupsReady bool) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	if rollupsReady {
		return loadSitesFromRollups(ctx, pool, report)
	}
	rows, err := pool.Query(ctx, `
SELECT site_id,
       env,
       count(*)::bigint,
       count(DISTINCT client_ip)::bigint,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint,
       coalesce(avg(request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::float8,
       coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::float8,
       min(ts),
       max(ts)
FROM access_events
WHERE ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3)
GROUP BY site_id, env
ORDER BY count(*) DESC`, report.Since, report.Until, report.SiteID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item SiteSummary
		if err := rows.Scan(
			&item.SiteID,
			&item.Env,
			&item.Requests,
			&item.UniqueIPs,
			&item.Status4xx,
			&item.Status5xx,
			&item.AvgRequestTimeMS,
			&item.P95RequestTimeMS,
			&item.FirstSeen,
			&item.LastSeen,
		); err != nil {
			return err
		}
		item.Status4xxRate = ratio(item.Status4xx, item.Requests)
		item.Status5xxRate = ratio(item.Status5xx, item.Requests)
		report.Sites = append(report.Sites, item)
	}
	return rows.Err()
}

func loadSitesFromRollups(ctx context.Context, pool *pgxpool.Pool, report *Report) error {
	fullMinuteStart, fullMinuteEnd, _ := rollups.FullMinuteRange(report.Since, report.Until)
	fullHourStart, fullHourEnd, _ := rollups.FullHourRange(report.Since, report.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT site_id,
         env,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx,
         sum(request_time_count)::bigint AS request_time_count,
         sum(request_time_sum_ms)::bigint AS request_time_sum_ms,
         min(bucket_ts) AS first_seen,
         max(bucket_ts + interval '1 minute') AS last_seen
  FROM rollup_1m
  WHERE bucket_ts >= $4 AND bucket_ts < $5
    AND ($3 = '' OR site_id = $3)
  GROUP BY site_id, env
),
edge_rows AS (
  SELECT site_id,
         env,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
         count(*) FILTER (WHERE request_time_ms IS NOT NULL)::bigint AS request_time_count,
         coalesce(sum(request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::bigint AS request_time_sum_ms,
         min(ts) AS first_seen,
         max(ts) AS last_seen
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND (ts < $4 OR ts >= $5)
  GROUP BY site_id, env
),
site_counts AS (
  SELECT site_id,
         env,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx,
         sum(request_time_count)::bigint AS request_time_count,
         sum(request_time_sum_ms)::bigint AS request_time_sum_ms,
         min(first_seen) AS first_seen,
         max(last_seen) AS last_seen
  FROM (
    SELECT * FROM rollup_rows
    UNION ALL
    SELECT * FROM edge_rows
  ) combined_rows
  GROUP BY site_id, env
),
rollup_ips AS (
  SELECT site_id, env, ip_id
  FROM rollup_ip_1h
  WHERE bucket_ts >= $6 AND bucket_ts < $7
    AND ($3 = '' OR site_id = $3)
),
edge_ips AS (
  SELECT e.site_id,
         e.env,
         coalesce(e.ip_id, d.id) AS ip_id
  FROM access_events e
  LEFT JOIN dim_ips d ON d.ip = e.client_ip
  WHERE e.ts >= $1 AND e.ts < $2
    AND ($3 = '' OR e.site_id = $3)
    AND e.client_ip IS NOT NULL
    AND (e.ts < $6 OR e.ts >= $7)
),
site_ips AS (
  SELECT site_id,
         env,
         count(DISTINCT ip_id)::bigint AS unique_ips
  FROM (
    SELECT * FROM rollup_ips WHERE ip_id IS NOT NULL
    UNION ALL
    SELECT * FROM edge_ips WHERE ip_id IS NOT NULL
  ) combined_ips
  GROUP BY site_id, env
),
site_latency_rollups AS (
  SELECT site_id, env, bucket_le_ms, sum(requests)::bigint AS requests
  FROM rollup_site_latency_1h
  WHERE bucket_ts >= $6 AND bucket_ts < $7
    AND ($3 = '' OR site_id = $3)
  GROUP BY site_id, env, bucket_le_ms
),
site_latency_edges AS (
  SELECT site_id,
         env,
         CASE
           WHEN request_time_ms <= 50 THEN 50
           WHEN request_time_ms <= 100 THEN 100
           WHEN request_time_ms <= 200 THEN 200
           WHEN request_time_ms <= 300 THEN 300
           WHEN request_time_ms <= 500 THEN 500
           WHEN request_time_ms <= 750 THEN 750
           WHEN request_time_ms <= 1000 THEN 1000
           WHEN request_time_ms <= 1500 THEN 1500
           WHEN request_time_ms <= 2000 THEN 2000
           WHEN request_time_ms <= 3000 THEN 3000
           WHEN request_time_ms <= 5000 THEN 5000
           WHEN request_time_ms <= 10000 THEN 10000
           WHEN request_time_ms <= 30000 THEN 30000
           WHEN request_time_ms <= 60000 THEN 60000
           ELSE 2147483647
         END AS bucket_le_ms,
         count(*)::bigint AS requests
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND request_time_ms IS NOT NULL
    AND (ts < $6 OR ts >= $7)
  GROUP BY site_id, env, bucket_le_ms
),
site_latency_hist AS (
  SELECT site_id, env, bucket_le_ms, sum(requests)::bigint AS requests
  FROM (
    SELECT * FROM site_latency_rollups
    UNION ALL
    SELECT * FROM site_latency_edges
  ) rows
  GROUP BY site_id, env, bucket_le_ms
),
site_latency_ranked AS (
  SELECT site_id,
         env,
         bucket_le_ms,
         sum(requests) OVER (PARTITION BY site_id, env ORDER BY bucket_le_ms) AS cumulative,
         sum(requests) OVER (PARTITION BY site_id, env) AS total
  FROM site_latency_hist
),
site_p95 AS (
  SELECT site_id,
         env,
         min(bucket_le_ms) FILTER (WHERE cumulative >= ceil(total * 0.95))::float8 AS p95_request_time_ms
  FROM site_latency_ranked
  GROUP BY site_id, env
)
SELECT c.site_id,
       c.env,
       c.requests,
       coalesce(i.unique_ips, 0)::bigint,
       c.status_4xx,
       c.status_5xx,
       CASE WHEN c.request_time_count > 0 THEN c.request_time_sum_ms::float8 / c.request_time_count ELSE 0 END,
       coalesce(p.p95_request_time_ms, 0),
       c.first_seen,
       c.last_seen
FROM site_counts c
LEFT JOIN site_ips i ON i.site_id = c.site_id AND i.env = c.env
LEFT JOIN site_p95 p ON p.site_id = c.site_id AND p.env = c.env
ORDER BY c.requests DESC`, report.Since, report.Until, report.SiteID, fullMinuteStart, fullMinuteEnd, fullHourStart, fullHourEnd)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item SiteSummary
		if err := rows.Scan(
			&item.SiteID,
			&item.Env,
			&item.Requests,
			&item.UniqueIPs,
			&item.Status4xx,
			&item.Status5xx,
			&item.AvgRequestTimeMS,
			&item.P95RequestTimeMS,
			&item.FirstSeen,
			&item.LastSeen,
		); err != nil {
			return err
		}
		item.Status4xxRate = ratio(item.Status4xx, item.Requests)
		item.Status5xxRate = ratio(item.Status5xx, item.Requests)
		report.Sites = append(report.Sites, item)
	}
	return rows.Err()
}

func (s *Service) loadSourceIPs(ctx context.Context, report *Report, limit int, rollupsReady bool) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	if rollupsReady {
		return loadSourceIPsFromRollups(ctx, pool, report, limit)
	}
	rows, err := pool.Query(ctx, `
SELECT host(e.client_ip),
       count(*)::bigint,
       count(*) FILTER (WHERE e.status >= 400 AND e.status < 500)::bigint,
       count(*) FILTER (WHERE e.status >= 500 AND e.status < 600)::bigint,
       coalesce(sum(e.bytes_sent), 0)::bigint,
       min(e.ts),
       max(e.ts),
       coalesce(ii.reverse_dns, ''),
       coalesce(ii.asn, 0),
       coalesce(ii.asn_org, ''),
       coalesce(ii.network::text, ''),
       coalesce(ii.country_code, ''),
       coalesce(ii.known_actor, ''),
       coalesce(ii.actor_type, ''),
       coalesce(ii.risk_score, -1),
       coalesce(ii.forward_confirmed, false),
       coalesce(ii.verified_actor, false),
       coalesce(ii.is_tor_exit, false),
       coalesce(ii.manual_label, ''),
       coalesce(ii.manual_action, '')
FROM access_events e
LEFT JOIN ip_intel ii ON ii.ip = e.client_ip
WHERE e.ts >= $1 AND e.ts < $2 AND ($3 = '' OR e.site_id = $3) AND e.client_ip IS NOT NULL
GROUP BY e.client_ip, ii.reverse_dns, ii.asn, ii.asn_org, ii.network, ii.country_code, ii.known_actor, ii.actor_type, ii.risk_score, ii.forward_confirmed, ii.verified_actor, ii.is_tor_exit, ii.manual_label, ii.manual_action
ORDER BY count(*) DESC
LIMIT $4`, report.Since, report.Until, report.SiteID, limit)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item SourceIPSummary
		var riskScore int
		if err := rows.Scan(
			&item.IP,
			&item.Requests,
			&item.Status4xx,
			&item.Status5xx,
			&item.BytesSent,
			&item.FirstSeen,
			&item.LastSeen,
			&item.ReverseDNS,
			&item.ASN,
			&item.ASNOrg,
			&item.Network,
			&item.CountryCode,
			&item.KnownActor,
			&item.ActorType,
			&riskScore,
			&item.ForwardConfirmed,
			&item.VerifiedActor,
			&item.IsTorExit,
			&item.ManualLabel,
			&item.ManualAction,
		); err != nil {
			return err
		}
		if riskScore >= 0 {
			item.RiskScore = &riskScore
		}
		item.VerifiedSource = item.ForwardConfirmed || item.VerifiedActor
		report.SourceIPs = append(report.SourceIPs, item)
	}
	return rows.Err()
}

func loadSourceIPsFromRollups(ctx context.Context, pool *pgxpool.Pool, report *Report, limit int) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(report.Since, report.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT r.ip_id,
         NULL::inet AS raw_ip,
         sum(r.requests)::bigint AS requests,
         sum(r.status_4xx)::bigint AS status_4xx,
         sum(r.status_5xx)::bigint AS status_5xx,
         sum(r.bytes_sent)::bigint AS bytes_sent,
         min(r.first_seen_at) AS first_seen_at,
         max(r.last_seen_at) AS last_seen_at
  FROM rollup_ip_1h r
  WHERE r.bucket_ts >= $5 AND r.bucket_ts < $6
    AND ($3 = '' OR r.site_id = $3)
  GROUP BY r.ip_id
),
edge_rows AS (
  SELECT coalesce(e.ip_id, d.id) AS ip_id,
         CASE WHEN coalesce(e.ip_id, d.id) IS NULL THEN e.client_ip ELSE NULL END AS raw_ip,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE e.status >= 400 AND e.status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE e.status >= 500 AND e.status < 600)::bigint AS status_5xx,
         coalesce(sum(e.bytes_sent), 0)::bigint AS bytes_sent,
         min(e.ts) AS first_seen_at,
         max(e.ts) AS last_seen_at
  FROM access_events e
  LEFT JOIN dim_ips d ON d.ip = e.client_ip
  WHERE e.ts >= $1 AND e.ts < $2
    AND ($3 = '' OR e.site_id = $3)
    AND e.client_ip IS NOT NULL
    AND (e.ts < $5 OR e.ts >= $6)
  GROUP BY coalesce(e.ip_id, d.id), raw_ip
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
),
grouped AS (
  SELECT ip_id,
         raw_ip,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx,
         sum(bytes_sent)::bigint AS bytes_sent,
         min(first_seen_at) AS first_seen_at,
         max(last_seen_at) AS last_seen_at
  FROM combined
  GROUP BY ip_id, raw_ip
),
top_ips AS (
  SELECT *
  FROM grouped
  ORDER BY requests DESC
  LIMIT $4
)
SELECT host(coalesce(d.ip, t.raw_ip)),
       t.requests,
       t.status_4xx,
       t.status_5xx,
       t.bytes_sent,
       t.first_seen_at,
       t.last_seen_at,
       coalesce(ii.reverse_dns, ''),
       coalesce(ii.asn, 0),
       coalesce(ii.asn_org, ''),
       coalesce(ii.network::text, ''),
       coalesce(ii.country_code, ''),
       coalesce(ii.known_actor, ''),
       coalesce(ii.actor_type, ''),
       coalesce(ii.risk_score, -1),
       coalesce(ii.forward_confirmed, false),
       coalesce(ii.verified_actor, false),
       coalesce(ii.is_tor_exit, false),
       coalesce(ii.manual_label, ''),
       coalesce(ii.manual_action, '')
FROM top_ips t
LEFT JOIN dim_ips d ON d.id = t.ip_id
LEFT JOIN ip_intel ii ON ii.ip = coalesce(d.ip, t.raw_ip)
ORDER BY t.requests DESC`, report.Since, report.Until, report.SiteID, limit, fullStart, fullEnd)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item SourceIPSummary
		var riskScore int
		if err := rows.Scan(
			&item.IP,
			&item.Requests,
			&item.Status4xx,
			&item.Status5xx,
			&item.BytesSent,
			&item.FirstSeen,
			&item.LastSeen,
			&item.ReverseDNS,
			&item.ASN,
			&item.ASNOrg,
			&item.Network,
			&item.CountryCode,
			&item.KnownActor,
			&item.ActorType,
			&riskScore,
			&item.ForwardConfirmed,
			&item.VerifiedActor,
			&item.IsTorExit,
			&item.ManualLabel,
			&item.ManualAction,
		); err != nil {
			return err
		}
		if riskScore >= 0 {
			item.RiskScore = &riskScore
		}
		item.VerifiedSource = item.ForwardConfirmed || item.VerifiedActor
		report.SourceIPs = append(report.SourceIPs, item)
	}
	return rows.Err()
}

func (s *Service) loadUserAgents(ctx context.Context, report *Report, limit int, rollupsReady bool) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	if rollupsReady {
		return loadUserAgentsFromRollups(ctx, pool, report, limit)
	}
	rows, err := pool.Query(ctx, `
SELECT left(coalesce(max(d.user_agent), max(e.user_agent), ''), 300),
       coalesce(max(d.family), ''),
       coalesce(max(d.browser_family), ''),
       coalesce(max(d.browser_version), ''),
       coalesce(max(d.os_family), ''),
       coalesce(max(d.os_version), ''),
       coalesce(max(d.device_family), ''),
       coalesce(max(d.actor_type), ''),
       coalesce(max(d.known_actor), ''),
       coalesce(bool_or(d.is_bot), false),
       coalesce(bool_or(d.is_tool), false),
       coalesce(max(d.risk_score), 0),
       count(*)::bigint,
       count(DISTINCT e.client_ip)::bigint,
       count(*) FILTER (WHERE e.status >= 400 AND e.status < 500)::bigint,
       count(*) FILTER (WHERE e.status >= 500 AND e.status < 600)::bigint,
       count(DISTINCT e.client_ip) FILTER (WHERE coalesce(ii.forward_confirmed, false) OR coalesce(ii.verified_actor, false))::bigint,
       count(*) FILTER (WHERE coalesce(ii.forward_confirmed, false) OR coalesce(ii.verified_actor, false))::bigint,
       min(e.ts),
       max(e.ts)
FROM access_events e
LEFT JOIN ip_intel ii ON ii.ip = e.client_ip
LEFT JOIN dim_user_agents d ON d.user_agent_hash = e.user_agent_hash
WHERE e.ts >= $1 AND e.ts < $2 AND ($3 = '' OR e.site_id = $3)
GROUP BY e.user_agent_hash
ORDER BY count(*) DESC
LIMIT $4`, report.Since, report.Until, report.SiteID, limit)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item UserAgentSummary
		if err := rows.Scan(
			&item.Sample,
			&item.Family,
			&item.BrowserFamily,
			&item.BrowserVersion,
			&item.OSFamily,
			&item.OSVersion,
			&item.DeviceFamily,
			&item.ActorType,
			&item.KnownActor,
			&item.IsBot,
			&item.IsTool,
			&item.RiskScore,
			&item.Requests,
			&item.UniqueIPs,
			&item.Status4xx,
			&item.Status5xx,
			&item.VerifiedIPs,
			&item.VerifiedRequests,
			&item.FirstSeen,
			&item.LastSeen,
		); err != nil {
			return err
		}
		applyUserAgentAnalysis(&item)
		item.VerifiedSource = item.VerifiedIPs > 0 && item.VerifiedRequests > 0
		item.Status4xxRate = ratio(item.Status4xx, item.Requests)
		item.Status5xxRate = ratio(item.Status5xx, item.Requests)
		report.UserAgents = append(report.UserAgents, item)
	}
	return rows.Err()
}

func loadUserAgentsFromRollups(ctx context.Context, pool *pgxpool.Pool, report *Report, limit int) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(report.Since, report.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT r.user_agent_id::text AS agent_key,
         r.user_agent_id,
         left(coalesce(d.user_agent, ''), 300) AS sample,
         sum(r.requests)::bigint AS requests,
         sum(r.status_4xx)::bigint AS status_4xx,
         sum(r.status_5xx)::bigint AS status_5xx,
         min(r.first_seen_at) AS first_seen_at,
         max(r.last_seen_at) AS last_seen_at
  FROM rollup_user_agent_1h r
  JOIN dim_user_agents d ON d.id = r.user_agent_id
  WHERE r.bucket_ts >= $5 AND r.bucket_ts < $6
    AND ($3 = '' OR r.site_id = $3)
  GROUP BY r.user_agent_id, left(coalesce(d.user_agent, ''), 300)
),
edge_rows AS (
  SELECT CASE
           WHEN e.user_agent_id IS NOT NULL THEN e.user_agent_id::text
           ELSE 'sample:' || left(coalesce(e.user_agent, ''), 300)
         END AS agent_key,
         e.user_agent_id,
         left(coalesce(e.user_agent, ''), 300) AS sample,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE e.status >= 400 AND e.status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE e.status >= 500 AND e.status < 600)::bigint AS status_5xx,
         min(e.ts) AS first_seen_at,
         max(e.ts) AS last_seen_at
  FROM access_events e
  WHERE e.ts >= $1 AND e.ts < $2
    AND ($3 = '' OR e.site_id = $3)
    AND (e.ts < $5 OR e.ts >= $6)
  GROUP BY agent_key, e.user_agent_id, left(coalesce(e.user_agent, ''), 300)
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
),
top_agents AS (
  SELECT agent_key,
         max(user_agent_id) AS user_agent_id,
         sample,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx,
         min(first_seen_at) AS first_seen_at,
         max(last_seen_at) AS last_seen_at
  FROM combined
  GROUP BY agent_key, sample
  ORDER BY sum(requests) DESC
  LIMIT $4
),
agent_ip_rows AS (
  SELECT r.user_agent_id::text AS agent_key,
         d.ip,
         sum(r.requests)::bigint AS requests
  FROM rollup_ip_user_agent_1h r
  JOIN dim_ips d ON d.id = r.ip_id
  JOIN top_agents t ON t.agent_key = r.user_agent_id::text
  WHERE r.bucket_ts >= $5 AND r.bucket_ts < $6
    AND ($3 = '' OR r.site_id = $3)
  GROUP BY r.user_agent_id, d.ip
  UNION ALL
  SELECT CASE
           WHEN e.user_agent_id IS NOT NULL THEN e.user_agent_id::text
           ELSE 'sample:' || left(coalesce(e.user_agent, ''), 300)
         END AS agent_key,
         e.client_ip AS ip,
         count(*)::bigint AS requests
  FROM access_events e
  JOIN top_agents t ON t.agent_key = CASE
    WHEN e.user_agent_id IS NOT NULL THEN e.user_agent_id::text
    ELSE 'sample:' || left(coalesce(e.user_agent, ''), 300)
  END
  WHERE e.ts >= $1 AND e.ts < $2
    AND ($3 = '' OR e.site_id = $3)
    AND e.client_ip IS NOT NULL
    AND (e.ts < $5 OR e.ts >= $6)
  GROUP BY e.user_agent_id, left(coalesce(e.user_agent, ''), 300), e.client_ip
),
agent_ip_stats AS (
  SELECT rows.agent_key,
         count(DISTINCT rows.ip)::bigint AS unique_ips,
         count(DISTINCT rows.ip) FILTER (WHERE coalesce(ii.forward_confirmed, false) OR coalesce(ii.verified_actor, false))::bigint AS verified_ips,
         coalesce(sum(rows.requests) FILTER (WHERE coalesce(ii.forward_confirmed, false) OR coalesce(ii.verified_actor, false)), 0)::bigint AS verified_requests
  FROM agent_ip_rows rows
  LEFT JOIN ip_intel ii ON ii.ip = rows.ip
  GROUP BY rows.agent_key
)
SELECT t.sample,
       coalesce(d.family, ''),
       coalesce(d.browser_family, ''),
       coalesce(d.browser_version, ''),
       coalesce(d.os_family, ''),
       coalesce(d.os_version, ''),
       coalesce(d.device_family, ''),
       coalesce(d.actor_type, ''),
       coalesce(d.known_actor, ''),
       coalesce(d.is_bot, false),
       coalesce(d.is_tool, false),
       coalesce(d.risk_score, 0),
       t.requests,
       coalesce(s.unique_ips, 0)::bigint,
       t.status_4xx,
       t.status_5xx,
       coalesce(s.verified_ips, 0)::bigint,
       coalesce(s.verified_requests, 0)::bigint,
       t.first_seen_at,
       t.last_seen_at
FROM top_agents t
LEFT JOIN dim_user_agents d ON d.id = t.user_agent_id
LEFT JOIN agent_ip_stats s ON s.agent_key = t.agent_key
ORDER BY t.requests DESC`, report.Since, report.Until, report.SiteID, limit, fullStart, fullEnd)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item UserAgentSummary
		if err := rows.Scan(
			&item.Sample,
			&item.Family,
			&item.BrowserFamily,
			&item.BrowserVersion,
			&item.OSFamily,
			&item.OSVersion,
			&item.DeviceFamily,
			&item.ActorType,
			&item.KnownActor,
			&item.IsBot,
			&item.IsTool,
			&item.RiskScore,
			&item.Requests,
			&item.UniqueIPs,
			&item.Status4xx,
			&item.Status5xx,
			&item.VerifiedIPs,
			&item.VerifiedRequests,
			&item.FirstSeen,
			&item.LastSeen,
		); err != nil {
			return err
		}
		applyUserAgentAnalysis(&item)
		item.VerifiedSource = item.VerifiedIPs > 0 && item.VerifiedRequests > 0
		item.Status4xxRate = ratio(item.Status4xx, item.Requests)
		item.Status5xxRate = ratio(item.Status5xx, item.Requests)
		report.UserAgents = append(report.UserAgents, item)
	}
	return rows.Err()
}

func applyUserAgentAnalysis(item *UserAgentSummary) {
	analysis := useragent.Analyze(item.Sample, item.Requests)
	if item.Family == "" || isGenericUserAgentFamily(item.Family, item.ActorType) {
		if item.BrowserFamily != "" {
			item.Family = item.BrowserFamily
		} else {
			item.Family = analysis.Family
		}
	}
	if item.ActorType == "" {
		item.ActorType = analysis.ActorType
	}
	if item.KnownActor == "" {
		item.KnownActor = analysis.KnownActor
	}
	if item.BrowserFamily == "" {
		item.BrowserFamily = analysis.BrowserFamily
	}
	if item.BrowserVersion == "" {
		item.BrowserVersion = analysis.BrowserVersion
	}
	if item.OSFamily == "" {
		item.OSFamily = analysis.OSFamily
	}
	if item.OSVersion == "" {
		item.OSVersion = analysis.OSVersion
	}
	if item.DeviceFamily == "" {
		item.DeviceFamily = analysis.DeviceFamily
	}
	item.IsBot = item.IsBot || analysis.IsBot
	item.IsTool = item.IsTool || analysis.IsTool
	if item.RiskScore <= 0 {
		item.RiskScore = analysis.RiskScore
	}
}

func isGenericUserAgentFamily(family string, actorType string) bool {
	switch strings.ToLower(strings.TrimSpace(family)) {
	case "", "unknown", "browser", "tool", "crawler", "bot":
		return true
	}
	normalizedActor := strings.ToLower(strings.TrimSpace(actorType))
	return normalizedActor != "" && strings.EqualFold(strings.TrimSpace(family), normalizedActor)
}

func (s *Service) loadSlowPaths(ctx context.Context, report *Report, limit int, rollupsReady bool) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	if rollupsReady {
		return loadSlowPathsFromRollups(ctx, pool, report, limit)
	}
	rows, err := pool.Query(ctx, `
SELECT site_id,
       env,
       coalesce(path, ''),
       count(*)::bigint,
       coalesce(avg(request_time_ms), 0)::float8,
       coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY request_time_ms), 0)::float8,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint,
       min(ts),
       max(ts)
FROM access_events
WHERE ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3) AND request_time_ms IS NOT NULL
GROUP BY site_id, env, path
HAVING count(*) >= 20
ORDER BY percentile_cont(0.95) WITHIN GROUP (ORDER BY request_time_ms) DESC, count(*) DESC
LIMIT $4`, report.Since, report.Until, report.SiteID, limit)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item SlowPathSummary
		if err := rows.Scan(
			&item.SiteID,
			&item.Env,
			&item.Path,
			&item.Requests,
			&item.AvgRequestTimeMS,
			&item.P95RequestTimeMS,
			&item.Status5xx,
			&item.FirstSeen,
			&item.LastSeen,
		); err != nil {
			return err
		}
		report.SlowPaths = append(report.SlowPaths, item)
	}
	return rows.Err()
}

func loadSlowPathsFromRollups(ctx context.Context, pool *pgxpool.Pool, report *Report, limit int) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(report.Since, report.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT r.site_id,
         r.env,
         d.path,
         r.bucket_le_ms,
         sum(r.requests)::bigint AS requests,
         sum(r.status_5xx)::bigint AS status_5xx,
         sum(r.request_time_sum_ms)::bigint AS request_time_sum_ms,
         min(r.first_seen_at) AS first_seen_at,
         max(r.last_seen_at) AS last_seen_at
  FROM rollup_path_latency_1h r
  JOIN dim_paths d ON d.id = r.path_id
  WHERE r.bucket_ts >= $4 AND r.bucket_ts < $5
    AND ($3 = '' OR r.site_id = $3)
  GROUP BY r.site_id, r.env, d.path, r.bucket_le_ms
),
edge_rows AS (
  SELECT e.site_id,
         e.env,
         coalesce(d.path, e.path, '') AS path,
         CASE
           WHEN e.request_time_ms <= 50 THEN 50
           WHEN e.request_time_ms <= 100 THEN 100
           WHEN e.request_time_ms <= 200 THEN 200
           WHEN e.request_time_ms <= 300 THEN 300
           WHEN e.request_time_ms <= 500 THEN 500
           WHEN e.request_time_ms <= 750 THEN 750
           WHEN e.request_time_ms <= 1000 THEN 1000
           WHEN e.request_time_ms <= 1500 THEN 1500
           WHEN e.request_time_ms <= 2000 THEN 2000
           WHEN e.request_time_ms <= 3000 THEN 3000
           WHEN e.request_time_ms <= 5000 THEN 5000
           WHEN e.request_time_ms <= 10000 THEN 10000
           WHEN e.request_time_ms <= 30000 THEN 30000
           WHEN e.request_time_ms <= 60000 THEN 60000
           ELSE 2147483647
         END AS bucket_le_ms,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE e.status >= 500 AND e.status < 600)::bigint AS status_5xx,
         coalesce(sum(e.request_time_ms), 0)::bigint AS request_time_sum_ms,
         min(e.ts) AS first_seen_at,
         max(e.ts) AS last_seen_at
  FROM access_events e
  LEFT JOIN dim_paths d ON d.path_hash = e.path_hash
  WHERE e.ts >= $1 AND e.ts < $2
    AND ($3 = '' OR e.site_id = $3)
    AND e.request_time_ms IS NOT NULL
    AND (e.ts < $4 OR e.ts >= $5)
  GROUP BY e.site_id, e.env, coalesce(d.path, e.path, ''), bucket_le_ms
),
hist AS (
  SELECT site_id,
         env,
         path,
         bucket_le_ms,
         sum(requests)::bigint AS requests,
         sum(status_5xx)::bigint AS status_5xx,
         sum(request_time_sum_ms)::bigint AS request_time_sum_ms,
         min(first_seen_at) AS first_seen_at,
         max(last_seen_at) AS last_seen_at
  FROM (
    SELECT * FROM rollup_rows
    UNION ALL
    SELECT * FROM edge_rows
  ) rows
  GROUP BY site_id, env, path, bucket_le_ms
),
ranked AS (
  SELECT site_id,
         env,
         path,
         bucket_le_ms,
         requests,
         status_5xx,
         request_time_sum_ms,
         first_seen_at,
         last_seen_at,
         sum(requests) OVER (PARTITION BY site_id, env, path ORDER BY bucket_le_ms) AS cumulative,
         sum(requests) OVER (PARTITION BY site_id, env, path) AS total
  FROM hist
),
paths AS (
  SELECT site_id,
         env,
         path,
         sum(requests)::bigint AS requests,
         CASE WHEN sum(requests) > 0 THEN sum(request_time_sum_ms)::float8 / sum(requests) ELSE 0 END AS avg_request_time_ms,
         min(bucket_le_ms) FILTER (WHERE cumulative >= ceil(total * 0.95))::float8 AS p95_request_time_ms,
         sum(status_5xx)::bigint AS status_5xx,
         min(first_seen_at) AS first_seen_at,
         max(last_seen_at) AS last_seen_at
  FROM ranked
  GROUP BY site_id, env, path
)
SELECT site_id,
       env,
       path,
       requests,
       avg_request_time_ms,
       coalesce(p95_request_time_ms, 0),
       status_5xx,
       first_seen_at,
       last_seen_at
FROM paths
WHERE requests >= 20
ORDER BY p95_request_time_ms DESC, requests DESC
LIMIT $6`, report.Since, report.Until, report.SiteID, fullStart, fullEnd, limit)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item SlowPathSummary
		if err := rows.Scan(
			&item.SiteID,
			&item.Env,
			&item.Path,
			&item.Requests,
			&item.AvgRequestTimeMS,
			&item.P95RequestTimeMS,
			&item.Status5xx,
			&item.FirstSeen,
			&item.LastSeen,
		); err != nil {
			return err
		}
		report.SlowPaths = append(report.SlowPaths, item)
	}
	return rows.Err()
}

func (s *Service) loadStatusBreakdown(ctx context.Context, report *Report, rollupsReady bool) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	if rollupsReady {
		return loadStatusBreakdownFromRollups(ctx, pool, report)
	}
	rows, err := pool.Query(ctx, `
SELECT coalesce(status, 0), count(*)::bigint
FROM access_events
WHERE ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3)
GROUP BY status
ORDER BY count(*) DESC, status
LIMIT 32`, report.Since, report.Until, report.SiteID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item StatusSummary
		if err := rows.Scan(&item.Status, &item.Requests); err != nil {
			return err
		}
		report.StatusBreakdown = append(report.StatusBreakdown, item)
	}
	return rows.Err()
}

func loadStatusBreakdownFromRollups(ctx context.Context, pool *pgxpool.Pool, report *Report) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(report.Since, report.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT status, sum(requests)::bigint AS requests
  FROM rollup_status_1h
  WHERE bucket_ts >= $4 AND bucket_ts < $5
    AND ($3 = '' OR site_id = $3)
  GROUP BY status
),
edge_rows AS (
  SELECT coalesce(status, 0) AS status, count(*)::bigint AS requests
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND (ts < $4 OR ts >= $5)
  GROUP BY coalesce(status, 0)
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
)
SELECT status, sum(requests)::bigint
FROM combined
GROUP BY status
ORDER BY sum(requests) DESC, status
LIMIT 32`, report.Since, report.Until, report.SiteID, fullStart, fullEnd)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var item StatusSummary
		if err := rows.Scan(&item.Status, &item.Requests); err != nil {
			return err
		}
		report.StatusBreakdown = append(report.StatusBreakdown, item)
	}
	return rows.Err()
}

func (s *Service) detectIssues(ctx context.Context, report *Report, limit int, rollupsReady bool) error {
	report.Issues = append(report.Issues, siteIssues(report.Sites)...)
	report.Issues = append(report.Issues, sourceIPIssues(report.SourceIPs)...)
	report.Issues = append(report.Issues, userAgentIssues(report.UserAgents)...)
	report.Issues = append(report.Issues, slowPathIssues(report.SlowPaths)...)
	report.Issues = append(report.Issues, adminProbeIssues(report.AdminProbes)...)
	report.Issues = append(report.Issues, injectionProbeIssues(report.InjectionProbes)...)
	report.Issues = append(report.Issues, torSourceIssues(report.TorSources)...)

	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	if rollupsReady {
		return detectPathHotspotsFromRollups(ctx, pool, report, limit)
	}

	rows, err := pool.Query(ctx, `
SELECT site_id,
       env,
       coalesce(path, ''),
       count(*)::bigint,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint,
       min(ts),
       max(ts)
FROM access_events
WHERE ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3)
GROUP BY site_id, env, path
HAVING count(*) >= 30
ORDER BY count(*) DESC
LIMIT $4`, report.Since, report.Until, report.SiteID, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var siteID, env, path string
		var requests, status5xx int64
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&siteID, &env, &path, &requests, &status5xx, &firstSeen, &lastSeen); err != nil {
			return err
		}
		rate := ratio(status5xx, requests)
		if status5xx >= 5 && rate >= 0.20 {
			score := clamp(int(rate*80)+int(min(status5xx/5, 20)), 30, 95)
			report.Issues = append(report.Issues, Issue{
				RuleKey:    "path_5xx_hotspot",
				Severity:   severityFor(score),
				Title:      "Path 5xx hotspot",
				Summary:    fmt.Sprintf("%s returned %d server errors across %d requests", path, status5xx, requests),
				SiteID:     siteID,
				Env:        env,
				ActorType:  "path",
				ActorValue: path,
				Score:      score,
				Requests:   requests,
				Events:     status5xx,
				Rate:       rate,
				FirstSeen:  firstSeen,
				LastSeen:   lastSeen,
			})
		}
	}
	return rows.Err()
}

func detectPathHotspotsFromRollups(ctx context.Context, pool *pgxpool.Pool, report *Report, limit int) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(report.Since, report.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT r.site_id,
         r.env,
         d.path,
         sum(r.requests)::bigint AS requests,
         sum(r.status_5xx)::bigint AS status_5xx,
         min(r.first_seen_at) AS first_seen_at,
         max(r.last_seen_at) AS last_seen_at
  FROM rollup_path_1h r
  JOIN dim_paths d ON d.id = r.path_id
  WHERE r.bucket_ts >= $4 AND r.bucket_ts < $5
    AND ($3 = '' OR r.site_id = $3)
  GROUP BY r.site_id, r.env, d.path
),
edge_rows AS (
  SELECT site_id,
         env,
         coalesce(path, '') AS path,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND ($3 = '' OR site_id = $3)
    AND (ts < $4 OR ts >= $5)
  GROUP BY site_id, env, coalesce(path, '')
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
),
grouped AS (
  SELECT site_id,
         env,
         path,
         sum(requests)::bigint AS requests,
         sum(status_5xx)::bigint AS status_5xx,
         min(first_seen_at) AS first_seen_at,
         max(last_seen_at) AS last_seen_at
  FROM combined
  GROUP BY site_id, env, path
)
SELECT site_id, env, path, requests, status_5xx, first_seen_at, last_seen_at
FROM grouped
WHERE requests >= 30
ORDER BY requests DESC
LIMIT $6`, report.Since, report.Until, report.SiteID, fullStart, fullEnd, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var siteID, env, path string
		var requests, status5xx int64
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&siteID, &env, &path, &requests, &status5xx, &firstSeen, &lastSeen); err != nil {
			return err
		}
		rate := ratio(status5xx, requests)
		if status5xx >= 5 && rate >= 0.20 {
			score := clamp(int(rate*80)+int(min(status5xx/5, 20)), 30, 95)
			report.Issues = append(report.Issues, Issue{
				RuleKey:    "path_5xx_hotspot",
				Severity:   severityFor(score),
				Title:      "Path 5xx hotspot",
				Summary:    fmt.Sprintf("%s returned %d server errors across %d requests", path, status5xx, requests),
				SiteID:     siteID,
				Env:        env,
				ActorType:  "path",
				ActorValue: path,
				Score:      score,
				Requests:   requests,
				Events:     status5xx,
				Rate:       rate,
				FirstSeen:  firstSeen,
				LastSeen:   lastSeen,
			})
		}
	}
	return rows.Err()
}

func siteIssues(sites []SiteSummary) []Issue {
	issues := []Issue{}
	for _, site := range sites {
		if site.Status5xx >= 10 && site.Status5xxRate >= 0.02 {
			score := clamp(int(site.Status5xxRate*100)+int(min(site.Status5xx/10, 35)), 35, 100)
			issues = append(issues, Issue{
				RuleKey:   "site_5xx_rate",
				Severity:  severityFor(score),
				Title:     "Elevated site 5xx rate",
				Summary:   fmt.Sprintf("%s/%s has %.2f%% 5xx responses", site.SiteID, site.Env, site.Status5xxRate*100),
				SiteID:    site.SiteID,
				Env:       site.Env,
				Score:     score,
				Requests:  site.Requests,
				Events:    site.Status5xx,
				Rate:      site.Status5xxRate,
				FirstSeen: site.FirstSeen,
				LastSeen:  site.LastSeen,
			})
		}
		if site.P95RequestTimeMS >= 3000 && site.Requests >= 100 {
			score := clamp(int(site.P95RequestTimeMS/100)+20, 30, 90)
			issues = append(issues, Issue{
				RuleKey:   "site_slow_p95",
				Severity:  severityFor(score),
				Title:     "Slow site response p95",
				Summary:   fmt.Sprintf("%s/%s has %.0fms p95 request time", site.SiteID, site.Env, site.P95RequestTimeMS),
				SiteID:    site.SiteID,
				Env:       site.Env,
				Score:     score,
				Requests:  site.Requests,
				Events:    site.Requests,
				Rate:      site.P95RequestTimeMS,
				FirstSeen: site.FirstSeen,
				LastSeen:  site.LastSeen,
			})
		}
	}
	return issues
}

func sourceIPIssues(ips []SourceIPSummary) []Issue {
	issues := []Issue{}
	for _, ip := range ips {
		if ip.Requests >= 50 && ip.Status5xx >= 10 && ratio(ip.Status5xx, ip.Requests) >= 0.10 {
			rate := ratio(ip.Status5xx, ip.Requests)
			score := clamp(int(rate*70)+int(min(ip.Status5xx/10, 30)), 35, 100)
			issues = append(issues, Issue{
				RuleKey:    "ip_5xx_burst",
				Severity:   severityFor(score),
				Title:      "High 5xx rate from source IP",
				Summary:    fmt.Sprintf("%s generated %d server errors across %d requests", ip.IP, ip.Status5xx, ip.Requests),
				ActorType:  "ip",
				ActorValue: ip.IP,
				Score:      score,
				Requests:   ip.Requests,
				Events:     ip.Status5xx,
				Rate:       rate,
				FirstSeen:  ip.FirstSeen,
				LastSeen:   ip.LastSeen,
				Evidence: map[string]any{
					"reverse_dns":     ip.ReverseDNS,
					"known_actor":     ip.KnownActor,
					"verified_source": ip.VerifiedSource,
				},
			})
		}
		if ip.Status4xx >= 100 && ratio(ip.Status4xx, ip.Requests) >= 0.50 {
			rate := ratio(ip.Status4xx, ip.Requests)
			score := clamp(int(rate*60)+int(min(ip.Status4xx/50, 30)), 25, 90)
			issues = append(issues, Issue{
				RuleKey:    "ip_4xx_scan",
				Severity:   severityFor(score),
				Title:      "High 4xx volume from source IP",
				Summary:    fmt.Sprintf("%s generated %d client errors across %d requests", ip.IP, ip.Status4xx, ip.Requests),
				ActorType:  "ip",
				ActorValue: ip.IP,
				Score:      score,
				Requests:   ip.Requests,
				Events:     ip.Status4xx,
				Rate:       rate,
				FirstSeen:  ip.FirstSeen,
				LastSeen:   ip.LastSeen,
				Evidence: map[string]any{
					"reverse_dns":     ip.ReverseDNS,
					"known_actor":     ip.KnownActor,
					"verified_source": ip.VerifiedSource,
				},
			})
		}
	}
	return issues
}

func userAgentIssues(agents []UserAgentSummary) []Issue {
	issues := []Issue{}
	for _, ua := range agents {
		if ua.ActorType == "missing" && ua.Requests >= 100 {
			score := clamp(45+int(min(ua.Requests/1000, 25)), 45, 75)
			issues = append(issues, Issue{
				RuleKey:    "missing_user_agent",
				Severity:   severityFor(score),
				Title:      "High traffic with missing user agent",
				Summary:    fmt.Sprintf("%d requests had no user-agent header", ua.Requests),
				ActorType:  "user_agent",
				ActorValue: ua.Sample,
				Score:      score,
				Requests:   ua.Requests,
				Events:     ua.Requests,
				Rate:       1,
				FirstSeen:  ua.FirstSeen,
				LastSeen:   ua.LastSeen,
			})
		}
		if ua.ActorType == "tool" && ua.Requests >= 100 {
			score := clamp(ua.RiskScore+int(min(ua.Requests/1000, 20)), 40, 85)
			issues = append(issues, Issue{
				RuleKey:    "tool_user_agent_volume",
				Severity:   severityFor(score),
				Title:      "High volume from scripted user agent",
				Summary:    fmt.Sprintf("%s made %d requests", ua.Family, ua.Requests),
				ActorType:  "user_agent",
				ActorValue: ua.Sample,
				Score:      score,
				Requests:   ua.Requests,
				Events:     ua.Requests,
				Rate:       ratio(ua.Status4xx+ua.Status5xx, ua.Requests),
				FirstSeen:  ua.FirstSeen,
				LastSeen:   ua.LastSeen,
			})
		}
		if ua.ActorType == "crawler" && !ua.VerifiedSource && ua.Requests >= 1000 && ua.KnownActor != "" {
			score := clamp(45+int(min(ua.Requests/1000, 25)), 45, 80)
			issues = append(issues, Issue{
				RuleKey:    "unverified_crawler_claim",
				Severity:   severityFor(score),
				Title:      "Crawler user agent lacks verified source",
				Summary:    fmt.Sprintf("%s traffic has not been source-verified", ua.KnownActor),
				ActorType:  "user_agent",
				ActorValue: ua.Sample,
				Score:      score,
				Requests:   ua.Requests,
				Events:     ua.Requests,
				Rate:       ratio(ua.VerifiedRequests, ua.Requests),
				FirstSeen:  ua.FirstSeen,
				LastSeen:   ua.LastSeen,
			})
		}
	}
	return issues
}

func slowPathIssues(paths []SlowPathSummary) []Issue {
	issues := []Issue{}
	for _, path := range paths {
		if path.Requests < 20 || path.P95RequestTimeMS < 3000 {
			continue
		}
		score := clamp(int(path.P95RequestTimeMS/100)+20, 30, 90)
		issues = append(issues, Issue{
			RuleKey:    "path_slow_p95",
			Severity:   severityFor(score),
			Title:      "Slow path response p95",
			Summary:    fmt.Sprintf("%s has %.0fms p95 request time across %d requests", path.Path, path.P95RequestTimeMS, path.Requests),
			SiteID:     path.SiteID,
			Env:        path.Env,
			ActorType:  "path",
			ActorValue: path.Path,
			Score:      score,
			Requests:   path.Requests,
			Events:     path.Requests,
			Rate:       path.P95RequestTimeMS,
			FirstSeen:  path.FirstSeen,
			LastSeen:   path.LastSeen,
		})
	}
	return issues
}

func sortIssues(issues []Issue) {
	for i := 1; i < len(issues); i++ {
		item := issues[i]
		j := i - 1
		for j >= 0 && issueLess(item, issues[j]) {
			issues[j+1] = issues[j]
			j--
		}
		issues[j+1] = item
	}
}

func issueLess(a Issue, b Issue) bool {
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	if !a.LastSeen.Equal(b.LastSeen) {
		return a.LastSeen.After(b.LastSeen)
	}
	return a.RuleKey < b.RuleKey
}

func severityFor(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

func ratio(part int64, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) / float64(total)
}

func min(a int64, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func clamp(value int, low int, high int) int {
	return int(math.Max(float64(low), math.Min(float64(high), float64(value))))
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 25
	}
	if limit > ResultMaxLimit {
		return ResultMaxLimit
	}
	return limit
}

func resolveWindow(now time.Time, rangeValue string, from time.Time, to time.Time) (time.Time, time.Time, string, error) {
	duration, label := parseRange(rangeValue)
	since := now.Add(-duration)
	until := now
	if !from.IsZero() || !to.IsZero() {
		label = "custom"
	}
	if !from.IsZero() {
		since = from.UTC()
	}
	if !to.IsZero() {
		until = to.UTC()
	}
	if !until.After(since) {
		return since, until, label, fmt.Errorf("to must be after from")
	}
	return since, until, label, nil
}

func parseRange(value string) (time.Duration, string) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "15m":
		return 15 * time.Minute, "15m"
	case "6h":
		return 6 * time.Hour, "6h"
	case "24h", "daily", "day":
		return 24 * time.Hour, "24h"
	case "7d", "weekly", "week":
		return 7 * 24 * time.Hour, "7d"
	case "30d", "monthly", "month":
		return 30 * 24 * time.Hour, "30d"
	case "90d", "quarterly", "quarter":
		return 90 * 24 * time.Hour, "90d"
	case "365d", "annual", "yearly", "year", "1y":
		return 365 * 24 * time.Hour, "365d"
	case "1h", "":
		return time.Hour, "1h"
	default:
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed, value
		}
		return time.Hour, "1h"
	}
}
