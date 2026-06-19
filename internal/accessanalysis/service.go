package accessanalysis

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"originpulse/internal/db"
	"originpulse/internal/servicefingerprints"
)

type Options struct {
	Range  string    `json:"range"`
	Limit  int       `json:"limit"`
	SiteID string    `json:"site_id"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
}

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
	ActorType        string    `json:"actor_type"`
	KnownActor       string    `json:"known_actor,omitempty"`
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

	if err := pool.QueryRow(ctx, `
SELECT count(*)::bigint,
       count(DISTINCT client_ip)::bigint,
       count(DISTINCT user_agent_hash)::bigint,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint,
       count(*) FILTER (WHERE coalesce(user_agent, '') = '')::bigint,
       count(*) FILTER (WHERE request_time_ms >= 1000)::bigint,
       coalesce(sum(bytes_sent), 0)::bigint,
       coalesce(avg(request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::float8,
       coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::float8
FROM access_events
WHERE ts >= $1 AND ts < $2 AND ($3 = '' OR site_id = $3)`, report.Since, report.Until, report.SiteID).Scan(
		&report.Totals.Requests,
		&report.Totals.UniqueIPs,
		&report.Totals.UniqueUserAgents,
		&report.Totals.Status4xx,
		&report.Totals.Status5xx,
		&report.Totals.EmptyUserAgents,
		&report.Totals.SlowRequests,
		&report.Totals.BytesSent,
		&report.Totals.AvgRequestTimeMS,
		&report.Totals.P95RequestTimeMS,
	); err != nil {
		return report, err
	}
	report.Totals.Status4xxRate = ratio(report.Totals.Status4xx, report.Totals.Requests)
	report.Totals.Status5xxRate = ratio(report.Totals.Status5xx, report.Totals.Requests)
	report.Totals.SlowRequestsRate = ratio(report.Totals.SlowRequests, report.Totals.Requests)
	report.Totals.EmptyUserAgentPct = ratio(report.Totals.EmptyUserAgents, report.Totals.Requests)

	if err := s.loadSites(ctx, &report); err != nil {
		return report, err
	}
	if err := s.loadSourceIPs(ctx, &report, limit); err != nil {
		return report, err
	}
	if err := s.loadUserAgents(ctx, &report, limit); err != nil {
		return report, err
	}
	if err := s.loadSlowPaths(ctx, &report, limit); err != nil {
		return report, err
	}
	if err := s.loadAdminProbes(ctx, &report, limit); err != nil {
		return report, err
	}
	if err := s.loadInjectionProbes(ctx, &report, limit); err != nil {
		return report, err
	}
	if err := s.loadTorSources(ctx, &report, limit); err != nil {
		return report, err
	}
	if err := s.loadStatusBreakdown(ctx, &report); err != nil {
		return report, err
	}
	if err := s.detectIssues(ctx, &report, limit); err != nil {
		return report, err
	}
	sortIssues(report.Issues)

	return report, nil
}

func (s *Service) loadSites(ctx context.Context, report *Report) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
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

func (s *Service) loadSourceIPs(ctx context.Context, report *Report, limit int) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
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
       coalesce(ii.network, ''),
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

func (s *Service) loadUserAgents(ctx context.Context, report *Report, limit int) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	rows, err := pool.Query(ctx, `
SELECT left(coalesce(e.user_agent, ''), 300),
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
WHERE e.ts >= $1 AND e.ts < $2 AND ($3 = '' OR e.site_id = $3)
GROUP BY e.user_agent_hash, left(coalesce(e.user_agent, ''), 300)
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
		item.Family, item.ActorType, item.KnownActor, item.RiskScore = classifyUserAgent(item.Sample, item.Requests)
		item.VerifiedSource = item.VerifiedIPs > 0 && item.VerifiedRequests > 0
		item.Status4xxRate = ratio(item.Status4xx, item.Requests)
		item.Status5xxRate = ratio(item.Status5xx, item.Requests)
		report.UserAgents = append(report.UserAgents, item)
	}
	return rows.Err()
}

func (s *Service) loadSlowPaths(ctx context.Context, report *Report, limit int) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
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

func (s *Service) loadStatusBreakdown(ctx context.Context, report *Report) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
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

func (s *Service) detectIssues(ctx context.Context, report *Report, limit int) error {
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

func classifyUserAgent(value string, requests int64) (string, string, string, int) {
	ua := strings.ToLower(strings.TrimSpace(value))
	if ua == "" {
		return "empty", "missing", "", 55
	}

	if match, ok := servicefingerprints.MatchUserAgent(ua); ok {
		return match.Family, match.ActorType, match.KnownActor, match.RiskScore
	}

	switch {
	case strings.Contains(ua, "pingdom") || strings.Contains(ua, "uptime") || strings.Contains(ua, "statuscake") || strings.Contains(ua, "datadog") || strings.Contains(ua, "newrelic"):
		return "monitor", "monitor", "", 20
	case strings.Contains(ua, "curl"):
		return "curl", "tool", "", 65
	case strings.Contains(ua, "wget"):
		return "wget", "tool", "", 65
	case strings.Contains(ua, "python-requests") || strings.Contains(ua, "aiohttp"):
		return "python", "tool", "", 70
	case strings.Contains(ua, "go-http-client"):
		return "go-http-client", "tool", "", 65
	case strings.Contains(ua, "java/") || strings.Contains(ua, "okhttp") || strings.Contains(ua, "apache-httpclient"):
		return "java-client", "tool", "", 60
	case strings.Contains(ua, "mozilla/") && (strings.Contains(ua, "chrome/") || strings.Contains(ua, "safari/") || strings.Contains(ua, "firefox/") || strings.Contains(ua, "edg/")):
		return "browser", "browser", "", 15
	case strings.Contains(ua, "bot") || strings.Contains(ua, "spider") || strings.Contains(ua, "crawler"):
		return "generic-crawler", "crawler", "", 50
	default:
		if requests >= 10000 {
			return "unknown-high-volume", "unknown", "", 60
		}
		if requests >= 1000 {
			return "unknown-volume", "unknown", "", 45
		}
		return "unknown", "unknown", "", 30
	}
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
	if limit > 250 {
		return 250
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
