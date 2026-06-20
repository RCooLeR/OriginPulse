package ipintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"originpulse/internal/servicefingerprints"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/rollups"
)

var (
	ErrInvalidIP           = errors.New("invalid IP address")
	ErrDatabaseDisabled    = errors.New("database is disabled")
	ErrInvalidManualAction = errors.New("invalid manual IP intel action")
)

const DetailMaxLimit = 500

type DetailOptions struct {
	IP     string
	Range  string
	Limit  int
	SiteID string
	From   time.Time
	To     time.Time
}

type ManualIntelOptions struct {
	IP           string
	ManualLabel  string
	ManualAction string
}

type Detail struct {
	IP               string            `json:"ip"`
	Range            string            `json:"range"`
	SiteID           string            `json:"site_id,omitempty"`
	Since            time.Time         `json:"since"`
	Until            time.Time         `json:"until"`
	GeneratedAt      time.Time         `json:"generated_at"`
	DatabaseEnabled  bool              `json:"database_enabled"`
	Traffic          TrafficSummary    `json:"traffic"`
	Sites            []DetailSite      `json:"sites"`
	TopPaths         []DetailPath      `json:"top_paths"`
	URLHits          []DetailURLHit    `json:"url_hits"`
	RecentRequests   []DetailRequest   `json:"recent_requests"`
	TopUserAgents    []DetailUserAgent `json:"top_user_agents"`
	StoredIntel      StoredIntel       `json:"stored_intel"`
	DNS              DNSDetails        `json:"dns"`
	GeoIP            GeoIPDetails      `json:"geoip,omitempty"`
	ASN              ASNDetails        `json:"asn"`
	RDAP             RDAPDetails       `json:"rdap"`
	LookupErrors     []string          `json:"lookup_errors,omitempty"`
	DatabaseSource   map[string]any    `json:"database_source,omitempty"`
	ExternalProvider string            `json:"external_provider,omitempty"`
}

type TrafficSummary struct {
	Requests         int64     `json:"requests"`
	UniquePaths      int64     `json:"unique_paths"`
	UniqueUserAgents int64     `json:"unique_user_agents"`
	Status4xx        int64     `json:"status_4xx"`
	Status5xx        int64     `json:"status_5xx"`
	BytesSent        int64     `json:"bytes_sent"`
	AvgRequestTimeMS float64   `json:"avg_request_time_ms"`
	P95RequestTimeMS float64   `json:"p95_request_time_ms"`
	FirstSeen        time.Time `json:"first_seen,omitempty"`
	LastSeen         time.Time `json:"last_seen,omitempty"`
}

type DetailSite struct {
	SiteID    string    `json:"site_id"`
	Env       string    `json:"env"`
	Requests  int64     `json:"requests"`
	Status4xx int64     `json:"status_4xx"`
	Status5xx int64     `json:"status_5xx"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type DetailPath struct {
	Path      string `json:"path"`
	Requests  int64  `json:"requests"`
	Status4xx int64  `json:"status_4xx"`
	Status5xx int64  `json:"status_5xx"`
	BytesSent int64  `json:"bytes_sent"`
}

type DetailURLHit struct {
	SiteID           string    `json:"site_id"`
	Env              string    `json:"env"`
	Method           string    `json:"method"`
	Scheme           string    `json:"scheme,omitempty"`
	Host             string    `json:"host,omitempty"`
	Path             string    `json:"path"`
	Query            string    `json:"query,omitempty"`
	Requests         int64     `json:"requests"`
	Status2xx        int64     `json:"status_2xx"`
	Status3xx        int64     `json:"status_3xx"`
	Status4xx        int64     `json:"status_4xx"`
	Status5xx        int64     `json:"status_5xx"`
	BytesSent        int64     `json:"bytes_sent"`
	AvgRequestTimeMS float64   `json:"avg_request_time_ms"`
	P95RequestTimeMS float64   `json:"p95_request_time_ms"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
}

type DetailRequest struct {
	Timestamp     time.Time `json:"ts"`
	SiteID        string    `json:"site_id"`
	Env           string    `json:"env"`
	Method        string    `json:"method"`
	Scheme        string    `json:"scheme,omitempty"`
	Host          string    `json:"host,omitempty"`
	Path          string    `json:"path"`
	Query         string    `json:"query,omitempty"`
	Status        int       `json:"status"`
	BytesSent     int64     `json:"bytes_sent"`
	Referer       string    `json:"referer,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	RequestTimeMS *int      `json:"request_time_ms,omitempty"`
}

type DetailUserAgent struct {
	Sample    string `json:"sample"`
	Requests  int64  `json:"requests"`
	Status4xx int64  `json:"status_4xx"`
	Status5xx int64  `json:"status_5xx"`
}

type StoredIntel struct {
	ASN              int64     `json:"asn,omitempty"`
	ASNOrg           string    `json:"asn_org,omitempty"`
	Network          string    `json:"network,omitempty"`
	CountryCode      string    `json:"country_code,omitempty"`
	ReverseDNS       string    `json:"reverse_dns,omitempty"`
	ForwardConfirmed bool      `json:"forward_confirmed"`
	KnownActor       string    `json:"known_actor,omitempty"`
	ActorType        string    `json:"actor_type,omitempty"`
	VerifiedActor    bool      `json:"verified_actor"`
	IsTorExit        bool      `json:"is_tor_exit"`
	IsDatacenter     bool      `json:"is_datacenter"`
	ManualLabel      string    `json:"manual_label,omitempty"`
	ManualAction     string    `json:"manual_action,omitempty"`
	RiskScore        int       `json:"risk_score,omitempty"`
	RefreshedAt      time.Time `json:"refreshed_at,omitempty"`
}

type GeoIPDetails struct {
	Loaded      bool    `json:"loaded"`
	CountryCode string  `json:"country_code,omitempty"`
	CountryName string  `json:"country_name,omitempty"`
	CityName    string  `json:"city_name,omitempty"`
	TimeZone    string  `json:"time_zone,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	Error       string  `json:"error,omitempty"`
}

func (s *Service) ApplyManualIntel(ctx context.Context, opts ManualIntelOptions) error {
	addr, err := netip.ParseAddr(strings.TrimSpace(opts.IP))
	if err != nil {
		return ErrInvalidIP
	}
	if !s.Enabled() {
		return ErrDatabaseDisabled
	}
	action, err := normalizeManualAction(opts.ManualAction)
	if err != nil {
		return err
	}
	label := normalizeManualLabel(opts.ManualLabel)
	if action == "" {
		label = ""
	}

	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	sourceJSON, err := json.Marshal(map[string]any{
		"manual_intel_updated_at": now,
	})
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
INSERT INTO ip_intel (ip, manual_label, manual_action, verified_actor, risk_score, source, refreshed_at)
VALUES ($1::inet, $2, $3, $4, $5, $6::jsonb, $7)
ON CONFLICT (ip) DO UPDATE SET
  manual_label = EXCLUDED.manual_label,
  manual_action = EXCLUDED.manual_action,
  verified_actor = CASE WHEN $8 = 'verified' THEN true ELSE ip_intel.verified_actor END,
  risk_score = CASE WHEN $8 = 'suspicious' THEN greatest(coalesce(ip_intel.risk_score, 0), 80) ELSE ip_intel.risk_score END,
  source = ip_intel.source || EXCLUDED.source,
  refreshed_at = coalesce(ip_intel.refreshed_at, EXCLUDED.refreshed_at)`,
		addr.String(),
		emptyToNil(label),
		emptyToNil(action),
		action == "verified",
		manualRiskScore(action),
		string(sourceJSON),
		now,
		action,
	)
	return err
}

func normalizeManualAction(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "clear":
		return "", nil
	case "verified", "suspicious", "watch", "ignored":
		return strings.ToLower(strings.TrimSpace(value)), nil
	default:
		return "", ErrInvalidManualAction
	}
}

func normalizeManualLabel(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 160 {
		return value[:160]
	}
	return value
}

func manualRiskScore(action string) any {
	if action == "suspicious" {
		return 80
	}
	return nil
}

type DNSDetails struct {
	ReverseNames       []string `json:"reverse_names,omitempty"`
	ForwardAddresses   []string `json:"forward_addresses,omitempty"`
	ForwardConfirmed   bool     `json:"forward_confirmed"`
	ReverseLookupError string   `json:"reverse_lookup_error,omitempty"`
	ForwardLookupError string   `json:"forward_lookup_error,omitempty"`
}

type ASNDetails struct {
	ASN         int64  `json:"asn,omitempty"`
	Prefix      string `json:"prefix,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Registry    string `json:"registry,omitempty"`
	Allocated   string `json:"allocated,omitempty"`
	Name        string `json:"name,omitempty"`
	Source      string `json:"source,omitempty"`
	Error       string `json:"error,omitempty"`
}

type RDAPDetails struct {
	Provider     string       `json:"provider,omitempty"`
	Handle       string       `json:"handle,omitempty"`
	Name         string       `json:"name,omitempty"`
	Type         string       `json:"type,omitempty"`
	CountryCode  string       `json:"country_code,omitempty"`
	StartAddress string       `json:"start_address,omitempty"`
	EndAddress   string       `json:"end_address,omitempty"`
	IPVersion    string       `json:"ip_version,omitempty"`
	CIDRs        []string     `json:"cidrs,omitempty"`
	Registration string       `json:"registration,omitempty"`
	LastChanged  string       `json:"last_changed,omitempty"`
	Entities     []RDAPEntity `json:"entities,omitempty"`
	Links        []RDAPLink   `json:"links,omitempty"`
	Error        string       `json:"error,omitempty"`
}

type RDAPEntity struct {
	Handle string   `json:"handle,omitempty"`
	Name   string   `json:"name,omitempty"`
	Roles  []string `json:"roles,omitempty"`
}

type RDAPLink struct {
	Rel  string `json:"rel,omitempty"`
	Href string `json:"href,omitempty"`
}

type rdapResponse struct {
	ObjectClassName string `json:"objectClassName"`
	Handle          string `json:"handle"`
	StartAddress    string `json:"startAddress"`
	EndAddress      string `json:"endAddress"`
	IPVersion       string `json:"ipVersion"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	Country         string `json:"country"`
	CIDRs           []struct {
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Handle     string   `json:"handle"`
		Roles      []string `json:"roles"`
		VCardArray any      `json:"vcardArray"`
	} `json:"entities"`
	Links []struct {
		Rel  string `json:"rel"`
		Href string `json:"href"`
	} `json:"links"`
}

func (s *Service) Details(ctx context.Context, opts DetailOptions) (Detail, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(opts.IP))
	if err != nil {
		return Detail{}, ErrInvalidIP
	}

	limit := normalizeDetailLimit(opts.Limit)
	now := time.Now().UTC()
	since, until, label, err := resolveDetailWindow(now, opts.Range, opts.From, opts.To)
	out := Detail{
		IP:               addr.String(),
		Range:            label,
		SiteID:           strings.TrimSpace(opts.SiteID),
		Since:            since,
		Until:            until,
		GeneratedAt:      now,
		DatabaseEnabled:  s.Enabled(),
		Sites:            []DetailSite{},
		TopPaths:         []DetailPath{},
		URLHits:          []DetailURLHit{},
		RecentRequests:   []DetailRequest{},
		TopUserAgents:    []DetailUserAgent{},
		ExternalProvider: "GeoLite2 City + Team Cymru DNS + RDAP bootstrap",
	}
	if err != nil {
		return out, err
	}

	out.GeoIP = s.geoIPDetails(out.IP)
	if out.GeoIP.Error != "" && out.GeoIP.Loaded {
		out.LookupErrors = append(out.LookupErrors, out.GeoIP.Error)
	}

	out.DNS = lookupDNSDetails(ctx, out.IP)
	if out.DNS.ReverseLookupError != "" {
		out.LookupErrors = append(out.LookupErrors, out.DNS.ReverseLookupError)
	}
	if out.DNS.ForwardLookupError != "" {
		out.LookupErrors = append(out.LookupErrors, out.DNS.ForwardLookupError)
	}

	out.ASN = lookupASNDetails(ctx, addr)
	if out.ASN.Error != "" {
		out.LookupErrors = append(out.LookupErrors, out.ASN.Error)
	}

	out.RDAP = lookupRDAPDetails(ctx, out.IP)
	if out.RDAP.Error != "" {
		out.LookupErrors = append(out.LookupErrors, out.RDAP.Error)
	}

	if s.Enabled() {
		if err := s.loadStoredIntel(ctx, &out); err != nil {
			return out, err
		}
		applyExternalServiceFingerprint(&out)
		if err := s.loadDetailTraffic(ctx, &out, limit); err != nil {
			return out, err
		}
		if err := s.cacheExternalIntel(ctx, out); err != nil {
			return out, err
		}
	}

	return out, nil
}

func (s *Service) loadStoredIntel(ctx context.Context, out *Detail) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}

	var sourceText string
	var refreshedAt time.Time
	err = pool.QueryRow(ctx, `
SELECT coalesce(asn, 0),
       coalesce(asn_org, ''),
       coalesce(network::text, ''),
       coalesce(country_code, ''),
       coalesce(reverse_dns, ''),
       coalesce(forward_confirmed, false),
       coalesce(known_actor, ''),
       coalesce(actor_type, ''),
       coalesce(verified_actor, false),
       coalesce(is_tor_exit, false),
       coalesce(is_datacenter, false),
       coalesce(manual_label, ''),
       coalesce(manual_action, ''),
       coalesce(risk_score, 0),
       coalesce(source, '{}'::jsonb)::text,
       coalesce(refreshed_at, '0001-01-01T00:00:00Z'::timestamptz)
FROM ip_intel
WHERE ip = $1::inet`, out.IP).Scan(
		&out.StoredIntel.ASN,
		&out.StoredIntel.ASNOrg,
		&out.StoredIntel.Network,
		&out.StoredIntel.CountryCode,
		&out.StoredIntel.ReverseDNS,
		&out.StoredIntel.ForwardConfirmed,
		&out.StoredIntel.KnownActor,
		&out.StoredIntel.ActorType,
		&out.StoredIntel.VerifiedActor,
		&out.StoredIntel.IsTorExit,
		&out.StoredIntel.IsDatacenter,
		&out.StoredIntel.ManualLabel,
		&out.StoredIntel.ManualAction,
		&out.StoredIntel.RiskScore,
		&sourceText,
		&refreshedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !refreshedAt.IsZero() && refreshedAt.Year() > 1 {
		out.StoredIntel.RefreshedAt = refreshedAt
	}
	if sourceText != "" {
		_ = json.Unmarshal([]byte(sourceText), &out.DatabaseSource)
	}
	return nil
}

func (s *Service) loadDetailTraffic(ctx context.Context, out *Detail, limit int) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}

	rollupsReady, err := rollups.DimensionRollupsReady(ctx, pool, out.Since, out.Until, out.SiteID)
	if err != nil {
		return err
	}
	if rollupsReady {
		if err := loadDetailTrafficSummaryFromRollups(ctx, pool, out); err != nil {
			return err
		}
		if err := loadDetailSitesFromRollups(ctx, pool, out, limit); err != nil {
			return err
		}
	} else {
		if err := loadDetailTrafficSummaryFromRaw(ctx, pool, out); err != nil {
			return err
		}
		if err := loadDetailSitesFromRaw(ctx, pool, out, limit); err != nil {
			return err
		}
	}

	if rollupsReady {
		if err := loadDetailTopPathsFromRollups(ctx, pool, out, limit); err != nil {
			return err
		}
	} else {
		if err := loadDetailTopPathsFromRaw(ctx, pool, out, limit); err != nil {
			return err
		}
	}

	urlRows, err := pool.Query(ctx, `
SELECT site_id,
       env,
       coalesce(method, ''),
       coalesce(scheme, ''),
       coalesce(host, ''),
       coalesce(path, ''),
       left(coalesce(query, ''), 500),
       count(*)::bigint,
       count(*) FILTER (WHERE status >= 200 AND status < 300)::bigint,
       count(*) FILTER (WHERE status >= 300 AND status < 400)::bigint,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint,
       coalesce(sum(bytes_sent), 0)::bigint,
       coalesce(avg(request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::float8,
       coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::float8,
       min(ts),
       max(ts)
FROM access_events
WHERE client_ip = $1::inet AND ts >= $2 AND ts < $3 AND ($4 = '' OR site_id = $4)
GROUP BY site_id, env, method, scheme, host, path, query
ORDER BY count(*) DESC, max(ts) DESC
LIMIT $5`, out.IP, out.Since, out.Until, out.SiteID, limit)
	if err != nil {
		return err
	}
	defer urlRows.Close()
	for urlRows.Next() {
		var item DetailURLHit
		if err := urlRows.Scan(
			&item.SiteID,
			&item.Env,
			&item.Method,
			&item.Scheme,
			&item.Host,
			&item.Path,
			&item.Query,
			&item.Requests,
			&item.Status2xx,
			&item.Status3xx,
			&item.Status4xx,
			&item.Status5xx,
			&item.BytesSent,
			&item.AvgRequestTimeMS,
			&item.P95RequestTimeMS,
			&item.FirstSeen,
			&item.LastSeen,
		); err != nil {
			return err
		}
		out.URLHits = append(out.URLHits, item)
	}
	if err := urlRows.Err(); err != nil {
		return err
	}

	requestRows, err := pool.Query(ctx, `
SELECT ts,
       site_id,
       env,
       coalesce(method, ''),
       coalesce(scheme, ''),
       coalesce(host, ''),
       coalesce(path, ''),
       left(coalesce(query, ''), 500),
       coalesce(status, 0),
       coalesce(bytes_sent, 0)::bigint,
       coalesce(referer, ''),
       left(coalesce(user_agent, ''), 300),
       coalesce(request_time_ms, -1)
FROM access_events
WHERE client_ip = $1::inet AND ts >= $2 AND ts < $3 AND ($4 = '' OR site_id = $4)
ORDER BY ts DESC
LIMIT $5`, out.IP, out.Since, out.Until, out.SiteID, limit)
	if err != nil {
		return err
	}
	defer requestRows.Close()
	for requestRows.Next() {
		var item DetailRequest
		var requestTimeMS int
		if err := requestRows.Scan(
			&item.Timestamp,
			&item.SiteID,
			&item.Env,
			&item.Method,
			&item.Scheme,
			&item.Host,
			&item.Path,
			&item.Query,
			&item.Status,
			&item.BytesSent,
			&item.Referer,
			&item.UserAgent,
			&requestTimeMS,
		); err != nil {
			return err
		}
		if requestTimeMS >= 0 {
			item.RequestTimeMS = &requestTimeMS
		}
		out.RecentRequests = append(out.RecentRequests, item)
	}
	if err := requestRows.Err(); err != nil {
		return err
	}

	if rollupsReady {
		return loadDetailTopUserAgentsFromRollups(ctx, pool, out, limit)
	}
	return loadDetailTopUserAgentsFromRaw(ctx, pool, out, limit)
}

func loadDetailTrafficSummaryFromRaw(ctx context.Context, pool *pgxpool.Pool, out *Detail) error {
	if err := pool.QueryRow(ctx, `
SELECT count(*)::bigint,
       count(DISTINCT path_hash)::bigint,
       count(DISTINCT user_agent_hash)::bigint,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint,
       coalesce(sum(bytes_sent), 0)::bigint,
       coalesce(avg(request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::float8,
       coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::float8,
       coalesce(min(ts), '0001-01-01T00:00:00Z'::timestamptz),
       coalesce(max(ts), '0001-01-01T00:00:00Z'::timestamptz)
FROM access_events
WHERE client_ip = $1::inet AND ts >= $2 AND ts < $3 AND ($4 = '' OR site_id = $4)`,
		out.IP, out.Since, out.Until, out.SiteID,
	).Scan(
		&out.Traffic.Requests,
		&out.Traffic.UniquePaths,
		&out.Traffic.UniqueUserAgents,
		&out.Traffic.Status4xx,
		&out.Traffic.Status5xx,
		&out.Traffic.BytesSent,
		&out.Traffic.AvgRequestTimeMS,
		&out.Traffic.P95RequestTimeMS,
		&out.Traffic.FirstSeen,
		&out.Traffic.LastSeen,
	); err != nil {
		return err
	}
	return nil
}

func loadDetailSitesFromRaw(ctx context.Context, pool *pgxpool.Pool, out *Detail, limit int) error {
	siteRows, err := pool.Query(ctx, `
SELECT site_id,
       env,
       count(*)::bigint,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint,
       min(ts),
       max(ts)
FROM access_events
WHERE client_ip = $1::inet AND ts >= $2 AND ts < $3 AND ($4 = '' OR site_id = $4)
GROUP BY site_id, env
ORDER BY count(*) DESC
LIMIT $5`, out.IP, out.Since, out.Until, out.SiteID, limit)
	if err != nil {
		return err
	}
	defer siteRows.Close()
	for siteRows.Next() {
		var item DetailSite
		if err := siteRows.Scan(&item.SiteID, &item.Env, &item.Requests, &item.Status4xx, &item.Status5xx, &item.FirstSeen, &item.LastSeen); err != nil {
			return err
		}
		out.Sites = append(out.Sites, item)
	}
	if err := siteRows.Err(); err != nil {
		return err
	}
	return nil
}

func loadDetailTrafficSummaryFromRollups(ctx context.Context, pool *pgxpool.Pool, out *Detail) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(out.Since, out.Until)
	err := pool.QueryRow(ctx, `
WITH rollup_rows AS (
  SELECT r.requests,
         r.status_4xx,
         r.status_5xx,
         r.bytes_sent,
         r.first_seen_at,
         r.last_seen_at
  FROM rollup_ip_1h r
  JOIN dim_ips d ON d.id = r.ip_id
  WHERE d.ip = $1::inet
    AND r.bucket_ts >= $5 AND r.bucket_ts < $6
    AND ($4 = '' OR r.site_id = $4)
),
edge_rows AS (
  SELECT count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
         coalesce(sum(bytes_sent), 0)::bigint AS bytes_sent,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM access_events
  WHERE client_ip = $1::inet
    AND ts >= $2 AND ts < $3
    AND ($4 = '' OR site_id = $4)
    AND (ts < $5 OR ts >= $6)
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
       coalesce(min(first_seen_at), '0001-01-01T00:00:00Z'::timestamptz),
       coalesce(max(last_seen_at), '0001-01-01T00:00:00Z'::timestamptz)
FROM combined`, out.IP, out.Since, out.Until, out.SiteID, fullStart, fullEnd).Scan(
		&out.Traffic.Requests,
		&out.Traffic.Status4xx,
		&out.Traffic.Status5xx,
		&out.Traffic.BytesSent,
		&out.Traffic.FirstSeen,
		&out.Traffic.LastSeen,
	)
	if err != nil {
		return err
	}
	return pool.QueryRow(ctx, `
SELECT count(DISTINCT path_id)::bigint,
       count(DISTINCT user_agent_id)::bigint,
       coalesce(avg(request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::float8,
       coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY request_time_ms) FILTER (WHERE request_time_ms IS NOT NULL), 0)::float8
FROM access_events
WHERE client_ip = $1::inet AND ts >= $2 AND ts < $3 AND ($4 = '' OR site_id = $4)`,
		out.IP, out.Since, out.Until, out.SiteID,
	).Scan(
		&out.Traffic.UniquePaths,
		&out.Traffic.UniqueUserAgents,
		&out.Traffic.AvgRequestTimeMS,
		&out.Traffic.P95RequestTimeMS,
	)
}

func loadDetailSitesFromRollups(ctx context.Context, pool *pgxpool.Pool, out *Detail, limit int) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(out.Since, out.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT r.site_id,
         r.env,
         sum(r.requests)::bigint AS requests,
         sum(r.status_4xx)::bigint AS status_4xx,
         sum(r.status_5xx)::bigint AS status_5xx,
         min(r.first_seen_at) AS first_seen_at,
         max(r.last_seen_at) AS last_seen_at
  FROM rollup_ip_1h r
  JOIN dim_ips d ON d.id = r.ip_id
  WHERE d.ip = $1::inet
    AND r.bucket_ts >= $5 AND r.bucket_ts < $6
    AND ($4 = '' OR r.site_id = $4)
  GROUP BY r.site_id, r.env
),
edge_rows AS (
  SELECT site_id,
         env,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
         min(ts) AS first_seen_at,
         max(ts) AS last_seen_at
  FROM access_events
  WHERE client_ip = $1::inet
    AND ts >= $2 AND ts < $3
    AND ($4 = '' OR site_id = $4)
    AND (ts < $5 OR ts >= $6)
  GROUP BY site_id, env
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
),
grouped AS (
  SELECT site_id,
         env,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx,
         min(first_seen_at) AS first_seen_at,
         max(last_seen_at) AS last_seen_at
  FROM combined
  GROUP BY site_id, env
)
SELECT site_id, env, requests, status_4xx, status_5xx, first_seen_at, last_seen_at
FROM grouped
ORDER BY requests DESC
LIMIT $7`, out.IP, out.Since, out.Until, out.SiteID, fullStart, fullEnd, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item DetailSite
		if err := rows.Scan(&item.SiteID, &item.Env, &item.Requests, &item.Status4xx, &item.Status5xx, &item.FirstSeen, &item.LastSeen); err != nil {
			return err
		}
		out.Sites = append(out.Sites, item)
	}
	return rows.Err()
}

func loadDetailTopPathsFromRaw(ctx context.Context, pool *pgxpool.Pool, out *Detail, limit int) error {
	rows, err := pool.Query(ctx, `
SELECT coalesce(path, ''),
       count(*)::bigint,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint,
       coalesce(sum(bytes_sent), 0)::bigint
FROM access_events
WHERE client_ip = $1::inet AND ts >= $2 AND ts < $3 AND ($4 = '' OR site_id = $4)
GROUP BY path
ORDER BY count(*) DESC
LIMIT $5`, out.IP, out.Since, out.Until, out.SiteID, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item DetailPath
		if err := rows.Scan(&item.Path, &item.Requests, &item.Status4xx, &item.Status5xx, &item.BytesSent); err != nil {
			return err
		}
		out.TopPaths = append(out.TopPaths, item)
	}
	return rows.Err()
}

func loadDetailTopPathsFromRollups(ctx context.Context, pool *pgxpool.Pool, out *Detail, limit int) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(out.Since, out.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT p.path,
         sum(r.requests)::bigint AS requests,
         sum(r.status_4xx)::bigint AS status_4xx,
         sum(r.status_5xx)::bigint AS status_5xx,
         sum(r.bytes_sent)::bigint AS bytes_sent
  FROM rollup_ip_path_1h r
  JOIN dim_ips d ON d.id = r.ip_id
  JOIN dim_paths p ON p.id = r.path_id
  WHERE d.ip = $1::inet
    AND r.bucket_ts >= $5 AND r.bucket_ts < $6
    AND ($4 = '' OR r.site_id = $4)
  GROUP BY p.path
),
edge_rows AS (
  SELECT coalesce(path, '') AS path,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx,
         coalesce(sum(bytes_sent), 0)::bigint AS bytes_sent
  FROM access_events
  WHERE client_ip = $1::inet
    AND ts >= $2 AND ts < $3
    AND ($4 = '' OR site_id = $4)
    AND (ts < $5 OR ts >= $6)
  GROUP BY path
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
),
grouped AS (
  SELECT path,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx,
         sum(bytes_sent)::bigint AS bytes_sent
  FROM combined
  GROUP BY path
)
SELECT path, requests, status_4xx, status_5xx, bytes_sent
FROM grouped
ORDER BY requests DESC
LIMIT $7`, out.IP, out.Since, out.Until, out.SiteID, fullStart, fullEnd, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item DetailPath
		if err := rows.Scan(&item.Path, &item.Requests, &item.Status4xx, &item.Status5xx, &item.BytesSent); err != nil {
			return err
		}
		out.TopPaths = append(out.TopPaths, item)
	}
	return rows.Err()
}

func loadDetailTopUserAgentsFromRaw(ctx context.Context, pool *pgxpool.Pool, out *Detail, limit int) error {
	rows, err := pool.Query(ctx, `
SELECT left(coalesce(user_agent, ''), 220),
       count(*)::bigint,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint
FROM access_events
WHERE client_ip = $1::inet AND ts >= $2 AND ts < $3 AND ($4 = '' OR site_id = $4)
GROUP BY user_agent_hash, left(coalesce(user_agent, ''), 220)
ORDER BY count(*) DESC
LIMIT $5`, out.IP, out.Since, out.Until, out.SiteID, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item DetailUserAgent
		if err := rows.Scan(&item.Sample, &item.Requests, &item.Status4xx, &item.Status5xx); err != nil {
			return err
		}
		out.TopUserAgents = append(out.TopUserAgents, item)
	}
	return rows.Err()
}

func loadDetailTopUserAgentsFromRollups(ctx context.Context, pool *pgxpool.Pool, out *Detail, limit int) error {
	fullStart, fullEnd, _ := rollups.FullHourRange(out.Since, out.Until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT left(coalesce(ua.user_agent, ''), 220) AS sample,
         sum(r.requests)::bigint AS requests,
         sum(r.status_4xx)::bigint AS status_4xx,
         sum(r.status_5xx)::bigint AS status_5xx
  FROM rollup_ip_user_agent_1h r
  JOIN dim_ips d ON d.id = r.ip_id
  JOIN dim_user_agents ua ON ua.id = r.user_agent_id
  WHERE d.ip = $1::inet
    AND r.bucket_ts >= $5 AND r.bucket_ts < $6
    AND ($4 = '' OR r.site_id = $4)
  GROUP BY left(coalesce(ua.user_agent, ''), 220)
),
edge_rows AS (
  SELECT left(coalesce(user_agent, ''), 220) AS sample,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx
  FROM access_events
  WHERE client_ip = $1::inet
    AND ts >= $2 AND ts < $3
    AND ($4 = '' OR site_id = $4)
    AND (ts < $5 OR ts >= $6)
  GROUP BY user_agent_hash, left(coalesce(user_agent, ''), 220)
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
),
grouped AS (
  SELECT sample,
         sum(requests)::bigint AS requests,
         sum(status_4xx)::bigint AS status_4xx,
         sum(status_5xx)::bigint AS status_5xx
  FROM combined
  GROUP BY sample
)
SELECT sample, requests, status_4xx, status_5xx
FROM grouped
ORDER BY requests DESC
LIMIT $7`, out.IP, out.Since, out.Until, out.SiteID, fullStart, fullEnd, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item DetailUserAgent
		if err := rows.Scan(&item.Sample, &item.Requests, &item.Status4xx, &item.Status5xx); err != nil {
			return err
		}
		out.TopUserAgents = append(out.TopUserAgents, item)
	}
	return rows.Err()
}

func (s *Service) cacheExternalIntel(ctx context.Context, out Detail) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}

	asn := out.ASN.ASN
	asnOrg := out.ASN.Name
	network := validCIDR(out.ASN.Prefix)
	country := firstString([]string{out.GeoIP.CountryCode, out.ASN.CountryCode})
	if network == "" {
		network = firstValidCIDR(out.RDAP.CIDRs)
	}
	if country == "" {
		country = out.RDAP.CountryCode
	}
	fingerprint, fingerprintVerified, matchedFingerprint := externalServiceFingerprint(out)
	knownActor := ""
	actorType := ""
	riskScore := 0
	var isDatacenter any
	if matchedFingerprint {
		knownActor = fingerprint.KnownActor
		actorType = fingerprint.ActorType
		riskScore = fingerprint.RiskScore
		isDatacenter = fingerprint.ActorType == "datacenter"
	}

	source := map[string]any{
		"asn": map[string]any{
			"source":       out.ASN.Source,
			"prefix":       out.ASN.Prefix,
			"registry":     out.ASN.Registry,
			"allocated":    out.ASN.Allocated,
			"lookup_error": out.ASN.Error,
		},
		"rdap": map[string]any{
			"provider":     out.RDAP.Provider,
			"handle":       out.RDAP.Handle,
			"name":         out.RDAP.Name,
			"type":         out.RDAP.Type,
			"cidrs":        out.RDAP.CIDRs,
			"entities":     out.RDAP.Entities,
			"lookup_error": out.RDAP.Error,
		},
		"dns": map[string]any{
			"reverse_names":     out.DNS.ReverseNames,
			"forward_addresses": out.DNS.ForwardAddresses,
			"forward_confirmed": out.DNS.ForwardConfirmed,
		},
		"geoip": map[string]any{
			"loaded":       out.GeoIP.Loaded,
			"country_code": out.GeoIP.CountryCode,
			"country_name": out.GeoIP.CountryName,
			"city_name":    out.GeoIP.CityName,
			"time_zone":    out.GeoIP.TimeZone,
			"latitude":     out.GeoIP.Latitude,
			"longitude":    out.GeoIP.Longitude,
			"lookup_error": out.GeoIP.Error,
		},
	}
	if matchedFingerprint {
		source["service_fingerprint"] = map[string]any{
			"id":             fingerprint.ID,
			"known_actor":    fingerprint.KnownActor,
			"actor_type":     fingerprint.ActorType,
			"risk_score":     fingerprint.RiskScore,
			"verified_actor": fingerprintVerified,
		}
	}
	sourceJSON, err := json.Marshal(source)
	if err != nil {
		return err
	}

	_, err = pool.Exec(ctx, `
INSERT INTO ip_intel (
  ip, asn, asn_org, network, country_code, reverse_dns, forward_confirmed, known_actor, actor_type, verified_actor, is_datacenter, risk_score, source, refreshed_at
) VALUES (
  $1::inet, nullif($2, 0), nullif($3, ''), nullif($4, '')::cidr, nullif($5, ''), nullif($6, ''), $7, nullif($8, ''), nullif($9, ''), $10, $11, nullif($12, 0), $13::jsonb, $14
)
ON CONFLICT (ip) DO UPDATE SET
  asn = coalesce(EXCLUDED.asn, ip_intel.asn),
  asn_org = coalesce(EXCLUDED.asn_org, ip_intel.asn_org),
  network = coalesce(EXCLUDED.network, ip_intel.network),
  country_code = coalesce(EXCLUDED.country_code, ip_intel.country_code),
  reverse_dns = coalesce(EXCLUDED.reverse_dns, ip_intel.reverse_dns),
  forward_confirmed = EXCLUDED.forward_confirmed OR ip_intel.forward_confirmed,
  known_actor = CASE WHEN ip_intel.is_tor_exit THEN ip_intel.known_actor ELSE coalesce(EXCLUDED.known_actor, ip_intel.known_actor) END,
  actor_type = CASE WHEN ip_intel.is_tor_exit THEN ip_intel.actor_type ELSE coalesce(EXCLUDED.actor_type, ip_intel.actor_type) END,
  verified_actor = EXCLUDED.verified_actor OR ip_intel.verified_actor,
  is_datacenter = coalesce(EXCLUDED.is_datacenter, ip_intel.is_datacenter),
  risk_score = CASE WHEN ip_intel.is_tor_exit THEN ip_intel.risk_score ELSE coalesce(EXCLUDED.risk_score, ip_intel.risk_score) END,
  source = ip_intel.source || EXCLUDED.source,
  refreshed_at = EXCLUDED.refreshed_at`,
		out.IP,
		asn,
		asnOrg,
		network,
		country,
		firstString(out.DNS.ReverseNames),
		out.DNS.ForwardConfirmed,
		knownActor,
		actorType,
		fingerprintVerified,
		isDatacenter,
		riskScore,
		string(sourceJSON),
		out.GeneratedAt,
	)
	return err
}

func applyExternalServiceFingerprint(out *Detail) {
	if out.StoredIntel.IsTorExit {
		return
	}
	fingerprint, verified, ok := externalServiceFingerprint(*out)
	if !ok {
		return
	}
	out.StoredIntel.KnownActor = fingerprint.KnownActor
	out.StoredIntel.ActorType = fingerprint.ActorType
	out.StoredIntel.VerifiedActor = out.StoredIntel.VerifiedActor || verified
	out.StoredIntel.IsDatacenter = fingerprint.ActorType == "datacenter"
	out.StoredIntel.RiskScore = fingerprint.RiskScore
}

func externalServiceFingerprint(out Detail) (servicefingerprints.Match, bool, bool) {
	if match, ok := servicefingerprints.MatchReverseDNS(out.DNS.ReverseNames); ok {
		return match, out.DNS.ForwardConfirmed && match.KnownActor != "", true
	}
	if match, ok := servicefingerprints.MatchASNOrg(out.ASN.Name); ok {
		return match, true, true
	}
	if match, ok := servicefingerprints.MatchASNOrg(out.RDAP.Name); ok {
		return match, true, true
	}
	return servicefingerprints.Match{}, false, false
}

func (s *Service) geoIPDetails(ip string) GeoIPDetails {
	if s == nil || s.geoIP == nil || !s.geoIP.Loaded() {
		return GeoIPDetails{Loaded: false}
	}
	result, err := s.geoIP.Lookup(ip)
	if err != nil {
		return GeoIPDetails{Loaded: true, Error: err.Error()}
	}
	return GeoIPDetails{
		Loaded:      true,
		CountryCode: result.CountryCode,
		CountryName: result.CountryName,
		CityName:    result.CityName,
		TimeZone:    result.TimeZone,
		Latitude:    result.Latitude,
		Longitude:   result.Longitude,
	}
}

func lookupDNSDetails(ctx context.Context, ip string) DNSDetails {
	var out DNSDetails
	names, reverseErr := lookupReverse(ctx, ip)
	out.ReverseNames = names
	out.ReverseLookupError = reverseErr
	out.ForwardConfirmed = forwardConfirms(ctx, names, ip)
	if len(names) == 0 {
		return out
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	seen := map[string]bool{}
	for _, name := range names {
		ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", name)
		if err != nil {
			out.ForwardLookupError = err.Error()
			continue
		}
		for _, candidate := range ips {
			value := candidate.String()
			if !seen[value] {
				seen[value] = true
				out.ForwardAddresses = append(out.ForwardAddresses, value)
			}
		}
	}
	return out
}

func lookupASNDetails(ctx context.Context, addr netip.Addr) ASNDetails {
	host, ok := cymruHost(addr)
	if !ok {
		return ASNDetails{}
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	txts, err := net.DefaultResolver.LookupTXT(lookupCtx, host)
	if err != nil {
		return ASNDetails{Source: "Team Cymru", Error: err.Error()}
	}
	for _, txt := range txts {
		fields := strings.Split(txt, "|")
		if len(fields) < 5 {
			continue
		}
		asn, _ := strconv.ParseInt(strings.TrimSpace(fields[0]), 10, 64)
		name := ""
		if len(fields) > 5 {
			name = strings.TrimSpace(fields[5])
		}
		return ASNDetails{
			ASN:         asn,
			Prefix:      strings.TrimSpace(fields[1]),
			CountryCode: strings.TrimSpace(fields[2]),
			Registry:    strings.TrimSpace(fields[3]),
			Allocated:   strings.TrimSpace(fields[4]),
			Name:        name,
			Source:      "Team Cymru",
		}
	}
	return ASNDetails{Source: "Team Cymru", Error: "ASN response was empty"}
}

func lookupRDAPDetails(ctx context.Context, ip string) RDAPDetails {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	endpoint := "https://rdap.org/ip/" + url.PathEscape(ip)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return RDAPDetails{Provider: "rdap.org", Error: err.Error()}
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "OriginPulse/1.0")

	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return RDAPDetails{Provider: "rdap.org", Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return RDAPDetails{Provider: "rdap.org", Error: fmt.Sprintf("RDAP returned %s", resp.Status)}
	}

	var raw rdapResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return RDAPDetails{Provider: "rdap.org", Error: err.Error()}
	}

	out := RDAPDetails{
		Provider:     "rdap.org",
		Handle:       raw.Handle,
		Name:         raw.Name,
		Type:         raw.Type,
		CountryCode:  raw.Country,
		StartAddress: raw.StartAddress,
		EndAddress:   raw.EndAddress,
		IPVersion:    raw.IPVersion,
		CIDRs:        rdapCIDRs(raw),
		Entities:     rdapEntities(raw),
		Links:        rdapLinks(raw),
	}
	for _, event := range raw.Events {
		switch strings.ToLower(event.Action) {
		case "registration":
			out.Registration = event.Date
		case "last changed", "last update of rdap database":
			if out.LastChanged == "" {
				out.LastChanged = event.Date
			}
		}
	}
	return out
}

func cymruHost(addr netip.Addr) (string, bool) {
	if addr.Is4() {
		parts := strings.Split(addr.String(), ".")
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		return strings.Join(parts, ".") + ".origin.asn.cymru.com", true
	}
	if addr.Is6() {
		bytes := addr.As16()
		nibbles := make([]string, 0, 32)
		for i := len(bytes) - 1; i >= 0; i-- {
			low := bytes[i] & 0x0f
			high := bytes[i] >> 4
			nibbles = append(nibbles, fmt.Sprintf("%x", low), fmt.Sprintf("%x", high))
		}
		return strings.Join(nibbles, ".") + ".origin6.asn.cymru.com", true
	}
	return "", false
}

func rdapCIDRs(raw rdapResponse) []string {
	out := []string{}
	for _, item := range raw.CIDRs {
		prefix := item.V4Prefix
		if prefix == "" {
			prefix = item.V6Prefix
		}
		if prefix != "" && item.Length > 0 {
			out = append(out, fmt.Sprintf("%s/%d", prefix, item.Length))
		}
	}
	return out
}

func rdapEntities(raw rdapResponse) []RDAPEntity {
	out := []RDAPEntity{}
	for _, entity := range raw.Entities {
		item := RDAPEntity{
			Handle: entity.Handle,
			Roles:  entity.Roles,
			Name:   rdapEntityName(entity.VCardArray),
		}
		if item.Handle != "" || item.Name != "" || len(item.Roles) > 0 {
			out = append(out, item)
		}
		if len(out) >= 8 {
			break
		}
	}
	return out
}

func rdapEntityName(vcard any) string {
	arr, ok := vcard.([]any)
	if !ok || len(arr) < 2 {
		return ""
	}
	fields, ok := arr[1].([]any)
	if !ok {
		return ""
	}
	for _, field := range fields {
		row, ok := field.([]any)
		if !ok || len(row) < 4 {
			continue
		}
		key, _ := row[0].(string)
		if key != "fn" && key != "org" {
			continue
		}
		switch value := row[3].(type) {
		case string:
			return value
		case []any:
			parts := []string{}
			for _, part := range value {
				if text, ok := part.(string); ok && text != "" {
					parts = append(parts, text)
				}
			}
			return strings.Join(parts, " ")
		}
	}
	return ""
}

func rdapLinks(raw rdapResponse) []RDAPLink {
	out := []RDAPLink{}
	for _, link := range raw.Links {
		if link.Href == "" {
			continue
		}
		out = append(out, RDAPLink{Rel: link.Rel, Href: link.Href})
		if len(out) >= 4 {
			break
		}
	}
	return out
}

func normalizeDetailLimit(limit int) int {
	if limit <= 0 {
		return 8
	}
	if limit > DetailMaxLimit {
		return DetailMaxLimit
	}
	return limit
}

func validCIDR(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if _, err := netip.ParsePrefix(value); err != nil {
		return ""
	}
	return value
}

func firstValidCIDR(values []string) string {
	for _, value := range values {
		if parsed := validCIDR(value); parsed != "" {
			return parsed
		}
	}
	return ""
}

func resolveDetailWindow(now time.Time, rangeValue string, from time.Time, to time.Time) (time.Time, time.Time, string, error) {
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
		return since, until, label, errors.New("to must be after from")
	}
	return since, until, label, nil
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
