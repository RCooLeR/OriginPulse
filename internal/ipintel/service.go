package ipintel

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/db"
	"originpulse/internal/geoip"
	"originpulse/internal/rollups"
	"originpulse/internal/servicefingerprints"
)

type Options struct {
	Range string `json:"range"`
	Limit int    `json:"limit"`
}

type Result struct {
	Range           string        `json:"range"`
	Since           time.Time     `json:"since"`
	GeneratedAt     time.Time     `json:"generated_at"`
	DatabaseEnabled bool          `json:"database_enabled"`
	Refreshed       int           `json:"refreshed"`
	Failed          int           `json:"failed"`
	Items           []RefreshedIP `json:"items"`
}

type RefreshedIP struct {
	IP               string    `json:"ip"`
	Requests         int64     `json:"requests"`
	ReverseDNS       string    `json:"reverse_dns,omitempty"`
	CountryCode      string    `json:"country_code,omitempty"`
	CityName         string    `json:"city_name,omitempty"`
	TimeZone         string    `json:"time_zone,omitempty"`
	KnownActor       string    `json:"known_actor,omitempty"`
	ActorType        string    `json:"actor_type,omitempty"`
	RiskScore        int       `json:"risk_score"`
	ForwardConfirmed bool      `json:"forward_confirmed"`
	VerifiedActor    bool      `json:"verified_actor"`
	IsTorExit        bool      `json:"is_tor_exit"`
	IsDatacenter     bool      `json:"is_datacenter"`
	DNSErrors        []string  `json:"dns_errors,omitempty"`
	RefreshedAt      time.Time `json:"refreshed_at"`
}

const torExitListURL = "https://check.torproject.org/torbulkexitlist"

type Service struct {
	db    *db.Store
	geoIP *geoip.Manager
}

func NewService(store *db.Store, geoIP ...*geoip.Manager) *Service {
	var manager *geoip.Manager
	if len(geoIP) > 0 {
		manager = geoIP[0]
	}
	return &Service{db: store, geoIP: manager}
}

func (s *Service) Enabled() bool {
	return s != nil && s.db != nil && s.db.Enabled()
}

func (s *Service) RefreshTop(ctx context.Context, opts Options) (Result, error) {
	duration, label := parseRange(opts.Range)
	limit := normalizeLimit(opts.Limit)
	now := time.Now().UTC()
	result := Result{
		Range:           label,
		Since:           now.Add(-duration),
		GeneratedAt:     now,
		DatabaseEnabled: s.Enabled(),
		Items:           []RefreshedIP{},
	}
	if !s.Enabled() {
		return result, nil
	}

	pool, err := s.db.Pool()
	if err != nil {
		return result, err
	}

	torExits, torCheckAvailable := fetchTorExitSet(ctx)
	topIPs, err := loadRefreshTopIPs(ctx, pool, result.Since, now, limit)
	if err != nil {
		return result, err
	}

	for _, item := range topIPs {
		item.RefreshedAt = now

		geo, geoErr := s.lookupGeoIP(item.IP)
		if geoErr == "" {
			item.CountryCode = geo.CountryCode
			item.CityName = geo.CityName
			item.TimeZone = geo.TimeZone
		} else if geoErr != "" && geoErr != geoip.ErrNotLoaded.Error() {
			item.DNSErrors = append(item.DNSErrors, geoErr)
			result.Failed++
		}

		names, lookupErr := lookupReverse(ctx, item.IP)
		if lookupErr != "" {
			item.DNSErrors = append(item.DNSErrors, lookupErr)
			result.Failed++
		}
		item.ReverseDNS = firstName(names)
		item.ActorType, item.KnownActor, item.RiskScore = classify(names, item.Requests)
		item.ForwardConfirmed = forwardConfirms(ctx, names, item.IP)
		item.VerifiedActor = item.ForwardConfirmed && item.KnownActor != ""
		if torCheckAvailable {
			_, item.IsTorExit = torExits[item.IP]
			if item.IsTorExit {
				item.ActorType = "tor"
				item.KnownActor = "Tor exit"
				if item.RiskScore < 80 {
					item.RiskScore = 80
				}
			}
		}
		item.IsDatacenter = item.ActorType == "datacenter"

		if err := s.upsert(ctx, item, names, torCheckAvailable); err != nil {
			return result, err
		}
		result.Refreshed++
		result.Items = append(result.Items, item)
	}

	return result, nil
}

func loadRefreshTopIPs(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, limit int) ([]RefreshedIP, error) {
	rollupsReady, err := rollups.DimensionRollupsReady(ctx, pool, since, until, "")
	if err != nil {
		return nil, err
	}
	if rollupsReady {
		return loadRefreshTopIPsFromRollups(ctx, pool, since, until, limit)
	}
	return loadRefreshTopIPsFromRaw(ctx, pool, since, until, limit)
}

func loadRefreshTopIPsFromRaw(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, limit int) ([]RefreshedIP, error) {
	rows, err := pool.Query(ctx, `
SELECT host(client_ip), count(*)::bigint
FROM access_events
WHERE ts >= $1 AND ts < $3 AND client_ip IS NOT NULL
GROUP BY client_ip
ORDER BY count(*) DESC
LIMIT $2`, since, limit, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]RefreshedIP, 0, limit)
	for rows.Next() {
		var item RefreshedIP
		if err := rows.Scan(&item.IP, &item.Requests); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func loadRefreshTopIPsFromRollups(ctx context.Context, pool *pgxpool.Pool, since time.Time, until time.Time, limit int) ([]RefreshedIP, error) {
	fullStart, fullEnd, _ := rollups.FullHourRange(since, until)
	rows, err := pool.Query(ctx, `
WITH rollup_rows AS (
  SELECT d.ip, sum(r.requests)::bigint AS requests
  FROM rollup_ip_1h r
  JOIN dim_ips d ON d.id = r.ip_id
  WHERE r.bucket_ts >= $3 AND r.bucket_ts < $4
  GROUP BY d.ip
),
edge_rows AS (
  SELECT client_ip AS ip, count(*)::bigint AS requests
  FROM access_events
  WHERE ts >= $1 AND ts < $2
    AND client_ip IS NOT NULL
    AND (ts < $3 OR ts >= $4)
  GROUP BY client_ip
),
combined AS (
  SELECT * FROM rollup_rows
  UNION ALL
  SELECT * FROM edge_rows
)
SELECT host(ip), sum(requests)::bigint
FROM combined
GROUP BY ip
ORDER BY sum(requests) DESC
LIMIT $5`, since, until, fullStart, fullEnd, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]RefreshedIP, 0, limit)
	for rows.Next() {
		var item RefreshedIP
		if err := rows.Scan(&item.IP, &item.Requests); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Service) upsert(ctx context.Context, item RefreshedIP, reverseNames []string, torCheckAvailable bool) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}

	source := map[string]any{
		"strategy":      "reverse_dns_top_ips",
		"requests":      item.Requests,
		"reverse_names": reverseNames,
		"dns_errors":    item.DNSErrors,
		"tor_checked":   torCheckAvailable,
		"is_tor_exit":   item.IsTorExit,
		"geoip": map[string]any{
			"country_code": item.CountryCode,
			"city_name":    item.CityName,
			"time_zone":    item.TimeZone,
		},
	}
	sourceJSON, err := json.Marshal(source)
	if err != nil {
		return err
	}

	_, err = pool.Exec(ctx, `
INSERT INTO ip_intel (
  ip, country_code, reverse_dns, known_actor, actor_type, forward_confirmed, verified_actor, is_tor_exit, is_datacenter, risk_score, source, refreshed_at
) VALUES (
  $1::inet, nullif($2, ''), $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12
)
ON CONFLICT (ip) DO UPDATE SET
  country_code = coalesce(EXCLUDED.country_code, ip_intel.country_code),
  reverse_dns = EXCLUDED.reverse_dns,
  known_actor = EXCLUDED.known_actor,
  actor_type = EXCLUDED.actor_type,
  forward_confirmed = EXCLUDED.forward_confirmed,
  verified_actor = EXCLUDED.verified_actor,
  is_tor_exit = CASE WHEN $13 THEN EXCLUDED.is_tor_exit ELSE ip_intel.is_tor_exit END,
  is_datacenter = EXCLUDED.is_datacenter,
  risk_score = EXCLUDED.risk_score,
  source = EXCLUDED.source,
  refreshed_at = EXCLUDED.refreshed_at`,
		item.IP,
		item.CountryCode,
		emptyToNil(item.ReverseDNS),
		emptyToNil(item.KnownActor),
		emptyToNil(item.ActorType),
		item.ForwardConfirmed,
		item.VerifiedActor,
		item.IsTorExit,
		item.IsDatacenter,
		item.RiskScore,
		string(sourceJSON),
		item.RefreshedAt,
		torCheckAvailable,
	)
	return err
}

func (s *Service) lookupGeoIP(ip string) (geoip.CityResult, string) {
	if s == nil || s.geoIP == nil {
		return geoip.CityResult{}, geoip.ErrNotLoaded.Error()
	}
	result, err := s.geoIP.Lookup(ip)
	if err != nil {
		return geoip.CityResult{}, err.Error()
	}
	return result, ""
}

func fetchTorExitSet(ctx context.Context) (map[string]struct{}, bool) {
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(lookupCtx, http.MethodGet, torExitListURL, nil)
	if err != nil {
		return nil, false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false
	}

	exits := map[string]struct{}{}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			exits[ip.String()] = struct{}{}
		}
	}
	if scanner.Err() != nil {
		return nil, false
	}
	return exits, true
}

func lookupReverse(ctx context.Context, ip string) ([]string, string) {
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(lookupCtx, ip)
	if err != nil {
		return nil, err.Error()
	}
	normalized := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if name != "" {
			normalized = append(normalized, name)
		}
	}
	return normalized, ""
}

func forwardConfirms(ctx context.Context, names []string, ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil || len(names) == 0 {
		return false
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for _, name := range names {
		ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", name)
		if err != nil {
			continue
		}
		for _, candidate := range ips {
			if sameIP(candidate, parsed) {
				return true
			}
		}
	}
	return false
}

func sameIP(a net.IP, b net.IP) bool {
	if a4 := a.To4(); a4 != nil {
		if b4 := b.To4(); b4 != nil {
			return a4.Equal(b4)
		}
	}
	return a.Equal(b)
}

func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func classify(names []string, requests int64) (string, string, int) {
	if match, ok := servicefingerprints.MatchReverseDNS(names); ok {
		return match.ActorType, match.KnownActor, match.RiskScore
	}

	switch {
	case requests >= 10000:
		return "unknown", "", 65
	case requests >= 1000:
		return "unknown", "", 50
	case requests >= 100:
		return "unknown", "", 35
	default:
		return "unknown", "", 20
	}
}

func emptyToNil(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
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

func parseRange(value string) (time.Duration, string) {
	switch value {
	case "15m":
		return 15 * time.Minute, "15m"
	case "6h":
		return 6 * time.Hour, "6h"
	case "24h":
		return 24 * time.Hour, "24h"
	case "7d":
		return 7 * 24 * time.Hour, "7d"
	case "30d":
		return 30 * 24 * time.Hour, "30d"
	case "1h", "":
		return time.Hour, "1h"
	default:
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed, value
		}
		return time.Hour, "1h"
	}
}
