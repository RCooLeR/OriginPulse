package ipintel

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/config"
	"originpulse/internal/db"
	"originpulse/internal/geoip"
	"originpulse/internal/rollups"
	"originpulse/internal/servicefingerprints"
)

type Options struct {
	Range string `json:"range"`
	Limit int    `json:"limit"`
}

const ResultMaxLimit = 5000

type Result struct {
	Range            string        `json:"range"`
	Since            time.Time     `json:"since"`
	GeneratedAt      time.Time     `json:"generated_at"`
	DatabaseEnabled  bool          `json:"database_enabled"`
	Refreshed        int           `json:"refreshed"`
	Failed           int           `json:"failed"`
	LookupFailed     int           `json:"lookup_failed"`
	GeoIPFailed      int           `json:"geoip_failed"`
	ReverseDNSFailed int           `json:"reverse_dns_failed"`
	ProviderRanges   int           `json:"provider_ranges"`
	ProviderFailed   int           `json:"provider_failed"`
	Items            []RefreshedIP `json:"items"`
}

type RefreshedIP struct {
	IP               string    `json:"ip"`
	Requests         int64     `json:"requests"`
	ReverseDNS       string    `json:"reverse_dns,omitempty"`
	ASN              int64     `json:"asn,omitempty"`
	ASNOrg           string    `json:"asn_org,omitempty"`
	Network          string    `json:"network,omitempty"`
	CountryCode      string    `json:"country_code,omitempty"`
	CityName         string    `json:"city_name,omitempty"`
	TimeZone         string    `json:"time_zone,omitempty"`
	KnownActor       string    `json:"known_actor,omitempty"`
	ActorType        string    `json:"actor_type,omitempty"`
	RiskScore        int       `json:"risk_score"`
	ForwardConfirmed bool      `json:"forward_confirmed"`
	VerifiedActor    bool      `json:"verified_actor"`
	ProviderVerified bool      `json:"provider_verified"`
	ProviderID       string    `json:"provider_id,omitempty"`
	ProviderName     string    `json:"provider_name,omitempty"`
	ProviderSource   string    `json:"provider_source_url,omitempty"`
	ProviderRange    string    `json:"provider_range,omitempty"`
	ProviderAt       time.Time `json:"provider_refreshed_at,omitempty"`
	IsTorExit        bool      `json:"is_tor_exit"`
	IsDatacenter     bool      `json:"is_datacenter"`
	Status4xx        int64     `json:"status_4xx"`
	Status5xx        int64     `json:"status_5xx"`
	DNSErrors        []string  `json:"dns_errors,omitempty"`
	RefreshedAt      time.Time `json:"refreshed_at"`
}

const (
	torExitListURL       = "https://check.torproject.org/torbulkexitlist"
	refreshIPWorkerLimit = 16
)

type refreshOutcome struct {
	item             RefreshedIP
	lookupFailed     int
	geoIPFailed      int
	reverseDNSFailed int
	err              error
}

type Service struct {
	db        *db.Store
	geoIP     *geoip.Manager
	allowlist []config.IPAllowlistEntry
}

func NewService(store *db.Store, geoIP ...*geoip.Manager) *Service {
	var manager *geoip.Manager
	if len(geoIP) > 0 {
		manager = geoIP[0]
	}
	return &Service{db: store, geoIP: manager}
}

func (s *Service) SetAllowlist(entries []config.IPAllowlistEntry) {
	if s == nil {
		return
	}
	s.allowlist = append([]config.IPAllowlistEntry(nil), entries...)
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

	outcomes := s.refreshIPBatch(ctx, topIPs, torExits, torCheckAvailable, now)
	result.Items = make([]RefreshedIP, 0, len(outcomes))
	for _, outcome := range outcomes {
		if outcome.err != nil {
			result.Failed++
			if err == nil {
				err = outcome.err
			}
			continue
		}
		result.Refreshed++
		result.LookupFailed += outcome.lookupFailed
		result.GeoIPFailed += outcome.geoIPFailed
		result.ReverseDNSFailed += outcome.reverseDNSFailed
		result.Items = append(result.Items, outcome.item)
	}
	if err != nil {
		return result, err
	}

	return result, nil
}

func (s *Service) refreshIPBatch(ctx context.Context, items []RefreshedIP, torExits map[string]struct{}, torCheckAvailable bool, refreshedAt time.Time) []refreshOutcome {
	if len(items) == 0 {
		return []refreshOutcome{}
	}
	workerCount := refreshWorkerCount(len(items))
	jobs := make(chan RefreshedIP)
	outcomes := make(chan refreshOutcome, len(items))
	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				outcomes <- s.refreshOneIP(ctx, item, torExits, torCheckAvailable, refreshedAt)
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, item := range items {
			select {
			case jobs <- item:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(outcomes)
	}()

	result := make([]refreshOutcome, 0, len(items))
	for outcome := range outcomes {
		result = append(result, outcome)
	}
	return result
}

func (s *Service) refreshOneIP(ctx context.Context, item RefreshedIP, torExits map[string]struct{}, torCheckAvailable bool, refreshedAt time.Time) refreshOutcome {
	item.RefreshedAt = refreshedAt
	lookupFailed := 0

	geo, geoErr := s.lookupGeoIP(item.IP)
	if geoErr == "" {
		item.CountryCode = geo.CountryCode
		item.CityName = geo.CityName
		item.TimeZone = geo.TimeZone
	} else if geoErr != "" && geoErr != geoip.ErrNotLoaded.Error() {
		item.DNSErrors = append(item.DNSErrors, geoErr)
		lookupFailed++
	}
	geoIPFailed := lookupFailed

	reverseDNSFailed := 0
	names, lookupErr := lookupReverse(ctx, item.IP)
	if lookupErr != "" {
		item.DNSErrors = append(item.DNSErrors, lookupErr)
		lookupFailed++
		reverseDNSFailed++
	}
	item.ReverseDNS = firstName(names)
	item.ActorType, item.KnownActor, item.RiskScore = classify(names, item.Requests)
	item.ForwardConfirmed = forwardConfirms(ctx, names, item.IP)
	item.VerifiedActor = item.ForwardConfirmed && item.KnownActor != "" && !isInfrastructureActorType(item.ActorType)
	if addr, err := netip.ParseAddr(item.IP); err == nil {
		asn := lookupASNDetails(ctx, addr)
		if asn.Error == "" {
			item.ASN = asn.ASN
			item.ASNOrg = asn.Name
			item.Network = validCIDR(asn.Prefix)
			if item.CountryCode == "" {
				item.CountryCode = asn.CountryCode
			}
		}
	}
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
	applyASNFingerprint(&item)
	if match, ok := s.officialProviderMatch(ctx, item.IP); ok {
		item.ProviderVerified = true
		item.ProviderID = match.ID
		item.ProviderName = match.Name
		item.ProviderSource = match.SourceURL
		item.ProviderRange = match.Range
		item.ProviderAt = match.FetchedAt
		item.KnownActor = match.Name
		item.ActorType = match.ActorType
		if baseline := providerBaselineRisk(match.ActorType); item.RiskScore < baseline {
			item.RiskScore = baseline
		}
	}
	item.IsDatacenter = isInfrastructureActorType(item.ActorType)
	applyTrafficRisk(&item)
	if match, ok := matchAllowlist(item.IP, s.allowlist); ok {
		item.KnownActor = match.label
		item.ActorType = match.actorType
		item.VerifiedActor = true
		if item.RiskScore == 0 || item.RiskScore > 10 {
			item.RiskScore = 10
		}
	}

	if err := s.upsert(ctx, item, names, torCheckAvailable); err != nil {
		return refreshOutcome{item: item, lookupFailed: lookupFailed, geoIPFailed: geoIPFailed, reverseDNSFailed: reverseDNSFailed, err: err}
	}
	return refreshOutcome{item: item, lookupFailed: lookupFailed, geoIPFailed: geoIPFailed, reverseDNSFailed: reverseDNSFailed}
}

func refreshWorkerCount(itemCount int) int {
	if itemCount <= 0 {
		return 0
	}
	if itemCount < refreshIPWorkerLimit {
		return itemCount
	}
	return refreshIPWorkerLimit
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
SELECT host(client_ip),
       count(*)::bigint,
       count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint,
       count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint
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
		if err := rows.Scan(&item.IP, &item.Requests, &item.Status4xx, &item.Status5xx); err != nil {
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
  SELECT d.ip,
         sum(r.requests)::bigint AS requests,
         sum(r.status_4xx)::bigint AS status_4xx,
         sum(r.status_5xx)::bigint AS status_5xx
  FROM rollup_ip_1h r
  JOIN dim_ips d ON d.id = r.ip_id
  WHERE r.bucket_ts >= $3 AND r.bucket_ts < $4
  GROUP BY d.ip
),
edge_rows AS (
  SELECT client_ip AS ip,
         count(*)::bigint AS requests,
         count(*) FILTER (WHERE status >= 400 AND status < 500)::bigint AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600)::bigint AS status_5xx
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
SELECT host(ip),
       sum(requests)::bigint,
       sum(status_4xx)::bigint,
       sum(status_5xx)::bigint
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
		if err := rows.Scan(&item.IP, &item.Requests, &item.Status4xx, &item.Status5xx); err != nil {
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
		"status_4xx":    item.Status4xx,
		"status_5xx":    item.Status5xx,
		"reverse_names": reverseNames,
		"dns_errors":    item.DNSErrors,
		"asn": map[string]any{
			"asn":     item.ASN,
			"asn_org": item.ASNOrg,
			"network": item.Network,
		},
		"tor_checked": torCheckAvailable,
		"is_tor_exit": item.IsTorExit,
		"provider": map[string]any{
			"verified":     item.ProviderVerified,
			"id":           item.ProviderID,
			"name":         item.ProviderName,
			"range":        item.ProviderRange,
			"source_url":   item.ProviderSource,
			"refreshed_at": item.ProviderAt,
		},
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
  ip, asn, asn_org, network, country_code, reverse_dns, known_actor, actor_type, forward_confirmed, verified_actor, provider_verified, provider_id, provider_name, provider_source_url, provider_range, provider_refreshed_at, is_tor_exit, is_datacenter, risk_score, source, refreshed_at
) VALUES (
  $1::inet, nullif($2, 0), nullif($3, ''), nullif($4, '')::cidr, nullif($5, ''), $6, $7, $8, $9, $10, $11, nullif($12, ''), nullif($13, ''), nullif($14, ''), nullif($15, '')::cidr, CASE WHEN $16::timestamptz = '0001-01-01T00:00:00Z'::timestamptz THEN NULL ELSE $16::timestamptz END, $17, $18, $19, $20::jsonb, $21
)
ON CONFLICT (ip) DO UPDATE SET
  asn = coalesce(EXCLUDED.asn, ip_intel.asn),
  asn_org = coalesce(EXCLUDED.asn_org, ip_intel.asn_org),
  network = coalesce(EXCLUDED.network, ip_intel.network),
  country_code = coalesce(EXCLUDED.country_code, ip_intel.country_code),
  reverse_dns = EXCLUDED.reverse_dns,
  known_actor = CASE WHEN ip_intel.manual_action = 'allowlisted' THEN coalesce(ip_intel.manual_label, ip_intel.known_actor) ELSE EXCLUDED.known_actor END,
  actor_type = CASE WHEN ip_intel.manual_action = 'allowlisted' THEN coalesce(ip_intel.actor_type, 'allowlist') ELSE EXCLUDED.actor_type END,
  forward_confirmed = EXCLUDED.forward_confirmed,
  verified_actor = CASE WHEN ip_intel.manual_action IN ('allowlisted', 'verified') THEN true ELSE EXCLUDED.verified_actor END,
  provider_verified = EXCLUDED.provider_verified,
  provider_id = EXCLUDED.provider_id,
  provider_name = EXCLUDED.provider_name,
  provider_source_url = EXCLUDED.provider_source_url,
  provider_range = EXCLUDED.provider_range,
  provider_refreshed_at = EXCLUDED.provider_refreshed_at,
  is_tor_exit = CASE WHEN $22 THEN EXCLUDED.is_tor_exit ELSE ip_intel.is_tor_exit END,
  is_datacenter = EXCLUDED.is_datacenter,
  risk_score = CASE
    WHEN ip_intel.manual_action = 'allowlisted' THEN least(coalesce(EXCLUDED.risk_score, ip_intel.risk_score, 10), 10)
    WHEN ip_intel.manual_action = 'suspicious' THEN greatest(coalesce(EXCLUDED.risk_score, ip_intel.risk_score, 0), 80)
    ELSE EXCLUDED.risk_score
  END,
  source = EXCLUDED.source,
  refreshed_at = EXCLUDED.refreshed_at`,
		item.IP,
		item.ASN,
		item.ASNOrg,
		item.Network,
		item.CountryCode,
		emptyToNil(item.ReverseDNS),
		emptyToNil(item.KnownActor),
		emptyToNil(item.ActorType),
		item.ForwardConfirmed,
		item.VerifiedActor,
		item.ProviderVerified,
		item.ProviderID,
		item.ProviderName,
		item.ProviderSource,
		item.ProviderRange,
		item.ProviderAt,
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

func applyASNFingerprint(item *RefreshedIP) {
	if item == nil || item.IsTorExit {
		return
	}
	match, ok := servicefingerprints.MatchASNOrg(item.ASNOrg)
	if !ok {
		return
	}
	item.ActorType = match.ActorType
	item.KnownActor = match.KnownActor
	item.RiskScore = match.RiskScore
}

func providerBaselineRisk(actorType string) int {
	switch strings.ToLower(strings.TrimSpace(actorType)) {
	case "cloud", "datacenter":
		return 55
	case "edge":
		return 45
	default:
		return 25
	}
}

func isInfrastructureActorType(actorType string) bool {
	switch strings.ToLower(strings.TrimSpace(actorType)) {
	case "cloud", "datacenter", "edge", "hosting", "vps":
		return true
	default:
		return false
	}
}

func applyTrafficRisk(item *RefreshedIP) {
	if item == nil || item.Requests <= 0 {
		return
	}
	errors := item.Status4xx + item.Status5xx
	if errors < 50 {
		return
	}
	errorRate := float64(errors) / float64(item.Requests)
	if errorRate >= 0.80 && (item.ProviderVerified || item.IsDatacenter || isInfrastructureActorType(item.ActorType)) {
		if item.RiskScore < 85 {
			item.RiskScore = 85
		}
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
	if limit > ResultMaxLimit {
		return ResultMaxLimit
	}
	return limit
}

func parseRange(value string) (time.Duration, string) {
	switch value {
	case "15m":
		return 15 * time.Minute, "15m"
	case "30m":
		return 30 * time.Minute, "30m"
	case "3h":
		return 3 * time.Hour, "3h"
	case "6h":
		return 6 * time.Hour, "6h"
	case "24h":
		return 24 * time.Hour, "24h"
	case "7d":
		return 7 * 24 * time.Hour, "7d"
	case "30d":
		return 30 * 24 * time.Hour, "30d"
	case "90d":
		return 90 * 24 * time.Hour, "90d"
	case "365d":
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
