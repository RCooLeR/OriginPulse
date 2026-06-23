package ipintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

type ProviderRangeRefreshResult struct {
	Providers int `json:"providers"`
	Ranges    int `json:"ranges"`
	Failed    int `json:"failed"`
}

type officialProvider struct {
	ID        string
	Name      string
	ActorType string
	URL       string
	Kind      string
}

type providerMatch struct {
	ID        string
	Name      string
	ActorType string
	Range     string
	SourceURL string
	FetchedAt time.Time
}

var officialProviders = []officialProvider{
	{ID: "openai-gptbot", Name: "OpenAI GPTBot", ActorType: "crawler", URL: "https://openai.com/gptbot.json", Kind: "json"},
	{ID: "openai-searchbot", Name: "OpenAI SearchBot", ActorType: "crawler", URL: "https://openai.com/searchbot.json", Kind: "json"},
	{ID: "openai-chatgpt-user", Name: "OpenAI ChatGPT-User", ActorType: "fetcher", URL: "https://openai.com/chatgpt-user.json", Kind: "json"},
	{ID: "google-common-crawlers", Name: "Google Common Crawlers", ActorType: "crawler", URL: "https://developers.google.com/crawling/ipranges/common-crawlers.json", Kind: "json"},
	{ID: "google-special-crawlers", Name: "Google Special Crawlers", ActorType: "crawler", URL: "https://developers.google.com/crawling/ipranges/special-crawlers.json", Kind: "json"},
	{ID: "google-user-fetchers", Name: "Google User-Triggered Fetchers", ActorType: "fetcher", URL: "https://developers.google.com/crawling/ipranges/user-triggered-fetchers.json", Kind: "json"},
	{ID: "google-user-fetchers-google", Name: "Google User-Triggered Fetchers Google", ActorType: "fetcher", URL: "https://developers.google.com/crawling/ipranges/user-triggered-fetchers-google.json", Kind: "json"},
	{ID: "google-user-agents", Name: "Google User-Triggered Agents", ActorType: "fetcher", URL: "https://developers.google.com/crawling/ipranges/user-triggered-agents.json", Kind: "json"},
	{ID: "bingbot", Name: "Bingbot", ActorType: "crawler", URL: "https://www.bing.com/toolbox/bingbot.json", Kind: "json"},
	{ID: "duckduckbot", Name: "DuckDuckBot", ActorType: "crawler", URL: "https://duckduckgo.com/duckduckbot.json", Kind: "json"},
	{ID: "ahrefsbot", Name: "AhrefsBot", ActorType: "crawler", URL: "https://api.ahrefs.com/v3/public/crawler-ip-ranges", Kind: "json"},
	{ID: "perplexitybot", Name: "PerplexityBot", ActorType: "crawler", URL: "https://www.perplexity.com/perplexitybot.json", Kind: "json"},
	{ID: "perplexity-user", Name: "Perplexity User", ActorType: "fetcher", URL: "https://www.perplexity.com/perplexity-user.json", Kind: "json"},
	{ID: "addsearchbot", Name: "AddSearchBot", ActorType: "crawler", URL: "https://www.addsearch.com/docs/indexing/whitelisting-addsearch-bot/", Kind: "text"},
	{ID: "aws", Name: "Amazon Web Services", ActorType: "cloud", URL: "https://ip-ranges.amazonaws.com/ip-ranges.json", Kind: "json"},
	{ID: "cloudflare", Name: "Cloudflare", ActorType: "edge", URL: "https://www.cloudflare.com/ips-v4", Kind: "text"},
	{ID: "cloudflare-ipv6", Name: "Cloudflare IPv6", ActorType: "edge", URL: "https://www.cloudflare.com/ips-v6", Kind: "text"},
	{ID: "microsoft-365", Name: "Microsoft 365", ActorType: "platform", URL: "https://endpoints.office.com/endpoints/worldwide?clientrequestid=8f3f9a68-8f58-4f8c-9a91-9f2e1f8b5f6e", Kind: "json"},
	{ID: "applebot", Name: "Applebot", ActorType: "crawler", URL: "https://search.developer.apple.com/applebot.json", Kind: "json"},
	{ID: "github", Name: "GitHub", ActorType: "platform", URL: "https://api.github.com/meta", Kind: "json"},
	{ID: "fastly", Name: "Fastly", ActorType: "edge", URL: "https://api.fastly.com/public-ip-list", Kind: "json"},
	{ID: "uptimerobot", Name: "UptimeRobot", ActorType: "monitor", URL: "https://api.uptimerobot.com/meta/ips", Kind: "json"},
	{ID: "pingdom-ipv4", Name: "Pingdom IPv4", ActorType: "monitor", URL: "https://my.pingdom.com/probes/ipv4", Kind: "text"},
	{ID: "pingdom-ipv6", Name: "Pingdom IPv6", ActorType: "monitor", URL: "https://my.pingdom.com/probes/ipv6", Kind: "text"},
	{ID: "stripe", Name: "Stripe", ActorType: "payment", URL: "https://docs.stripe.com/ips.md", Kind: "text"},
	{ID: "paypal", Name: "PayPal", ActorType: "payment", URL: "https://www.paypal.com/us/cshelp/article/what-are-the-internet-protocol-ip-addresses-for-paypal-server-endpoints-ts1056", Kind: "text"},
}

var providerCIDRPattern = regexp.MustCompile(`(?i)\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b|(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}(?:/\d{1,3})?`)

func (s *Service) RefreshOfficialProviderRanges(ctx context.Context) (ProviderRangeRefreshResult, error) {
	var result ProviderRangeRefreshResult
	if !s.Enabled() {
		return result, nil
	}
	pool, err := s.db.Pool()
	if err != nil {
		return result, err
	}
	now := time.Now().UTC()
	var firstErr error
	for _, provider := range officialProviders {
		ranges, err := fetchOfficialProviderRanges(ctx, provider)
		if err != nil {
			result.Failed++
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", provider.ID, err)
			}
			continue
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return result, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM official_provider_ranges WHERE provider_id = $1`, provider.ID); err != nil {
			_ = tx.Rollback(ctx)
			return result, err
		}
		for _, cidr := range ranges {
			if _, err := tx.Exec(ctx, `
INSERT INTO official_provider_ranges (provider_id, provider_name, actor_type, cidr, source_url, fetched_at)
VALUES ($1, $2, $3, $4::cidr, $5, $6)`,
				provider.ID, provider.Name, provider.ActorType, cidr, provider.URL, now); err != nil {
				_ = tx.Rollback(ctx)
				return result, err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return result, err
		}
		result.Providers++
		result.Ranges += len(ranges)
	}
	return result, firstErr
}

func (s *Service) officialProviderMatch(ctx context.Context, ip string) (providerMatch, bool) {
	if !s.Enabled() || strings.TrimSpace(ip) == "" {
		return providerMatch{}, false
	}
	pool, err := s.db.Pool()
	if err != nil {
		return providerMatch{}, false
	}
	var match providerMatch
	err = pool.QueryRow(ctx, `
SELECT provider_id, provider_name, actor_type, cidr::text, source_url, fetched_at
FROM official_provider_ranges
WHERE $1::inet <<= cidr
ORDER BY masklen(cidr) DESC, provider_id
LIMIT 1`, ip).Scan(&match.ID, &match.Name, &match.ActorType, &match.Range, &match.SourceURL, &match.FetchedAt)
	return match, err == nil
}

func (s *Service) BackfillProviderMatches(ctx context.Context, rangeValue string, limit int) (int64, error) {
	if !s.Enabled() {
		return 0, nil
	}
	if limit <= 0 {
		limit = 5000
	}
	if limit > 250000 {
		limit = 250000
	}
	duration, _ := parseRange(rangeValue)
	since := time.Now().UTC().Add(-duration)
	pool, err := s.db.Pool()
	if err != nil {
		return 0, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = tx.Rollback(context.Background())
	}()
	if _, err := tx.Exec(ctx, `
CREATE TEMP TABLE startup_provider_ip_candidates ON COMMIT DROP AS
WITH candidates AS (
  SELECT ip, request_count::bigint AS requests, last_seen_at
  FROM dim_ips
  UNION ALL
  SELECT ip, 0::bigint AS requests, refreshed_at AS last_seen_at
  FROM ip_intel
),
grouped AS (
  SELECT ip, sum(requests)::bigint AS requests, max(last_seen_at) AS last_seen_at
  FROM candidates
  WHERE ip IS NOT NULL
  GROUP BY ip
)
SELECT ip
FROM grouped
WHERE last_seen_at IS NULL OR last_seen_at >= $2
ORDER BY requests DESC, last_seen_at DESC NULLS LAST
LIMIT $1`, limit, since); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `CREATE UNIQUE INDEX ON startup_provider_ip_candidates (ip)`); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `
CREATE TEMP TABLE startup_provider_ip_matches ON COMMIT DROP AS
SELECT c.ip,
       r.provider_id,
       r.provider_name,
       r.actor_type,
       r.cidr AS provider_range,
       r.source_url,
       r.fetched_at
FROM startup_provider_ip_candidates c
JOIN LATERAL (
  SELECT provider_id, provider_name, actor_type, cidr, source_url, fetched_at
  FROM official_provider_ranges
  WHERE c.ip <<= cidr
  ORDER BY masklen(cidr) DESC, provider_id
  LIMIT 1
) r ON true`); err != nil {
		return 0, err
	}
	sourceJSON, err := json.Marshal(map[string]any{
		"strategy": "startup_provider_range_backfill",
	})
	if err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO ip_intel (
  ip, known_actor, actor_type, verified_actor, provider_verified, provider_id, provider_name, provider_source_url, provider_range, provider_refreshed_at, risk_score, source, refreshed_at
)
SELECT ip,
       provider_name,
       actor_type,
       false,
       true,
       provider_id,
       provider_name,
       source_url,
       provider_range,
       fetched_at,
       CASE WHEN lower(actor_type) IN ('cloud', 'datacenter') THEN 55 WHEN lower(actor_type) = 'edge' THEN 45 ELSE 25 END,
       $1::jsonb,
       now()
FROM startup_provider_ip_matches
ON CONFLICT (ip) DO UPDATE SET
  known_actor = CASE WHEN ip_intel.manual_action = 'allowlisted' THEN coalesce(ip_intel.manual_label, ip_intel.known_actor) ELSE EXCLUDED.known_actor END,
  actor_type = CASE WHEN ip_intel.manual_action = 'allowlisted' THEN coalesce(ip_intel.actor_type, 'allowlist') ELSE EXCLUDED.actor_type END,
  verified_actor = CASE WHEN ip_intel.manual_action IN ('allowlisted', 'verified') THEN true ELSE false END,
  provider_verified = true,
  provider_id = EXCLUDED.provider_id,
  provider_name = EXCLUDED.provider_name,
  provider_source_url = EXCLUDED.provider_source_url,
  provider_range = EXCLUDED.provider_range,
  provider_refreshed_at = EXCLUDED.provider_refreshed_at,
  risk_score = CASE
    WHEN ip_intel.manual_action = 'allowlisted' THEN least(coalesce(ip_intel.risk_score, EXCLUDED.risk_score, 10), 10)
    WHEN ip_intel.manual_action = 'suspicious' THEN greatest(coalesce(ip_intel.risk_score, EXCLUDED.risk_score, 0), 80)
    ELSE greatest(coalesce(ip_intel.risk_score, 0), EXCLUDED.risk_score)
  END,
  source = coalesce(ip_intel.source, '{}'::jsonb) || EXCLUDED.source,
  refreshed_at = greatest(coalesce(ip_intel.refreshed_at, EXCLUDED.refreshed_at), EXCLUDED.refreshed_at)`, string(sourceJSON))
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE ip_intel ii
SET provider_verified = false,
    provider_id = NULL,
    provider_name = NULL,
    provider_source_url = NULL,
    provider_range = NULL,
    provider_refreshed_at = NULL
FROM startup_provider_ip_candidates c
WHERE ii.ip = c.ip
  AND ii.provider_verified = true
  AND NOT EXISTS (SELECT 1 FROM startup_provider_ip_matches m WHERE m.ip = c.ip)`); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func fetchOfficialProviderRanges(ctx context.Context, provider officialProvider) ([]string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, provider.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/html, text/plain;q=0.9, */*;q=0.8")
	req.Header.Set("User-Agent", "OriginPulse/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	if provider.Kind == "json" || json.Valid(body) {
		ranges := parseProviderJSONRanges(body)
		if len(ranges) > 0 {
			return ranges, nil
		}
	}
	return parseProviderTextRanges(body), nil
}

func parseProviderJSONRanges(body []byte) []string {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil
	}
	var raw []string
	var walk func(any)
	walk = func(item any) {
		switch typed := item.(type) {
		case string:
			raw = append(raw, typed)
		case []any:
			for _, child := range typed {
				walk(child)
			}
		case map[string]any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return normalizeProviderRanges(raw)
}

func parseProviderTextRanges(body []byte) []string {
	return normalizeProviderRanges(providerCIDRPattern.FindAllString(string(body), -1))
}

func normalizeProviderRanges(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.Trim(strings.TrimSpace(value), ".,;:()[]{}<>\"'")
		if value == "" {
			continue
		}
		cidr := ""
		if prefix, err := netip.ParsePrefix(value); err == nil {
			if skipProviderAddr(prefix.Addr()) {
				continue
			}
			cidr = prefix.Masked().String()
		} else if addr, err := netip.ParseAddr(value); err == nil {
			if skipProviderAddr(addr) {
				continue
			}
			if addr.Is4() {
				cidr = netip.PrefixFrom(addr, 32).String()
			} else {
				cidr = netip.PrefixFrom(addr, 128).String()
			}
		}
		if cidr == "" || seen[cidr] {
			continue
		}
		seen[cidr] = true
		out = append(out, cidr)
	}
	sort.Strings(out)
	return out
}

func skipProviderAddr(addr netip.Addr) bool {
	return !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback()
}
