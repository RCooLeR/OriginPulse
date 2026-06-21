package ipintel

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"originpulse/internal/config"
)

type allowlistMatch struct {
	label     string
	actorType string
	source    string
}

func (s *Service) SeedAllowlist(ctx context.Context, entries []config.IPAllowlistEntry) error {
	if s == nil || !s.Enabled() || len(entries) == 0 {
		return nil
	}
	s.SetAllowlist(entries)
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, entry := range entries {
		normalized := normalizeAllowlistEntry(entry)
		if normalized.Value == "" {
			continue
		}
		sourceJSON, err := allowlistSourceJSON(normalized, now)
		if err != nil {
			return err
		}
		if addr, err := netip.ParseAddr(normalized.Value); err == nil {
			if _, err := pool.Exec(ctx, allowlistExactSQL, addr.String(), normalized.Label, normalized.ActorType, string(sourceJSON), now); err != nil {
				return err
			}
			continue
		}
		prefix, err := netip.ParsePrefix(normalized.Value)
		if err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, allowlistCIDRSQL, prefix.String(), normalized.Label, normalized.ActorType, string(sourceJSON), now); err != nil {
			return err
		}
	}
	return nil
}

func matchAllowlist(ip string, entries []config.IPAllowlistEntry) (allowlistMatch, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return allowlistMatch{}, false
	}
	for _, entry := range entries {
		normalized := normalizeAllowlistEntry(entry)
		if normalized.Value == "" {
			continue
		}
		if exact, err := netip.ParseAddr(normalized.Value); err == nil && exact == addr {
			return allowlistMatch{label: normalized.Label, actorType: normalized.ActorType, source: normalized.Source}, true
		}
		if prefix, err := netip.ParsePrefix(normalized.Value); err == nil && prefix.Contains(addr) {
			return allowlistMatch{label: normalized.Label, actorType: normalized.ActorType, source: normalized.Source}, true
		}
	}
	return allowlistMatch{}, false
}

func normalizeAllowlistEntry(entry config.IPAllowlistEntry) config.IPAllowlistEntry {
	entry.Value = strings.TrimSpace(entry.Value)
	entry.Label = strings.Join(strings.Fields(entry.Label), " ")
	entry.ActorType = strings.TrimSpace(strings.ToLower(entry.ActorType))
	entry.Source = strings.TrimSpace(strings.ToLower(entry.Source))
	if entry.Label == "" {
		entry.Label = "Allowlisted IP"
	}
	if entry.ActorType == "" {
		entry.ActorType = "allowlist"
	}
	if entry.Source == "" {
		entry.Source = "manual"
	}
	return entry
}

func allowlistSourceJSON(entry config.IPAllowlistEntry, now time.Time) ([]byte, error) {
	return json.Marshal(map[string]any{
		"allowlist": map[string]any{
			"value":      entry.Value,
			"label":      entry.Label,
			"actor_type": entry.ActorType,
			"source":     entry.Source,
			"updated_at": now,
		},
	})
}

const allowlistExactSQL = `
INSERT INTO ip_intel (ip, known_actor, actor_type, verified_actor, manual_label, manual_action, risk_score, source, refreshed_at)
VALUES ($1::inet, $2, $3, true, $2, 'allowlisted', 10, $4::jsonb, $5)
ON CONFLICT (ip) DO UPDATE SET
  known_actor = coalesce(nullif(ip_intel.known_actor, ''), EXCLUDED.known_actor),
  actor_type = coalesce(nullif(ip_intel.actor_type, ''), EXCLUDED.actor_type),
  verified_actor = true,
  manual_label = EXCLUDED.manual_label,
  manual_action = EXCLUDED.manual_action,
  risk_score = least(coalesce(ip_intel.risk_score, 10), 10),
  source = ip_intel.source || EXCLUDED.source,
  refreshed_at = coalesce(ip_intel.refreshed_at, EXCLUDED.refreshed_at)`

const allowlistCIDRSQL = `
INSERT INTO ip_intel (ip, network, known_actor, actor_type, verified_actor, manual_label, manual_action, risk_score, source, refreshed_at)
SELECT d.ip, $1::cidr, $2, $3, true, $2, 'allowlisted', 10, $4::jsonb, $5
FROM dim_ips d
WHERE d.ip <<= $1::cidr
ON CONFLICT (ip) DO UPDATE SET
  network = coalesce(ip_intel.network, EXCLUDED.network),
  known_actor = coalesce(nullif(ip_intel.known_actor, ''), EXCLUDED.known_actor),
  actor_type = coalesce(nullif(ip_intel.actor_type, ''), EXCLUDED.actor_type),
  verified_actor = true,
  manual_label = EXCLUDED.manual_label,
  manual_action = EXCLUDED.manual_action,
  risk_score = least(coalesce(ip_intel.risk_score, 10), 10),
  source = ip_intel.source || EXCLUDED.source,
  refreshed_at = coalesce(ip_intel.refreshed_at, EXCLUDED.refreshed_at)`
