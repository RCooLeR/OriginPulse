package accessanalysis

import (
	"testing"

	"originpulse/internal/useragent"
)

func TestClassifyUserAgent(t *testing.T) {
	tests := []struct {
		name       string
		userAgent  string
		requests   int64
		family     string
		actorType  string
		knownActor string
	}{
		{
			name:       "browser",
			userAgent:  "Mozilla/5.0 AppleWebKit/537.36 Chrome/125.0 Safari/537.36",
			family:     "Chrome",
			actorType:  "browser",
			knownActor: "",
		},
		{
			name:       "googlebot",
			userAgent:  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			family:     "googlebot",
			actorType:  "crawler",
			knownActor: "Google",
		},
		{
			name:       "addsearch",
			userAgent:  "Mozilla/5.0 (compatible; AddSearchBot/1.0; +http://www.addsearch.com/bot/)",
			family:     "addsearch",
			actorType:  "crawler",
			knownActor: "AddSearch",
		},
		{
			name:       "uptime robot",
			userAgent:  "UptimeRobot/2.0",
			family:     "uptimerobot",
			actorType:  "monitor",
			knownActor: "UptimeRobot",
		},
		{
			name:       "scripted",
			userAgent:  "python-requests/2.32",
			family:     "python-requests",
			actorType:  "tool",
			knownActor: "",
		},
		{
			name:       "missing",
			userAgent:  "",
			family:     "empty",
			actorType:  "missing",
			knownActor: "",
		},
		{
			name:       "high volume unknown",
			userAgent:  "MysteryClient/1.0",
			requests:   12000,
			family:     "mysteryclient",
			actorType:  "unknown",
			knownActor: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := useragent.Analyze(tt.userAgent, tt.requests)
			if analysis.Family != tt.family || analysis.ActorType != tt.actorType || analysis.KnownActor != tt.knownActor {
				t.Fatalf("Analyze() = (%q, %q, %q, %d), want (%q, %q, %q, risk)",
					analysis.Family, analysis.ActorType, analysis.KnownActor, analysis.RiskScore, tt.family, tt.actorType, tt.knownActor)
			}
			if analysis.RiskScore <= 0 {
				t.Fatalf("risk = %d, want positive", analysis.RiskScore)
			}
		})
	}
}

func TestApplyUserAgentAnalysisKeepsStoredMetadata(t *testing.T) {
	item := UserAgentSummary{
		Sample:         "Mozilla/5.0 AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
		BrowserFamily:  "Chrome",
		BrowserVersion: "126.0",
		OSFamily:       "Windows",
		OSVersion:      "10/11",
		DeviceFamily:   "Desktop",
		ActorType:      "browser",
		Requests:       42,
	}

	applyUserAgentAnalysis(&item)

	if item.Family != "Chrome" || item.BrowserFamily != "Chrome" || item.OSFamily != "Windows" {
		t.Fatalf("metadata = family %q browser %q os %q, want Chrome/Chrome/Windows", item.Family, item.BrowserFamily, item.OSFamily)
	}
	if item.ActorType != "browser" || item.DeviceFamily != "Desktop" {
		t.Fatalf("actor/device = %q/%q, want browser/Desktop", item.ActorType, item.DeviceFamily)
	}
}

func TestNormalizeLimitAllowsDeeperPaginatedLists(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", limit: 0, want: 25},
		{name: "negative", limit: -1, want: 25},
		{name: "keeps requested", limit: 250, want: 250},
		{name: "max", limit: ResultMaxLimit, want: ResultMaxLimit},
		{name: "clamped", limit: ResultMaxLimit + 1, want: ResultMaxLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeLimit(tt.limit); got != tt.want {
				t.Fatalf("normalizeLimit(%d) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}
