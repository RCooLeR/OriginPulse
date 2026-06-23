package ipintel

import (
	"testing"
	"time"
)

func TestNormalizeManualAction(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "verified", input: " Verified ", want: "verified"},
		{name: "suspicious", input: "suspicious", want: "suspicious"},
		{name: "clear", input: "clear", want: ""},
		{name: "empty", input: "", want: ""},
		{name: "invalid", input: "trusted", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeManualAction(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizeManualAction(%q) error = nil, want error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeManualAction(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeManualAction(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeManualLabel(t *testing.T) {
	got := normalizeManualLabel("  Operator   marked   suspicious  ")
	if got != "Operator marked suspicious" {
		t.Fatalf("normalizeManualLabel() = %q, want compacted label", got)
	}

	long := ""
	for len(long) < 200 {
		long += "x"
	}
	if got := normalizeManualLabel(long); len(got) != 160 {
		t.Fatalf("normalizeManualLabel(long) len = %d, want 160", len(got))
	}
}

func TestNormalizeDetailLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", limit: 0, want: 8},
		{name: "negative", limit: -1, want: 8},
		{name: "keeps requested", limit: 250, want: 250},
		{name: "max", limit: DetailMaxLimit, want: DetailMaxLimit},
		{name: "clamped", limit: DetailMaxLimit + 1, want: DetailMaxLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeDetailLimit(tt.limit); got != tt.want {
				t.Fatalf("normalizeDetailLimit(%d) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}

func TestNormalizeDetailOffset(t *testing.T) {
	tests := []struct {
		name   string
		offset int
		want   int
	}{
		{name: "default", offset: 0, want: 0},
		{name: "negative", offset: -10, want: 0},
		{name: "keeps requested", offset: 80, want: 80},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeDetailOffset(tt.offset); got != tt.want {
				t.Fatalf("normalizeDetailOffset(%d) = %d, want %d", tt.offset, got, tt.want)
			}
		})
	}
}

func TestNormalizeLimitAllowsDeeperRefreshBatches(t *testing.T) {
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

func TestRefreshWorkerCount(t *testing.T) {
	if got := refreshWorkerCount(0); got != 0 {
		t.Fatalf("refreshWorkerCount(0) = %d, want 0", got)
	}
	if got := refreshWorkerCount(3); got != 3 {
		t.Fatalf("refreshWorkerCount(3) = %d, want 3", got)
	}
	if got := refreshWorkerCount(ResultMaxLimit); got != refreshIPWorkerLimit {
		t.Fatalf("refreshWorkerCount(max) = %d, want %d", got, refreshIPWorkerLimit)
	}
}

func TestClassifyReverseDNSServiceFingerprints(t *testing.T) {
	tests := []struct {
		name       string
		names      []string
		requests   int64
		actorType  string
		knownActor string
	}{
		{
			name:       "addsearch",
			names:      []string{"crawler-1.addsearch.example"},
			actorType:  "crawler",
			knownActor: "AddSearch",
		},
		{
			name:       "ahrefs",
			names:      []string{"node.ahrefs.net"},
			actorType:  "crawler",
			knownActor: "Ahrefs",
		},
		{
			name:       "aws datacenter",
			names:      []string{"ec2-203-0-113-10.compute-1.amazonaws.com"},
			actorType:  "datacenter",
			knownActor: "AWS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actorType, knownActor, risk := classify(tt.names, tt.requests)
			if actorType != tt.actorType || knownActor != tt.knownActor {
				t.Fatalf("classify() = (%q, %q, %d), want (%q, %q, risk)",
					actorType, knownActor, risk, tt.actorType, tt.knownActor)
			}
			if risk <= 0 {
				t.Fatalf("risk = %d, want positive", risk)
			}
		})
	}
}

func TestApplyASNFingerprintClassifiesButDoesNotVerifyProvider(t *testing.T) {
	item := RefreshedIP{ASNOrg: "AMAZON-AES", RiskScore: 20}

	applyASNFingerprint(&item)

	if item.KnownActor != "AWS" || item.ActorType != "datacenter" {
		t.Fatalf("applyASNFingerprint() = (%q, %q), want AWS datacenter", item.KnownActor, item.ActorType)
	}
	if item.VerifiedActor {
		t.Fatal("applyASNFingerprint() should not mark ASN provider matches verified")
	}
	if item.RiskScore != 55 {
		t.Fatalf("RiskScore = %d, want AWS fingerprint risk 55", item.RiskScore)
	}
}

func TestApplyTrafficRiskMarksNoisyProviderSuspicious(t *testing.T) {
	item := RefreshedIP{
		ActorType:        "cloud",
		ProviderVerified: true,
		Requests:         3538,
		Status4xx:        3536,
		RiskScore:        55,
	}

	applyTrafficRisk(&item)

	if item.RiskScore != 85 {
		t.Fatalf("RiskScore = %d, want 85", item.RiskScore)
	}
}

func TestApplyASNFingerprintKeepsTorExit(t *testing.T) {
	item := RefreshedIP{
		ASNOrg:        "AMAZON-AES",
		KnownActor:    "Tor exit",
		ActorType:     "tor",
		RiskScore:     80,
		IsTorExit:     true,
		VerifiedActor: false,
	}

	applyASNFingerprint(&item)

	if item.KnownActor != "Tor exit" || item.ActorType != "tor" {
		t.Fatalf("applyASNFingerprint() changed Tor label to (%q, %q)", item.KnownActor, item.ActorType)
	}
	if item.VerifiedActor {
		t.Fatal("applyASNFingerprint() should not mark Tor exit as verified provider")
	}
}

func TestParseRangeLongDayWindows(t *testing.T) {
	tests := []struct {
		value string
		want  time.Duration
	}{
		{"90d", 90 * 24 * time.Hour},
		{"365d", 365 * 24 * time.Hour},
	}
	for _, tt := range tests {
		got, label := parseRange(tt.value)
		if got != tt.want || label != tt.value {
			t.Fatalf("parseRange(%q) = %s/%q, want %s/%q", tt.value, got, label, tt.want, tt.value)
		}
	}
}
