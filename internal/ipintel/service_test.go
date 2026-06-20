package ipintel

import "testing"

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
