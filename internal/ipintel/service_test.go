package ipintel

import "testing"

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
