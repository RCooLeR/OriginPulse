package servicefingerprints

import "testing"

func TestMatchUserAgent(t *testing.T) {
	tests := []struct {
		name       string
		userAgent  string
		family     string
		actorType  string
		knownActor string
	}{
		{
			name:       "addsearch",
			userAgent:  "Mozilla/5.0 (compatible; AddSearchBot/1.0; +http://www.addsearch.com/bot/)",
			family:     "addsearch",
			actorType:  "crawler",
			knownActor: "AddSearch",
		},
		{
			name:       "ahrefs",
			userAgent:  "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
			family:     "ahrefs",
			actorType:  "crawler",
			knownActor: "Ahrefs",
		},
		{
			name:       "openai search",
			userAgent:  "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot",
			family:     "openai",
			actorType:  "crawler",
			knownActor: "OpenAI",
		},
		{
			name:       "uptime robot",
			userAgent:  "UptimeRobot/2.0",
			family:     "uptimerobot",
			actorType:  "monitor",
			knownActor: "UptimeRobot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, ok := MatchUserAgent(tt.userAgent)
			if !ok {
				t.Fatalf("MatchUserAgent() did not match")
			}
			if match.Family != tt.family || match.ActorType != tt.actorType || match.KnownActor != tt.knownActor {
				t.Fatalf("MatchUserAgent() = (%q, %q, %q), want (%q, %q, %q)",
					match.Family, match.ActorType, match.KnownActor, tt.family, tt.actorType, tt.knownActor)
			}
			if match.RiskScore <= 0 {
				t.Fatalf("RiskScore = %d, want positive", match.RiskScore)
			}
		})
	}
}

func TestMatchReverseDNS(t *testing.T) {
	tests := []struct {
		name       string
		names      []string
		actorType  string
		knownActor string
	}{
		{
			name:       "googlebot suffix",
			names:      []string{"crawl-66-249-66-1.googlebot.com."},
			actorType:  "crawler",
			knownActor: "Google",
		},
		{
			name:       "addsearch contains",
			names:      []string{"crawler-1.addsearch.example"},
			actorType:  "crawler",
			knownActor: "AddSearch",
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
			match, ok := MatchReverseDNS(tt.names)
			if !ok {
				t.Fatalf("MatchReverseDNS() did not match")
			}
			if match.ActorType != tt.actorType || match.KnownActor != tt.knownActor {
				t.Fatalf("MatchReverseDNS() = (%q, %q), want (%q, %q)",
					match.ActorType, match.KnownActor, tt.actorType, tt.knownActor)
			}
		})
	}
}

func TestMatchASNOrg(t *testing.T) {
	match, ok := MatchASNOrg("AHREFS PTE. LTD.")
	if !ok {
		t.Fatalf("MatchASNOrg() did not match")
	}
	if match.KnownActor != "Ahrefs" || match.ActorType != "crawler" {
		t.Fatalf("MatchASNOrg() = (%q, %q), want Ahrefs crawler", match.KnownActor, match.ActorType)
	}
}

func TestMatchASNOrgPrefersCloudProvider(t *testing.T) {
	match, ok := MatchASNOrg("AMAZON-AES")
	if !ok {
		t.Fatalf("MatchASNOrg() did not match")
	}
	if match.KnownActor != "AWS" || match.ActorType != "datacenter" {
		t.Fatalf("MatchASNOrg() = (%q, %q), want AWS datacenter", match.KnownActor, match.ActorType)
	}
}
