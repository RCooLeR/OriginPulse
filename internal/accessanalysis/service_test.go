package accessanalysis

import "testing"

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
			family:     "browser",
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
			family:     "python",
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
			family:     "unknown-high-volume",
			actorType:  "unknown",
			knownActor: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			family, actorType, knownActor, risk := classifyUserAgent(tt.userAgent, tt.requests)
			if family != tt.family || actorType != tt.actorType || knownActor != tt.knownActor {
				t.Fatalf("classifyUserAgent() = (%q, %q, %q, %d), want (%q, %q, %q, risk)",
					family, actorType, knownActor, risk, tt.family, tt.actorType, tt.knownActor)
			}
			if risk <= 0 {
				t.Fatalf("risk = %d, want positive", risk)
			}
		})
	}
}
