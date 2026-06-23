package useragent

import "testing"

func TestAnalyzeBrowserAndOS(t *testing.T) {
	got := Analyze("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36", 12)
	if got.Family != "Chrome" || got.ActorType != "browser" {
		t.Fatalf("family/actor = %q/%q, want Chrome/browser", got.Family, got.ActorType)
	}
	if got.BrowserFamily != "Chrome" || got.BrowserVersion != "126.0.6478" {
		t.Fatalf("browser = %q %q, want Chrome 126.0.6478", got.BrowserFamily, got.BrowserVersion)
	}
	if got.OSFamily != "Windows" || got.OSVersion != "10/11" || got.DeviceFamily != "Desktop" {
		t.Fatalf("os/device = %q %q %q, want Windows 10/11 Desktop", got.OSFamily, got.OSVersion, got.DeviceFamily)
	}
}

func TestAnalyzeKnownCrawler(t *testing.T) {
	got := Analyze("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", 500)
	if got.Family != "ahrefs" || got.ActorType != "crawler" || got.KnownActor != "Ahrefs" {
		t.Fatalf("known crawler = %q/%q/%q, want ahrefs/crawler/Ahrefs", got.Family, got.ActorType, got.KnownActor)
	}
	if !got.IsBot || got.IsTool {
		t.Fatalf("bot/tool = %v/%v, want true/false", got.IsBot, got.IsTool)
	}
}

func TestAnalyzeTool(t *testing.T) {
	got := Analyze("curl/8.7.1", 3)
	if got.Family != "curl" || got.ActorType != "tool" || got.BrowserVersion != "8.7.1" {
		t.Fatalf("tool = %q/%q/%q, want curl/tool/8.7.1", got.Family, got.ActorType, got.BrowserVersion)
	}
	if got.IsBot || !got.IsTool {
		t.Fatalf("bot/tool = %v/%v, want false/true", got.IsBot, got.IsTool)
	}
}

func TestAnalyzeMobileSafari(t *testing.T) {
	got := Analyze("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1", 20)
	if got.Family != "Safari" || got.BrowserFamily != "Safari" || got.BrowserVersion != "17.5" {
		t.Fatalf("browser = %q/%q/%q, want Safari/Safari/17.5", got.Family, got.BrowserFamily, got.BrowserVersion)
	}
	if got.OSFamily != "iOS" || got.OSVersion != "17.5" || got.DeviceFamily != "Mobile" {
		t.Fatalf("os/device = %q %q %q, want iOS 17.5 Mobile", got.OSFamily, got.OSVersion, got.DeviceFamily)
	}
}

func TestAnalyzeEdgeBrowser(t *testing.T) {
	got := Analyze("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.87", 20)
	if got.Family != "Microsoft Edge" || got.BrowserFamily != "Microsoft Edge" || got.BrowserVersion != "126.0.2592" {
		t.Fatalf("browser = %q/%q/%q, want Microsoft Edge/Microsoft Edge/126.0.2592", got.Family, got.BrowserFamily, got.BrowserVersion)
	}
	if got.ActorType != "browser" || got.IsBot || got.IsTool {
		t.Fatalf("actor/bot/tool = %q/%v/%v, want browser/false/false", got.ActorType, got.IsBot, got.IsTool)
	}
}

func TestAnalyzePythonRequestsTool(t *testing.T) {
	got := Analyze("python-requests/2.32.3", 5)
	if got.Family != "python-requests" || got.ActorType != "tool" || got.BrowserVersion != "2.32.3" {
		t.Fatalf("tool = %q/%q/%q, want python-requests/tool/2.32.3", got.Family, got.ActorType, got.BrowserVersion)
	}
	if !got.IsTool || got.IsBot {
		t.Fatalf("tool/bot = %v/%v, want true/false", got.IsTool, got.IsBot)
	}
}

func TestAnalyzeKnownMaliciousScanner(t *testing.T) {
	got := Analyze("sqlmap/1.8.7#stable (https://sqlmap.org)", 1)
	if got.Family != "sqlmap" || got.ActorType != "malicious" || got.KnownActor != "sqlmap" {
		t.Fatalf("scanner = %q/%q/%q, want sqlmap/malicious/sqlmap", got.Family, got.ActorType, got.KnownActor)
	}
	if got.RiskScore < 90 {
		t.Fatalf("RiskScore = %d, want high scanner risk", got.RiskScore)
	}
}

func TestAnalyzeLegacySearchBots(t *testing.T) {
	tests := []struct {
		agent string
		actor string
	}{
		{"Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)", "Yahoo"},
		{"Mozilla/2.0 (compatible; Ask Jeeves/Teoma)", "Ask"},
		{"Aolbot-News/1.0", "AOL"},
		{"msnbot/2.0b (+http://search.msn.com/msnbot.htm)", "Bing"},
	}
	for _, tt := range tests {
		got := Analyze(tt.agent, 1)
		if got.ActorType != "crawler" || got.KnownActor != tt.actor {
			t.Fatalf("Analyze(%q) = %q/%q, want crawler/%s", tt.agent, got.ActorType, got.KnownActor, tt.actor)
		}
	}
}
