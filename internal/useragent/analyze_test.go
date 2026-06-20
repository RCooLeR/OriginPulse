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
