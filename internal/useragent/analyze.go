package useragent

import (
	"regexp"
	"strings"

	"originpulse/internal/servicefingerprints"
)

type Analysis struct {
	Family         string
	BrowserFamily  string
	BrowserVersion string
	OSFamily       string
	OSVersion      string
	DeviceFamily   string
	ActorType      string
	KnownActor     string
	IsBot          bool
	IsTool         bool
	RiskScore      int
}

func Analyze(value string, requests int64) Analysis {
	sample := strings.TrimSpace(value)
	lower := strings.ToLower(sample)
	if lower == "" {
		return Analysis{Family: "empty", ActorType: "missing", DeviceFamily: "unknown", RiskScore: 55}
	}

	out := Analysis{Family: readableToken(sample), ActorType: "unknown", DeviceFamily: "unknown", RiskScore: volumeRisk(requests)}
	if match, ok := servicefingerprints.MatchUserAgent(sample); ok {
		out.Family = match.Family
		out.KnownActor = match.KnownActor
		out.ActorType = match.ActorType
		out.RiskScore = match.RiskScore
		out.IsBot = match.ActorType == "crawler"
		out.IsTool = match.ActorType == "tool" || match.ActorType == "monitor"
	}

	browser, browserVersion := detectBrowser(sample)
	osFamily, osVersion := detectOS(sample)
	toolFamily, toolVersion := detectTool(sample)
	out.BrowserFamily = browser
	out.BrowserVersion = browserVersion
	out.OSFamily = osFamily
	out.OSVersion = osVersion
	out.DeviceFamily = detectDevice(sample, osFamily)

	switch {
	case toolFamily != "":
		out.Family = toolFamily
		if toolVersion != "" {
			out.BrowserVersion = toolVersion
		}
		if out.ActorType == "unknown" {
			out.ActorType = "tool"
		}
		out.IsTool = true
		if out.RiskScore < 60 {
			out.RiskScore = 65
		}
	case out.KnownActor != "":
		// Keep catalog classification.
	case browser != "":
		out.Family = browser
		if out.ActorType == "unknown" {
			out.ActorType = "browser"
		}
		if out.RiskScore > 30 {
			out.RiskScore = 15
		}
	case strings.Contains(lower, "bot") || strings.Contains(lower, "spider") || strings.Contains(lower, "crawler"):
		out.Family = "generic-crawler"
		if out.ActorType == "unknown" {
			out.ActorType = "crawler"
		}
		out.IsBot = true
		if out.RiskScore < 50 {
			out.RiskScore = 50
		}
	}

	if out.ActorType == "crawler" {
		out.IsBot = true
	}
	if out.ActorType == "tool" || out.ActorType == "monitor" {
		out.IsTool = true
	}
	return out
}

func detectBrowser(sample string) (string, string) {
	patterns := []struct {
		re   *regexp.Regexp
		name string
	}{
		{regexp.MustCompile(`(?i)EdgA?/([\d.]+)`), "Microsoft Edge"},
		{regexp.MustCompile(`(?i)OPR/([\d.]+)`), "Opera"},
		{regexp.MustCompile(`(?i)SamsungBrowser/([\d.]+)`), "Samsung Internet"},
		{regexp.MustCompile(`(?i)CriOS/([\d.]+)`), "Chrome iOS"},
		{regexp.MustCompile(`(?i)FxiOS/([\d.]+)`), "Firefox iOS"},
		{regexp.MustCompile(`(?i)Firefox/([\d.]+)`), "Firefox"},
		{regexp.MustCompile(`(?i)(?:Chrome|Chromium)/([\d.]+)`), "Chrome"},
		{regexp.MustCompile(`(?i)Version/([\d.]+).*Safari/`), "Safari"},
		{regexp.MustCompile(`(?i)MSIE\s([\d.]+)`), "Internet Explorer"},
		{regexp.MustCompile(`(?i)Trident/.*rv:([\d.]+)`), "Internet Explorer"},
	}
	for _, pattern := range patterns {
		if match := pattern.re.FindStringSubmatch(sample); len(match) > 1 {
			return pattern.name, normalizeVersion(match[1])
		}
	}
	return "", ""
}

func detectTool(sample string) (string, string) {
	patterns := []struct {
		re   *regexp.Regexp
		name string
	}{
		{regexp.MustCompile(`(?i)curl/([\d.]+)`), "curl"},
		{regexp.MustCompile(`(?i)Wget/([\d.]+)`), "Wget"},
		{regexp.MustCompile(`(?i)python-requests/([\d.]+)`), "python-requests"},
		{regexp.MustCompile(`(?i)aiohttp/([\d.]+)`), "aiohttp"},
		{regexp.MustCompile(`(?i)Go-http-client/([\d.]+)`), "go-http-client"},
		{regexp.MustCompile(`(?i)okhttp/([\d.]+)`), "okhttp"},
		{regexp.MustCompile(`(?i)Java/([\d.]+)`), "java-client"},
	}
	for _, pattern := range patterns {
		if match := pattern.re.FindStringSubmatch(sample); len(match) > 1 {
			return pattern.name, normalizeVersion(match[1])
		}
	}
	return "", ""
}

func detectOS(sample string) (string, string) {
	if match := regexp.MustCompile(`(?i)Windows NT ([\d.]+)`).FindStringSubmatch(sample); len(match) > 1 {
		return "Windows", windowsVersion(match[1])
	}
	if match := regexp.MustCompile(`(?i)Mac OS X ([\d_]+)`).FindStringSubmatch(sample); len(match) > 1 {
		return "macOS", strings.ReplaceAll(match[1], "_", ".")
	}
	if match := regexp.MustCompile(`(?i)(?:iPhone|CPU) OS ([\d_]+)`).FindStringSubmatch(sample); len(match) > 1 {
		return "iOS", strings.ReplaceAll(match[1], "_", ".")
	}
	if match := regexp.MustCompile(`(?i)Android ([\d.]+)`).FindStringSubmatch(sample); len(match) > 1 {
		return "Android", normalizeVersion(match[1])
	}
	if match := regexp.MustCompile(`(?i)CrOS [^ ]+ ([\d.]+)`).FindStringSubmatch(sample); len(match) > 1 {
		return "Chrome OS", normalizeVersion(match[1])
	}
	if strings.Contains(strings.ToLower(sample), "linux") {
		return "Linux", ""
	}
	return "", ""
}

func detectDevice(sample string, osFamily string) string {
	lower := strings.ToLower(sample)
	switch {
	case strings.Contains(lower, "ipad") || strings.Contains(lower, "tablet"):
		return "Tablet"
	case strings.Contains(lower, "mobile") || strings.Contains(lower, "iphone") || strings.Contains(lower, "android"):
		return "Mobile"
	case osFamily == "Windows" || osFamily == "macOS" || osFamily == "Linux" || osFamily == "Chrome OS":
		return "Desktop"
	default:
		return "unknown"
	}
}

func readableToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == '/' || r == ';' || r == '(' || r == ')' || r == ' '
	})
	if len(fields) == 0 || fields[0] == "" {
		return "unknown"
	}
	return strings.ToLower(fields[0])
}

func normalizeVersion(value string) string {
	parts := strings.Split(value, ".")
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return strings.Join(parts, ".")
}

func windowsVersion(value string) string {
	switch value {
	case "10.0":
		return "10/11"
	case "6.3":
		return "8.1"
	case "6.2":
		return "8"
	case "6.1":
		return "7"
	default:
		return value
	}
}

func volumeRisk(requests int64) int {
	switch {
	case requests >= 10000:
		return 60
	case requests >= 1000:
		return 45
	default:
		return 30
	}
}
