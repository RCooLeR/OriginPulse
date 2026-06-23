package servicefingerprints

import "strings"

type Fingerprint struct {
	ID                 string
	Family             string
	KnownActor         string
	ActorType          string
	RiskScore          int
	UserAgentContains  []string
	ReverseDNSContains []string
	ReverseDNSSuffixes []string
	ASNOrgContains     []string
}

type Match struct {
	ID         string
	Family     string
	KnownActor string
	ActorType  string
	RiskScore  int
}

var catalog = []Fingerprint{
	{
		ID:                 "pantheon",
		Family:             "pantheon",
		KnownActor:         "Pantheon",
		ActorType:          "platform",
		RiskScore:          10,
		ReverseDNSContains: []string{"pantheon"},
		ASNOrgContains:     []string{"pantheon"},
	},
	{
		ID:                 "google",
		Family:             "googlebot",
		KnownActor:         "Google",
		ActorType:          "crawler",
		RiskScore:          25,
		UserAgentContains:  []string{"googlebot", "google-inspectiontool", "googleother", "adsbot-google", "mediapartners-google", "apis-google"},
		ReverseDNSSuffixes: []string{"googlebot.com", "google.com"},
	},
	{
		ID:                 "bing",
		Family:             "bingbot",
		KnownActor:         "Bing",
		ActorType:          "crawler",
		RiskScore:          25,
		UserAgentContains:  []string{"bingbot", "msnbot", "bingpreview"},
		ReverseDNSSuffixes: []string{"search.msn.com", "bing.com", "msn.com"},
	},
	{
		ID:                 "meta",
		Family:             "facebook",
		KnownActor:         "Meta",
		ActorType:          "crawler",
		RiskScore:          30,
		UserAgentContains:  []string{"facebookexternalhit", "facebot", "facebookcatalog", "facebookbot", "meta-externalagent"},
		ReverseDNSSuffixes: []string{"facebook.com", "fbsv.net", "meta.com"},
		ASNOrgContains:     []string{"facebook", "meta platforms"},
	},
	{
		ID:                 "applebot",
		Family:             "applebot",
		KnownActor:         "Apple",
		ActorType:          "crawler",
		RiskScore:          30,
		UserAgentContains:  []string{"applebot"},
		ReverseDNSSuffixes: []string{"applebot.apple.com", "apple.com"},
		ASNOrgContains:     []string{"apple"},
	},
	{
		ID:                 "duckduckgo",
		Family:             "duckduckbot",
		KnownActor:         "DuckDuckGo",
		ActorType:          "crawler",
		RiskScore:          30,
		UserAgentContains:  []string{"duckduckbot", "duckassistbot"},
		ReverseDNSSuffixes: []string{"duckduckgo.com"},
		ASNOrgContains:     []string{"duck duck go", "duckduckgo"},
	},
	{
		ID:                 "yahoo-slurp",
		Family:             "slurp",
		KnownActor:         "Yahoo",
		ActorType:          "crawler",
		RiskScore:          35,
		UserAgentContains:  []string{"yahoo! slurp", "yahoo slurp", "slurp"},
		ReverseDNSSuffixes: []string{"crawl.yahoo.net", "yahoo.net", "yahoo.com"},
		ASNOrgContains:     []string{"yahoo"},
	},
	{
		ID:                "ask-teoma",
		Family:            "teoma",
		KnownActor:        "Ask",
		ActorType:         "crawler",
		RiskScore:         45,
		UserAgentContains: []string{"ask jeeves/teoma", "teoma"},
		ASNOrgContains:    []string{"ask.com", "iac search"},
	},
	{
		ID:                "aolbot",
		Family:            "aolbot",
		KnownActor:        "AOL",
		ActorType:         "crawler",
		RiskScore:         40,
		UserAgentContains: []string{"aolbot", "aolbot-news"},
		ASNOrgContains:    []string{"aol"},
	},
	{
		ID:                 "yandex",
		Family:             "yandex",
		KnownActor:         "Yandex",
		ActorType:          "crawler",
		RiskScore:          45,
		UserAgentContains:  []string{"yandexbot", "yandeximages", "yandexaccessibilitybot"},
		ReverseDNSSuffixes: []string{"yandex.ru", "yandex.net", "yandex.com"},
		ASNOrgContains:     []string{"yandex"},
	},
	{
		ID:                 "baidu",
		Family:             "baidu",
		KnownActor:         "Baidu",
		ActorType:          "crawler",
		RiskScore:          45,
		UserAgentContains:  []string{"baiduspider"},
		ReverseDNSSuffixes: []string{"baidu.com", "baidu.jp"},
		ASNOrgContains:     []string{"baidu"},
	},
	{
		ID:                 "ahrefs",
		Family:             "ahrefs",
		KnownActor:         "Ahrefs",
		ActorType:          "crawler",
		RiskScore:          45,
		UserAgentContains:  []string{"ahrefsbot", "ahrefssiteaudit"},
		ReverseDNSContains: []string{"ahrefs"},
		ASNOrgContains:     []string{"ahrefs"},
	},
	{
		ID:                 "semrush",
		Family:             "semrush",
		KnownActor:         "Semrush",
		ActorType:          "crawler",
		RiskScore:          45,
		UserAgentContains:  []string{"semrushbot", "semrush"},
		ReverseDNSContains: []string{"semrush"},
		ASNOrgContains:     []string{"semrush"},
	},
	{
		ID:                 "addsearch",
		Family:             "addsearch",
		KnownActor:         "AddSearch",
		ActorType:          "crawler",
		RiskScore:          35,
		UserAgentContains:  []string{"addsearchbot"},
		ReverseDNSContains: []string{"addsearch"},
		ASNOrgContains:     []string{"addsearch"},
	},
	{
		ID:                 "commoncrawl",
		Family:             "commoncrawl",
		KnownActor:         "Common Crawl",
		ActorType:          "crawler",
		RiskScore:          35,
		UserAgentContains:  []string{"ccbot"},
		ReverseDNSContains: []string{"commoncrawl"},
		ASNOrgContains:     []string{"common crawl"},
	},
	{
		ID:                 "moz",
		Family:             "moz",
		KnownActor:         "Moz",
		ActorType:          "crawler",
		RiskScore:          45,
		UserAgentContains:  []string{"dotbot"},
		ReverseDNSContains: []string{"moz.com"},
		ASNOrgContains:     []string{"moz"},
	},
	{
		ID:                "mj12",
		Family:            "mj12",
		KnownActor:        "Majestic",
		ActorType:         "crawler",
		RiskScore:         45,
		UserAgentContains: []string{"mj12bot"},
		ASNOrgContains:    []string{"majestic"},
	},
	{
		ID:                "screaming-frog",
		Family:            "screaming-frog",
		KnownActor:        "Screaming Frog",
		ActorType:         "crawler",
		RiskScore:         50,
		UserAgentContains: []string{"screaming frog seo spider"},
		ASNOrgContains:    []string{"screaming frog"},
	},
	{
		ID:                "sitebulb",
		Family:            "sitebulb",
		KnownActor:        "Sitebulb",
		ActorType:         "crawler",
		RiskScore:         50,
		UserAgentContains: []string{"sitebulb"},
		ASNOrgContains:    []string{"sitebulb"},
	},
	{
		ID:                "blexbot",
		Family:            "blexbot",
		KnownActor:        "BLEXBot",
		ActorType:         "crawler",
		RiskScore:         50,
		UserAgentContains: []string{"blexbot"},
	},
	{
		ID:                "openai",
		Family:            "openai",
		KnownActor:        "OpenAI",
		ActorType:         "crawler",
		RiskScore:         40,
		UserAgentContains: []string{"gptbot", "chatgpt-user", "oai-searchbot"},
		ASNOrgContains:    []string{"openai"},
	},
	{
		ID:                "anthropic",
		Family:            "anthropic",
		KnownActor:        "Anthropic",
		ActorType:         "crawler",
		RiskScore:         40,
		UserAgentContains: []string{"claudebot", "claude-web", "claude-searchbot", "anthropic-ai"},
		ASNOrgContains:    []string{"anthropic"},
	},
	{
		ID:                "perplexity",
		Family:            "perplexity",
		KnownActor:        "Perplexity",
		ActorType:         "crawler",
		RiskScore:         40,
		UserAgentContains: []string{"perplexitybot", "perplexity-user"},
		ASNOrgContains:    []string{"perplexity"},
	},
	{
		ID:                "bytespider",
		Family:            "bytespider",
		KnownActor:        "ByteDance",
		ActorType:         "crawler",
		RiskScore:         45,
		UserAgentContains: []string{"bytespider"},
		ASNOrgContains:    []string{"bytedance"},
	},
	{
		ID:                "amazonbot",
		Family:            "amazonbot",
		KnownActor:        "Amazon",
		ActorType:         "crawler",
		RiskScore:         40,
		UserAgentContains: []string{"amazonbot"},
	},
	{
		ID:                "pingdom",
		Family:            "pingdom",
		KnownActor:        "Pingdom",
		ActorType:         "monitor",
		RiskScore:         20,
		UserAgentContains: []string{"pingdom"},
		ASNOrgContains:    []string{"pingdom"},
	},
	{
		ID:                "uptimerobot",
		Family:            "uptimerobot",
		KnownActor:        "UptimeRobot",
		ActorType:         "monitor",
		RiskScore:         20,
		UserAgentContains: []string{"uptimerobot", "uptime robot"},
		ASNOrgContains:    []string{"uptimerobot"},
	},
	{
		ID:                "statuscake",
		Family:            "statuscake",
		KnownActor:        "StatusCake",
		ActorType:         "monitor",
		RiskScore:         20,
		UserAgentContains: []string{"statuscake"},
		ASNOrgContains:    []string{"statuscake"},
	},
	{
		ID:                "datadog",
		Family:            "datadog",
		KnownActor:        "Datadog",
		ActorType:         "monitor",
		RiskScore:         20,
		UserAgentContains: []string{"datadog"},
		ASNOrgContains:    []string{"datadog"},
	},
	{
		ID:                "newrelic",
		Family:            "newrelic",
		KnownActor:        "New Relic",
		ActorType:         "monitor",
		RiskScore:         20,
		UserAgentContains: []string{"newrelic", "new relic"},
		ASNOrgContains:    []string{"new relic"},
	},
	{
		ID:                 "aws",
		Family:             "aws",
		KnownActor:         "AWS",
		ActorType:          "datacenter",
		RiskScore:          55,
		ReverseDNSSuffixes: []string{"amazonaws.com"},
		ASNOrgContains:     []string{"amazon"},
	},
	{
		ID:                 "google-cloud",
		Family:             "google-cloud",
		KnownActor:         "Google Cloud",
		ActorType:          "datacenter",
		RiskScore:          55,
		ReverseDNSSuffixes: []string{"googleusercontent.com"},
		ASNOrgContains:     []string{"google cloud"},
	},
	{
		ID:                 "azure",
		Family:             "azure",
		KnownActor:         "Azure",
		ActorType:          "datacenter",
		RiskScore:          55,
		ReverseDNSSuffixes: []string{"azure.com", "cloudapp.net", "trafficmanager.net"},
		ASNOrgContains:     []string{"microsoft azure"},
	},
	{
		ID:                 "cloudflare",
		Family:             "cloudflare",
		KnownActor:         "Cloudflare",
		ActorType:          "datacenter",
		RiskScore:          45,
		ReverseDNSSuffixes: []string{"cloudflare.com"},
		ASNOrgContains:     []string{"cloudflare"},
	},
	{
		ID:                 "fastly",
		Family:             "fastly",
		KnownActor:         "Fastly",
		ActorType:          "datacenter",
		RiskScore:          45,
		ReverseDNSSuffixes: []string{"fastly.net"},
		ASNOrgContains:     []string{"fastly"},
	},
	{
		ID:                 "akamai",
		Family:             "akamai",
		KnownActor:         "Akamai",
		ActorType:          "datacenter",
		RiskScore:          45,
		ReverseDNSSuffixes: []string{"akamai.com", "akamaitechnologies.com", "akamaiedge.net"},
		ASNOrgContains:     []string{"akamai"},
	},
	{
		ID:                 "contabo",
		Family:             "contabo",
		KnownActor:         "Contabo",
		ActorType:          "datacenter",
		RiskScore:          65,
		ReverseDNSContains: []string{"contabo"},
		ASNOrgContains:     []string{"contabo"},
	},
	{
		ID:                "sqlmap",
		Family:            "sqlmap",
		KnownActor:        "sqlmap",
		ActorType:         "malicious",
		RiskScore:         95,
		UserAgentContains: []string{"sqlmap"},
	},
	{
		ID:                "nikto",
		Family:            "nikto",
		KnownActor:        "Nikto",
		ActorType:         "malicious",
		RiskScore:         95,
		UserAgentContains: []string{"nikto"},
	},
	{
		ID:                "nuclei",
		Family:            "nuclei",
		KnownActor:        "Nuclei",
		ActorType:         "malicious",
		RiskScore:         95,
		UserAgentContains: []string{"nuclei"},
	},
	{
		ID:                "masscan",
		Family:            "masscan",
		KnownActor:        "masscan",
		ActorType:         "malicious",
		RiskScore:         95,
		UserAgentContains: []string{"masscan"},
	},
	{
		ID:                "zgrab",
		Family:            "zgrab",
		KnownActor:        "zgrab",
		ActorType:         "malicious",
		RiskScore:         90,
		UserAgentContains: []string{"zgrab", "zmap"},
	},
	{
		ID:                "dirbuster",
		Family:            "dirbuster",
		KnownActor:        "Directory scanner",
		ActorType:         "malicious",
		RiskScore:         90,
		UserAgentContains: []string{"dirbuster", "gobuster", "ffuf", "dirsearch", "feroxbuster"},
	},
	{
		ID:                "wpscan",
		Family:            "wpscan",
		KnownActor:        "WPScan",
		ActorType:         "malicious",
		RiskScore:         90,
		UserAgentContains: []string{"wpscan"},
	},
	{
		ID:                "vulnerability-scanner",
		Family:            "vulnerability-scanner",
		KnownActor:        "Vulnerability scanner",
		ActorType:         "malicious",
		RiskScore:         90,
		UserAgentContains: []string{"acunetix", "nessus", "openvas", "netsparker", "burpcollaborator", "burp suite"},
	},
}

func MatchUserAgent(value string) (Match, bool) {
	value = normalize(value)
	if value == "" {
		return Match{}, false
	}
	for _, fingerprint := range catalog {
		if containsAny(value, fingerprint.UserAgentContains) {
			return fingerprint.match(), true
		}
	}
	return Match{}, false
}

func MatchReverseDNS(names []string) (Match, bool) {
	for _, name := range names {
		name = normalizeHost(name)
		if name == "" {
			continue
		}
		for _, fingerprint := range catalog {
			if containsAny(name, fingerprint.ReverseDNSContains) || hasHostSuffixAny(name, fingerprint.ReverseDNSSuffixes) {
				return fingerprint.match(), true
			}
		}
	}
	return Match{}, false
}

func MatchASNOrg(value string) (Match, bool) {
	value = normalize(value)
	if value == "" {
		return Match{}, false
	}
	for _, fingerprint := range catalog {
		if containsAny(value, fingerprint.ASNOrgContains) {
			return fingerprint.match(), true
		}
	}
	return Match{}, false
}

func (f Fingerprint) match() Match {
	return Match{
		ID:         f.ID,
		Family:     f.Family,
		KnownActor: f.KnownActor,
		ActorType:  f.ActorType,
		RiskScore:  f.RiskScore,
	}
}

func containsAny(value string, needles []string) bool {
	for _, needle := range needles {
		if needle = normalize(needle); needle != "" && strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func hasHostSuffixAny(host string, suffixes []string) bool {
	for _, suffix := range suffixes {
		suffix = normalizeHost(suffix)
		if suffix == "" {
			continue
		}
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeHost(value string) string {
	return strings.TrimSuffix(normalize(value), ".")
}
