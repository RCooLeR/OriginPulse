package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultPipelineUsesParallelIndexing(t *testing.T) {
	cfg := Default()
	if cfg.Pipeline.IndexWorkers != 2 {
		t.Fatalf("Pipeline.IndexWorkers = %d, want 2", cfg.Pipeline.IndexWorkers)
	}
	if cfg.Pipeline.MaxSegments != 500 {
		t.Fatalf("Pipeline.MaxSegments = %d, want 500", cfg.Pipeline.MaxSegments)
	}
}

func TestDefaultRetentionMatchesCurrentStoragePlan(t *testing.T) {
	cfg := Default()

	tests := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{name: "raw files", got: cfg.Retention.RawFileMaxAge, want: 14 * 24 * time.Hour},
		{name: "hot events", got: cfg.Retention.HotEventMaxAge, want: 60 * 24 * time.Hour},
		{name: "daily archive after", got: cfg.Retention.DailyArchiveAfter, want: 7 * 24 * time.Hour},
		{name: "weekly archive after", got: cfg.Retention.WeeklyArchiveAfter, want: 30 * 24 * time.Hour},
		{name: "archive retention", got: cfg.Retention.ArchiveMaxAge, want: 90 * 24 * time.Hour},
		{name: "serialized reports", got: cfg.Retention.ReportMaxAge, want: 5 * 365 * 24 * time.Hour},
		{name: "temporary imports", got: cfg.Retention.TemporaryImportMaxAge, want: 7 * 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %s, want %s", tt.name, tt.got, tt.want)
			}
		})
	}

	if !cfg.Retention.DeleteRawFiles {
		t.Fatal("raw files should be removed after the intake buffer by default")
	}
	if !cfg.Retention.DeleteHotEvents {
		t.Fatal("hot access events should expire by default")
	}
	if !cfg.Retention.DeleteTemporaryImports {
		t.Fatal("temporary archive imports should expire by default")
	}
	if cfg.Retention.DeleteRollups {
		t.Fatal("rollups should be retained by default for long-horizon dashboards")
	}
}

func TestDefaultGeoIPCanSeedBeforeMaxMindDownload(t *testing.T) {
	cfg := Default()
	if filepath.ToSlash(filepath.Clean(cfg.GeoIP.SeedPath)) != "assets/geoip/GeoLite2-City.mmdb" {
		t.Fatalf("GeoIP.SeedPath = %q, want bundled GeoLite2-City seed", cfg.GeoIP.SeedPath)
	}
	if cfg.GeoIP.SeedPathEnv != "GEOIP_SEED_PATH" {
		t.Fatalf("GeoIP.SeedPathEnv = %q, want GEOIP_SEED_PATH", cfg.GeoIP.SeedPathEnv)
	}
	if cfg.GeoIP.AccountIDEnv != "MAXMIND_ACCOUNT_ID" || cfg.GeoIP.LicenseKeyEnv != "MAXMIND_LICENSE_KEY" {
		t.Fatalf("MaxMind credential envs = %q/%q", cfg.GeoIP.AccountIDEnv, cfg.GeoIP.LicenseKeyEnv)
	}
	if !strings.Contains(cfg.GeoIP.DownloadURL, "GeoLite2-City") {
		t.Fatalf("GeoIP.DownloadURL = %q, want GeoLite2-City download", cfg.GeoIP.DownloadURL)
	}
}

func TestDefaultIPIntelBackgroundRefresh(t *testing.T) {
	cfg := Default()
	if !cfg.IPIntel.Enabled {
		t.Fatal("IP intel background refresh should be enabled by default")
	}
	if cfg.IPIntel.Interval != 15*time.Minute {
		t.Fatalf("IPIntel.Interval = %s, want 15m", cfg.IPIntel.Interval)
	}
	if cfg.IPIntel.Range != "24h" {
		t.Fatalf("IPIntel.Range = %q, want 24h", cfg.IPIntel.Range)
	}
	if cfg.IPIntel.Limit != 500 {
		t.Fatalf("IPIntel.Limit = %d, want 500", cfg.IPIntel.Limit)
	}
	if !cfg.IPIntel.StartupBackfill {
		t.Fatal("IP intel startup backfill should be enabled by default")
	}
	if cfg.IPIntel.StartupBackfillRange != "365d" {
		t.Fatalf("IPIntel.StartupBackfillRange = %q, want 365d", cfg.IPIntel.StartupBackfillRange)
	}
	if cfg.IPIntel.StartupBackfillLimit != 5000 {
		t.Fatalf("IPIntel.StartupBackfillLimit = %d, want 5000", cfg.IPIntel.StartupBackfillLimit)
	}
	if cfg.IPIntel.StartupUserAgentLimit != 50000 {
		t.Fatalf("IPIntel.StartupUserAgentLimit = %d, want 50000", cfg.IPIntel.StartupUserAgentLimit)
	}
}

func TestLocalSiteDoesNotRequirePantheonSiteID(t *testing.T) {
	cfg := Default()
	cfg.Sites = []SiteConfig{{
		ID:         "example-apache-site",
		Name:       "Example Apache Site",
		SourceType: "local",
		LocalPath:  "./tmp/example.com",
		Enabled:    true,
		Envs:       []string{"live"},
	}}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate local site: %v", err)
	}
	if got := cfg.Sites[0].SourceType; got != "local" {
		t.Fatalf("SourceType = %q, want local", got)
	}
}

func TestLocalSiteCanBeInferredFromLocalPath(t *testing.T) {
	cfg := Default()
	cfg.Sites = []SiteConfig{{
		ID:        "apache-direct",
		Name:      "Apache Direct",
		LocalPath: "./tmp/apache-direct",
		Enabled:   true,
	}}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate inferred local site: %v", err)
	}
	if got := cfg.Sites[0].SourceType; got != "local" {
		t.Fatalf("SourceType = %q, want local", got)
	}
}

func TestLocalSiteValidatesFilenameMasks(t *testing.T) {
	cfg := Default()
	cfg.Sites = []SiteConfig{{
		ID:            "apache-direct",
		Name:          "Apache Direct",
		SourceType:    "local",
		LocalPath:     "./tmp/apache-direct",
		FilenameMasks: []string{"["},
		Enabled:       true,
	}}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid filename mask error")
	}
}
