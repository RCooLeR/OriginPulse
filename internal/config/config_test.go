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
}

func TestDefaultRetentionMatchesScenarioCStoragePlan(t *testing.T) {
	cfg := Default()

	tests := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{name: "raw files", got: cfg.Retention.RawFileMaxAge, want: 14 * 24 * time.Hour},
		{name: "hot events", got: cfg.Retention.HotEventMaxAge, want: 90 * 24 * time.Hour},
		{name: "daily archive after", got: cfg.Retention.DailyArchiveAfter, want: 14 * 24 * time.Hour},
		{name: "weekly archive after", got: cfg.Retention.WeeklyArchiveAfter, want: 90 * 24 * time.Hour},
		{name: "weekly archive retention", got: cfg.Retention.ArchiveMaxAge, want: 2 * 365 * 24 * time.Hour},
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
