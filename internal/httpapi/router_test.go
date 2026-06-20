package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"originpulse/internal/accessanalysis"
	"originpulse/internal/alerts"
	"originpulse/internal/combiner"
	"originpulse/internal/config"
	"originpulse/internal/geoip"
	"originpulse/internal/investigation"
	"originpulse/internal/ipintel"
	"originpulse/internal/notifications"
	"originpulse/internal/pantheon"
	"originpulse/internal/reports"
)

func TestPipelineRequestOptionsIncludesIndexWorkers(t *testing.T) {
	from := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	req := pipelineRequest{
		Force:        true,
		SkipCombine:  true,
		LogTypes:     []string{"nginx-access", "php-error"},
		MaxSegments:  17,
		IndexWorkers: 4,
	}

	opts := req.options(from, to)
	if !opts.From.Equal(from) || !opts.To.Equal(to) {
		t.Fatalf("time range = %s..%s, want %s..%s", opts.From, opts.To, from, to)
	}
	if !opts.Force || !opts.SkipCombine {
		t.Fatal("boolean pipeline controls were not carried into options")
	}
	if opts.MaxSegments != 17 {
		t.Fatalf("MaxSegments = %d, want 17", opts.MaxSegments)
	}
	if opts.IndexWorkers != 4 {
		t.Fatalf("IndexWorkers = %d, want 4", opts.IndexWorkers)
	}
	if len(opts.LogTypes) != 2 {
		t.Fatalf("LogTypes = %#v, want 2 entries", opts.LogTypes)
	}
	if opts.TriggeredBy != "api" {
		t.Fatalf("TriggeredBy = %q, want api", opts.TriggeredBy)
	}
}

func TestRetentionUnavailableResultKeepsConfiguredPolicy(t *testing.T) {
	cfg := config.Default()
	result := retentionUnavailableResult(cfg, true)

	if result.Enabled {
		t.Fatal("disabled retention result reported enabled")
	}
	if !result.DryRun {
		t.Fatal("disabled retention result did not preserve dry-run status")
	}
	if result.RawFileMaxAge != cfg.Retention.RawFileMaxAge.String() {
		t.Fatalf("RawFileMaxAge = %q, want %q", result.RawFileMaxAge, cfg.Retention.RawFileMaxAge)
	}
	if result.HotEventMaxAge != cfg.Retention.HotEventMaxAge.String() {
		t.Fatalf("HotEventMaxAge = %q, want %q", result.HotEventMaxAge, cfg.Retention.HotEventMaxAge)
	}
	if result.ArchiveMaxAge != cfg.Retention.ArchiveMaxAge.String() {
		t.Fatalf("ArchiveMaxAge = %q, want %q", result.ArchiveMaxAge, cfg.Retention.ArchiveMaxAge)
	}
	if result.ReportMaxAge != cfg.Retention.ReportMaxAge.String() {
		t.Fatalf("ReportMaxAge = %q, want %q", result.ReportMaxAge, cfg.Retention.ReportMaxAge)
	}
	if result.TemporaryImportMaxAge != cfg.Retention.TemporaryImportMaxAge.String() {
		t.Fatalf("TemporaryImportMaxAge = %q, want %q", result.TemporaryImportMaxAge, cfg.Retention.TemporaryImportMaxAge)
	}
}

func TestStorageAuditUnavailableReportKeepsConfiguredRetentionPolicy(t *testing.T) {
	cfg := config.Default()
	report := storageAuditUnavailableReport(cfg)

	if report.Enabled {
		t.Fatal("disabled storage audit report reported enabled")
	}
	if report.Retention.Enabled != cfg.Retention.Enabled {
		t.Fatalf("Retention.Enabled = %v, want %v", report.Retention.Enabled, cfg.Retention.Enabled)
	}
	if report.Retention.RawFileMaxAge != cfg.Retention.RawFileMaxAge.String() {
		t.Fatalf("RawFileMaxAge = %q, want %q", report.Retention.RawFileMaxAge, cfg.Retention.RawFileMaxAge)
	}
	if report.Retention.HotEventMaxAge != cfg.Retention.HotEventMaxAge.String() {
		t.Fatalf("HotEventMaxAge = %q, want %q", report.Retention.HotEventMaxAge, cfg.Retention.HotEventMaxAge)
	}
	if report.Retention.DailyArchiveAfter != cfg.Retention.DailyArchiveAfter.String() {
		t.Fatalf("DailyArchiveAfter = %q, want %q", report.Retention.DailyArchiveAfter, cfg.Retention.DailyArchiveAfter)
	}
	if report.Retention.WeeklyArchiveAfter != cfg.Retention.WeeklyArchiveAfter.String() {
		t.Fatalf("WeeklyArchiveAfter = %q, want %q", report.Retention.WeeklyArchiveAfter, cfg.Retention.WeeklyArchiveAfter)
	}
	if report.Retention.ArchiveMaxAge != cfg.Retention.ArchiveMaxAge.String() {
		t.Fatalf("ArchiveMaxAge = %q, want %q", report.Retention.ArchiveMaxAge, cfg.Retention.ArchiveMaxAge)
	}
	if report.Retention.ReportMaxAge != cfg.Retention.ReportMaxAge.String() {
		t.Fatalf("ReportMaxAge = %q, want %q", report.Retention.ReportMaxAge, cfg.Retention.ReportMaxAge)
	}
	if report.Retention.TemporaryImportMaxAge != cfg.Retention.TemporaryImportMaxAge.String() {
		t.Fatalf("TemporaryImportMaxAge = %q, want %q", report.Retention.TemporaryImportMaxAge, cfg.Retention.TemporaryImportMaxAge)
	}
}

func TestGeoIPStatusReportsDisabledWhenUpdaterMissing(t *testing.T) {
	cfg := config.Default()
	cfg.GeoIP.Enabled = false
	api := API{cfg: cfg}
	rec := httptest.NewRecorder()

	api.geoIPStatus(rec, httptest.NewRequest("GET", "/api/v1/system/geoip", nil))

	var status geoip.Status
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.Enabled || status.Loaded {
		t.Fatalf("status = enabled:%v loaded:%v, want disabled/unloaded", status.Enabled, status.Loaded)
	}
}

func TestParseLimitUsesDeeperDashboardDefaults(t *testing.T) {
	tests := []struct {
		name        string
		defaultSize int
		maxSize     int
	}{
		{name: "access analysis", defaultSize: 100, maxSize: accessanalysis.ResultMaxLimit},
		{name: "traffic investigation", defaultSize: 100, maxSize: investigation.DetailMaxLimit},
		{name: "ip detail drawer", defaultSize: 50, maxSize: ipintel.DetailMaxLimit},
		{name: "user agent drawer", defaultSize: 50, maxSize: investigation.DetailMaxLimit},
		{name: "security signal drawer", defaultSize: 50, maxSize: investigation.DetailMaxLimit},
		{name: "alerts list", defaultSize: 100, maxSize: alerts.RecentMaxLimit},
		{name: "alert detail drawer", defaultSize: 100, maxSize: alerts.DetailMaxLimit},
		{name: "ip intel refresh", defaultSize: 100, maxSize: ipintel.ResultMaxLimit},
		{name: "report catalog", defaultSize: 100, maxSize: reports.RecentMaxLimit},
		{name: "notification history", defaultSize: 100, maxSize: notifications.RecentMaxLimit},
		{name: "raw files", defaultSize: 100, maxSize: pantheon.RawFileRecentMaxLimit},
		{name: "segments", defaultSize: 100, maxSize: combiner.RecentSegmentsMaxLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if got := parseLimit(req, tt.defaultSize, tt.maxSize); got != tt.defaultSize {
				t.Fatalf("default limit = %d, want %d", got, tt.defaultSize)
			}

			req = httptest.NewRequest("GET", "/?limit=999999", nil)
			if got := parseLimit(req, tt.defaultSize, tt.maxSize); got != tt.maxSize {
				t.Fatalf("clamped limit = %d, want %d", got, tt.maxSize)
			}
		})
	}
}

func TestParseOffset(t *testing.T) {
	tests := []struct {
		raw  string
		want int
	}{
		{raw: "", want: 0},
		{raw: "-5", want: 0},
		{raw: "bogus", want: 0},
		{raw: "24", want: 24},
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/?offset="+tt.raw, nil)
		if got := parseOffset(req); got != tt.want {
			t.Fatalf("parseOffset(%q) = %d, want %d", tt.raw, got, tt.want)
		}
	}
}

func TestParseNamedOffset(t *testing.T) {
	req := httptest.NewRequest("GET", "/?top_ip_offset=42", nil)
	if got := parseNamedOffset(req, "top_ip_offset"); got != 42 {
		t.Fatalf("parseNamedOffset(top_ip_offset) = %d, want 42", got)
	}

	req = httptest.NewRequest("GET", "/?offset=10&top_ip_offset=42", nil)
	if got := parseNamedOffset(req, "top_ip_offset"); got != 42 {
		t.Fatalf("parseNamedOffset(named with generic offset) = %d, want 42", got)
	}

	req = httptest.NewRequest("GET", "/?offset=10", nil)
	if got := parseNamedOffset(req, "top_ip_offset"); got != 10 {
		t.Fatalf("parseNamedOffset(generic fallback) = %d, want 10", got)
	}

	req = httptest.NewRequest("GET", "/?top_ip_offset=-1", nil)
	if got := parseNamedOffset(req, "top_ip_offset"); got != 0 {
		t.Fatalf("parseNamedOffset(negative) = %d, want 0", got)
	}
}
