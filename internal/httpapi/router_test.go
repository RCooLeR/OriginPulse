package httpapi

import (
	"net/http/httptest"
	"testing"
	"time"

	"originpulse/internal/accessanalysis"
	"originpulse/internal/alerts"
	"originpulse/internal/combiner"
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
