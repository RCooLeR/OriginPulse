package pipeline

import (
	"testing"
	"time"

	"originpulse/internal/combiner"
	"originpulse/internal/config"
)

func TestNormalizeOptionsUsesConfiguredWorkers(t *testing.T) {
	cfg := config.Default()
	cfg.Pipeline.IndexWorkers = 3
	cfg.Pipeline.MaxSegments = 700
	service := New(cfg, nil, nil, nil, nil)

	opts := service.normalizeOptions(Options{})
	if opts.IndexWorkers != 3 {
		t.Fatalf("IndexWorkers = %d, want 3", opts.IndexWorkers)
	}
	if opts.MaxSegments != 700 {
		t.Fatalf("MaxSegments = %d, want 700", opts.MaxSegments)
	}
}

func TestNormalizeOptionsClampsWorkersToSegments(t *testing.T) {
	service := New(config.Default(), nil, nil, nil, nil)

	opts := service.normalizeOptions(Options{MaxSegments: 2, IndexWorkers: 8})
	if opts.IndexWorkers != 2 {
		t.Fatalf("IndexWorkers = %d, want 2", opts.IndexWorkers)
	}
}

func TestNormalizeOptionsDefaults(t *testing.T) {
	service := New(config.Default(), nil, nil, nil, nil)

	opts := service.normalizeOptions(Options{})
	if opts.MaxSegments != 500 {
		t.Fatalf("MaxSegments = %d, want 500", opts.MaxSegments)
	}
	if opts.IndexWorkers != config.Default().Pipeline.IndexWorkers {
		t.Fatalf("IndexWorkers = %d, want default %d", opts.IndexWorkers, config.Default().Pipeline.IndexWorkers)
	}
	if len(opts.LogTypes) != len(config.Default().Collection.LogTypes) {
		t.Fatalf("LogTypes = %#v, want configured collection log types", opts.LogTypes)
	}
	for i, logType := range config.Default().Collection.LogTypes {
		if opts.LogTypes[i] != logType {
			t.Fatalf("LogTypes = %#v, want configured collection log types", opts.LogTypes)
		}
	}
}

func TestRecentOptionsPreservePipelineControls(t *testing.T) {
	opts := Options{
		Force:              true,
		SkipCombine:        true,
		SkipRollupRecovery: true,
		PreferRecent:       true,
		SiteID:             "site-a",
		Env:                "live",
		LogTypes:           []string{"nginx-access", "php-error"},
		MaxSegments:        7,
		IndexWorkers:       4,
	}
	service := New(config.Default(), nil, nil, nil, nil)
	normalized := service.normalizeOptions(opts)

	if !normalized.Force || !normalized.SkipCombine || !normalized.SkipRollupRecovery || !normalized.PreferRecent {
		t.Fatal("boolean pipeline controls were not preserved")
	}
	if normalized.SiteID != "site-a" || normalized.Env != "live" {
		t.Fatalf("scope = %q/%q, want site-a/live", normalized.SiteID, normalized.Env)
	}
	if normalized.MaxSegments != 7 {
		t.Fatalf("MaxSegments = %d, want 7", normalized.MaxSegments)
	}
	if normalized.IndexWorkers != 4 {
		t.Fatalf("IndexWorkers = %d, want 4", normalized.IndexWorkers)
	}
	if len(normalized.LogTypes) != 2 {
		t.Fatalf("LogTypes = %#v, want 2 entries", normalized.LogTypes)
	}
}

func TestResultJobMetaIncludesPipelineCounters(t *testing.T) {
	meta := resultJobMeta(Result{
		CombinedSegments:  2,
		IndexedSegments:   3,
		EventsInserted:    5,
		LogEventsInserted: 7,
		RollupsRepaired:   11,
		SecurityProbes:    13,
		ErrorEvents:       17,
		SlowRequests:      19,
		FailedSites:       2,
		FailedSegments:    4,
		FailedSiteIDs:     []string{"site-a", "site-b"},
	})

	if meta["combined_segments"] != 2 || meta["indexed_segments"] != 3 {
		t.Fatalf("segment counters = %#v", meta)
	}
	if meta["events_inserted"] != 5 || meta["log_events_inserted"] != 7 {
		t.Fatalf("event counters = %#v", meta)
	}
	if meta["rollups_repaired"] != 11 || meta["security_probes"] != 13 {
		t.Fatalf("analysis counters = %#v", meta)
	}
	if meta["error_events"] != 17 || meta["slow_request_events"] != 19 {
		t.Fatalf("signal counters = %#v", meta)
	}
	if meta["failed_sites"] != 2 || meta["failed_segments"] != 4 {
		t.Fatalf("failure counters = %#v", meta)
	}
	if got := meta["failed_site_ids"].([]string); len(got) != 2 || got[0] != "site-a" || got[1] != "site-b" {
		t.Fatalf("failed_site_ids = %#v", meta["failed_site_ids"])
	}
}

func TestGroupSegmentsBySitePreservesSiteOrder(t *testing.T) {
	now := time.Now()
	groups := groupSegmentsBySite([]combiner.SegmentManifest{
		{ID: "1", SiteID: "site-a", BucketStart: now},
		{ID: "2", SiteID: "site-b", BucketStart: now},
		{ID: "3", SiteID: "site-a", BucketStart: now},
		{ID: "4", SiteID: "", BucketStart: now},
	})

	if len(groups) != 3 {
		t.Fatalf("groups = %#v, want 3 groups", groups)
	}
	if groups[0].SiteID != "site-a" || len(groups[0].Segments) != 2 {
		t.Fatalf("first group = %#v, want site-a with two segments", groups[0])
	}
	if groups[1].SiteID != "site-b" || len(groups[1].Segments) != 1 {
		t.Fatalf("second group = %#v, want site-b with one segment", groups[1])
	}
	if groups[2].SiteID != "unknown" || len(groups[2].Segments) != 1 {
		t.Fatalf("third group = %#v, want unknown with one segment", groups[2])
	}
}
