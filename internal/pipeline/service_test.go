package pipeline

import (
	"testing"

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
		LogTypes:           []string{"nginx-access", "php-error"},
		MaxSegments:        7,
		IndexWorkers:       4,
	}
	service := New(config.Default(), nil, nil, nil, nil)
	normalized := service.normalizeOptions(opts)

	if !normalized.Force || !normalized.SkipCombine || !normalized.SkipRollupRecovery {
		t.Fatal("boolean pipeline controls were not preserved")
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
}
