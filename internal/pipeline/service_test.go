package pipeline

import (
	"testing"

	"originpulse/internal/config"
)

func TestNormalizeOptionsUsesConfiguredWorkers(t *testing.T) {
	cfg := config.Default()
	cfg.Pipeline.IndexWorkers = 3
	service := New(cfg, nil, nil, nil, nil)

	opts := service.normalizeOptions(Options{MaxSegments: 10})
	if opts.IndexWorkers != 3 {
		t.Fatalf("IndexWorkers = %d, want 3", opts.IndexWorkers)
	}
	if opts.MaxSegments != 10 {
		t.Fatalf("MaxSegments = %d, want 10", opts.MaxSegments)
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
	if opts.MaxSegments != 100 {
		t.Fatalf("MaxSegments = %d, want 100", opts.MaxSegments)
	}
	if opts.IndexWorkers != config.Default().Pipeline.IndexWorkers {
		t.Fatalf("IndexWorkers = %d, want default %d", opts.IndexWorkers, config.Default().Pipeline.IndexWorkers)
	}
	if len(opts.LogTypes) != 1 || opts.LogTypes[0] != "nginx-access" {
		t.Fatalf("LogTypes = %#v, want nginx-access", opts.LogTypes)
	}
}

func TestRecentOptionsPreservePipelineControls(t *testing.T) {
	opts := Options{
		Force:        true,
		SkipCombine:  true,
		LogTypes:     []string{"nginx-access", "php-error"},
		MaxSegments:  7,
		IndexWorkers: 4,
	}
	service := New(config.Default(), nil, nil, nil, nil)
	normalized := service.normalizeOptions(opts)

	if !normalized.Force || !normalized.SkipCombine {
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
