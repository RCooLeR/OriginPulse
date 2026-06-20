package httpapi

import (
	"testing"
	"time"
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
