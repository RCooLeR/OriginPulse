package config

import "testing"

func TestDefaultPipelineUsesParallelIndexing(t *testing.T) {
	cfg := Default()
	if cfg.Pipeline.IndexWorkers != 2 {
		t.Fatalf("Pipeline.IndexWorkers = %d, want 2", cfg.Pipeline.IndexWorkers)
	}
}
