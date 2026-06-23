package jobs

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNormalizeOffset(t *testing.T) {
	tests := []struct {
		name   string
		offset int
		want   int
	}{
		{name: "default", offset: 0, want: 0},
		{name: "negative", offset: -1, want: 0},
		{name: "keeps requested", offset: 12, want: 12},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeOffset(tt.offset); got != tt.want {
				t.Fatalf("normalizeOffset(%d) = %d, want %d", tt.offset, got, tt.want)
			}
		})
	}
}

func TestRecentPageUsesMemoryFallback(t *testing.T) {
	store := NewStore(10)
	first := store.Start(context.Background(), "collect", "test", map[string]any{"site": "one"})
	store.Finish(first.ID, StatusSuccess, "done", nil)
	second := store.Start(context.Background(), "pipeline", "test", nil)
	store.Finish(second.ID, StatusFailed, "failed", errors.New("boom"))

	page := store.RecentPage(1, 1)
	if page.Total != 2 {
		t.Fatalf("Total = %d, want 2", page.Total)
	}
	if page.Limit != 1 || page.Offset != 1 {
		t.Fatalf("page limit/offset = %d/%d, want 1/1", page.Limit, page.Offset)
	}
	if len(page.Jobs) != 1 || page.Jobs[0].ID != first.ID {
		t.Fatalf("paged job = %#v, want first job", page.Jobs)
	}
}

func TestFinishWithMetaMergesJobMetadata(t *testing.T) {
	store := NewStore(10)
	job := store.Start(context.Background(), "collect", "test", map[string]any{"site_id": "one"})
	store.FinishWithMeta(job.ID, StatusSuccess, "done", nil, map[string]any{"files_downloaded": 12})

	page := store.RecentPage(10, 0)
	if len(page.Jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(page.Jobs))
	}
	meta := page.Jobs[0].Meta
	if meta["site_id"] != "one" || meta["files_downloaded"] != 12 {
		t.Fatalf("meta = %#v, want original and finish metadata", meta)
	}
}

func TestStepMethodsAreNoopWithoutDatabase(t *testing.T) {
	store := NewStore(10)
	step := store.StartStep(context.Background(), "job-1", "connect sftp", map[string]any{"server": "127.0.0.1"})
	if step.ID != 0 {
		t.Fatalf("step ID = %d, want 0 without database", step.ID)
	}
	store.FinishStep(step, StatusSuccess, "done", nil, nil)
	page := store.StepsPage(context.Background(), 10, 0, "")
	if page.Total != 0 || len(page.Steps) != 0 {
		t.Fatalf("StepsPage = total %d rows %d, want empty no-db page", page.Total, len(page.Steps))
	}
}

func TestNilStoreStepMethodsAreSafe(t *testing.T) {
	var store *Store
	step := store.StartStep(context.Background(), "job-1", "connect", nil)
	store.FinishStep(step, StatusSuccess, "done", nil, nil)
	page := store.StepsPage(context.Background(), 0, -1, "")
	if page.Limit != 100 || page.Offset != 0 || page.Total != 0 {
		t.Fatalf("nil StepsPage = %#v, want normalized empty page", page)
	}
}

func TestStatsFromJobsIncludesZeroStatuses(t *testing.T) {
	stats := statsFromJobs([]Job{
		{Status: StatusRunning},
		{Status: StatusSuccess},
		{Status: StatusSuccess},
		{Status: StatusFailed},
	})
	if stats[StatusRunning] != 1 || stats[StatusSuccess] != 2 || stats[StatusFailed] != 1 {
		t.Fatalf("stats = %#v, want running=1 success=2 failed=1", stats)
	}
	if stats[StatusSkipped] != 0 {
		t.Fatalf("skipped = %d, want 0", stats[StatusSkipped])
	}
}

func TestClampFinishTimePreventsNegativeDuration(t *testing.T) {
	started := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	finished := started.Add(-500 * time.Millisecond)
	if got := clampFinishTime(started, finished); !got.Equal(started) {
		t.Fatalf("clampFinishTime = %s, want start time %s", got, started)
	}
}
