package jobs

import (
	"context"
	"errors"
	"testing"
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
	first := store.Start(context.Background(), "collect", "test", map[string]string{"site": "one"})
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
