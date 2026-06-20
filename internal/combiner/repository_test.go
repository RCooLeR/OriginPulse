package combiner

import "testing"

func TestNormalizeRecentSegmentsLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", limit: 0, want: 25},
		{name: "negative", limit: -1, want: 25},
		{name: "keeps requested", limit: 250, want: 250},
		{name: "max", limit: RecentSegmentsMaxLimit, want: RecentSegmentsMaxLimit},
		{name: "clamped", limit: RecentSegmentsMaxLimit + 1, want: RecentSegmentsMaxLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeRecentSegmentsLimit(tt.limit); got != tt.want {
				t.Fatalf("normalizeRecentSegmentsLimit(%d) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}

func TestNormalizeRecentSegmentsOffset(t *testing.T) {
	tests := []struct {
		name   string
		offset int
		want   int
	}{
		{name: "default", offset: 0, want: 0},
		{name: "negative", offset: -1, want: 0},
		{name: "keeps requested", offset: 100, want: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeRecentSegmentsOffset(tt.offset); got != tt.want {
				t.Fatalf("normalizeRecentSegmentsOffset(%d) = %d, want %d", tt.offset, got, tt.want)
			}
		})
	}
}
