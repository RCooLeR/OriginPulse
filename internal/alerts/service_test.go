package alerts

import "testing"

func TestNormalizeRecentLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", limit: 0, want: 25},
		{name: "negative", limit: -1, want: 25},
		{name: "keeps requested", limit: 250, want: 250},
		{name: "max", limit: RecentMaxLimit, want: RecentMaxLimit},
		{name: "clamped", limit: RecentMaxLimit + 1, want: RecentMaxLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeRecentLimit(tt.limit); got != tt.want {
				t.Fatalf("normalizeRecentLimit(%d) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}

func TestNormalizeDetailLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", limit: 0, want: 50},
		{name: "negative", limit: -1, want: 50},
		{name: "keeps requested", limit: 250, want: 250},
		{name: "max", limit: DetailMaxLimit, want: DetailMaxLimit},
		{name: "clamped", limit: DetailMaxLimit + 1, want: DetailMaxLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeDetailLimit(tt.limit); got != tt.want {
				t.Fatalf("normalizeDetailLimit(%d) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}
