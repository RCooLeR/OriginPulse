package reports

import "testing"

func TestNormalizeRecentLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", limit: 0, want: 25},
		{name: "negative", limit: -1, want: 25},
		{name: "small", limit: 8, want: 8},
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
