package combiner

import (
	"path/filepath"
	"testing"
)

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

func TestNormalizeStoredRawPathRemapsDataRawPath(t *testing.T) {
	rawDir := filepath.Join("/app", "data", "raw")
	got := normalizeStoredRawPath(`D:\Development\projects\apps\rcooler\OriginPulse\data\raw\site-a\live\appserver-1\nginx\nginx-access.log`, rawDir)
	want := filepath.Join(rawDir, "site-a", "live", "appserver-1", "nginx", "nginx-access.log")
	if got != want {
		t.Fatalf("normalizeStoredRawPath = %q, want %q", got, want)
	}
}

func TestNormalizeStoredRawPathKeepsUnrelatedPath(t *testing.T) {
	path := filepath.Join("/tmp", "originpulse", "raw", "nginx-access.log")
	if got := normalizeStoredRawPath(path, filepath.Join("/app", "data", "raw")); got != path {
		t.Fatalf("normalizeStoredRawPath = %q, want unchanged %q", got, path)
	}
}

func TestNormalizeStoredCombinedPathRemapsDataCombinedPath(t *testing.T) {
	combinedDir := filepath.Join("/app", "data", "combined")
	got := normalizeStoredCombinedPath(`D:\Development\projects\apps\rcooler\OriginPulse\data\combined\nginx-access\2026\06\18\08.log.gz`, combinedDir)
	want := filepath.Join(combinedDir, "nginx-access", "2026", "06", "18", "08.log.gz")
	if got != want {
		t.Fatalf("normalizeStoredCombinedPath = %q, want %q", got, want)
	}
}
