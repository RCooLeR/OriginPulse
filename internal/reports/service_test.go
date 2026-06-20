package reports

import (
	"context"
	"testing"

	"originpulse/internal/config"
)

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

func TestNormalizeOffset(t *testing.T) {
	if got := normalizeOffset(-10); got != 0 {
		t.Fatalf("normalizeOffset(-10) = %d, want 0", got)
	}
	if got := normalizeOffset(24); got != 24 {
		t.Fatalf("normalizeOffset(24) = %d, want 24", got)
	}
}

func TestCatalogDisabledStoreReturnsEmptyPage(t *testing.T) {
	service := NewService(configForTest(), nil, nil, nil, nil, nil, nil)
	catalog, err := service.Catalog(context.Background(), CatalogOptions{Limit: 50, Offset: 16, ReportType: "daily"})
	if err != nil {
		t.Fatalf("Catalog() error = %v", err)
	}
	if len(catalog.Reports) != 0 || catalog.Total != 0 {
		t.Fatalf("catalog = %#v, want empty disabled catalog", catalog)
	}
	if catalog.Limit != 50 || catalog.Offset != 16 {
		t.Fatalf("limit/offset = %d/%d, want 50/16", catalog.Limit, catalog.Offset)
	}
	if len(catalog.ReportTypes) != 0 {
		t.Fatalf("report types = %#v, want none", catalog.ReportTypes)
	}
}

func configForTest() config.Config {
	return config.Default()
}
