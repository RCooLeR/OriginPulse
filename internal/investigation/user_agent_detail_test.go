package investigation

import (
	"context"
	"errors"
	"testing"
)

func TestUserAgentDetailsRequiresIdentifier(t *testing.T) {
	service := NewService(nil)
	_, err := service.UserAgentDetails(context.Background(), UserAgentOptions{Range: "24h"})
	if !errors.Is(err, ErrUserAgentRequired) {
		t.Fatalf("error = %v, want ErrUserAgentRequired", err)
	}
}

func TestUserAgentDetailsDisabledDatabaseReturnsShell(t *testing.T) {
	service := NewService(nil)
	detail, err := service.UserAgentDetails(context.Background(), UserAgentOptions{Sample: "curl/8.0.1", Range: "24h"})
	if err != nil {
		t.Fatalf("UserAgentDetails() error = %v", err)
	}
	if detail.DatabaseEnabled {
		t.Fatal("database should be disabled")
	}
	if detail.UserAgent.Sample != "curl/8.0.1" {
		t.Fatalf("sample = %q, want curl/8.0.1", detail.UserAgent.Sample)
	}
}

func TestNormalizeLimitAllowsDeeperDrawerPages(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", limit: 0, want: 10},
		{name: "negative", limit: -1, want: 10},
		{name: "keeps requested", limit: 250, want: 250},
		{name: "max", limit: DetailMaxLimit, want: DetailMaxLimit},
		{name: "clamped", limit: DetailMaxLimit + 1, want: DetailMaxLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeLimit(tt.limit); got != tt.want {
				t.Fatalf("normalizeLimit(%d) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}

func TestNormalizeOffset(t *testing.T) {
	tests := []struct {
		name   string
		offset int
		want   int
	}{
		{name: "default", offset: 0, want: 0},
		{name: "negative", offset: -1, want: 0},
		{name: "keeps requested", offset: 120, want: 120},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeOffset(tt.offset); got != tt.want {
				t.Fatalf("normalizeOffset(%d) = %d, want %d", tt.offset, got, tt.want)
			}
		})
	}
}
