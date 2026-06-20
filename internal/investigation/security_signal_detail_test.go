package investigation

import (
	"context"
	"errors"
	"testing"
)

func TestSecuritySignalDetailsRequiresSelector(t *testing.T) {
	service := NewService(nil)
	_, err := service.SecuritySignalDetails(context.Background(), SecuritySignalOptions{Range: "24h"})
	if !errors.Is(err, ErrSecuritySignalRequired) {
		t.Fatalf("error = %v, want ErrSecuritySignalRequired", err)
	}
}

func TestSecuritySignalDetailsDisabledDatabaseReturnsShell(t *testing.T) {
	service := NewService(nil)
	detail, err := service.SecuritySignalDetails(context.Background(), SecuritySignalOptions{
		Kind:     "injection",
		Category: "sql_injection",
		IP:       "203.0.113.10",
		Range:    "24h",
	})
	if err != nil {
		t.Fatalf("SecuritySignalDetails() error = %v", err)
	}
	if detail.DatabaseEnabled {
		t.Fatal("database should be disabled")
	}
	if detail.Signal.Kind != "injection" {
		t.Fatalf("kind = %q, want injection", detail.Signal.Kind)
	}
	if detail.Signal.Category != "sql_injection" {
		t.Fatalf("category = %q, want sql_injection", detail.Signal.Category)
	}
	if detail.Signal.IP != "203.0.113.10" {
		t.Fatalf("ip = %q, want 203.0.113.10", detail.Signal.IP)
	}
	if detail.RelatedIPsLimit != 10 || detail.RelatedRequestsLimit != 10 {
		t.Fatalf("limits = %d/%d, want 10/10", detail.RelatedIPsLimit, detail.RelatedRequestsLimit)
	}
	if detail.RelatedIPsOffset != 0 || detail.RelatedRequestsOffset != 0 {
		t.Fatalf("offsets = %d/%d, want 0/0", detail.RelatedIPsOffset, detail.RelatedRequestsOffset)
	}
}
