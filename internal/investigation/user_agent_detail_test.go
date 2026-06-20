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
