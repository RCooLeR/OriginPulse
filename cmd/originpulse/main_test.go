package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunHealthcheckAcceptsHealthyScheduler(t *testing.T) {
	server := healthcheckServer(t, map[string]any{
		"ok": true,
		"database": map[string]any{
			"configured": true,
			"ok":         true,
		},
		"uptime_sec": 10,
		"scheduler": map[string]any{
			"collection_enabled":     true,
			"collection_interval_ms": 1000,
			"failed_since_start":     0,
			"last_cycle_finished_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
	defer server.Close()

	if err := runHealthcheck(context.Background(), server.URL, time.Second); err != nil {
		t.Fatalf("runHealthcheck returned error: %v", err)
	}
}

func TestRunHealthcheckRejectsSchedulerFailures(t *testing.T) {
	server := healthcheckServer(t, map[string]any{
		"ok": true,
		"scheduler": map[string]any{
			"failed_since_start": 1,
		},
	})
	defer server.Close()

	err := runHealthcheck(context.Background(), server.URL, time.Second)
	if err == nil || !strings.Contains(err.Error(), "failed job") {
		t.Fatalf("runHealthcheck error = %v, want scheduler failure", err)
	}
}

func TestRunHealthcheckRejectsStaleScheduler(t *testing.T) {
	server := healthcheckServer(t, map[string]any{
		"ok":         true,
		"uptime_sec": 10,
		"scheduler": map[string]any{
			"collection_enabled":     true,
			"collection_interval_ms": 1000,
			"failed_since_start":     0,
			"last_cycle_finished_at": time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano),
		},
	})
	defer server.Close()

	err := runHealthcheck(context.Background(), server.URL, time.Second)
	if err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("runHealthcheck error = %v, want stale scheduler failure", err)
	}
}

func healthcheckServer(t *testing.T, payload map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("encode healthcheck payload: %v", err)
		}
	}))
}
