package db

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"originpulse/internal/config"
)

func TestMigrateUsesItsLockedConnection(t *testing.T) {
	url := strings.TrimSpace(os.Getenv("ORIGINPULSE_TEST_DATABASE_URL"))
	if url == "" {
		t.Skip("ORIGINPULSE_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	store, err := Open(ctx, config.DatabaseConfig{URL: url, MaxConns: 1})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(store.Close)

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate with one connection: %v", err)
	}
}
