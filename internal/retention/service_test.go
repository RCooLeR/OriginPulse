package retention

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/config"
	"originpulse/internal/db"
)

func TestRemoveLocalFilesDeletesFilesAndPrunesEmptyParents(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "raw", "site", "live")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(nested, "nginx-access.log")
	if err := os.WriteFile(path, []byte("line\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	deleted, failed := removeLocalFiles([]string{path})
	if deleted != 1 || failed != 0 {
		t.Fatalf("removeLocalFiles() = deleted %d failed %d, want 1/0", deleted, failed)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("removed file still exists or unexpected stat error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "raw")); !os.IsNotExist(err) {
		t.Fatalf("empty parent directories should be pruned, stat error: %v", err)
	}
}

func TestRemoveLocalFilesIgnoresMissingFiles(t *testing.T) {
	deleted, failed := removeLocalFiles([]string{filepath.Join(t.TempDir(), "missing.log")})
	if deleted != 0 || failed != 0 {
		t.Fatalf("removeLocalFiles() = deleted %d failed %d, want 0/0", deleted, failed)
	}
}

func TestRemoveLocalFilesReportsDeletionFailures(t *testing.T) {
	root := t.TempDir()
	nonEmptyDir := filepath.Join(root, "archive")
	if err := os.MkdirAll(nonEmptyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nonEmptyDir, "child"), []byte("keep"), 0o644); err != nil {
		t.Fatalf("write child: %v", err)
	}

	deleted, failed := removeLocalFiles([]string{nonEmptyDir})
	if deleted != 0 || failed != 1 {
		t.Fatalf("removeLocalFiles() = deleted %d failed %d, want 0/1", deleted, failed)
	}
}

func TestDryRunHotEventCountExcludesTemporaryImports(t *testing.T) {
	store := testRetentionStore(t)
	ctx := context.Background()
	pool, err := store.Pool()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	siteID := fmt.Sprintf("retention-test-%d", now.UnixNano())
	tempImportID := fmt.Sprintf("00000000-0000-4000-8000-%012d", now.UnixNano()%1_000_000_000_000)
	if _, err := pool.Exec(ctx, `INSERT INTO sites (id, name, pantheon_site_id, enabled) VALUES ($1, $2, $3, true)`, siteID, "Retention Test", "retention-test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM access_events WHERE site_id = $1`, siteID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM temporary_imports WHERE id = $1::uuid`, tempImportID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM sites WHERE id = $1`, siteID)
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO temporary_imports (id, range_start, range_end, imported_at, expires_at, status, reason)
VALUES ($1::uuid, $2, $3, $4, $5, 'imported', 'retention test')`,
		tempImportID, now.Add(-100*24*time.Hour), now.Add(-99*24*time.Hour), now.Add(-8*24*time.Hour), now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	oldTS := now.Add(-100 * 24 * time.Hour)
	if err := insertRetentionAccessEvent(ctx, pool, siteID, oldTS, "normal"); err != nil {
		t.Fatal(err)
	}
	if err := insertRetentionAccessEvent(ctx, pool, siteID, oldTS.Add(time.Second), "temporary", tempImportID); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Retention.Enabled = true
	cfg.Retention.HotEventMaxAge = 90 * 24 * time.Hour
	cfg.Retention.TemporaryImportMaxAge = 7 * 24 * time.Hour
	service := NewService(cfg, store)
	result, err := service.Run(ctx, Options{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessEventsMatched != 1 {
		t.Fatalf("AccessEventsMatched = %d, want only the non-temporary hot event", result.AccessEventsMatched)
	}
	if result.TemporaryEventsMatched != 1 || result.TemporaryImportsMatched != 1 {
		t.Fatalf("temporary matches = events:%d imports:%d, want 1/1", result.TemporaryEventsMatched, result.TemporaryImportsMatched)
	}
}

func insertRetentionAccessEvent(ctx context.Context, pool *pgxpool.Pool, siteID string, ts time.Time, key string, temporaryImportID ...string) error {
	sum := sha256.Sum256([]byte(siteID + key + ts.Format(time.RFC3339Nano)))
	var tempID any
	if len(temporaryImportID) > 0 && strings.TrimSpace(temporaryImportID[0]) != "" {
		tempID = temporaryImportID[0]
	}
	_, err := pool.Exec(ctx, `
INSERT INTO access_events (
  ts, site_id, env, container_id, client_ip, method, path, status, fingerprint, temporary_import_id
)
VALUES ($1, $2, 'live', 'appserver', '192.0.2.10', 'GET', '/retention-test', 200, $3, nullif($4::text, '')::uuid)`,
		ts, siteID, sum[:], tempID)
	return err
}

func testRetentionStore(t *testing.T) *db.Store {
	t.Helper()
	url := os.Getenv("ORIGINPULSE_TEST_DATABASE_URL")
	if strings.TrimSpace(url) == "" {
		t.Skip("ORIGINPULSE_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	store, err := db.Open(ctx, config.DatabaseConfig{URL: url, MaxConns: 1})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	return store
}
