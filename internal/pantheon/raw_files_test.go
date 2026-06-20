package pantheon

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"originpulse/internal/config"
	"originpulse/internal/db"
)

func TestRawFileRepositoryKeepsDownloadedStatusForUnchangedDiscovery(t *testing.T) {
	url := os.Getenv("ORIGINPULSE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ORIGINPULSE_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	store, err := db.Open(ctx, config.DatabaseConfig{URL: url, MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)

	pool, err := store.Pool()
	if err != nil {
		t.Fatal(err)
	}

	siteID := fmt.Sprintf("test-incremental-%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, `INSERT INTO sites (id, name, pantheon_site_id, enabled) VALUES ($1, $2, $3, true)`, siteID, "Incremental Test", "test-site-id"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM raw_files WHERE site_id = $1`, siteID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM sites WHERE id = $1`, siteID)
	})

	repo := NewRawFileRepository(store)
	mtime := time.Now().UTC().Truncate(time.Microsecond)
	file := RawFile{
		SiteID:      siteID,
		Env:         "live",
		ContainerID: "appserver-test",
		LogType:     "nginx-access",
		RemotePath:  "logs/nginx/nginx-access.log",
		RemoteSize:  1024,
		RemoteMTime: mtime,
		LocalPath:   "data/raw/test/nginx-access.log",
		SHA256:      "initial-sha",
	}

	if err := repo.MarkDownloaded(ctx, file); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkDiscovered(ctx, file); err != nil {
		t.Fatal(err)
	}

	shouldDownload, err := repo.ShouldDownload(ctx, file)
	if err != nil {
		t.Fatal(err)
	}
	if shouldDownload {
		t.Fatal("unchanged downloaded file should not require another download")
	}

	var status string
	var sha string
	var downloadedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT status, coalesce(sha256, ''), downloaded_at FROM raw_files WHERE site_id = $1`, siteID).Scan(&status, &sha, &downloadedAt); err != nil {
		t.Fatal(err)
	}
	if status != "downloaded" {
		t.Fatalf("status = %q, want downloaded", status)
	}
	if sha != "initial-sha" {
		t.Fatalf("sha = %q, want initial-sha", sha)
	}
	if downloadedAt == nil {
		t.Fatal("downloaded_at was cleared")
	}

	changed := file
	changed.RemoteSize++
	if err := repo.MarkDiscovered(ctx, changed); err != nil {
		t.Fatal(err)
	}
	shouldDownload, err = repo.ShouldDownload(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if !shouldDownload {
		t.Fatal("changed remote file should require download")
	}
}

func TestNormalizeRawFileRecentLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", limit: 0, want: 25},
		{name: "negative", limit: -1, want: 25},
		{name: "keeps requested", limit: 250, want: 250},
		{name: "max", limit: RawFileRecentMaxLimit, want: RawFileRecentMaxLimit},
		{name: "clamped", limit: RawFileRecentMaxLimit + 1, want: RawFileRecentMaxLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeRawFileRecentLimit(tt.limit); got != tt.want {
				t.Fatalf("normalizeRawFileRecentLimit(%d) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}
