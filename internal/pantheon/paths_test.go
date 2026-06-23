package pantheon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectLogType(t *testing.T) {
	cases := map[string]string{
		"logs/nginx/nginx-access.log":            "nginx-access",
		"logs/nginx/nginx-access.log-2026.gz":    "nginx-access",
		"logs/nginx/nginx-error.log":             "nginx-error",
		"logs/php/php-fpm-error.log-20260623":    "php-error",
		"logs/php/php-error.log":                 "php-error",
		"logs/php/php-slow.log-2026-06-17.gz":    "php-slow",
		"logs/mysql/mysqld-slow-query.log":       "mysql-slow",
		"logs/other/something-unexpected.log.gz": "unknown",
	}

	for path, expected := range cases {
		if got := DetectLogType(path); got != expected {
			t.Fatalf("DetectLogType(%q) = %q, want %q", path, got, expected)
		}
	}
}

func TestDetectLocalLogType(t *testing.T) {
	cases := map[string]string{
		"example-dashboard-access.log":  "apache-access",
		"example-dashboard-error.log.1": "apache-error",
		"logs/php/php-fpm-error.log-20260623":       "php-error",
	}

	for path, expected := range cases {
		if got := DetectLocalLogType(path); got != expected {
			t.Fatalf("DetectLocalLogType(%q) = %q, want %q", path, got, expected)
		}
	}
}

func TestMatchesLocalFilenameMasks(t *testing.T) {
	if !matchesLocalFilenameMasks("example-dashboard-access.log", []string{"example-dashboard-*"}) {
		t.Fatal("expected example mask to match")
	}
	if matchesLocalFilenameMasks("other-access.log", []string{"example-dashboard-*"}) {
		t.Fatal("unexpected match for unrelated log")
	}
	if !matchesLocalFilenameMasks("anything.log", nil) {
		t.Fatal("empty masks should allow recognized files")
	}
}

func TestLocalRawPath(t *testing.T) {
	got := LocalRawPath("/data/raw", "client-a", "live", "appserver-203-0-113-10", "/logs/nginx/nginx-access.log")
	want := filepath.Join("/data/raw", "client-a", "live", "appserver-203-0-113-10", "nginx", "nginx-access.log")
	if got != want {
		t.Fatalf("LocalRawPath = %q, want %q", got, want)
	}
}

func TestContainerIDSanitizesAddress(t *testing.T) {
	got := ContainerID("appserver", "203.0.113.10")
	if got != "appserver-203.0.113.10" {
		t.Fatalf("ContainerID = %q", got)
	}
}

func TestAppendableLocalSize(t *testing.T) {
	dir := t.TempDir()
	activePath := filepath.Join(dir, "nginx-access.log")
	if err := os.WriteFile(activePath, []byte("existing"), 0o640); err != nil {
		t.Fatal(err)
	}

	size, ok := appendableLocalSize("logs/nginx/nginx-access.log", activePath, 32)
	if !ok {
		t.Fatal("active growing log should be appendable")
	}
	if size != int64(len("existing")) {
		t.Fatalf("size = %d, want %d", size, len("existing"))
	}

	if _, ok := appendableLocalSize("logs/nginx/nginx-access.log-20260617.gz", activePath, 32); ok {
		t.Fatal("gzip rotated logs should not be appendable")
	}
	if _, ok := appendableLocalSize("logs/nginx/nginx-access.log", activePath, int64(len("existing"))); ok {
		t.Fatal("same-size active log should not be appendable")
	}
}

func TestDownloadStatsAddIncludesServerCounts(t *testing.T) {
	stats := DownloadStats{FilesSeen: 1, FilesDownloaded: 1, ServersAttempted: 1, ServersSucceeded: 1}
	stats.add(DownloadStats{
		FilesSeen:        2,
		FilesSkipped:     2,
		BytesDownloaded:  42,
		ServersAttempted: 2,
		ServersFailed:    1,
		ServerErrors:     []string{"appserver failed"},
	})

	if stats.FilesSeen != 3 || stats.FilesDownloaded != 1 || stats.FilesSkipped != 2 || stats.BytesDownloaded != 42 {
		t.Fatalf("file stats = %#v, want merged counters", stats)
	}
	if stats.ServersAttempted != 3 || stats.ServersSucceeded != 1 || stats.ServersFailed != 1 {
		t.Fatalf("server stats = %#v, want attempted=3 succeeded=1 failed=1", stats)
	}
	if len(stats.ServerErrors) != 1 || stats.ServerErrors[0] != "appserver failed" {
		t.Fatalf("server errors = %#v, want one preserved error", stats.ServerErrors)
	}
}
