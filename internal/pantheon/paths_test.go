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
