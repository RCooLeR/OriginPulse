package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDownloadGeoLite2CityMMDBExtractsDatabase(t *testing.T) {
	const payload = "fake-mmdb-payload"
	var sawAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		sawAuth = ok && user == "acct" && pass == "license"
		w.Header().Set("Content-Type", "application/gzip")
		if _, err := w.Write(geoLiteArchive(t, "GeoLite2-City_20260620/GeoLite2-City.mmdb", []byte(payload))); err != nil {
			t.Fatalf("write response: %v", err)
		}
	}))
	defer server.Close()

	dbPath := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")
	if err := DownloadGeoLite2CityMMDB(dbPath, server.URL, "acct", "license", time.Second); err != nil {
		t.Fatalf("DownloadGeoLite2CityMMDB() error = %v", err)
	}
	if !sawAuth {
		t.Fatal("download did not send MaxMind basic auth credentials")
	}
	got, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read db: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("db payload = %q, want %q", string(got), payload)
	}
}

func TestDownloadGeoLite2CityMMDBRequiresCredentials(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")
	err := DownloadGeoLite2CityMMDB(dbPath, "http://example.invalid/db.tar.gz", "", "", time.Second)
	if err == nil || !strings.Contains(err.Error(), "MAXMIND_ACCOUNT_ID") {
		t.Fatalf("error = %v, want missing credentials error", err)
	}
	if _, statErr := os.Stat(dbPath); !os.IsNotExist(statErr) {
		t.Fatalf("db file exists after credential failure: %v", statErr)
	}
}

func TestUpdaterEnsureAndLoadReportsMissingDatabaseWithoutCredentials(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")
	updater := NewUpdater(UpdaterConfig{DBPath: dbPath, DownloadURL: "http://example.invalid/db.tar.gz", HTTPTimeout: time.Second})
	err := updater.EnsureAndLoad(t.Context(), NewManager(dbPath))
	if err == nil || !strings.Contains(err.Error(), "GeoLite2 database is missing") {
		t.Fatalf("EnsureAndLoad() error = %v, want missing database message", err)
	}
}

func geoLiteArchive(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(payload))}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatalf("write tar payload: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}
