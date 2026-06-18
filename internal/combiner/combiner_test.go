package combiner

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"originpulse/internal/config"
)

func TestCombineWritesDeterministicHourlySegment(t *testing.T) {
	tmp := t.TempDir()
	cfg := config.Default()
	cfg.Collection.RawDir = filepath.Join(tmp, "raw")
	cfg.Combiner.CombinedDir = filepath.Join(tmp, "combined")
	cfg.Combiner.QuarantineDir = filepath.Join(tmp, "quarantine")
	cfg.Combiner.FinalizeAfter = time.Hour

	rawPath := filepath.Join(cfg.Collection.RawDir, "client-a", "live", "appserver-1", "nginx", "nginx-access.log")
	if err := os.MkdirAll(filepath.Dir(rawPath), 0o750); err != nil {
		t.Fatalf("mkdir raw: %v", err)
	}

	line2 := `203.0.113.2 - - [17/Jun/2026:14:02:00 +0000] "GET /b HTTP/1.1" 200 20 "-" "curl/8"`
	line1 := `203.0.113.1 - - [17/Jun/2026:14:01:00 +0000] "GET /a HTTP/1.1" 200 10 "-" "curl/8"`
	bad := `this is not parseable`
	content := line2 + "\n" + line1 + "\n" + line1 + "\n" + bad + "\n"
	if err := os.WriteFile(rawPath, []byte(content), 0o640); err != nil {
		t.Fatalf("write raw: %v", err)
	}

	service := NewService(cfg, nil)
	from := time.Date(2026, 6, 17, 14, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	result, err := service.Combine(t.Context(), Options{LogType: "nginx-access", From: from, To: to})
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if result.SegmentsWritten != 1 {
		t.Fatalf("segments = %d, want 1", result.SegmentsWritten)
	}
	if result.LinesCombined != 2 {
		t.Fatalf("lines combined = %d, want 2", result.LinesCombined)
	}
	if result.LinesQuarantined != 1 {
		t.Fatalf("lines quarantined = %d, want 1", result.LinesQuarantined)
	}

	lines := readCombinedLines(t, result.Segments[0].Path)
	if len(lines) != 2 {
		t.Fatalf("combined lines = %d, want 2", len(lines))
	}
	if lines[0].Raw != line1 || lines[1].Raw != line2 {
		t.Fatalf("combined lines not sorted: %#v", lines)
	}

	firstSHA := result.Segments[0].SHA256
	result2, err := service.Combine(t.Context(), Options{LogType: "nginx-access", From: from, To: to})
	if err != nil {
		t.Fatalf("combine rerun: %v", err)
	}
	if result2.Segments[0].SHA256 != firstSHA {
		t.Fatalf("rerun sha = %s, want %s", result2.Segments[0].SHA256, firstSHA)
	}
}

func readCombinedLines(t *testing.T, path string) []CombinedLine {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open combined: %v", err)
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gzipReader.Close()

	var lines []CombinedLine
	scanner := bufio.NewScanner(gzipReader)
	for scanner.Scan() {
		var line CombinedLine
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			t.Fatalf("unmarshal combined line: %v", err)
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan combined: %v", err)
	}
	return lines
}
