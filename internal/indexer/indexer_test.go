package indexer

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"originpulse/internal/combiner"
	"originpulse/internal/parser"
)

func TestParseCombinedEvents(t *testing.T) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	fingerprint := sha256.Sum256([]byte("valid access line"))
	lines := []any{
		combiner.CombinedLine{
			SiteID:      "site-a",
			Env:         "live",
			ContainerID: "nginx-1",
			LogType:     "nginx-access",
			Raw:         `203.0.113.10 - - [17/Jun/2026:14:22:31 +0000] "GET /foo?bar=baz HTTP/1.1" 404 123 "-" "curl/8.0.1"`,
			Fingerprint: hex.EncodeToString(fingerprint[:]),
		},
		"not json",
		combiner.CombinedLine{
			SiteID:      "site-a",
			Env:         "live",
			ContainerID: "nginx-1",
			LogType:     "nginx-access",
			Raw:         "not an access line",
			Fingerprint: hex.EncodeToString(fingerprint[:]),
		},
	}
	for _, line := range lines {
		switch value := line.(type) {
		case string:
			_, _ = writer.Write([]byte(value + "\n"))
		default:
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("marshal combined line: %v", err)
			}
			_, _ = writer.Write(append(data, '\n'))
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	reader, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("open gzip: %v", err)
	}
	defer reader.Close()

	events, seen, invalid, err := parseCombinedEvents(context.Background(), reader)
	if err != nil {
		t.Fatalf("parseCombinedEvents: %v", err)
	}
	if seen != 2 {
		t.Fatalf("seen = %d, want 2", seen)
	}
	if invalid != 2 {
		t.Fatalf("invalid = %d, want 2", invalid)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].LineNo != 1 || events[0].Event.Path != "/foo" || events[0].Event.Query != "bar=baz" {
		t.Fatalf("parsed event = %#v", events[0])
	}
}

func TestClassifySecurityProbesMatchesEncodedSQLTautology(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{name: "encoded spaces and equals", query: "id=1%20OR%201%3D1"},
		{name: "plus spaces and literal equals", query: "id=1+and+1=1"},
		{name: "double encoded quote", query: "id=1%2527%2520OR%25201%253D1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probes := classifySecurityProbes(parser.AccessEvent{
				Method:   "GET",
				Path:     "/search",
				Query:    tt.query,
				ClientIP: "203.0.113.10",
				Status:   404,
			})
			if len(probes) != 1 {
				t.Fatalf("probes = %#v, want one SQL injection probe", probes)
			}
			if probes[0].Family != "injection" || probes[0].Category != "sql_injection" || probes[0].MatchReason != "tautology" {
				t.Fatalf("probe = %#v, want SQL tautology", probes[0])
			}
		})
	}
}

func TestClassifySecurityProbesMatchesDecodedTraversal(t *testing.T) {
	probes := classifySecurityProbes(parser.AccessEvent{
		Method:   "GET",
		Path:     "/download",
		Query:    "file=%252e%252e%252fwp-config.php",
		ClientIP: "203.0.113.10",
		Status:   404,
	})
	if len(probes) != 1 {
		t.Fatalf("probes = %#v, want one decoded traversal/secret probe", probes)
	}
	if probes[0].Family != "injection" {
		t.Fatalf("probe = %#v, want injection family", probes[0])
	}
}
