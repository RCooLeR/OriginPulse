package parser

import (
	"testing"
	"time"
)

func TestParseAccessTimestampCommonLogFormat(t *testing.T) {
	line := `203.0.113.10 - - [17/Jun/2026:14:22:31 +0000] "GET / HTTP/1.1" 200 123 "-" "curl/8"`
	got, err := ParseAccessTimestamp(line)
	if err != nil {
		t.Fatalf("ParseAccessTimestamp: %v", err)
	}
	want := time.Date(2026, 6, 17, 14, 22, 31, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("timestamp = %s, want %s", got, want)
	}
}

func TestParseAccessTimestampRFC3339(t *testing.T) {
	got, err := ParseAccessTimestamp(`2026-06-17T14:22:31Z GET /`)
	if err != nil {
		t.Fatalf("ParseAccessTimestamp: %v", err)
	}
	want := time.Date(2026, 6, 17, 14, 22, 31, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("timestamp = %s, want %s", got, want)
	}
}

func TestParseAccessTimestampMissing(t *testing.T) {
	if _, err := ParseAccessTimestamp(`not a log line`); err == nil {
		t.Fatal("expected missing timestamp error")
	}
}

func TestParseAccessLine(t *testing.T) {
	line := `203.0.113.10 - - [17/Jun/2026:14:22:31 +0000] "GET /foo?bar=baz HTTP/1.1" 404 123 "https://example.com/start" "Mozilla/5.0"`
	event, err := ParseAccessLine(line)
	if err != nil {
		t.Fatalf("ParseAccessLine: %v", err)
	}
	if event.ClientIP != "203.0.113.10" {
		t.Fatalf("client ip = %q", event.ClientIP)
	}
	if event.Method != "GET" || event.Path != "/foo" || event.Query != "bar=baz" {
		t.Fatalf("request fields = %#v", event)
	}
	if event.Status != 404 || event.BytesSent != 123 {
		t.Fatalf("status/bytes = %d/%d", event.Status, event.BytesSent)
	}
	if event.Referer != "https://example.com/start" || event.UserAgent != "Mozilla/5.0" {
		t.Fatalf("referer/user-agent = %q/%q", event.Referer, event.UserAgent)
	}
}

func TestParseAccessLineWithBOM(t *testing.T) {
	line := "\ufeff" + `203.0.113.10 - - [17/Jun/2026:14:22:31 +0000] "GET / HTTP/1.1" 200 123 "-" "curl/8"`
	event, err := ParseAccessLine(line)
	if err != nil {
		t.Fatalf("ParseAccessLine: %v", err)
	}
	if event.ClientIP != "203.0.113.10" {
		t.Fatalf("client ip = %q", event.ClientIP)
	}
}

func TestParseAccessLineUsesForwardedPublicIP(t *testing.T) {
	line := `10.1.1.34 - - [17/Jun/2026:14:22:31 +0000] "GET / HTTP/1.1" 200 123 "-" "curl/8" 0.123 "212.47.78.48, 140.248.75.59, 10.1.1.34"`
	event, err := ParseAccessLine(line)
	if err != nil {
		t.Fatalf("ParseAccessLine: %v", err)
	}
	if event.ClientIP != "212.47.78.48" {
		t.Fatalf("client ip = %q", event.ClientIP)
	}
}

func TestParseAccessLineSkipsUnixForwardedPeer(t *testing.T) {
	line := `unix: - - [17/Jun/2026:14:22:31 +0000] "GET / HTTP/1.1" 503 123 "-" "curl/8" 0.123 "178.18.254.57, 140.248.74.81, unix:"`
	event, err := ParseAccessLine(line)
	if err != nil {
		t.Fatalf("ParseAccessLine: %v", err)
	}
	if event.ClientIP != "178.18.254.57" {
		t.Fatalf("client ip = %q", event.ClientIP)
	}
}
