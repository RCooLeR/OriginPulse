package parser

import (
	"testing"
	"time"
)

func TestParseLogLinePHPError(t *testing.T) {
	event, err := ParseLogLine(`[20-Jun-2026 01:02:29 UTC] PHP Warning: Undefined array key in /code/index.php on line 1`, "php-error")
	if err != nil {
		t.Fatalf("ParseLogLine: %v", err)
	}
	if event.TS.Year() != 2026 || event.Severity != "warning" || event.LogType != "php-error" {
		t.Fatalf("event = %#v", event)
	}
}

func TestParseLogLineMySQLLongOneDigitHour(t *testing.T) {
	event, err := ParseLogLine(`2026-06-20  1:26:10 110662 [Warning] Aborted connection`, "mysql")
	if err != nil {
		t.Fatalf("ParseLogLine: %v", err)
	}
	if event.TS.Hour() != 1 || event.Severity != "warning" {
		t.Fatalf("event = %#v", event)
	}
}

func TestParseLogLineMySQLSlowTime(t *testing.T) {
	event, err := ParseLogLine(`# Time: 260618 13:46:23`, "mysql-slow")
	if err != nil {
		t.Fatalf("ParseLogLine: %v", err)
	}
	if event.TS.Year() != 2026 || event.TS.Month() != 6 || event.TS.Day() != 18 {
		t.Fatalf("event = %#v", event)
	}
}

func TestParseLogLineApacheError(t *testing.T) {
	line := `[Tue Jun 23 00:28:25.918877 2026] [authz_core:error] [pid 2116256:tid 139853127743040] [client 176.65.139.236:16664] AH01630: client denied by server configuration: /var/www/app/public/.env`
	event, err := ParseLogLine(line, "apache-error")
	if err != nil {
		t.Fatalf("ParseLogLine: %v", err)
	}
	want := time.Date(2026, 6, 23, 0, 28, 25, 918877000, time.UTC)
	if !event.TS.Equal(want) {
		t.Fatalf("TS = %s, want %s", event.TS, want)
	}
	if event.Severity != "error" || event.LogType != "apache-error" {
		t.Fatalf("event = %#v", event)
	}
}
