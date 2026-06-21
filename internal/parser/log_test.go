package parser

import "testing"

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
