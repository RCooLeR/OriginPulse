package parser

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

var ErrInvalidLogLine = errors.New("invalid log line")

type LogEvent struct {
	TS       time.Time
	LogType  string
	Severity string
	Message  string
	Raw      string
}

var (
	nginxErrorTSRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+\[([a-z]+)\]\s*(.*)$`)
	apacheErrorRe  = regexp.MustCompile(`^\[([A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\]\s*(.*)$`)
	phpBracketRe   = regexp.MustCompile(`^\[([0-9]{2}-[A-Za-z]{3}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}(?: [A-Z]{2,4})?)\]\s*(.*)$`)
	isoLogTSRe     = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.\d+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)\s*(.*)$`)
	mysqlLongRe    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})\s+(\d{1,2}:\d{2}:\d{2})\s*(.*)$`)
	mysqlShortRe   = regexp.MustCompile(`^(?:# Time:\s*)?(\d{6}\s+\d{1,2}:\d{2}:\d{2})\s*(.*)$`)
	bracketLevelRe = regexp.MustCompile(`\[([A-Za-z]+)\]`)
)

func ParseLogLine(line string, logType string) (LogEvent, error) {
	raw := strings.TrimRight(strings.TrimPrefix(line, "\ufeff"), "\r")
	if strings.TrimSpace(raw) == "" {
		return LogEvent{}, ErrInvalidLogLine
	}
	if ts, severity, message, ok := parseNginxError(raw); ok {
		return newLogEvent(ts, logType, severity, message, raw), nil
	}
	if ts, severity, message, ok := parseApacheError(raw); ok {
		return newLogEvent(ts, logType, severity, message, raw), nil
	}
	if ts, message, ok := parsePHPLog(raw); ok {
		return newLogEvent(ts, logType, severityFromText(message), message, raw), nil
	}
	if ts, message, ok := parseISOLog(raw); ok {
		return newLogEvent(ts, logType, severityFromText(message), message, raw), nil
	}
	if ts, message, ok := parseMySQLLongLog(raw); ok {
		return newLogEvent(ts, logType, severityFromText(message), message, raw), nil
	}
	if ts, message, ok := parseMySQLShortLog(raw); ok {
		return newLogEvent(ts, logType, severityFromText(message), message, raw), nil
	}
	return LogEvent{}, ErrInvalidLogLine
}

func ParseLogTimestamp(line string) (time.Time, error) {
	event, err := ParseLogLine(line, "")
	if err != nil {
		return time.Time{}, err
	}
	return event.TS, nil
}

func parseNginxError(line string) (time.Time, string, string, bool) {
	match := nginxErrorTSRe.FindStringSubmatch(line)
	if match == nil {
		return time.Time{}, "", "", false
	}
	ts, err := time.ParseInLocation("2006/01/02 15:04:05", match[1], time.UTC)
	if err != nil {
		return time.Time{}, "", "", false
	}
	return ts.UTC(), strings.ToLower(match[2]), strings.TrimSpace(match[3]), true
}

func parseApacheError(line string) (time.Time, string, string, bool) {
	match := apacheErrorRe.FindStringSubmatch(line)
	if match == nil {
		return time.Time{}, "", "", false
	}
	var ts time.Time
	var err error
	for _, layout := range []string{"Mon Jan _2 15:04:05.999999 2006", "Mon Jan _2 15:04:05 2006"} {
		ts, err = time.ParseInLocation(layout, match[1], time.UTC)
		if err == nil {
			break
		}
	}
	if err != nil {
		return time.Time{}, "", "", false
	}
	message := strings.TrimSpace(match[2])
	severity := severityFromText(message)
	if bracket := bracketLevelRe.FindStringSubmatch(message); bracket != nil {
		parts := strings.Split(bracket[1], ":")
		severity = normalizeSeverity(parts[len(parts)-1])
	}
	return ts.UTC(), severity, message, true
}

func parsePHPLog(line string) (time.Time, string, bool) {
	match := phpBracketRe.FindStringSubmatch(line)
	if match == nil {
		return time.Time{}, "", false
	}
	ts, err := time.Parse("02-Jan-2006 15:04:05 MST", match[1])
	if err != nil {
		ts, err = time.ParseInLocation("02-Jan-2006 15:04:05", match[1], time.UTC)
	}
	if err != nil {
		return time.Time{}, "", false
	}
	return ts.UTC(), strings.TrimSpace(match[2]), true
}

func parseISOLog(line string) (time.Time, string, bool) {
	match := isoLogTSRe.FindStringSubmatch(line)
	if match == nil {
		return time.Time{}, "", false
	}
	value := strings.Replace(match[1], " ", "T", 1)
	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999999-0700",
		"2006-01-02T15:04:05-0700",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, value); err == nil {
			return ts.UTC(), strings.TrimSpace(match[2]), true
		}
	}
	if ts, err := time.ParseInLocation("2006-01-02T15:04:05", value, time.UTC); err == nil {
		return ts.UTC(), strings.TrimSpace(match[2]), true
	}
	return time.Time{}, "", false
}

func parseMySQLShortLog(line string) (time.Time, string, bool) {
	match := mysqlShortRe.FindStringSubmatch(line)
	if match == nil {
		return time.Time{}, "", false
	}
	for _, layout := range []string{"060102 15:04:05", "060102 15:04:5"} {
		if ts, err := time.ParseInLocation(layout, match[1], time.UTC); err == nil {
			return ts.UTC(), strings.TrimSpace(match[2]), true
		}
	}
	return time.Time{}, "", false
}

func parseMySQLLongLog(line string) (time.Time, string, bool) {
	match := mysqlLongRe.FindStringSubmatch(line)
	if match == nil {
		return time.Time{}, "", false
	}
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", match[1]+" "+padHour(match[2]), time.UTC)
	if err != nil {
		return time.Time{}, "", false
	}
	return ts.UTC(), strings.TrimSpace(match[3]), true
}

func padHour(value string) string {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 || len(parts[0]) >= 2 {
		return value
	}
	return "0" + value
}

func newLogEvent(ts time.Time, logType string, severity string, message string, raw string) LogEvent {
	return LogEvent{
		TS:       ts.UTC(),
		LogType:  strings.TrimSpace(logType),
		Severity: normalizeSeverity(severity),
		Message:  strings.TrimSpace(message),
		Raw:      raw,
	}
}

func severityFromText(value string) string {
	lower := strings.ToLower(value)
	if match := bracketLevelRe.FindStringSubmatch(value); match != nil {
		return normalizeSeverity(match[1])
	}
	switch {
	case strings.Contains(lower, "fatal"), strings.Contains(lower, "critical"), strings.Contains(lower, "panic"), strings.Contains(lower, "[crit]"), strings.Contains(lower, "[emerg]"):
		return "critical"
	case strings.Contains(lower, "error"), strings.Contains(lower, "exception"), strings.Contains(lower, "[error]"):
		return "error"
	case strings.Contains(lower, "warning"), strings.Contains(lower, "warn"), strings.Contains(lower, "[warn]"):
		return "warning"
	case strings.Contains(lower, "notice"), strings.Contains(lower, "note"):
		return "notice"
	default:
		return "info"
	}
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "emerg", "alert", "crit", "critical", "fatal", "panic":
		return "critical"
	case "err", "error":
		return "error"
	case "warn", "warning":
		return "warning"
	case "notice":
		return "notice"
	case "debug":
		return "debug"
	case "info", "":
		return "info"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}
