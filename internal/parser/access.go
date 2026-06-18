package parser

import (
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var bracketTimestamp = regexp.MustCompile(`\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]`)

var ErrTimestampNotFound = errors.New("timestamp not found")
var ErrInvalidAccessLine = errors.New("invalid access log line")

type AccessEvent struct {
	TS        time.Time
	ClientIP  string
	Method    string
	Scheme    string
	Host      string
	Path      string
	Query     string
	Status    int
	BytesSent int64
	Referer   string
	UserAgent string
}

func ParseAccessTimestamp(line string) (time.Time, error) {
	line = cleanLogLine(line)
	if line == "" {
		return time.Time{}, ErrTimestampNotFound
	}

	if match := bracketTimestamp.FindStringSubmatch(line); len(match) == 2 {
		ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", match[1])
		if err != nil {
			return time.Time{}, err
		}
		return ts.UTC(), nil
	}

	firstField := line
	if idx := strings.IndexAny(line, " \t"); idx >= 0 {
		firstField = line[:idx]
	}

	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700"} {
		ts, err := time.Parse(layout, firstField)
		if err == nil {
			return ts.UTC(), nil
		}
	}

	return time.Time{}, ErrTimestampNotFound
}

func ParseAccessLine(line string) (AccessEvent, error) {
	line = cleanLogLine(line)
	ts, err := ParseAccessTimestamp(line)
	if err != nil {
		return AccessEvent{}, err
	}

	fields := splitAccessFields(line)
	if len(fields) < 7 {
		return AccessEvent{}, ErrInvalidAccessLine
	}

	requestIndex := -1
	for i, field := range fields {
		if strings.Contains(field, " HTTP/") || strings.HasPrefix(field, "GET ") || strings.HasPrefix(field, "POST ") {
			requestIndex = i
			break
		}
	}
	if requestIndex <= 0 || requestIndex+2 >= len(fields) {
		return AccessEvent{}, ErrInvalidAccessLine
	}

	status, _ := strconv.Atoi(fields[requestIndex+1])
	bytesSent := parseBytes(fields[requestIndex+2])

	event := AccessEvent{
		TS:        ts,
		ClientIP:  bestClientIP(fields),
		Status:    status,
		BytesSent: bytesSent,
	}

	requestParts := strings.Split(fields[requestIndex], " ")
	if len(requestParts) >= 2 {
		event.Method = requestParts[0]
		target := requestParts[1]
		event.Path, event.Query, event.Scheme, event.Host = parseTarget(target)
	}

	if requestIndex+3 < len(fields) {
		event.Referer = dashToEmpty(fields[requestIndex+3])
	}
	if requestIndex+4 < len(fields) {
		event.UserAgent = dashToEmpty(fields[requestIndex+4])
	}
	return event, nil
}

func cleanLogLine(line string) string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "\ufeff")
	return strings.TrimSpace(line)
}

func splitAccessFields(line string) []string {
	fields := make([]string, 0, 12)
	var current strings.Builder
	inQuote := false
	inBracket := false
	escaped := false

	for _, r := range line {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case r == '[' && !inQuote:
			inBracket = true
			current.WriteRune(r)
		case r == ']' && !inQuote:
			inBracket = false
			current.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuote && !inBracket:
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	return fields
}

func parseTarget(target string) (string, string, string, string) {
	if parsed, err := url.Parse(target); err == nil {
		if parsed.IsAbs() {
			return emptyPath(parsed.Path), parsed.RawQuery, parsed.Scheme, parsed.Host
		}
		return emptyPath(parsed.Path), parsed.RawQuery, "", ""
	}

	if idx := strings.Index(target, "?"); idx >= 0 {
		return emptyPath(target[:idx]), target[idx+1:], "", ""
	}
	return emptyPath(target), "", "", ""
}

func bestClientIP(fields []string) string {
	if len(fields) == 0 {
		return ""
	}

	forwarded := make([]string, 0)
	for i := len(fields) - 1; i >= 0; i-- {
		field := fields[i]
		if !strings.Contains(field, ",") {
			continue
		}
		for _, part := range strings.Split(field, ",") {
			forwarded = append(forwarded, strings.TrimSpace(part))
		}
	}

	for _, candidate := range forwarded {
		if ip, ok := parseIPCandidate(candidate); ok && isPublicIP(ip) {
			return ip.String()
		}
	}
	for _, candidate := range append(forwarded, fields[0]) {
		if ip, ok := parseIPCandidate(candidate); ok {
			return ip.String()
		}
	}
	return ""
}

func parseIPCandidate(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "[]")
	if value == "" || value == "-" || strings.EqualFold(value, "unix:") {
		return netip.Addr{}, false
	}
	if host, _, ok := strings.Cut(value, ":"); ok && strings.Count(value, ":") == 1 {
		value = host
	}
	ip, err := netip.ParseAddr(value)
	return ip, err == nil
}

func isPublicIP(ip netip.Addr) bool {
	return ip.IsValid() &&
		!ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsUnspecified()
}

func emptyPath(value string) string {
	if value == "" {
		return "/"
	}
	return value
}

func parseBytes(value string) int64 {
	if value == "-" || value == "" {
		return 0
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func dashToEmpty(value string) string {
	if value == "-" {
		return ""
	}
	return value
}
