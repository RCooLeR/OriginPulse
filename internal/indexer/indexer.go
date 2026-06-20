package indexer

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/combiner"
	"originpulse/internal/db"
	"originpulse/internal/parser"
	"originpulse/internal/rollups"
)

var ErrDatabaseRequired = errors.New("indexing requires DATABASE_URL")

type Options struct {
	SegmentPath string
	Force       bool
	SkipRollups bool
}

type Result struct {
	SegmentID          string    `json:"segment_id,omitempty"`
	SegmentPath        string    `json:"segment_path"`
	SegmentStatus      string    `json:"segment_status,omitempty"`
	AlreadyIndexed     bool      `json:"already_indexed"`
	EventsSeen         int       `json:"events_seen"`
	ValidEvents        int       `json:"valid_events"`
	InvalidEvents      int       `json:"invalid_events"`
	EventsStoredBefore int       `json:"events_stored_before"`
	EventsDeleted      int       `json:"events_deleted"`
	EventsInserted     int       `json:"events_inserted"`
	EventsConflicted   int       `json:"events_conflicted"`
	EventsStored       int       `json:"events_stored"`
	EventsSkipped      int       `json:"events_skipped"`
	RollupsUpdated     int       `json:"rollups_updated"`
	SecurityProbes     int       `json:"security_probes"`
	ErrorEvents        int       `json:"error_events"`
	SlowRequestEvents  int       `json:"slow_request_events"`
	RangeStart         time.Time `json:"range_start,omitempty"`
	RangeEnd           time.Time `json:"range_end,omitempty"`
}

type TemporaryImportOptions struct {
	SourceName        string
	Reader            io.Reader
	TemporaryImportID string
	ImportedUntil     time.Time
}

type TemporaryImportResult struct {
	SourceName        string    `json:"source_name"`
	EventsSeen        int       `json:"events_seen"`
	ValidEvents       int       `json:"valid_events"`
	InvalidEvents     int       `json:"invalid_events"`
	EventsInserted    int       `json:"events_inserted"`
	EventsConflicted  int       `json:"events_conflicted"`
	EventsSkipped     int       `json:"events_skipped"`
	RollupsUpdated    int       `json:"rollups_updated"`
	SecurityProbes    int       `json:"security_probes"`
	ErrorEvents       int       `json:"error_events"`
	SlowRequestEvents int       `json:"slow_request_events"`
	RangeStart        time.Time `json:"range_start,omitempty"`
	RangeEnd          time.Time `json:"range_end,omitempty"`
}

type Service struct {
	db *db.Store
}

var sqlSelectFromRe = regexp.MustCompile(`(^|[^a-z0-9_])select(%20|\+|\s)+[^&]{0,240}(%20|\+|\s)+from([^a-z0-9_]|$)`)
var pathTraversalRe = regexp.MustCompile(`(^|[^.])(\.\.(/|%2f|%5c)|%2e%2e(/|%2f|%5c))`)

const slowRequestThresholdMS = 1000
const rollupRepairChunk = 6 * time.Hour

type securityProbe struct {
	Family      string
	Category    string
	RuleKey     string
	MatchReason string
}

type parsedSegmentEvent struct {
	LineNo        int64
	CombinedLine  combiner.CombinedLine
	Event         parser.AccessEvent
	Fingerprint   []byte
	PathHash      []byte
	QueryHash     []byte
	UserAgentHash []byte
	Dimensions    dimensionIDs
}

type dimensionStat struct {
	Value string
	Hash  []byte
	First time.Time
	Last  time.Time
	Count int64
}

func NewService(store *db.Store) *Service {
	return &Service{db: store}
}

func (s *Service) IndexSegment(ctx context.Context, opts Options) (Result, error) {
	if s == nil || s.db == nil || !s.db.Enabled() {
		return Result{}, ErrDatabaseRequired
	}
	if opts.SegmentPath == "" {
		return Result{}, fmt.Errorf("segment path is required")
	}
	segmentPath, err := filepath.Abs(opts.SegmentPath)
	if err != nil {
		return Result{}, err
	}
	pool, err := s.db.Pool()
	if err != nil {
		return Result{}, err
	}

	segment, err := s.segmentForPath(ctx, pool, segmentPath)
	if err != nil {
		return Result{}, err
	}

	storedBefore, err := s.countEventsForSegment(ctx, pool, segment.ID)
	if err != nil {
		return Result{}, err
	}
	alreadyIndexed := !opts.Force && segment.Status == "indexed" && (segment.LineCount == 0 || storedBefore > 0)

	result := Result{
		SegmentID:          segment.ID,
		SegmentPath:        segmentPath,
		SegmentStatus:      segment.Status,
		AlreadyIndexed:     alreadyIndexed,
		EventsStoredBefore: int(storedBefore),
		RangeStart:         segment.BucketStart,
		RangeEnd:           segment.BucketEnd,
	}

	events, seen, invalid, err := s.parseSegmentEvents(ctx, opts.SegmentPath)
	if err != nil {
		return result, err
	}
	result.EventsSeen = seen
	result.InvalidEvents = invalid
	result.ValidEvents = len(events)
	if result.AlreadyIndexed {
		result.EventsSkipped = result.EventsSeen
		return result, nil
	}

	inserted, conflicted, deleted, securityProbes, errorFacts, slowFacts, err := s.bulkStoreSegmentEvents(ctx, pool, segment.ID, events)
	if err != nil {
		return result, err
	}
	result.EventsInserted = inserted
	result.EventsConflicted = conflicted
	result.EventsDeleted = deleted
	result.EventsSkipped = result.InvalidEvents + conflicted
	result.SecurityProbes = securityProbes
	result.ErrorEvents = errorFacts
	result.SlowRequestEvents = slowFacts

	storedCount, err := s.countEventsForSegment(ctx, pool, segment.ID)
	if err != nil {
		return result, err
	}
	result.EventsStored = int(storedCount)

	if !opts.SkipRollups {
		rollups, err := s.rebuildRollups(ctx, pool, segment.BucketStart, segment.BucketEnd)
		if err != nil {
			return result, err
		}
		result.RollupsUpdated = rollups
	}
	if !opts.SkipRollups {
		if _, err := pool.Exec(ctx, `
UPDATE access_events
SET rollups_1h_backfilled_at = now()
WHERE segment_id = $1::uuid`, segment.ID); err != nil {
			return result, err
		}
	}

	if _, err := pool.Exec(ctx, `UPDATE combined_segments SET indexed_at = now(), status = 'indexed' WHERE id = $1`, segment.ID); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Service) ImportTemporaryCombinedGzip(ctx context.Context, opts TemporaryImportOptions) (TemporaryImportResult, error) {
	if s == nil || s.db == nil || !s.db.Enabled() {
		return TemporaryImportResult{}, ErrDatabaseRequired
	}
	if opts.Reader == nil {
		return TemporaryImportResult{}, fmt.Errorf("reader is required")
	}
	if strings.TrimSpace(opts.TemporaryImportID) == "" {
		return TemporaryImportResult{}, fmt.Errorf("temporary import id is required")
	}
	if opts.ImportedUntil.IsZero() {
		return TemporaryImportResult{}, fmt.Errorf("imported until is required")
	}
	pool, err := s.db.Pool()
	if err != nil {
		return TemporaryImportResult{}, err
	}

	gzipReader, err := gzip.NewReader(opts.Reader)
	if err != nil {
		return TemporaryImportResult{}, err
	}
	defer gzipReader.Close()

	result := TemporaryImportResult{SourceName: opts.SourceName}
	scanner := bufio.NewScanner(gzipReader)
	scanner.Buffer(make([]byte, 0, 128*1024), 10*1024*1024)
	var segmentLineNo int64
	for scanner.Scan() {
		segmentLineNo++
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		var combinedLine combiner.CombinedLine
		if err := json.Unmarshal(scanner.Bytes(), &combinedLine); err != nil {
			result.InvalidEvents++
			result.EventsSkipped++
			continue
		}
		result.EventsSeen++
		valid, inserted, eventID, event, dimensions, err := s.insertEvent(ctx, pool, "", segmentLineNo, combinedLine, false, opts.TemporaryImportID, opts.ImportedUntil)
		if err != nil {
			return result, err
		}
		if !valid {
			result.InvalidEvents++
			result.EventsSkipped++
			continue
		}
		result.ValidEvents++
		if result.RangeStart.IsZero() || event.TS.Before(result.RangeStart) {
			result.RangeStart = event.TS
		}
		if event.TS.After(result.RangeEnd) {
			result.RangeEnd = event.TS
		}
		if inserted {
			result.EventsInserted++
			probes, err := s.insertSecurityProbes(ctx, pool, eventID, "", combinedLine, event, opts.TemporaryImportID)
			if err != nil {
				return result, err
			}
			result.SecurityProbes += probes
			errorFacts, slowFacts, err := s.insertEventFacts(ctx, pool, eventID, "", segmentLineNo, combinedLine, event, dimensions, opts.TemporaryImportID)
			if err != nil {
				return result, err
			}
			result.ErrorEvents += errorFacts
			result.SlowRequestEvents += slowFacts
		} else {
			result.EventsConflicted++
			result.EventsSkipped++
		}
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	if result.EventsInserted > 0 && !result.RangeStart.IsZero() && !result.RangeEnd.IsZero() {
		start := result.RangeStart.UTC().Truncate(time.Hour)
		end := result.RangeEnd.UTC().Truncate(time.Hour).Add(time.Hour)
		rollups, err := s.rebuildRollups(ctx, pool, start, end)
		if err != nil {
			return result, err
		}
		result.RollupsUpdated = rollups
		if _, err := pool.Exec(ctx, `
UPDATE access_events
SET rollups_1h_backfilled_at = now()
WHERE temporary_import_id = $1::uuid`, opts.TemporaryImportID); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (s *Service) RebuildRollups(ctx context.Context, start time.Time, end time.Time) (int, error) {
	if s == nil || s.db == nil || !s.db.Enabled() {
		return 0, ErrDatabaseRequired
	}
	pool, err := s.db.Pool()
	if err != nil {
		return 0, err
	}
	start = start.UTC().Truncate(time.Hour)
	end = end.UTC().Truncate(time.Hour).Add(time.Hour)
	if !end.After(start) {
		return 0, nil
	}
	total := 0
	for chunkStart := start; chunkStart.Before(end); chunkStart = chunkStart.Add(rollupRepairChunk) {
		chunkEnd := chunkStart.Add(rollupRepairChunk)
		if chunkEnd.After(end) {
			chunkEnd = end
		}
		rows, err := s.rebuildRollups(ctx, pool, chunkStart, chunkEnd)
		if err != nil {
			return total, err
		}
		total += rows
	}
	if _, err := pool.Exec(ctx, `
UPDATE access_events
SET rollups_1h_backfilled_at = now()
WHERE ts >= $1 AND ts < $2`, start, end); err != nil {
		return total, err
	}
	return total, nil
}

func (s *Service) MarkRollupsBackfilledForSegments(ctx context.Context, segmentIDs []string) error {
	if len(segmentIDs) == 0 {
		return nil
	}
	if s == nil || s.db == nil || !s.db.Enabled() {
		return ErrDatabaseRequired
	}
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
UPDATE access_events
SET rollups_1h_backfilled_at = now()
WHERE segment_id::text = ANY($1)`, segmentIDs)
	return err
}

func (s *Service) RepairUnbackfilledRollups(ctx context.Context) (int, error) {
	if s == nil || s.db == nil || !s.db.Enabled() {
		return 0, ErrDatabaseRequired
	}
	pool, err := s.db.Pool()
	if err != nil {
		return 0, err
	}
	var minTS time.Time
	var maxTS time.Time
	var count int64
	if err := pool.QueryRow(ctx, `
SELECT min(ts), max(ts), count(*)::bigint
FROM access_events
WHERE rollups_1h_backfilled_at IS NULL`).Scan(&minTS, &maxTS, &count); err != nil {
		return 0, err
	}
	if count == 0 || minTS.IsZero() || maxTS.IsZero() {
		return 0, nil
	}
	return s.RebuildRollups(ctx, minTS, maxTS)
}

func (s *Service) parseSegmentEvents(ctx context.Context, segmentPath string) ([]parsedSegmentEvent, int, int, error) {
	file, err := os.Open(segmentPath)
	if err != nil {
		return nil, 0, 0, err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, 0, 0, err
	}
	defer gzipReader.Close()

	scanner := bufio.NewScanner(gzipReader)
	scanner.Buffer(make([]byte, 0, 128*1024), 10*1024*1024)
	events := make([]parsedSegmentEvent, 0, 4096)
	seen := 0
	invalid := 0
	var segmentLineNo int64
	for scanner.Scan() {
		segmentLineNo++
		select {
		case <-ctx.Done():
			return nil, seen, invalid, ctx.Err()
		default:
		}

		var combinedLine combiner.CombinedLine
		if err := json.Unmarshal(scanner.Bytes(), &combinedLine); err != nil {
			invalid++
			continue
		}
		seen++
		parsed, err := parser.ParseAccessLine(combinedLine.Raw)
		if err != nil {
			invalid++
			continue
		}
		parsed.Method = cleanText(parsed.Method)
		parsed.Scheme = cleanText(parsed.Scheme)
		parsed.Host = cleanText(parsed.Host)
		parsed.Path = cleanText(parsed.Path)
		parsed.Query = cleanText(parsed.Query)
		parsed.Referer = cleanText(parsed.Referer)
		parsed.UserAgent = cleanText(parsed.UserAgent)
		parsed.ClientIP = cleanText(parsed.ClientIP)

		fingerprint, err := hex.DecodeString(combinedLine.Fingerprint)
		if err != nil {
			return nil, seen, invalid, err
		}
		events = append(events, parsedSegmentEvent{
			LineNo:        segmentLineNo,
			CombinedLine:  combinedLine,
			Event:         parsed,
			Fingerprint:   fingerprint,
			PathHash:      hashBytes(parsed.Path),
			QueryHash:     hashBytes(parsed.Query),
			UserAgentHash: hashBytes(parsed.UserAgent),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, seen, invalid, err
	}
	return events, seen, invalid, nil
}

func (s *Service) bulkStoreSegmentEvents(ctx context.Context, pool *pgxpool.Pool, segmentID string, events []parsedSegmentEvent) (int, int, int, int, int, int, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, 0, 0, 0, 0, 0, err
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return 0, 0, 0, 0, 0, 0, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM security_probe_events WHERE segment_id = $1::uuid`, segmentID); err != nil {
		return 0, 0, 0, 0, 0, 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM error_events WHERE segment_id = $1::uuid`, segmentID); err != nil {
		return 0, 0, 0, 0, 0, 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM slow_request_events WHERE segment_id = $1::uuid`, segmentID); err != nil {
		return 0, 0, 0, 0, 0, 0, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM access_events WHERE segment_id = $1::uuid`, segmentID)
	if err != nil {
		return 0, 0, 0, 0, 0, 0, err
	}
	deleted := int(tag.RowsAffected())

	if err := s.bulkResolveDimensions(ctx, tx, events); err != nil {
		return 0, 0, deleted, 0, 0, 0, err
	}
	insertedIDs, err := s.bulkInsertAccessEvents(ctx, tx, segmentID, events)
	if err != nil {
		return 0, 0, deleted, 0, 0, 0, err
	}
	inserted := len(insertedIDs)
	conflicted := len(events) - inserted
	errorFacts, slowFacts, err := s.bulkInsertEventFacts(ctx, tx, segmentID, events, insertedIDs)
	if err != nil {
		return inserted, conflicted, deleted, 0, 0, 0, err
	}
	securityProbes, err := s.bulkInsertSecurityProbes(ctx, tx, segmentID, events, insertedIDs)
	if err != nil {
		return inserted, conflicted, deleted, 0, errorFacts, slowFacts, err
	}
	if err := tx.Commit(ctx); err != nil {
		return inserted, conflicted, deleted, securityProbes, errorFacts, slowFacts, err
	}
	return inserted, conflicted, deleted, securityProbes, errorFacts, slowFacts, nil
}

func (s *Service) bulkResolveDimensions(ctx context.Context, tx pgx.Tx, events []parsedSegmentEvent) error {
	ipStats := map[string]dimensionStat{}
	pathStats := map[string]dimensionStat{}
	queryStats := map[string]dimensionStat{}
	uaStats := map[string]dimensionStat{}
	for _, event := range events {
		trackDimension(ipStats, event.Event.ClientIP, nil, event.Event.TS)
		trackDimension(pathStats, hex.EncodeToString(event.PathHash), event.PathHash, event.Event.TS, event.Event.Path)
		trackDimension(queryStats, hex.EncodeToString(event.QueryHash), event.QueryHash, event.Event.TS, event.Event.Query)
		trackDimension(uaStats, hex.EncodeToString(event.UserAgentHash), event.UserAgentHash, event.Event.TS, event.Event.UserAgent)
	}
	ipIDs, err := bulkUpsertIPDimensions(ctx, tx, ipStats)
	if err != nil {
		return err
	}
	pathIDs, err := bulkUpsertHashDimensions(ctx, tx, "tmp_dim_paths", "dim_paths", "path", "path_hash", pathStats)
	if err != nil {
		return err
	}
	queryIDs, err := bulkUpsertHashDimensions(ctx, tx, "tmp_dim_queries", "dim_queries", "query", "query_hash", queryStats)
	if err != nil {
		return err
	}
	uaIDs, err := bulkUpsertHashDimensions(ctx, tx, "tmp_dim_user_agents", "dim_user_agents", "user_agent", "user_agent_hash", uaStats)
	if err != nil {
		return err
	}
	for i := range events {
		events[i].Dimensions.IPID = ipIDs[events[i].Event.ClientIP]
		events[i].Dimensions.PathID = pathIDs[hex.EncodeToString(events[i].PathHash)]
		events[i].Dimensions.QueryID = queryIDs[hex.EncodeToString(events[i].QueryHash)]
		events[i].Dimensions.UserAgentID = uaIDs[hex.EncodeToString(events[i].UserAgentHash)]
	}
	return nil
}

func trackDimension(stats map[string]dimensionStat, key string, hash []byte, seenAt time.Time, values ...string) {
	if key == "" {
		return
	}
	value := key
	if len(values) > 0 {
		value = values[0]
	}
	if value == "" {
		return
	}
	stat, ok := stats[key]
	if !ok {
		stats[key] = dimensionStat{Value: value, Hash: hash, First: seenAt, Last: seenAt, Count: 1}
		return
	}
	if seenAt.Before(stat.First) {
		stat.First = seenAt
	}
	if seenAt.After(stat.Last) {
		stat.Last = seenAt
	}
	stat.Count++
	stats[key] = stat
}

func bulkUpsertIPDimensions(ctx context.Context, tx pgx.Tx, stats map[string]dimensionStat) (map[string]int64, error) {
	ids := map[string]int64{}
	if len(stats) == 0 {
		return ids, nil
	}
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE tmp_dim_ips (ip text NOT NULL, first_seen_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL, request_count bigint NOT NULL) ON COMMIT DROP`); err != nil {
		return ids, err
	}
	rows := make([][]any, 0, len(stats))
	keys := make([]string, 0, len(stats))
	for key := range stats {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		stat := stats[key]
		rows = append(rows, []any{stat.Value, stat.First, stat.Last, stat.Count})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"tmp_dim_ips"}, []string{"ip", "first_seen_at", "last_seen_at", "request_count"}, pgx.CopyFromRows(rows)); err != nil {
		return ids, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO dim_ips (ip, first_seen_at, last_seen_at, request_count)
SELECT ip::inet, min(first_seen_at), max(last_seen_at), sum(request_count)::bigint
FROM tmp_dim_ips
GROUP BY ip
ON CONFLICT (ip) DO UPDATE SET
  first_seen_at = LEAST(dim_ips.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at = GREATEST(dim_ips.last_seen_at, EXCLUDED.last_seen_at),
  request_count = dim_ips.request_count + EXCLUDED.request_count`); err != nil {
		return ids, err
	}
	resultRows, err := tx.Query(ctx, `
SELECT t.ip, d.id
FROM (SELECT DISTINCT ip FROM tmp_dim_ips) t
JOIN dim_ips d ON d.ip = t.ip::inet`)
	if err != nil {
		return ids, err
	}
	defer resultRows.Close()
	for resultRows.Next() {
		var ip string
		var id int64
		if err := resultRows.Scan(&ip, &id); err != nil {
			return ids, err
		}
		ids[ip] = id
	}
	return ids, resultRows.Err()
}

func bulkUpsertHashDimensions(ctx context.Context, tx pgx.Tx, tempTable string, table string, valueColumn string, hashColumn string, stats map[string]dimensionStat) (map[string]int64, error) {
	ids := map[string]int64{}
	if len(stats) == 0 {
		return ids, nil
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(`CREATE TEMP TABLE %s (value text NOT NULL, hash bytea NOT NULL, first_seen_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL, request_count bigint NOT NULL) ON COMMIT DROP`, tempTable)); err != nil {
		return ids, err
	}
	rows := make([][]any, 0, len(stats))
	keys := make([]string, 0, len(stats))
	for key := range stats {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		stat := stats[key]
		rows = append(rows, []any{stat.Value, stat.Hash, stat.First, stat.Last, stat.Count})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{tempTable}, []string{"value", "hash", "first_seen_at", "last_seen_at", "request_count"}, pgx.CopyFromRows(rows)); err != nil {
		return ids, err
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(`
INSERT INTO %s (%s, %s, first_seen_at, last_seen_at, request_count)
SELECT value, hash, min(first_seen_at), max(last_seen_at), sum(request_count)::bigint
FROM %s
GROUP BY value, hash
ON CONFLICT (%s) DO UPDATE SET
  first_seen_at = LEAST(%s.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at = GREATEST(%s.last_seen_at, EXCLUDED.last_seen_at),
  request_count = %s.request_count + EXCLUDED.request_count`, table, valueColumn, hashColumn, tempTable, hashColumn, table, table, table)); err != nil {
		return ids, err
	}
	resultRows, err := tx.Query(ctx, fmt.Sprintf(`
SELECT t.hash, d.id
FROM (SELECT DISTINCT hash FROM %s) t
JOIN %s d ON d.%s = t.hash`, tempTable, table, hashColumn))
	if err != nil {
		return ids, err
	}
	defer resultRows.Close()
	for resultRows.Next() {
		var hash []byte
		var id int64
		if err := resultRows.Scan(&hash, &id); err != nil {
			return ids, err
		}
		ids[hex.EncodeToString(hash)] = id
	}
	return ids, resultRows.Err()
}

func (s *Service) bulkInsertAccessEvents(ctx context.Context, tx pgx.Tx, segmentID string, events []parsedSegmentEvent) (map[int64]int64, error) {
	inserted := map[int64]int64{}
	if len(events) == 0 {
		return inserted, nil
	}
	if _, err := tx.Exec(ctx, `
CREATE TEMP TABLE tmp_access_events (
  segment_line_no bigint NOT NULL,
  ts timestamptz NOT NULL,
  site_id text NOT NULL,
  env text NOT NULL,
  container_id text NOT NULL,
  client_ip text,
  method text,
  scheme text,
  host text,
  path text,
  path_hash bytea,
  query text,
  status int,
  bytes_sent bigint,
  referer text,
  user_agent text,
  user_agent_hash bytea,
  request_time_ms int,
  upstream_time_ms int,
  fingerprint bytea NOT NULL,
  segment_id text,
  raw_file_id text,
  raw_line_no bigint,
  ip_id bigint,
  path_id bigint,
  query_id bigint,
  user_agent_id bigint
) ON COMMIT DROP`); err != nil {
		return inserted, err
	}
	rows := make([][]any, 0, len(events))
	for _, item := range events {
		event := item.Event
		rows = append(rows, []any{
			item.LineNo,
			event.TS,
			item.CombinedLine.SiteID,
			item.CombinedLine.Env,
			item.CombinedLine.ContainerID,
			event.ClientIP,
			event.Method,
			event.Scheme,
			event.Host,
			event.Path,
			item.PathHash,
			event.Query,
			event.Status,
			event.BytesSent,
			event.Referer,
			event.UserAgent,
			item.UserAgentHash,
			event.RequestTimeMS,
			event.UpstreamTimeMS,
			item.Fingerprint,
			segmentID,
			item.CombinedLine.RawFileID,
			item.CombinedLine.RawLineNo,
			nullableID(item.Dimensions.IPID),
			nullableID(item.Dimensions.PathID),
			nullableID(item.Dimensions.QueryID),
			nullableID(item.Dimensions.UserAgentID),
		})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"tmp_access_events"}, []string{
		"segment_line_no", "ts", "site_id", "env", "container_id", "client_ip", "method", "scheme", "host", "path", "path_hash", "query",
		"status", "bytes_sent", "referer", "user_agent", "user_agent_hash", "request_time_ms", "upstream_time_ms", "fingerprint",
		"segment_id", "raw_file_id", "raw_line_no", "ip_id", "path_id", "query_id", "user_agent_id",
	}, pgx.CopyFromRows(rows)); err != nil {
		return inserted, err
	}
	resultRows, err := tx.Query(ctx, `
INSERT INTO access_events (
  ts, site_id, env, container_id, client_ip, method, scheme, host, path, path_hash, query,
  status, bytes_sent, referer, user_agent, user_agent_hash, request_time_ms, upstream_time_ms, fingerprint, segment_id,
  segment_line_no, raw_file_id, raw_line_no, ip_id, path_id, query_id, user_agent_id
)
SELECT
  ts, site_id, env, container_id, nullif(client_ip, '')::inet, nullif(method, ''), nullif(scheme, ''), nullif(host, ''), nullif(path, ''), path_hash, nullif(query, ''),
  nullif(status, 0), bytes_sent, nullif(referer, ''), nullif(user_agent, ''), user_agent_hash, nullif(request_time_ms, 0), nullif(upstream_time_ms, 0), fingerprint, nullif(segment_id, '')::uuid,
  segment_line_no, nullif(raw_file_id, '')::uuid, nullif(raw_line_no, 0), ip_id, path_id, query_id, user_agent_id
FROM tmp_access_events
ON CONFLICT (fingerprint, ts) DO NOTHING
RETURNING id, segment_line_no`)
	if err != nil {
		return inserted, err
	}
	defer resultRows.Close()
	for resultRows.Next() {
		var eventID int64
		var lineNo int64
		if err := resultRows.Scan(&eventID, &lineNo); err != nil {
			return inserted, err
		}
		inserted[lineNo] = eventID
	}
	return inserted, resultRows.Err()
}

func (s *Service) bulkInsertEventFacts(ctx context.Context, tx pgx.Tx, segmentID string, events []parsedSegmentEvent, insertedIDs map[int64]int64) (int, int, error) {
	if len(insertedIDs) == 0 {
		return 0, 0, nil
	}
	if err := copyInsertedEvents(ctx, tx, insertedIDs); err != nil {
		return 0, 0, err
	}
	errorTag, err := tx.Exec(ctx, `
INSERT INTO error_events (
  event_id, ts, site_id, env, container_id, client_ip, method,
  path_id, query_id, user_agent_id, status, bytes_sent, referer,
  segment_id, segment_line_no
)
SELECT i.event_id, e.ts, e.site_id, e.env, nullif(e.container_id, ''), nullif(e.client_ip, '')::inet, nullif(e.method, ''),
       e.path_id, e.query_id, e.user_agent_id, e.status, e.bytes_sent, nullif(e.referer, ''),
       $1::uuid, e.segment_line_no
FROM tmp_access_events e
JOIN tmp_inserted_events i ON i.segment_line_no = e.segment_line_no
WHERE e.status >= 400
ON CONFLICT (event_id) DO NOTHING`, segmentID)
	if err != nil {
		return 0, 0, err
	}
	slowTag, err := tx.Exec(ctx, `
INSERT INTO slow_request_events (
  event_id, ts, site_id, env, container_id, client_ip, method,
  path_id, query_id, user_agent_id, status, request_time_ms, upstream_time_ms,
  segment_id, segment_line_no
)
SELECT i.event_id, e.ts, e.site_id, e.env, nullif(e.container_id, ''), nullif(e.client_ip, '')::inet, nullif(e.method, ''),
       e.path_id, e.query_id, e.user_agent_id, nullif(e.status, 0), e.request_time_ms, nullif(e.upstream_time_ms, 0),
       $1::uuid, e.segment_line_no
FROM tmp_access_events e
JOIN tmp_inserted_events i ON i.segment_line_no = e.segment_line_no
WHERE e.request_time_ms >= $2
ON CONFLICT (event_id) DO NOTHING`, segmentID, slowRequestThresholdMS)
	if err != nil {
		return int(errorTag.RowsAffected()), 0, err
	}
	return int(errorTag.RowsAffected()), int(slowTag.RowsAffected()), nil
}

func copyInsertedEvents(ctx context.Context, tx pgx.Tx, insertedIDs map[int64]int64) error {
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE IF NOT EXISTS tmp_inserted_events (segment_line_no bigint PRIMARY KEY, event_id bigint NOT NULL) ON COMMIT DROP`); err != nil {
		return err
	}
	rows := make([][]any, 0, len(insertedIDs))
	for lineNo, eventID := range insertedIDs {
		rows = append(rows, []any{lineNo, eventID})
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"tmp_inserted_events"}, []string{"segment_line_no", "event_id"}, pgx.CopyFromRows(rows))
	return err
}

func (s *Service) bulkInsertSecurityProbes(ctx context.Context, tx pgx.Tx, segmentID string, events []parsedSegmentEvent, insertedIDs map[int64]int64) (int, error) {
	if len(insertedIDs) == 0 {
		return 0, nil
	}
	if _, err := tx.Exec(ctx, `
CREATE TEMP TABLE tmp_security_probe_events (
  event_id bigint NOT NULL,
  family text NOT NULL,
  category text NOT NULL,
  rule_key text NOT NULL,
  match_reason text,
  ts timestamptz NOT NULL,
  site_id text NOT NULL,
  env text NOT NULL,
  client_ip text,
  method text,
  path text,
  query text,
  status int,
  segment_id text
) ON COMMIT DROP`); err != nil {
		return 0, err
	}
	rows := make([][]any, 0)
	for _, item := range events {
		eventID, ok := insertedIDs[item.LineNo]
		if !ok {
			continue
		}
		for _, probe := range classifySecurityProbes(item.Event) {
			rows = append(rows, []any{
				eventID,
				probe.Family,
				probe.Category,
				probe.RuleKey,
				probe.MatchReason,
				item.Event.TS,
				item.CombinedLine.SiteID,
				item.CombinedLine.Env,
				item.Event.ClientIP,
				item.Event.Method,
				item.Event.Path,
				item.Event.Query,
				item.Event.Status,
				segmentID,
			})
		}
	}
	if len(rows) == 0 {
		return 0, nil
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"tmp_security_probe_events"}, []string{
		"event_id", "family", "category", "rule_key", "match_reason", "ts", "site_id", "env", "client_ip", "method", "path", "query", "status", "segment_id",
	}, pgx.CopyFromRows(rows)); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO security_probe_events (
  event_id, family, category, rule_key, match_reason, ts, site_id, env,
  client_ip, method, path, query, status, segment_id
)
SELECT event_id, family, category, rule_key, nullif(match_reason, ''), ts, site_id, env,
       nullif(client_ip, '')::inet, nullif(method, ''), nullif(path, ''), nullif(query, ''), nullif(status, 0), nullif(segment_id, '')::uuid
FROM tmp_security_probe_events
ON CONFLICT (event_id, family, category) DO NOTHING`)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *Service) segmentForPath(ctx context.Context, pool *pgxpool.Pool, path string) (combiner.SegmentManifest, error) {
	var segment combiner.SegmentManifest
	err := pool.QueryRow(ctx, `
SELECT id::text, log_type, bucket_start, bucket_end, path, coalesce(sha256, ''),
       line_count, min_ts, max_ts, status, indexed_at, indexed_at IS NOT NULL
FROM combined_segments
WHERE path = $1`, path,
	).Scan(
		&segment.ID,
		&segment.LogType,
		&segment.BucketStart,
		&segment.BucketEnd,
		&segment.Path,
		&segment.SHA256,
		&segment.LineCount,
		&segment.MinTS,
		&segment.MaxTS,
		&segment.Status,
		&segment.IndexedAt,
		&segment.Indexed,
	)
	return segment, err
}

func (s *Service) countEventsForSegment(ctx context.Context, pool *pgxpool.Pool, segmentID string) (int64, error) {
	var count int64
	err := pool.QueryRow(ctx, `SELECT count(*)::bigint FROM access_events WHERE segment_id = $1::uuid`, segmentID).Scan(&count)
	return count, err
}

func (s *Service) insertEvent(ctx context.Context, pool *pgxpool.Pool, segmentID string, segmentLineNo int64, combinedLine combiner.CombinedLine, skipInsert bool, temporaryImportID string, importedUntil time.Time) (bool, bool, int64, parser.AccessEvent, dimensionIDs, error) {
	parsed, err := parser.ParseAccessLine(combinedLine.Raw)
	if err != nil {
		return false, false, 0, parser.AccessEvent{}, dimensionIDs{}, nil
	}
	if skipInsert {
		return true, false, 0, parsed, dimensionIDs{}, nil
	}
	parsed.Method = cleanText(parsed.Method)
	parsed.Scheme = cleanText(parsed.Scheme)
	parsed.Host = cleanText(parsed.Host)
	parsed.Path = cleanText(parsed.Path)
	parsed.Query = cleanText(parsed.Query)
	parsed.Referer = cleanText(parsed.Referer)
	parsed.UserAgent = cleanText(parsed.UserAgent)
	parsed.ClientIP = cleanText(parsed.ClientIP)

	fingerprint, err := hex.DecodeString(combinedLine.Fingerprint)
	if err != nil {
		return false, false, 0, parser.AccessEvent{}, dimensionIDs{}, err
	}

	pathHash := hashBytes(parsed.Path)
	queryHash := hashBytes(parsed.Query)
	uaHash := hashBytes(parsed.UserAgent)
	dimensions, err := s.upsertDimensions(ctx, pool, parsed, pathHash, queryHash, uaHash)
	if err != nil {
		return false, false, 0, parser.AccessEvent{}, dimensionIDs{}, err
	}
	var eventID int64
	err = pool.QueryRow(ctx, `
INSERT INTO access_events (
  ts, site_id, env, container_id, client_ip, method, scheme, host, path, path_hash, query,
  status, bytes_sent, referer, user_agent, user_agent_hash, request_time_ms, upstream_time_ms, fingerprint, segment_id,
  segment_line_no, raw_file_id, raw_line_no, ip_id, path_id, query_id, user_agent_id,
  temporary_import_id, imported_until
) VALUES (
  $1, $2, $3, $4, nullif($5, '')::inet, nullif($6, ''), nullif($7, ''), nullif($8, ''), nullif($9, ''), $10, nullif($11, ''),
  nullif($12, 0), $13, nullif($14, ''), nullif($15, ''), $16, nullif($17, 0), nullif($18, 0), $19, nullif($20, '')::uuid,
  $21, nullif($22, '')::uuid, nullif($23, 0), $24, $25, $26, $27,
  nullif($28, '')::uuid, $29
)
ON CONFLICT (fingerprint, ts) DO NOTHING
RETURNING id`,
		parsed.TS,
		combinedLine.SiteID,
		combinedLine.Env,
		combinedLine.ContainerID,
		parsed.ClientIP,
		parsed.Method,
		parsed.Scheme,
		parsed.Host,
		parsed.Path,
		pathHash,
		parsed.Query,
		parsed.Status,
		parsed.BytesSent,
		parsed.Referer,
		parsed.UserAgent,
		uaHash,
		parsed.RequestTimeMS,
		parsed.UpstreamTimeMS,
		fingerprint,
		segmentID,
		segmentLineNo,
		combinedLine.RawFileID,
		combinedLine.RawLineNo,
		nullableID(dimensions.IPID),
		nullableID(dimensions.PathID),
		nullableID(dimensions.QueryID),
		nullableID(dimensions.UserAgentID),
		temporaryImportID,
		nullableTime(importedUntil),
	).Scan(&eventID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return true, false, 0, parsed, dimensions, nil
		}
		return false, false, 0, parser.AccessEvent{}, dimensionIDs{}, err
	}

	return true, true, eventID, parsed, dimensions, nil
}

type dimensionIDs struct {
	IPID        int64
	PathID      int64
	QueryID     int64
	UserAgentID int64
}

func (s *Service) upsertDimensions(ctx context.Context, pool *pgxpool.Pool, event parser.AccessEvent, pathHash []byte, queryHash []byte, uaHash []byte) (dimensionIDs, error) {
	var ids dimensionIDs
	var err error
	ids.IPID, err = upsertIPDimension(ctx, pool, event.ClientIP, event.TS)
	if err != nil {
		return ids, err
	}
	ids.PathID, err = upsertTextHashDimension(ctx, pool, `
INSERT INTO dim_paths (path, path_hash, first_seen_at, last_seen_at, request_count)
VALUES ($1, $2, $3, $3, 1)
ON CONFLICT (path_hash) DO UPDATE SET
  first_seen_at = LEAST(dim_paths.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at = GREATEST(dim_paths.last_seen_at, EXCLUDED.last_seen_at),
  request_count = dim_paths.request_count + 1
RETURNING id`, event.Path, pathHash, event.TS)
	if err != nil {
		return ids, err
	}
	ids.QueryID, err = upsertTextHashDimension(ctx, pool, `
INSERT INTO dim_queries (query, query_hash, first_seen_at, last_seen_at, request_count)
VALUES ($1, $2, $3, $3, 1)
ON CONFLICT (query_hash) DO UPDATE SET
  first_seen_at = LEAST(dim_queries.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at = GREATEST(dim_queries.last_seen_at, EXCLUDED.last_seen_at),
  request_count = dim_queries.request_count + 1
RETURNING id`, event.Query, queryHash, event.TS)
	if err != nil {
		return ids, err
	}
	ids.UserAgentID, err = upsertTextHashDimension(ctx, pool, `
INSERT INTO dim_user_agents (user_agent, user_agent_hash, first_seen_at, last_seen_at, request_count)
VALUES ($1, $2, $3, $3, 1)
ON CONFLICT (user_agent_hash) DO UPDATE SET
  first_seen_at = LEAST(dim_user_agents.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at = GREATEST(dim_user_agents.last_seen_at, EXCLUDED.last_seen_at),
  request_count = dim_user_agents.request_count + 1
RETURNING id`, event.UserAgent, uaHash, event.TS)
	return ids, err
}

func upsertIPDimension(ctx context.Context, pool *pgxpool.Pool, ip string, seenAt time.Time) (int64, error) {
	if ip == "" {
		return 0, nil
	}
	var id int64
	err := pool.QueryRow(ctx, `
INSERT INTO dim_ips (ip, first_seen_at, last_seen_at, request_count)
VALUES ($1::inet, $2, $2, 1)
ON CONFLICT (ip) DO UPDATE SET
  first_seen_at = LEAST(dim_ips.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at = GREATEST(dim_ips.last_seen_at, EXCLUDED.last_seen_at),
  request_count = dim_ips.request_count + 1
RETURNING id`, ip, seenAt).Scan(&id)
	return id, err
}

func upsertTextHashDimension(ctx context.Context, pool *pgxpool.Pool, query string, value string, hash []byte, seenAt time.Time) (int64, error) {
	if value == "" || len(hash) == 0 {
		return 0, nil
	}
	var id int64
	err := pool.QueryRow(ctx, query, value, hash, seenAt).Scan(&id)
	return id, err
}

func nullableID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func (s *Service) insertEventFacts(ctx context.Context, pool *pgxpool.Pool, eventID int64, segmentID string, segmentLineNo int64, combinedLine combiner.CombinedLine, event parser.AccessEvent, dimensions dimensionIDs, temporaryImportID string) (int, int, error) {
	if eventID == 0 {
		return 0, 0, nil
	}
	errorFacts := 0
	slowFacts := 0
	if event.Status >= 400 {
		tag, err := pool.Exec(ctx, `
INSERT INTO error_events (
  event_id, ts, site_id, env, container_id, client_ip, method,
  path_id, query_id, user_agent_id, status, bytes_sent, referer,
  segment_id, segment_line_no, temporary_import_id
) VALUES (
  $1, $2, $3, $4, nullif($5, ''), nullif($6, '')::inet, nullif($7, ''),
  $8, $9, $10, $11, $12, nullif($13, ''),
  nullif($14, '')::uuid, $15, nullif($16, '')::uuid
)
ON CONFLICT (event_id) DO NOTHING`,
			eventID,
			event.TS,
			combinedLine.SiteID,
			combinedLine.Env,
			combinedLine.ContainerID,
			event.ClientIP,
			event.Method,
			nullableID(dimensions.PathID),
			nullableID(dimensions.QueryID),
			nullableID(dimensions.UserAgentID),
			event.Status,
			event.BytesSent,
			event.Referer,
			segmentID,
			segmentLineNo,
			temporaryImportID,
		)
		if err != nil {
			return errorFacts, slowFacts, err
		}
		errorFacts = int(tag.RowsAffected())
	}
	if event.RequestTimeMS >= slowRequestThresholdMS {
		tag, err := pool.Exec(ctx, `
INSERT INTO slow_request_events (
  event_id, ts, site_id, env, container_id, client_ip, method,
  path_id, query_id, user_agent_id, status, request_time_ms, upstream_time_ms,
  segment_id, segment_line_no, temporary_import_id
) VALUES (
  $1, $2, $3, $4, nullif($5, ''), nullif($6, '')::inet, nullif($7, ''),
  $8, $9, $10, nullif($11, 0), $12, nullif($13, 0),
  nullif($14, '')::uuid, $15, nullif($16, '')::uuid
)
ON CONFLICT (event_id) DO NOTHING`,
			eventID,
			event.TS,
			combinedLine.SiteID,
			combinedLine.Env,
			combinedLine.ContainerID,
			event.ClientIP,
			event.Method,
			nullableID(dimensions.PathID),
			nullableID(dimensions.QueryID),
			nullableID(dimensions.UserAgentID),
			event.Status,
			event.RequestTimeMS,
			event.UpstreamTimeMS,
			segmentID,
			segmentLineNo,
			temporaryImportID,
		)
		if err != nil {
			return errorFacts, slowFacts, err
		}
		slowFacts = int(tag.RowsAffected())
	}
	return errorFacts, slowFacts, nil
}

func (s *Service) insertSecurityProbes(ctx context.Context, pool *pgxpool.Pool, eventID int64, segmentID string, combinedLine combiner.CombinedLine, event parser.AccessEvent, temporaryImportID string) (int, error) {
	if eventID == 0 || event.ClientIP == "" {
		return 0, nil
	}
	probes := classifySecurityProbes(event)
	if len(probes) == 0 {
		return 0, nil
	}

	inserted := 0
	for _, probe := range probes {
		tag, err := pool.Exec(ctx, `
INSERT INTO security_probe_events (
  event_id, family, category, rule_key, match_reason, ts, site_id, env,
  client_ip, method, path, query, status, segment_id, temporary_import_id
) VALUES (
  $1, $2, $3, $4, nullif($5, ''), $6, $7, $8,
  nullif($9, '')::inet, nullif($10, ''), nullif($11, ''), nullif($12, ''), nullif($13, 0), nullif($14, '')::uuid, nullif($15, '')::uuid
)
ON CONFLICT (event_id, family, category) DO NOTHING`,
			eventID,
			probe.Family,
			probe.Category,
			probe.RuleKey,
			probe.MatchReason,
			event.TS,
			combinedLine.SiteID,
			combinedLine.Env,
			event.ClientIP,
			event.Method,
			event.Path,
			event.Query,
			event.Status,
			segmentID,
			temporaryImportID,
		)
		if err != nil {
			return inserted, err
		}
		inserted += int(tag.RowsAffected())
	}
	return inserted, nil
}

func classifySecurityProbes(event parser.AccessEvent) []securityProbe {
	path := strings.ToLower(event.Path)
	query := strings.ToLower(event.Query)
	target := path
	if query != "" {
		target += "?" + query
	}

	probes := []securityProbe{}
	if category := classifyAdminProbe(path, target, strings.ToUpper(event.Method), event.Status); category != "" {
		probes = append(probes, securityProbe{
			Family:   "admin",
			Category: category,
			RuleKey:  "admin_" + category,
		})
	}
	if category, reason := classifyInjectionProbe(path, query, target); category != "" {
		probes = append(probes, securityProbe{
			Family:      "injection",
			Category:    category,
			RuleKey:     "probe_" + category,
			MatchReason: reason,
		})
	}
	return probes
}

func classifyAdminProbe(path string, target string, method string, status int) string {
	if strings.Contains(path, "phpmyadmin") || strings.Contains(path, "/pma") || strings.Contains(path, "adminer") ||
		strings.Contains(path, "/xmlrpc.php") || strings.Contains(path, "/wp-admin/install.php") ||
		strings.Contains(path, "/wp-admin/setup-config.php") {
		return "admin_tool"
	}
	if strings.Contains(target, "lostpassword") || strings.Contains(target, "lost-password") ||
		strings.Contains(target, "retrievepassword") || strings.Contains(target, "resetpass") ||
		strings.Contains(target, "forgot_password") || strings.Contains(target, "forgot-password") ||
		strings.Contains(target, "passwordreset") || strings.Contains(target, "reset_password") ||
		strings.Contains(target, "request-password-reset") || strings.HasPrefix(path, "/password/reset") ||
		strings.HasPrefix(path, "/password/email") || strings.HasPrefix(path, "/reset-password") ||
		strings.HasPrefix(path, "/forgot-password") || strings.HasPrefix(path, "/account/reset") {
		return "password_reset"
	}
	if method == "POST" && (path == "/wp-login.php" || strings.Contains(path, "/login") ||
		strings.Contains(path, "/user/login") || strings.Contains(path, "/site/login") ||
		strings.Contains(path, "/s/login") || strings.Contains(target, "controller=adminlogin") ||
		strings.Contains(target, "submitlogin") || strings.Contains(target, "adminlogin")) {
		return "admin_login"
	}
	if strings.Contains(path, "/wp-admin/admin-ajax.php") && status >= 200 && status < 400 {
		return ""
	}
	if strings.Contains(path, "/wp-login.php") || strings.Contains(path, "/wp-admin") ||
		strings.Contains(path, "/administrator") || strings.Contains(path, "/admin") ||
		strings.Contains(path, "/login") || strings.Contains(path, "/user/login") ||
		strings.Contains(path, "/backend") || strings.Contains(path, "/manager") {
		return "admin_path"
	}
	return ""
}

func classifyInjectionProbe(path string, query string, target string) (string, string) {
	if !looksLikeInjectionCandidate(path, query) {
		return "", ""
	}
	if strings.Contains(target, "union") && strings.Contains(target, "select") {
		return "sql_injection", "union_select"
	}
	if strings.Contains(target, ";select") || strings.Contains(target, "3bselect") || sqlSelectFromRe.MatchString(target) {
		return "sql_injection", "select_from"
	}
	if strings.Contains(target, "information_schema") {
		return "sql_injection", "information_schema"
	}
	if strings.Contains(target, "sleep(") || strings.Contains(target, "benchmark(") {
		return "sql_injection", "time_delay_function"
	}
	if strings.Contains(target, "extractvalue(") || strings.Contains(target, "updatexml(") || strings.Contains(target, "concat(") {
		return "sql_injection", "sql_function"
	}
	if strings.Contains(target, " or 1=1") || strings.Contains(target, " and 1=1") ||
		strings.Contains(target, "+or+1%3d") || strings.Contains(target, "+and+1%3d") ||
		strings.Contains(target, "%25%27%20or%20") || strings.Contains(target, "%27%20or%20") ||
		strings.Contains(target, "%27+or+") {
		return "sql_injection", "tautology"
	}
	if (strings.Contains(target, "--") || strings.Contains(target, "%2d%2d") ||
		strings.Contains(target, "/*") || strings.Contains(target, "%2f%2a") || strings.Contains(target, "%2f**")) &&
		(strings.Contains(target, "select") || strings.Contains(target, "union") ||
			strings.Contains(target, "information_schema") || strings.Contains(target, "concat(") ||
			strings.Contains(target, "sleep(") || strings.Contains(target, "benchmark(") ||
			strings.Contains(target, "extractvalue(") || strings.Contains(target, "updatexml(")) {
		return "sql_injection", "sql_comment_with_keyword"
	}
	if strings.Contains(target, "<script") || strings.Contains(target, "3cscript") {
		return "xss", "script_tag"
	}
	if strings.Contains(target, "javascript:") || strings.Contains(target, "onerror=") ||
		strings.Contains(target, "onload=") || strings.Contains(target, "alert(") {
		return "xss", "xss_payload"
	}
	if strings.HasPrefix(path, "/.env") || strings.Contains(target, "/.env") ||
		strings.Contains(target, "wp-config.php") || strings.Contains(target, "composer.json") ||
		strings.Contains(target, "composer.lock") || strings.Contains(target, "id_rsa") ||
		strings.Contains(target, "/.git/") {
		return "secret_file", "secret_file"
	}
	if pathTraversalRe.MatchString(target) || strings.Contains(target, "/etc/passwd") ||
		strings.Contains(target, "proc/self/environ") || strings.Contains(target, "boot.ini") {
		return "path_traversal", "path_traversal"
	}
	return "", ""
}

func looksLikeInjectionCandidate(path string, query string) bool {
	target := path + "?" + query
	for _, needle := range []string{
		".env", "wp-config.php", "composer.json", "composer.lock", "id_rsa", ".git/",
		"union", "select", "information_schema", "sleep(", "benchmark(", "extractvalue(",
		"updatexml(", "concat(", " or 1=1", " and 1=1", "+or+1%3d", "+and+1%3d",
		"--", "/*", "2d%2d", "2f%2a", "<script", "3cscript", "javascript:",
		"onerror=", "onload=", "alert(", "/etc/passwd", "proc/self/environ", "boot.ini",
		"..", "2e%2e",
	} {
		if strings.Contains(target, needle) {
			return true
		}
	}
	return false
}

func (s *Service) rebuildRollups(ctx context.Context, pool *pgxpool.Pool, start time.Time, end time.Time) (int, error) {
	return rollups.Rebuild(ctx, pool, start, end)
}

func hashBytes(value string) []byte {
	if value == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func cleanText(value string) string {
	return strings.ToValidUTF8(strings.ReplaceAll(value, "\x00", ""), "")
}
