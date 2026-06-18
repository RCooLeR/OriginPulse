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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"originpulse/internal/combiner"
	"originpulse/internal/db"
	"originpulse/internal/parser"
)

var ErrDatabaseRequired = errors.New("indexing requires DATABASE_URL")

type Options struct {
	SegmentPath string
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
	RangeStart         time.Time `json:"range_start,omitempty"`
	RangeEnd           time.Time `json:"range_end,omitempty"`
}

type Service struct {
	db *db.Store
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
	alreadyIndexed := segment.Status == "indexed" && (segment.LineCount == 0 || storedBefore > 0)

	result := Result{
		SegmentID:          segment.ID,
		SegmentPath:        segmentPath,
		SegmentStatus:      segment.Status,
		AlreadyIndexed:     alreadyIndexed,
		EventsStoredBefore: int(storedBefore),
		RangeStart:         segment.BucketStart,
		RangeEnd:           segment.BucketEnd,
	}
	if !result.AlreadyIndexed {
		tag, err := pool.Exec(ctx, `DELETE FROM access_events WHERE segment_id = $1::uuid`, segment.ID)
		if err != nil {
			return result, err
		}
		result.EventsDeleted = int(tag.RowsAffected())
	}
	file, err := os.Open(opts.SegmentPath)
	if err != nil {
		return result, err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return result, err
	}
	defer gzipReader.Close()

	scanner := bufio.NewScanner(gzipReader)
	scanner.Buffer(make([]byte, 0, 128*1024), 10*1024*1024)
	for scanner.Scan() {
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
		valid, inserted, err := s.insertEvent(ctx, pool, segment.ID, combinedLine, result.AlreadyIndexed)
		if err != nil {
			return result, err
		}
		if !valid {
			result.InvalidEvents++
			result.EventsSkipped++
			continue
		}
		result.ValidEvents++
		if result.AlreadyIndexed {
			result.EventsSkipped++
			continue
		}
		if inserted {
			result.EventsInserted++
		} else {
			result.EventsConflicted++
			result.EventsSkipped++
		}
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}

	storedCount, err := s.countEventsForSegment(ctx, pool, segment.ID)
	if err != nil {
		return result, err
	}
	result.EventsStored = int(storedCount)

	rollups, err := s.rebuildRollups(ctx, pool, segment.BucketStart, segment.BucketEnd)
	if err != nil {
		return result, err
	}
	result.RollupsUpdated = rollups

	if _, err := pool.Exec(ctx, `UPDATE combined_segments SET indexed_at = now(), status = 'indexed' WHERE id = $1`, segment.ID); err != nil {
		return result, err
	}
	return result, nil
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

func (s *Service) insertEvent(ctx context.Context, pool *pgxpool.Pool, segmentID string, combinedLine combiner.CombinedLine, skipInsert bool) (bool, bool, error) {
	parsed, err := parser.ParseAccessLine(combinedLine.Raw)
	if err != nil {
		return false, false, nil
	}
	if skipInsert {
		return true, false, nil
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
		return false, false, err
	}

	pathHash := hashBytes(parsed.Path)
	uaHash := hashBytes(parsed.UserAgent)
	tag, err := pool.Exec(ctx, `
INSERT INTO access_events (
  ts, site_id, env, container_id, client_ip, method, scheme, host, path, path_hash, query,
  status, bytes_sent, referer, user_agent, user_agent_hash, fingerprint, segment_id
) VALUES (
  $1, $2, $3, $4, nullif($5, '')::inet, nullif($6, ''), nullif($7, ''), nullif($8, ''), nullif($9, ''), $10, nullif($11, ''),
  nullif($12, 0), $13, nullif($14, ''), nullif($15, ''), $16, $17, $18
)
ON CONFLICT (fingerprint, ts) DO NOTHING`,
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
		fingerprint,
		segmentID,
	)
	if err != nil {
		return false, false, err
	}

	return true, tag.RowsAffected() > 0, nil
}

func (s *Service) rebuildRollups(ctx context.Context, pool *pgxpool.Pool, start time.Time, end time.Time) (int, error) {
	if _, err := pool.Exec(ctx, `DELETE FROM rollup_1m WHERE bucket_ts >= $1 AND bucket_ts < $2`, start, end); err != nil {
		return 0, err
	}

	rows, err := pool.Query(ctx, `
WITH grouped AS (
  SELECT date_trunc('minute', ts) AS bucket_ts,
         site_id,
         env,
         count(*) AS requests,
         count(*) FILTER (WHERE status >= 200 AND status < 300) AS status_2xx,
         count(*) FILTER (WHERE status >= 300 AND status < 400) AS status_3xx,
         count(*) FILTER (WHERE status >= 400 AND status < 500) AS status_4xx,
         count(*) FILTER (WHERE status >= 500 AND status < 600) AS status_5xx,
         count(DISTINCT client_ip) AS unique_ips,
         coalesce(sum(bytes_sent), 0) AS bytes_sent
  FROM access_events
  WHERE ts >= $1 AND ts < $2
  GROUP BY 1, 2, 3
)
INSERT INTO rollup_1m (
  bucket_ts, site_id, env, requests, status_2xx, status_3xx, status_4xx, status_5xx, unique_ips, bytes_sent
)
SELECT bucket_ts, site_id, env, requests, status_2xx, status_3xx, status_4xx, status_5xx, unique_ips, bytes_sent
FROM grouped
ON CONFLICT (bucket_ts, site_id, env) DO UPDATE
SET requests = EXCLUDED.requests,
    status_2xx = EXCLUDED.status_2xx,
    status_3xx = EXCLUDED.status_3xx,
    status_4xx = EXCLUDED.status_4xx,
    status_5xx = EXCLUDED.status_5xx,
    unique_ips = EXCLUDED.unique_ips,
    bytes_sent = EXCLUDED.bytes_sent
RETURNING 1`, start, end)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		count++
	}
	return count, rows.Err()
}

func hashBytes(value string) []byte {
	if value == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func cleanText(value string) string {
	return strings.ReplaceAll(value, "\x00", "")
}
