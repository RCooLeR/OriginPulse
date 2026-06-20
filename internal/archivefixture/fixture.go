package archivefixture

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/klauspost/compress/zstd"

	"originpulse/internal/combiner"
	"originpulse/internal/config"
)

type Options struct {
	SegmentID string
	Limit     int
}

type Result struct {
	ArchiveID  string    `json:"archive_id"`
	SegmentID  string    `json:"segment_id"`
	Path       string    `json:"path"`
	RangeStart time.Time `json:"range_start"`
	RangeEnd   time.Time `json:"range_end"`
	Lines      int       `json:"lines"`
}

type CompactionResult struct {
	DailyArchiveIDs   []string  `json:"daily_archive_ids"`
	DailyArchivePaths []string  `json:"daily_archive_paths"`
	SegmentIDs        []string  `json:"segment_ids"`
	WeekStart         time.Time `json:"week_start"`
	WeekEnd           time.Time `json:"week_end"`
	LogType           string    `json:"log_type"`
}

type segmentRecord struct {
	ID          string
	LogType     string
	Path        string
	BucketStart time.Time
	BucketEnd   time.Time
}

func Create(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, opts Options) (Result, error) {
	if opts.Limit <= 0 || opts.Limit > 1000 {
		opts.Limit = 25
	}
	segment, err := resolveSegment(ctx, pool, opts.SegmentID)
	if err != nil {
		return Result{}, err
	}
	lines, lineCount, err := fixtureLines(segment, opts.Limit)
	if err != nil {
		return Result{}, err
	}
	if lineCount == 0 {
		return Result{}, fmt.Errorf("segment %s has no importable lines", segment.ID)
	}

	path := filepath.Join(cfg.ArchiveDir(), "_smoke", fmt.Sprintf("originpulse-smoke-%s.tar.zst", time.Now().UTC().Format("20060102T150405Z")))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return Result{}, err
	}
	written, err := writeArchive(path, segment, lines)
	if err != nil {
		return Result{}, err
	}

	var archiveID string
	err = pool.QueryRow(ctx, `
INSERT INTO log_archives (
  log_type, granularity, range_start, range_end, path, sha256,
  source_file_count, source_bytes, compressed_bytes, status, expires_at
) VALUES (
  $1, 'daily', $2, $3, $4, $5, 1, $6, $7, 'ready', $8
)
RETURNING id::text`,
		segment.LogType,
		segment.BucketStart,
		segment.BucketEnd,
		path,
		written.sha256,
		written.sourceBytes,
		written.compressedBytes,
		time.Now().UTC().Add(24*time.Hour),
	).Scan(&archiveID)
	if err != nil {
		_ = os.Remove(path)
		return Result{}, err
	}

	return Result{
		ArchiveID:  archiveID,
		SegmentID:  segment.ID,
		Path:       path,
		RangeStart: segment.BucketStart,
		RangeEnd:   segment.BucketEnd,
		Lines:      lineCount,
	}, nil
}

func Cleanup(ctx context.Context, pool *pgxpool.Pool, result Result) error {
	if result.ArchiveID != "" {
		if _, err := pool.Exec(ctx, `DELETE FROM log_archives WHERE id = $1::uuid`, result.ArchiveID); err != nil {
			return err
		}
	}
	if result.Path != "" {
		_ = os.Remove(result.Path)
	}
	return nil
}

func CreateCompactionSet(ctx context.Context, cfg config.Config, pool *pgxpool.Pool) (CompactionResult, error) {
	logType := "nginx-access"
	siteID, err := firstSiteID(ctx, pool)
	if err != nil {
		return CompactionResult{}, err
	}
	now := time.Now().UTC()
	weekStart := now.AddDate(-3, 0, -int(now.Weekday()+7)).Truncate(24 * time.Hour)
	if weekStart.Weekday() != time.Monday {
		weekStart = weekStart.AddDate(0, 0, -int((weekStart.Weekday()+6)%7))
	}
	weekEnd := weekStart.Add(7 * 24 * time.Hour)
	result := CompactionResult{WeekStart: weekStart, WeekEnd: weekEnd, LogType: logType}
	for day := 0; day < 2; day++ {
		bucketStart := weekStart.Add(time.Duration(day) * 24 * time.Hour)
		bucketEnd := bucketStart.Add(time.Hour)
		segmentPath := filepath.Join(cfg.CombinedDir(), "_smoke", fmt.Sprintf("compaction-%s.log.gz", bucketStart.Format("20060102T15")))
		var segmentID string
		if err := pool.QueryRow(ctx, `
INSERT INTO combined_segments (
  log_type, bucket_start, bucket_end, path, line_count, min_ts, max_ts, status, indexed_at
) VALUES (
  $1, $2, $3, $4, 1, $2, $3, 'indexed', now()
)
RETURNING id::text`, logType, bucketStart, bucketEnd, segmentPath).Scan(&segmentID); err != nil {
			_ = CleanupCompactionSet(context.Background(), pool, result)
			return CompactionResult{}, err
		}
		result.SegmentIDs = append(result.SegmentIDs, segmentID)

		gzBytes, err := compactionMember(bucketStart, day, siteID)
		if err != nil {
			_ = CleanupCompactionSet(context.Background(), pool, result)
			return CompactionResult{}, err
		}
		archivePath := filepath.Join(cfg.ArchiveDir(), "_smoke", fmt.Sprintf("daily-compaction-%s.tar.zst", bucketStart.Format("20060102")))
		if err := os.MkdirAll(filepath.Dir(archivePath), 0o750); err != nil {
			_ = CleanupCompactionSet(context.Background(), pool, result)
			return CompactionResult{}, err
		}
		written, err := writeArchive(archivePath, segmentRecord{Path: segmentPath}, gzBytes)
		if err != nil {
			_ = CleanupCompactionSet(context.Background(), pool, result)
			return CompactionResult{}, err
		}
		var archiveID string
		if err := pool.QueryRow(ctx, `
INSERT INTO log_archives (
  log_type, granularity, range_start, range_end, path, sha256,
  source_file_count, source_bytes, compressed_bytes, status, expires_at
) VALUES (
  $1, 'daily', $2, $3, $4, $5, 1, $6, $7, 'ready', $8
)
RETURNING id::text`,
			logType,
			bucketStart.Truncate(24*time.Hour),
			bucketStart.Truncate(24*time.Hour).Add(24*time.Hour),
			archivePath,
			written.sha256,
			written.sourceBytes,
			written.compressedBytes,
			weekEnd.Add(2*365*24*time.Hour),
		).Scan(&archiveID); err != nil {
			_ = os.Remove(archivePath)
			_ = CleanupCompactionSet(context.Background(), pool, result)
			return CompactionResult{}, err
		}
		result.DailyArchiveIDs = append(result.DailyArchiveIDs, archiveID)
		result.DailyArchivePaths = append(result.DailyArchivePaths, archivePath)
		if _, err := pool.Exec(ctx, `
INSERT INTO log_archive_segments (archive_id, segment_id, original_path, bucket_start, bucket_end)
VALUES ($1::uuid, $2::uuid, $3, $4, $5)`, archiveID, segmentID, segmentPath, bucketStart, bucketEnd); err != nil {
			_ = CleanupCompactionSet(context.Background(), pool, result)
			return CompactionResult{}, err
		}
	}
	return result, nil
}

func CleanupCompactionSet(ctx context.Context, pool *pgxpool.Pool, result CompactionResult) error {
	if !result.WeekStart.IsZero() {
		var weeklyPaths []string
		rows, err := pool.Query(ctx, `
SELECT path
FROM log_archives
WHERE log_type = $1
  AND granularity = 'weekly'
  AND range_start = $2`, result.LogType, result.WeekStart)
		if err != nil {
			return err
		}
		for rows.Next() {
			var path string
			if err := rows.Scan(&path); err != nil {
				rows.Close()
				return err
			}
			weeklyPaths = append(weeklyPaths, path)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if _, err := pool.Exec(ctx, `
DELETE FROM log_archives
WHERE log_type = $1
  AND granularity = 'weekly'
  AND range_start = $2`, result.LogType, result.WeekStart); err != nil {
			return err
		}
		for _, path := range weeklyPaths {
			_ = os.Remove(path)
		}
	}
	for _, id := range result.DailyArchiveIDs {
		if _, err := pool.Exec(ctx, `DELETE FROM log_archives WHERE id = $1::uuid`, id); err != nil {
			return err
		}
	}
	for _, path := range result.DailyArchivePaths {
		_ = os.Remove(path)
	}
	for _, id := range result.SegmentIDs {
		if _, err := pool.Exec(ctx, `DELETE FROM combined_segments WHERE id = $1::uuid`, id); err != nil {
			return err
		}
	}
	return nil
}

func compactionMember(ts time.Time, index int, siteID string) ([]byte, error) {
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	fingerprint := sha256.Sum256([]byte(fmt.Sprintf("originpulse-compaction-smoke:%d:%d", ts.Unix(), index)))
	line := combiner.CombinedLine{
		TS:          ts.Format(time.RFC3339Nano),
		SiteID:      siteID,
		Env:         "live",
		ContainerID: "originpulse-smoke",
		LogType:     "nginx-access",
		Raw:         fmt.Sprintf(`127.0.0.1 - - [%s] "GET /_originpulse/compaction-smoke/%d HTTP/1.1" 200 12 "-" "OriginPulseSmoke/1.0" 0.001`, ts.Format("02/Jan/2006:15:04:05 -0700"), index),
		Fingerprint: hex.EncodeToString(fingerprint[:]),
	}
	encoded, err := json.Marshal(line)
	if err != nil {
		_ = writer.Close()
		return nil, err
	}
	if _, err := writer.Write(append(encoded, '\n')); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func firstSiteID(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	var siteID string
	if err := pool.QueryRow(ctx, `SELECT id FROM sites ORDER BY id LIMIT 1`).Scan(&siteID); err != nil {
		return "", err
	}
	return siteID, nil
}

func CountArchiveMembers(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	zstdReader, err := zstd.NewReader(file)
	if err != nil {
		return 0, err
	}
	defer zstdReader.Close()
	tarReader := tar.NewReader(zstdReader)
	count := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}
		if header.Typeflag == tar.TypeReg {
			count++
		}
	}
	return count, nil
}

func resolveSegment(ctx context.Context, pool *pgxpool.Pool, segmentID string) (segmentRecord, error) {
	var segment segmentRecord
	query := `
SELECT id::text, log_type, path, bucket_start, bucket_end
FROM combined_segments
WHERE status = 'indexed'
  AND path IS NOT NULL
  AND ($1 = '' OR id = $1::uuid)
ORDER BY bucket_start DESC
LIMIT 1`
	err := pool.QueryRow(ctx, query, segmentID).Scan(&segment.ID, &segment.LogType, &segment.Path, &segment.BucketStart, &segment.BucketEnd)
	if err != nil {
		return segment, err
	}
	return segment, nil
}

func fixtureLines(segment segmentRecord, limit int) ([]byte, int, error) {
	file, err := os.Open(segment.Path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return nil, 0, err
	}
	defer reader.Close()

	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 128*1024), 10*1024*1024)
	count := 0
	for scanner.Scan() {
		var line combiner.CombinedLine
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			continue
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("originpulse-archive-smoke:%s:%d:%s", segment.ID, count, line.Fingerprint)))
		line.Fingerprint = hex.EncodeToString(sum[:])
		line.RawFileID = ""
		line.RawLineNo = 0
		encoded, err := json.Marshal(line)
		if err != nil {
			_ = writer.Close()
			return nil, 0, err
		}
		if _, err := writer.Write(append(encoded, '\n')); err != nil {
			_ = writer.Close()
			return nil, 0, err
		}
		count++
		if count >= limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		_ = writer.Close()
		return nil, 0, err
	}
	if err := writer.Close(); err != nil {
		return nil, 0, err
	}
	return out.Bytes(), count, nil
}

type writtenArchive struct {
	sourceBytes     int64
	compressedBytes int64
	sha256          string
}

func writeArchive(path string, segment segmentRecord, gzBytes []byte) (writtenArchive, error) {
	tmpPath := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return writtenArchive{}, err
	}
	hasher := sha256.New()
	counting := &countingWriter{writer: io.MultiWriter(out, hasher)}
	zstdWriter, err := zstd.NewWriter(counting, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	if err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return writtenArchive{}, err
	}
	tarWriter := tar.NewWriter(zstdWriter)
	name := filepath.ToSlash(filepath.Join("_smoke", filepath.Base(segment.Path)))
	header := &tar.Header{
		Name:       name,
		Mode:       0o640,
		Size:       int64(len(gzBytes)),
		Typeflag:   tar.TypeReg,
		ModTime:    time.Unix(0, 0).UTC(),
		AccessTime: time.Unix(0, 0).UTC(),
		ChangeTime: time.Unix(0, 0).UTC(),
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		_ = tarWriter.Close()
		_ = zstdWriter.Close()
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return writtenArchive{}, err
	}
	if _, err := tarWriter.Write(gzBytes); err != nil {
		_ = tarWriter.Close()
		_ = zstdWriter.Close()
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return writtenArchive{}, err
	}
	if err := tarWriter.Close(); err != nil {
		_ = zstdWriter.Close()
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return writtenArchive{}, err
	}
	if err := zstdWriter.Close(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return writtenArchive{}, err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return writtenArchive{}, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return writtenArchive{}, err
	}
	return writtenArchive{
		sourceBytes:     int64(len(gzBytes)),
		compressedBytes: counting.n,
		sha256:          hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

type countingWriter struct {
	writer io.Writer
	n      int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.n += int64(n)
	return n, err
}
