package archive

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/klauspost/compress/zstd"

	"originpulse/internal/config"
	"originpulse/internal/db"
)

const archiveLockKey int64 = 7720005

type Options struct {
	DryRun        bool   `json:"dry_run"`
	LogType       string `json:"log_type"`
	MaxGroups     int    `json:"max_groups"`
	RemoveSources bool   `json:"remove_sources"`
}

type Result struct {
	Enabled                  bool      `json:"enabled"`
	DryRun                   bool      `json:"dry_run"`
	DailyCutoff              time.Time `json:"daily_cutoff"`
	WeeklyCutoff             time.Time `json:"weekly_cutoff"`
	GroupsMatched            int       `json:"groups_matched"`
	ArchivesWritten          int       `json:"archives_written"`
	DailyArchivesWritten     int       `json:"daily_archives_written"`
	WeeklyArchivesWritten    int       `json:"weekly_archives_written"`
	DailyArchivesCompacted   int       `json:"daily_archives_compacted"`
	FilesArchived            int       `json:"files_archived"`
	SourceBytes              int64     `json:"source_bytes"`
	CompressedBytes          int64     `json:"compressed_bytes"`
	SourceFilesDeleted       int       `json:"source_files_deleted"`
	SourceDeleteErrors       int       `json:"source_delete_errors"`
	DailyArchiveDeleteErrors int       `json:"daily_archive_delete_errors"`
	SkippedExisting          int       `json:"skipped_existing"`
}

type Service struct {
	cfg config.Config
	db  *db.Store
}

type group struct {
	LogType       string
	Granularity   string
	RangeStart    time.Time
	RangeEnd      time.Time
	Segments      []segment
	DailyArchives []dailyArchive
}

type segment struct {
	ID          string
	Path        string
	BucketStart time.Time
	BucketEnd   time.Time
}

type dailyArchive struct {
	ID              string
	Path            string
	SourceFileCount int
	SourceBytes     int64
	CompressedBytes int64
}

func NewService(cfg config.Config, store *db.Store) *Service {
	return &Service{cfg: cfg, db: store}
}

func (s *Service) Enabled() bool {
	return s != nil && s.db != nil && s.db.Enabled()
}

func (s *Service) Run(ctx context.Context, opts Options) (Result, error) {
	now := time.Now().UTC()
	result := Result{
		Enabled:      s.cfg.Retention.Enabled,
		DryRun:       opts.DryRun,
		DailyCutoff:  now.Add(-s.cfg.Retention.DailyArchiveAfter),
		WeeklyCutoff: now.Add(-s.cfg.Retention.WeeklyArchiveAfter),
	}
	if !s.cfg.Retention.Enabled {
		return result, nil
	}
	if !s.Enabled() {
		return result, db.ErrUnavailable
	}
	if opts.MaxGroups <= 0 {
		opts.MaxGroups = 25
	}

	err := s.db.WithAdvisoryLock(ctx, archiveLockKey, func(ctx context.Context) error {
		pool, err := s.db.Pool()
		if err != nil {
			return err
		}
		archiveLogTypes := normalizeLogTypes(opts.LogType, s.cfg.Collection.LogTypes)
		remaining := opts.MaxGroups
		for _, logType := range archiveLogTypes {
			if remaining <= 0 {
				break
			}
			typeOpts := opts
			typeOpts.LogType = logType
			typeOpts.MaxGroups = remaining
			groups, skipped, err := s.candidateGroups(ctx, pool, typeOpts, result.DailyCutoff, result.WeeklyCutoff)
			if err != nil {
				return err
			}
			result.GroupsMatched += len(groups)
			result.SkippedExisting += skipped
			if result.DryRun {
				for _, group := range groups {
					result.FilesArchived += len(group.Segments)
					for _, seg := range group.Segments {
						if info, err := os.Stat(seg.Path); err == nil {
							result.SourceBytes += info.Size()
						}
					}
				}
				remaining -= len(groups)
				continue
			}
			for _, group := range groups {
				written, err := s.writeGroup(ctx, pool, group)
				if err != nil {
					return err
				}
				result.ArchivesWritten++
				if group.Granularity == "daily" {
					result.DailyArchivesWritten++
				} else if group.Granularity == "weekly" {
					result.WeeklyArchivesWritten++
				}
				result.FilesArchived += written.SourceFileCount
				result.SourceBytes += written.SourceBytes
				result.CompressedBytes += written.CompressedBytes
				if opts.RemoveSources {
					deleted, failed, err := s.removeArchivedSources(ctx, pool, group)
					if err != nil {
						return err
					}
					result.SourceFilesDeleted += deleted
					result.SourceDeleteErrors += failed
					if group.Granularity == "weekly" && len(group.DailyArchives) > 0 {
						compacted, failed, err := s.removeCompactedDailyArchives(ctx, pool, group)
						if err != nil {
							return err
						}
						result.DailyArchivesCompacted += compacted
						result.DailyArchiveDeleteErrors += failed
					}
				}
			}
			remaining -= len(groups)
		}
		return nil
	})
	return result, err
}

func normalizeLogTypes(logType string, configured []string) []string {
	if trimmed := strings.TrimSpace(logType); trimmed != "" {
		return []string{trimmed}
	}
	out := make([]string, 0, len(configured))
	seen := map[string]struct{}{}
	for _, item := range configured {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	if len(out) == 0 {
		return []string{"nginx-access"}
	}
	return out
}

func (s *Service) candidateGroups(ctx context.Context, pool *pgxpool.Pool, opts Options, dailyCutoff time.Time, weeklyCutoff time.Time) ([]group, int, error) {
	weeklyFromDaily, skippedDailyArchives, err := s.weeklyGroupsFromDailyArchives(ctx, pool, opts.LogType, weeklyCutoff, opts.MaxGroups)
	if err != nil {
		return nil, 0, err
	}
	remainingWeekly := opts.MaxGroups - len(weeklyFromDaily)
	weeklyFromSegments := []group{}
	skippedWeeklySegments := 0
	if remainingWeekly > 0 {
		weeklyFromSegments, skippedWeeklySegments, err = s.groupsFor(ctx, pool, opts.LogType, "weekly", weeklyCutoff, time.Time{}, remainingWeekly)
		if err != nil {
			return nil, 0, err
		}
		existingWeekly := map[time.Time]bool{}
		for _, group := range weeklyFromDaily {
			existingWeekly[group.RangeStart] = true
		}
		filtered := weeklyFromSegments[:0]
		for _, group := range weeklyFromSegments {
			if existingWeekly[group.RangeStart] {
				skippedWeeklySegments++
				continue
			}
			filtered = append(filtered, group)
		}
		weeklyFromSegments = filtered
	}
	weekly := append(weeklyFromDaily, weeklyFromSegments...)
	remaining := opts.MaxGroups - len(weekly)
	if remaining <= 0 {
		return weekly, skippedDailyArchives + skippedWeeklySegments, nil
	}
	daily, skippedDaily, err := s.groupsFor(ctx, pool, opts.LogType, "daily", dailyCutoff, weeklyCutoff, remaining)
	if err != nil {
		return nil, 0, err
	}
	return append(weekly, daily...), skippedDailyArchives + skippedWeeklySegments + skippedDaily, nil
}

func (s *Service) weeklyGroupsFromDailyArchives(ctx context.Context, pool *pgxpool.Pool, logType string, weeklyCutoff time.Time, limit int) ([]group, int, error) {
	rows, err := pool.Query(ctx, `
WITH candidate_archives AS (
  SELECT date_trunc('week', range_start) AS range_start,
         date_trunc('week', range_start) + interval '7 days' AS range_end,
         id,
         path,
         source_file_count,
         source_bytes,
         compressed_bytes,
         EXISTS (
           SELECT 1 FROM log_archives weekly
           WHERE weekly.log_type = $1
             AND weekly.granularity = 'weekly'
             AND weekly.range_start = date_trunc('week', log_archives.range_start)
             AND weekly.status = 'ready'
         ) AS archived
  FROM log_archives
  WHERE log_type = $1
    AND granularity = 'daily'
    AND status = 'ready'
    AND range_end < $2
)
SELECT range_start,
       range_end,
       id::text,
       path,
       source_file_count,
       source_bytes,
       compressed_bytes,
       archived
FROM candidate_archives
WHERE NOT archived
ORDER BY range_start, path
LIMIT 100000`, logType, weeklyCutoff)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	groups := make([]group, 0)
	byStart := map[time.Time]int{}
	skipped := 0
	for rows.Next() {
		var rangeStart, rangeEnd time.Time
		var archive dailyArchive
		var archived bool
		if err := rows.Scan(&rangeStart, &rangeEnd, &archive.ID, &archive.Path, &archive.SourceFileCount, &archive.SourceBytes, &archive.CompressedBytes, &archived); err != nil {
			return nil, 0, err
		}
		if archived {
			skipped++
			continue
		}
		idx, ok := byStart[rangeStart]
		if !ok {
			if len(groups) >= limit {
				continue
			}
			idx = len(groups)
			byStart[rangeStart] = idx
			groups = append(groups, group{
				LogType:     logType,
				Granularity: "weekly",
				RangeStart:  rangeStart,
				RangeEnd:    rangeEnd,
			})
		}
		groups[idx].DailyArchives = append(groups[idx].DailyArchives, archive)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := s.loadDailyArchiveSegments(ctx, pool, groups); err != nil {
		return nil, 0, err
	}
	return groups, skipped, nil
}

func (s *Service) groupsFor(ctx context.Context, pool *pgxpool.Pool, logType string, granularity string, cutoff time.Time, lowerBound time.Time, limit int) ([]group, int, error) {
	var lower any
	if !lowerBound.IsZero() {
		lower = lowerBound.UTC()
	}
	rows, err := pool.Query(ctx, `
WITH candidates AS (
  SELECT CASE WHEN $2 = 'weekly'
              THEN date_trunc('week', bucket_start)
              ELSE date_trunc('day', bucket_start)
         END AS range_start,
         CASE WHEN $2 = 'weekly'
              THEN date_trunc('week', bucket_start) + interval '7 days'
              ELSE date_trunc('day', bucket_start) + interval '1 day'
         END AS range_end,
         id,
         bucket_start,
         bucket_end,
         path
  FROM combined_segments
  WHERE log_type = $1
    AND bucket_end < $3
    AND ($4::timestamptz IS NULL OR bucket_end >= $4)
    AND status = 'indexed'
    AND source_deleted_at IS NULL
)
SELECT range_start, range_end, id::text, bucket_start, bucket_end, path,
       EXISTS (
         SELECT 1 FROM log_archives a
         WHERE a.log_type = $1
           AND a.granularity = $2
           AND a.range_start = candidates.range_start
           AND a.status = 'ready'
       ) AS archived
FROM candidates
WHERE NOT EXISTS (
  SELECT 1 FROM log_archives a
  WHERE a.log_type = $1
    AND a.granularity = $2
    AND a.range_start = candidates.range_start
    AND a.status = 'ready'
)
ORDER BY range_start, bucket_start
LIMIT 100000`, logType, granularity, cutoff, lower)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	groups := make([]group, 0)
	byStart := map[time.Time]int{}
	skipped := 0
	for rows.Next() {
		var rangeStart, rangeEnd, bucketStart, bucketEnd time.Time
		var id string
		var path string
		var archived bool
		if err := rows.Scan(&rangeStart, &rangeEnd, &id, &bucketStart, &bucketEnd, &path, &archived); err != nil {
			return nil, 0, err
		}
		if archived {
			skipped++
			continue
		}
		idx, ok := byStart[rangeStart]
		if !ok {
			if len(groups) >= limit {
				continue
			}
			idx = len(groups)
			byStart[rangeStart] = idx
			groups = append(groups, group{
				LogType:     logType,
				Granularity: granularity,
				RangeStart:  rangeStart,
				RangeEnd:    rangeEnd,
			})
		}
		groups[idx].Segments = append(groups[idx].Segments, segment{ID: id, Path: path, BucketStart: bucketStart, BucketEnd: bucketEnd})
	}
	return groups, skipped, rows.Err()
}

func (s *Service) loadDailyArchiveSegments(ctx context.Context, pool *pgxpool.Pool, groups []group) error {
	for i := range groups {
		if len(groups[i].DailyArchives) == 0 {
			continue
		}
		for _, archive := range groups[i].DailyArchives {
			rows, err := pool.Query(ctx, `
SELECT segment_id::text, original_path, bucket_start, bucket_end
FROM log_archive_segments
WHERE archive_id = $1::uuid
ORDER BY bucket_start`, archive.ID)
			if err != nil {
				return err
			}
			for rows.Next() {
				var seg segment
				if err := rows.Scan(&seg.ID, &seg.Path, &seg.BucketStart, &seg.BucketEnd); err != nil {
					rows.Close()
					return err
				}
				groups[i].Segments = append(groups[i].Segments, seg)
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				return err
			}
			rows.Close()
		}
	}
	return nil
}

type writtenArchive struct {
	Path            string
	SHA256          string
	ID              string
	SourceFileCount int
	SourceBytes     int64
	CompressedBytes int64
}

func (s *Service) writeGroup(ctx context.Context, pool *pgxpool.Pool, group group) (writtenArchive, error) {
	if len(group.Segments) == 0 {
		return writtenArchive{}, nil
	}
	path := s.archivePath(group)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return writtenArchive{}, err
	}
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

	written := writtenArchive{Path: path}
	if len(group.DailyArchives) > 0 {
		names := map[string]int{}
		for _, archive := range group.DailyArchives {
			select {
			case <-ctx.Done():
				_ = tarWriter.Close()
				_ = zstdWriter.Close()
				_ = out.Close()
				_ = os.Remove(tmpPath)
				return writtenArchive{}, ctx.Err()
			default:
			}
			sourceCount, err := addArchiveMembersToTar(tarWriter, archive.Path, names)
			if err != nil {
				_ = tarWriter.Close()
				_ = zstdWriter.Close()
				_ = out.Close()
				_ = os.Remove(tmpPath)
				return writtenArchive{}, err
			}
			written.SourceFileCount += sourceCount
			written.SourceBytes += archive.SourceBytes
		}
	} else {
		for _, seg := range group.Segments {
			select {
			case <-ctx.Done():
				_ = tarWriter.Close()
				_ = zstdWriter.Close()
				_ = out.Close()
				_ = os.Remove(tmpPath)
				return writtenArchive{}, ctx.Err()
			default:
			}
			if err := addFileToTar(tarWriter, s.cfg.CombinedDir(), seg.Path); err != nil {
				_ = tarWriter.Close()
				_ = zstdWriter.Close()
				_ = out.Close()
				_ = os.Remove(tmpPath)
				return writtenArchive{}, err
			}
			if info, err := os.Stat(seg.Path); err == nil {
				written.SourceBytes += info.Size()
			}
			written.SourceFileCount++
		}
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
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return writtenArchive{}, err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return writtenArchive{}, err
	}
	if err := replaceFile(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return writtenArchive{}, err
	}
	written.CompressedBytes = counting.n
	written.SHA256 = hex.EncodeToString(hasher.Sum(nil))

	expiresAt := group.RangeEnd.Add(s.cfg.Retention.ArchiveMaxAge)
	err = pool.QueryRow(ctx, `
INSERT INTO log_archives (
  log_type, granularity, range_start, range_end, path, sha256,
  source_file_count, source_bytes, compressed_bytes, status, expires_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9, 'ready', $10
)
ON CONFLICT (log_type, granularity, range_start) DO UPDATE SET
  range_end = EXCLUDED.range_end,
  path = EXCLUDED.path,
  sha256 = EXCLUDED.sha256,
  source_file_count = EXCLUDED.source_file_count,
  source_bytes = EXCLUDED.source_bytes,
  compressed_bytes = EXCLUDED.compressed_bytes,
  status = EXCLUDED.status,
  expires_at = EXCLUDED.expires_at,
  created_at = now()
RETURNING id::text`,
		group.LogType,
		group.Granularity,
		group.RangeStart,
		group.RangeEnd,
		written.Path,
		written.SHA256,
		written.SourceFileCount,
		written.SourceBytes,
		written.CompressedBytes,
		expiresAt,
	).Scan(&written.ID)
	if err != nil {
		return written, err
	}
	return written, s.markSegmentsArchived(ctx, pool, group, written.ID)
}

func (s *Service) markSegmentsArchived(ctx context.Context, pool *pgxpool.Pool, group group, archiveID string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback(context.Background())
	}()
	for _, seg := range group.Segments {
		if _, err := tx.Exec(ctx, `
INSERT INTO log_archive_segments (archive_id, segment_id, original_path, bucket_start, bucket_end)
VALUES ($1::uuid, $2::uuid, $3, $4, $5)
ON CONFLICT (archive_id, segment_id) DO UPDATE SET
  original_path = EXCLUDED.original_path,
  bucket_start = EXCLUDED.bucket_start,
  bucket_end = EXCLUDED.bucket_end`,
			archiveID,
			seg.ID,
			seg.Path,
			seg.BucketStart,
			seg.BucketEnd,
		); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
UPDATE combined_segments
SET archive_id = $1::uuid,
    archived_at = now()
WHERE id = $2::uuid`, archiveID, seg.ID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Service) removeArchivedSources(ctx context.Context, pool *pgxpool.Pool, group group) (int, int, error) {
	deleted := 0
	failed := 0
	for _, seg := range group.Segments {
		select {
		case <-ctx.Done():
			return deleted, failed, ctx.Err()
		default:
		}
		if err := os.Remove(seg.Path); err != nil {
			if !os.IsNotExist(err) {
				failed++
				continue
			}
		} else {
			deleted++
		}
		if _, err := pool.Exec(ctx, `
UPDATE combined_segments
SET source_deleted_at = now()
WHERE id = $1::uuid`, seg.ID); err != nil {
			return deleted, failed, err
		}
		pruneEmptyParents(filepath.Dir(seg.Path), s.cfg.CombinedDir())
	}
	return deleted, failed, nil
}

func (s *Service) removeCompactedDailyArchives(ctx context.Context, pool *pgxpool.Pool, group group) (int, int, error) {
	deleted := 0
	failed := 0
	for _, archive := range group.DailyArchives {
		select {
		case <-ctx.Done():
			return deleted, failed, ctx.Err()
		default:
		}
		if err := os.Remove(archive.Path); err != nil {
			if !os.IsNotExist(err) {
				failed++
				continue
			}
		} else {
			deleted++
		}
		if _, err := pool.Exec(ctx, `
DELETE FROM log_archives
WHERE id = $1::uuid
  AND granularity = 'daily'`, archive.ID); err != nil {
			return deleted, failed, err
		}
		pruneEmptyParents(filepath.Dir(archive.Path), s.cfg.ArchiveDir())
	}
	return deleted, failed, nil
}

func (s *Service) archivePath(group group) string {
	start := group.RangeStart.UTC()
	name := fmt.Sprintf("%s-%s-%s.tar.zst", group.LogType, group.Granularity, start.Format("2006-01-02"))
	if group.Granularity == "weekly" {
		_, week := start.ISOWeek()
		name = fmt.Sprintf("%s-weekly-%s-W%02d.tar.zst", group.LogType, start.Format("2006"), week)
	}
	return filepath.Join(s.cfg.ArchiveDir(), group.LogType, group.Granularity, start.Format("2006"), name)
}

func addFileToTar(tw *tar.Writer, baseDir string, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}
	name, err := filepath.Rel(baseDir, path)
	if err != nil || strings.HasPrefix(name, "..") {
		name = filepath.Base(path)
	}
	name = filepath.ToSlash(name)
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = name
	header.ModTime = time.Unix(0, 0).UTC()
	header.AccessTime = time.Unix(0, 0).UTC()
	header.ChangeTime = time.Unix(0, 0).UTC()
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err = io.Copy(tw, file)
	return err
}

func addArchiveMembersToTar(tw *tar.Writer, archivePath string, names map[string]int) (int, error) {
	file, err := os.Open(archivePath)
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
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.ToSlash(header.Name)
		if name == "" {
			name = fmt.Sprintf("archive-member-%d.gz", count)
		}
		originalName := name
		suffix := 1
		for names[name] > 0 {
			suffix++
			ext := filepath.Ext(originalName)
			base := strings.TrimSuffix(originalName, ext)
			name = fmt.Sprintf("%s-%d%s", base, suffix, ext)
		}
		names[originalName]++
		if name != originalName {
			names[name]++
		}
		outHeader := *header
		outHeader.Name = name
		outHeader.ModTime = time.Unix(0, 0).UTC()
		outHeader.AccessTime = time.Unix(0, 0).UTC()
		outHeader.ChangeTime = time.Unix(0, 0).UTC()
		outHeader.Format = tar.FormatPAX
		if err := tw.WriteHeader(&outHeader); err != nil {
			return count, err
		}
		if _, err := io.Copy(tw, tarReader); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
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

func replaceFile(src string, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyFile(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

func copyFile(src string, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

func pruneEmptyParents(path string, stopAt string) {
	stopAt, _ = filepath.Abs(stopAt)
	for i := 0; i < 6; i++ {
		if path == "." || path == string(filepath.Separator) {
			return
		}
		abs, err := filepath.Abs(path)
		if err != nil || abs == stopAt {
			return
		}
		if err := os.Remove(path); err != nil {
			return
		}
		path = filepath.Dir(path)
	}
}
