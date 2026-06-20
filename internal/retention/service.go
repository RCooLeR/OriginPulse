package retention

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"originpulse/internal/config"
	"originpulse/internal/db"
	"originpulse/internal/rollups"
)

const retentionLockKey int64 = 7720003

type Options struct {
	DryRun               bool `json:"dry_run"`
	TemporaryImportsOnly bool `json:"temporary_imports_only"`
}

type Result struct {
	Enabled                 bool      `json:"enabled"`
	DryRun                  bool      `json:"dry_run"`
	TemporaryImportsOnly    bool      `json:"temporary_imports_only"`
	RawFileCutoff           time.Time `json:"raw_file_cutoff"`
	HotEventCutoff          time.Time `json:"hot_event_cutoff"`
	ArchiveCutoff           time.Time `json:"archive_cutoff"`
	ReportCutoff            time.Time `json:"report_cutoff"`
	TemporaryImportCutoff   time.Time `json:"temporary_import_cutoff"`
	RawFileMaxAge           string    `json:"raw_file_max_age"`
	HotEventMaxAge          string    `json:"hot_event_max_age"`
	ArchiveMaxAge           string    `json:"archive_max_age"`
	ReportMaxAge            string    `json:"report_max_age"`
	TemporaryImportMaxAge   string    `json:"temporary_import_max_age"`
	RawFilesMatched         int       `json:"raw_files_matched"`
	RawBytesMatched         int64     `json:"raw_bytes_matched"`
	CombinedSegmentsMatched int       `json:"combined_segments_matched"`
	AccessEventsMatched     int       `json:"access_events_matched"`
	RollupsMatched          int       `json:"rollups_matched"`
	ReportsMatched          int       `json:"reports_matched"`
	TemporaryImportsMatched int       `json:"temporary_imports_matched"`
	TemporaryEventsMatched  int       `json:"temporary_events_matched"`
	TemporaryFactsMatched   int       `json:"temporary_facts_matched"`
	ArchiveFilesMatched     int       `json:"archive_files_matched"`
	RawFilesDeleted         int       `json:"raw_files_deleted"`
	CombinedSegmentsDeleted int       `json:"combined_segments_deleted"`
	AccessEventsDeleted     int       `json:"access_events_deleted"`
	RollupsDeleted          int       `json:"rollups_deleted"`
	ReportsDeleted          int       `json:"reports_deleted"`
	TemporaryImportsDeleted int       `json:"temporary_imports_deleted"`
	TemporaryEventsDeleted  int       `json:"temporary_events_deleted"`
	TemporaryFactsDeleted   int       `json:"temporary_facts_deleted"`
	ArchiveFilesDeleted     int       `json:"archive_files_deleted"`
	RollupsRebuilt          int       `json:"rollups_rebuilt"`
	LocalFilesDeleted       int       `json:"local_files_deleted"`
	LocalFileErrors         int       `json:"local_file_errors"`
}

type Service struct {
	cfg config.Config
	db  *db.Store
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
		Enabled:               s.cfg.Retention.Enabled,
		DryRun:                opts.DryRun,
		TemporaryImportsOnly:  opts.TemporaryImportsOnly,
		RawFileCutoff:         now.Add(-s.cfg.Retention.RawFileMaxAge),
		HotEventCutoff:        now.Add(-s.cfg.Retention.HotEventMaxAge),
		ArchiveCutoff:         now.Add(-s.cfg.Retention.ArchiveMaxAge),
		ReportCutoff:          now.Add(-s.cfg.Retention.ReportMaxAge),
		TemporaryImportCutoff: now.Add(-s.cfg.Retention.TemporaryImportMaxAge),
		RawFileMaxAge:         s.cfg.Retention.RawFileMaxAge.String(),
		HotEventMaxAge:        s.cfg.Retention.HotEventMaxAge.String(),
		ArchiveMaxAge:         s.cfg.Retention.ArchiveMaxAge.String(),
		ReportMaxAge:          s.cfg.Retention.ReportMaxAge.String(),
		TemporaryImportMaxAge: s.cfg.Retention.TemporaryImportMaxAge.String(),
	}
	if !s.cfg.Retention.Enabled {
		return result, nil
	}
	if !s.Enabled() {
		return result, db.ErrUnavailable
	}

	err := s.db.WithAdvisoryLock(ctx, retentionLockKey, func(ctx context.Context) error {
		return s.runLocked(ctx, &result)
	})
	return result, err
}

func (s *Service) runLocked(ctx context.Context, result *Result) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}

	var rawFiles []string
	var combinedFiles []string
	var archiveFiles []string
	if result.TemporaryImportsOnly {
		if err := s.countTemporaryImports(ctx, result); err != nil {
			return err
		}
		if result.DryRun {
			return nil
		}
		return s.expireTemporaryImports(ctx, result)
	}
	if s.cfg.Retention.DeleteRawFiles && !result.DryRun {
		rawFiles, err = s.paths(ctx, `
SELECT local_path
FROM raw_files
WHERE log_type = 'nginx-access'
  AND remote_mtime < $1`, result.RawFileCutoff)
		if err != nil {
			return err
		}
	}
	if !result.DryRun {
		archiveFiles, err = s.paths(ctx, `
SELECT path
FROM log_archives
WHERE status = 'ready'
  AND (expires_at < now() OR range_end < $1)`, result.ArchiveCutoff)
		if err != nil {
			return err
		}
	}
	if s.cfg.Retention.DeleteCombinedFiles && !result.DryRun {
		combinedFiles, err = s.paths(ctx, `
SELECT path
FROM combined_segments
WHERE log_type = 'nginx-access'
  AND bucket_end < $1`, result.ArchiveCutoff)
		if err != nil {
			return err
		}
	}

	if err := pool.QueryRow(ctx, `
SELECT count(*)::int, coalesce(sum(remote_size), 0)::bigint
FROM raw_files
WHERE log_type = 'nginx-access'
  AND remote_mtime < $1`, result.RawFileCutoff).Scan(&result.RawFilesMatched, &result.RawBytesMatched); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)::int
FROM combined_segments
WHERE log_type = 'nginx-access'
  AND bucket_end < $1`, result.ArchiveCutoff).Scan(&result.CombinedSegmentsMatched); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)::int
FROM access_events
WHERE ts < $1`, result.HotEventCutoff).Scan(&result.AccessEventsMatched); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT (
  (SELECT count(*) FROM rollup_1m WHERE bucket_ts < $1) +
  (SELECT count(*) FROM rollup_ip_1h WHERE bucket_ts < $1) +
  (SELECT count(*) FROM rollup_path_1h WHERE bucket_ts < $1) +
  (SELECT count(*) FROM rollup_user_agent_1h WHERE bucket_ts < $1) +
  (SELECT count(*) FROM rollup_ip_path_1h WHERE bucket_ts < $1) +
  (SELECT count(*) FROM rollup_ip_user_agent_1h WHERE bucket_ts < $1) +
  (SELECT count(*) FROM rollup_status_1h WHERE bucket_ts < $1) +
  (SELECT count(*) FROM rollup_site_latency_1h WHERE bucket_ts < $1) +
  (SELECT count(*) FROM rollup_path_latency_1h WHERE bucket_ts < $1) +
  (SELECT count(*) FROM rollup_security_probe_1h WHERE bucket_ts < $1)
)::int`, result.ArchiveCutoff).Scan(&result.RollupsMatched); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)::int
FROM llm_reports
WHERE created_at < $1`, result.ReportCutoff).Scan(&result.ReportsMatched); err != nil {
		return err
	}
	if err := s.countTemporaryImports(ctx, result); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)::int
FROM log_archives
WHERE status = 'ready'
  AND (expires_at < now() OR range_end < $1)`, result.ArchiveCutoff).Scan(&result.ArchiveFilesMatched); err != nil {
		return err
	}

	if result.DryRun {
		return nil
	}

	if s.cfg.Retention.DeleteTemporaryImports {
		if err := s.expireTemporaryImports(ctx, result); err != nil {
			return err
		}
	}

	if s.cfg.Retention.DeleteHotEvents {
		tag, err := pool.Exec(ctx, `DELETE FROM access_events WHERE ts < $1 AND temporary_import_id IS NULL`, result.HotEventCutoff)
		if err != nil {
			return err
		}
		result.AccessEventsDeleted = int(tag.RowsAffected())
	}

	if s.cfg.Retention.DeleteRollups {
		tag, err := pool.Exec(ctx, `DELETE FROM rollup_1m WHERE bucket_ts < $1`, result.ArchiveCutoff)
		if err != nil {
			return err
		}
		result.RollupsDeleted = int(tag.RowsAffected())
		for _, table := range []string{"rollup_ip_1h", "rollup_path_1h", "rollup_user_agent_1h", "rollup_ip_path_1h", "rollup_ip_user_agent_1h", "rollup_status_1h", "rollup_site_latency_1h", "rollup_path_latency_1h", "rollup_security_probe_1h"} {
			tag, err := pool.Exec(ctx, `DELETE FROM `+table+` WHERE bucket_ts < $1`, result.ArchiveCutoff)
			if err != nil {
				return err
			}
			result.RollupsDeleted += int(tag.RowsAffected())
		}
	}

	tag, err := pool.Exec(ctx, `
DELETE FROM llm_reports
WHERE created_at < $1`, result.ReportCutoff)
	if err != nil {
		return err
	}
	result.ReportsDeleted = int(tag.RowsAffected())

	if s.cfg.Retention.DeleteCombinedFiles {
		tag, err = pool.Exec(ctx, `
DELETE FROM combined_segments
WHERE log_type = 'nginx-access'
  AND bucket_end < $1`, result.ArchiveCutoff)
		if err != nil {
			return err
		}
		result.CombinedSegmentsDeleted = int(tag.RowsAffected())
	}

	if s.cfg.Retention.DeleteRawFiles {
		tag, err = pool.Exec(ctx, `
DELETE FROM raw_files
WHERE log_type = 'nginx-access'
  AND remote_mtime < $1`, result.RawFileCutoff)
		if err != nil {
			return err
		}
		result.RawFilesDeleted = int(tag.RowsAffected())
	}

	tag, err = pool.Exec(ctx, `
DELETE FROM log_archives
WHERE status = 'ready'
  AND (expires_at < now() OR range_end < $1)`, result.ArchiveCutoff)
	if err != nil {
		return err
	}
	result.ArchiveFilesDeleted = int(tag.RowsAffected())

	if s.cfg.Retention.DeleteCombinedFiles {
		deleted, failed := removeLocalFiles(combinedFiles)
		result.LocalFilesDeleted += deleted
		result.LocalFileErrors += failed
	}
	if s.cfg.Retention.DeleteRawFiles {
		deleted, failed := removeLocalFiles(rawFiles)
		result.LocalFilesDeleted += deleted
		result.LocalFileErrors += failed
	}
	deleted, failed := removeLocalFiles(archiveFiles)
	result.LocalFilesDeleted += deleted
	result.LocalFileErrors += failed

	return nil
}

func (s *Service) countTemporaryImports(ctx context.Context, result *Result) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)::int
FROM temporary_imports
WHERE expires_at < now()
   OR imported_at < $1`, result.TemporaryImportCutoff).Scan(&result.TemporaryImportsMatched); err != nil {
		return err
	}
	if err := s.countTemporaryEvents(ctx, result); err != nil {
		return err
	}
	return pool.QueryRow(ctx, `
SELECT (
  (SELECT count(*) FROM security_probe_events WHERE temporary_import_id IN (
    SELECT id FROM temporary_imports
    WHERE expires_at < now()
       OR imported_at < $1
  )) +
  (SELECT count(*) FROM error_events WHERE temporary_import_id IN (
    SELECT id FROM temporary_imports
    WHERE expires_at < now()
       OR imported_at < $1
  )) +
  (SELECT count(*) FROM slow_request_events WHERE temporary_import_id IN (
    SELECT id FROM temporary_imports
    WHERE expires_at < now()
       OR imported_at < $1
  ))
)::int`, result.TemporaryImportCutoff).Scan(&result.TemporaryFactsMatched)
}

func (s *Service) countTemporaryEvents(ctx context.Context, result *Result) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	return pool.QueryRow(ctx, `
SELECT count(*)::int
FROM access_events
WHERE temporary_import_id IN (
  SELECT id FROM temporary_imports
  WHERE expires_at < now()
     OR imported_at < $1
)`, result.TemporaryImportCutoff).Scan(&result.TemporaryEventsMatched)
}

func (s *Service) expireTemporaryImports(ctx context.Context, result *Result) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	temporaryRanges, err := s.temporaryImportRanges(ctx, result.TemporaryImportCutoff)
	if err != nil {
		return err
	}
	if err := s.deleteTemporaryFacts(ctx, result); err != nil {
		return err
	}
	tag, err := pool.Exec(ctx, `
DELETE FROM access_events
WHERE temporary_import_id IN (
  SELECT id FROM temporary_imports
  WHERE expires_at < now()
     OR imported_at < $1
)`, result.TemporaryImportCutoff)
	if err != nil {
		return err
	}
	result.TemporaryEventsDeleted = int(tag.RowsAffected())
	tag, err = pool.Exec(ctx, `
DELETE FROM temporary_imports
WHERE expires_at < now()
   OR imported_at < $1`, result.TemporaryImportCutoff)
	if err != nil {
		return err
	}
	result.TemporaryImportsDeleted = int(tag.RowsAffected())
	for _, item := range temporaryRanges {
		rebuilt, err := rollups.Rebuild(ctx, pool, item.Start.UTC().Truncate(time.Hour), item.End.UTC().Truncate(time.Hour).Add(time.Hour))
		if err != nil {
			return err
		}
		result.RollupsRebuilt += rebuilt
	}
	return nil
}

func (s *Service) deleteTemporaryFacts(ctx context.Context, result *Result) error {
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	for _, table := range []string{"security_probe_events", "error_events", "slow_request_events"} {
		tag, err := pool.Exec(ctx, `
DELETE FROM `+table+`
WHERE temporary_import_id IN (
  SELECT id FROM temporary_imports
  WHERE expires_at < now()
     OR imported_at < $1
)`, result.TemporaryImportCutoff)
		if err != nil {
			return err
		}
		result.TemporaryFactsDeleted += int(tag.RowsAffected())
	}
	return nil
}

type timeRange struct {
	Start time.Time
	End   time.Time
}

func (s *Service) temporaryImportRanges(ctx context.Context, cutoff time.Time) ([]timeRange, error) {
	pool, err := s.db.Pool()
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(ctx, `
SELECT range_start, range_end
FROM temporary_imports
WHERE expires_at < now()
   OR imported_at < $1`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ranges := []timeRange{}
	for rows.Next() {
		var item timeRange
		if err := rows.Scan(&item.Start, &item.End); err != nil {
			return nil, err
		}
		if item.End.After(item.Start) {
			ranges = append(ranges, item)
		}
	}
	return ranges, rows.Err()
}

func (s *Service) paths(ctx context.Context, query string, cutoff time.Time) ([]string, error) {
	pool, err := s.db.Pool()
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(ctx, query, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	paths := make([]string, 0)
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, err
		}
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths, rows.Err()
}

func removeLocalFiles(paths []string) (int, int) {
	deleted := 0
	failed := 0
	for _, path := range paths {
		if err := os.Remove(path); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				failed++
				continue
			}
		} else {
			deleted++
		}
		pruneEmptyParents(filepath.Dir(path))
	}
	return deleted, failed
}

func pruneEmptyParents(path string) {
	for i := 0; i < 6; i++ {
		if path == "." || path == string(filepath.Separator) {
			return
		}
		if err := os.Remove(path); err != nil {
			return
		}
		path = filepath.Dir(path)
	}
}
