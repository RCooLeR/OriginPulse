package retention

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"originpulse/internal/config"
	"originpulse/internal/db"
)

const retentionLockKey int64 = 7720003

type Options struct {
	DryRun bool `json:"dry_run"`
}

type Result struct {
	Enabled                 bool      `json:"enabled"`
	DryRun                  bool      `json:"dry_run"`
	Cutoff                  time.Time `json:"cutoff"`
	MaxAge                  string    `json:"max_age"`
	RawFilesMatched         int       `json:"raw_files_matched"`
	RawBytesMatched         int64     `json:"raw_bytes_matched"`
	CombinedSegmentsMatched int       `json:"combined_segments_matched"`
	AccessEventsMatched     int       `json:"access_events_matched"`
	RollupsMatched          int       `json:"rollups_matched"`
	RawFilesDeleted         int       `json:"raw_files_deleted"`
	CombinedSegmentsDeleted int       `json:"combined_segments_deleted"`
	AccessEventsDeleted     int       `json:"access_events_deleted"`
	RollupsDeleted          int       `json:"rollups_deleted"`
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
	result := Result{
		Enabled: s.cfg.Retention.Enabled,
		DryRun:  opts.DryRun,
		Cutoff:  time.Now().UTC().Add(-s.cfg.Retention.MaxAge),
		MaxAge:  s.cfg.Retention.MaxAge.String(),
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
	if s.cfg.Retention.DeleteRawFiles && !result.DryRun {
		rawFiles, err = s.paths(ctx, `
SELECT local_path
FROM raw_files
WHERE log_type = 'nginx-access'
  AND remote_mtime < $1`, result.Cutoff)
		if err != nil {
			return err
		}
	}
	if s.cfg.Retention.DeleteCombinedFiles && !result.DryRun {
		combinedFiles, err = s.paths(ctx, `
SELECT path
FROM combined_segments
WHERE log_type = 'nginx-access'
  AND bucket_end < $1`, result.Cutoff)
		if err != nil {
			return err
		}
	}

	if err := pool.QueryRow(ctx, `
SELECT count(*)::int, coalesce(sum(remote_size), 0)::bigint
FROM raw_files
WHERE log_type = 'nginx-access'
  AND remote_mtime < $1`, result.Cutoff).Scan(&result.RawFilesMatched, &result.RawBytesMatched); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)::int
FROM combined_segments
WHERE log_type = 'nginx-access'
  AND bucket_end < $1`, result.Cutoff).Scan(&result.CombinedSegmentsMatched); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)::int
FROM access_events
WHERE ts < $1`, result.Cutoff).Scan(&result.AccessEventsMatched); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*)::int
FROM rollup_1m
WHERE bucket_ts < $1`, result.Cutoff).Scan(&result.RollupsMatched); err != nil {
		return err
	}

	if result.DryRun {
		return nil
	}

	tag, err := pool.Exec(ctx, `DELETE FROM access_events WHERE ts < $1`, result.Cutoff)
	if err != nil {
		return err
	}
	result.AccessEventsDeleted = int(tag.RowsAffected())

	tag, err = pool.Exec(ctx, `DELETE FROM rollup_1m WHERE bucket_ts < $1`, result.Cutoff)
	if err != nil {
		return err
	}
	result.RollupsDeleted = int(tag.RowsAffected())

	tag, err = pool.Exec(ctx, `
DELETE FROM combined_segments
WHERE log_type = 'nginx-access'
  AND bucket_end < $1`, result.Cutoff)
	if err != nil {
		return err
	}
	result.CombinedSegmentsDeleted = int(tag.RowsAffected())

	tag, err = pool.Exec(ctx, `
DELETE FROM raw_files
WHERE log_type = 'nginx-access'
  AND remote_mtime < $1`, result.Cutoff)
	if err != nil {
		return err
	}
	result.RawFilesDeleted = int(tag.RowsAffected())

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

	return nil
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
