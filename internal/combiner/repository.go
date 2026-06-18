package combiner

import (
	"context"
	"time"

	"originpulse/internal/db"
)

type RawSource struct {
	SiteID      string
	Env         string
	ContainerID string
	LogType     string
	LocalPath   string
}

type SegmentManifest struct {
	ID          string     `json:"id,omitempty"`
	LogType     string     `json:"log_type"`
	BucketStart time.Time  `json:"bucket_start"`
	BucketEnd   time.Time  `json:"bucket_end"`
	Path        string     `json:"path"`
	SHA256      string     `json:"sha256"`
	LineCount   int64      `json:"line_count"`
	MinTS       *time.Time `json:"min_ts,omitempty"`
	MaxTS       *time.Time `json:"max_ts,omitempty"`
	Status      string     `json:"status"`
	IndexedAt   *time.Time `json:"indexed_at,omitempty"`
	Indexed     bool       `json:"indexed"`
}

type Repository struct {
	db *db.Store
}

const pipelineLockKey int64 = 7720002

func NewRepository(store *db.Store) *Repository {
	return &Repository{db: store}
}

func (r *Repository) Enabled() bool {
	return r != nil && r.db != nil && r.db.Enabled()
}

func (r *Repository) WithPipelineLock(ctx context.Context, fn func(context.Context) error) error {
	if !r.Enabled() {
		return fn(ctx)
	}
	return r.db.WithAdvisoryLock(ctx, pipelineLockKey, fn)
}

func (r *Repository) DownloadedRawSources(ctx context.Context, logType string, modifiedSince time.Time) ([]RawSource, error) {
	if !r.Enabled() {
		return nil, nil
	}

	pool, err := r.db.Pool()
	if err != nil {
		return nil, err
	}

	var since any
	if !modifiedSince.IsZero() {
		since = modifiedSince.UTC()
	}

	rows, err := pool.Query(ctx, `
SELECT site_id, env, container_id, log_type, local_path
FROM raw_files
WHERE status = 'downloaded'
  AND log_type = $1
  AND ($2::timestamptz IS NULL OR remote_mtime >= $2)
ORDER BY site_id, env, container_id, local_path`, logType, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sources := make([]RawSource, 0)
	for rows.Next() {
		var source RawSource
		if err := rows.Scan(&source.SiteID, &source.Env, &source.ContainerID, &source.LogType, &source.LocalPath); err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

func (r *Repository) UpsertSegment(ctx context.Context, manifest SegmentManifest) error {
	if !r.Enabled() {
		return nil
	}

	pool, err := r.db.Pool()
	if err != nil {
		return err
	}

	_, err = pool.Exec(ctx, `
INSERT INTO combined_segments (
  log_type, bucket_start, bucket_end, path, sha256, line_count, min_ts, max_ts, status
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9
)
ON CONFLICT (log_type, bucket_start) DO UPDATE
SET bucket_end = EXCLUDED.bucket_end,
    path = EXCLUDED.path,
    sha256 = EXCLUDED.sha256,
    line_count = EXCLUDED.line_count,
    min_ts = EXCLUDED.min_ts,
    max_ts = EXCLUDED.max_ts,
    status = EXCLUDED.status,
    indexed_at = NULL,
    version = combined_segments.version + 1,
    generated_at = now()`,
		manifest.LogType,
		manifest.BucketStart,
		manifest.BucketEnd,
		manifest.Path,
		manifest.SHA256,
		manifest.LineCount,
		manifest.MinTS,
		manifest.MaxTS,
		manifest.Status,
	)
	return err
}

func (r *Repository) RecentSegments(ctx context.Context, limit int) ([]SegmentManifest, error) {
	if !r.Enabled() {
		return []SegmentManifest{}, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}

	pool, err := r.db.Pool()
	if err != nil {
		return nil, err
	}

	rows, err := pool.Query(ctx, `
SELECT id::text, log_type, bucket_start, bucket_end, path, coalesce(sha256, ''),
       line_count, min_ts, max_ts, status, indexed_at, indexed_at IS NOT NULL
FROM combined_segments
ORDER BY bucket_start DESC, log_type
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	segments := make([]SegmentManifest, 0, limit)
	for rows.Next() {
		var segment SegmentManifest
		if err := rows.Scan(
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
		); err != nil {
			return nil, err
		}
		segments = append(segments, segment)
	}
	return segments, rows.Err()
}

func (r *Repository) PendingIndexSegments(ctx context.Context, limit int) ([]SegmentManifest, error) {
	if !r.Enabled() {
		return []SegmentManifest{}, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	pool, err := r.db.Pool()
	if err != nil {
		return nil, err
	}

	rows, err := pool.Query(ctx, `
SELECT id::text, log_type, bucket_start, bucket_end, path, coalesce(sha256, ''),
       line_count, min_ts, max_ts, status, indexed_at, indexed_at IS NOT NULL
FROM combined_segments
WHERE indexed_at IS NULL
ORDER BY bucket_start, log_type
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	segments := make([]SegmentManifest, 0, limit)
	for rows.Next() {
		var segment SegmentManifest
		if err := rows.Scan(
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
		); err != nil {
			return nil, err
		}
		segments = append(segments, segment)
	}
	return segments, rows.Err()
}
