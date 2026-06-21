package combiner

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"originpulse/internal/db"
)

type RawSource struct {
	RawFileID   string
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

type SegmentPage struct {
	Segments []SegmentManifest `json:"segments"`
	Total    int               `json:"total"`
	Limit    int               `json:"limit"`
	Offset   int               `json:"offset"`
}

type Repository struct {
	db          *db.Store
	rawDir      string
	combinedDir string
}

const (
	pipelineLockKey        int64 = 7720002
	RecentSegmentsMaxLimit       = 500
)

func NewRepository(store *db.Store, rawDir ...string) *Repository {
	repository := &Repository{db: store}
	if len(rawDir) > 0 {
		repository.rawDir = rawDir[0]
	}
	if len(rawDir) > 1 {
		repository.combinedDir = rawDir[1]
	}
	return repository
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
SELECT id::text, site_id, env, container_id, log_type, local_path
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
		if err := rows.Scan(&source.RawFileID, &source.SiteID, &source.Env, &source.ContainerID, &source.LogType, &source.LocalPath); err != nil {
			return nil, err
		}
		source.LocalPath = normalizeStoredDataPath(source.LocalPath, "raw", r.rawDir)
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

func normalizeStoredRawPath(localPath string, rawDir string) string {
	return normalizeStoredDataPath(localPath, "raw", rawDir)
}

func normalizeStoredCombinedPath(segmentPath string, combinedDir string) string {
	return normalizeStoredDataPath(segmentPath, "combined", combinedDir)
}

func normalizeStoredDataPath(pathValue string, dataChild string, targetDir string) string {
	if strings.TrimSpace(pathValue) == "" || strings.TrimSpace(targetDir) == "" || strings.TrimSpace(dataChild) == "" {
		return pathValue
	}
	normalized := strings.ReplaceAll(pathValue, `\`, `/`)
	for strings.Contains(normalized, "//") {
		normalized = strings.ReplaceAll(normalized, "//", "/")
	}
	marker := "/data/" + strings.Trim(dataChild, "/") + "/"
	lower := strings.ToLower(normalized)
	idx := strings.Index(lower, marker)
	if idx < 0 && strings.HasPrefix(lower, strings.TrimPrefix(marker, "/")) {
		idx = -1
	}
	if idx < 0 && !strings.HasPrefix(lower, strings.TrimPrefix(marker, "/")) {
		return pathValue
	}
	start := idx + len(marker)
	if idx < 0 {
		start = len(strings.TrimPrefix(marker, "/"))
	}
	relative := strings.TrimPrefix(normalized[start:], "/")
	if relative == "" {
		return pathValue
	}
	return filepath.Join(targetDir, filepath.FromSlash(relative))
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
    status = CASE
      WHEN combined_segments.bucket_end IS NOT DISTINCT FROM EXCLUDED.bucket_end
        AND combined_segments.path IS NOT DISTINCT FROM EXCLUDED.path
        AND combined_segments.sha256 IS NOT DISTINCT FROM EXCLUDED.sha256
        AND combined_segments.line_count IS NOT DISTINCT FROM EXCLUDED.line_count
        AND combined_segments.min_ts IS NOT DISTINCT FROM EXCLUDED.min_ts
        AND combined_segments.max_ts IS NOT DISTINCT FROM EXCLUDED.max_ts
      THEN combined_segments.status
      ELSE EXCLUDED.status
    END,
    indexed_at = CASE
      WHEN combined_segments.bucket_end IS NOT DISTINCT FROM EXCLUDED.bucket_end
        AND combined_segments.path IS NOT DISTINCT FROM EXCLUDED.path
        AND combined_segments.sha256 IS NOT DISTINCT FROM EXCLUDED.sha256
        AND combined_segments.line_count IS NOT DISTINCT FROM EXCLUDED.line_count
        AND combined_segments.min_ts IS NOT DISTINCT FROM EXCLUDED.min_ts
        AND combined_segments.max_ts IS NOT DISTINCT FROM EXCLUDED.max_ts
      THEN combined_segments.indexed_at
      ELSE NULL
    END,
    version = CASE
      WHEN combined_segments.bucket_end IS NOT DISTINCT FROM EXCLUDED.bucket_end
        AND combined_segments.path IS NOT DISTINCT FROM EXCLUDED.path
        AND combined_segments.sha256 IS NOT DISTINCT FROM EXCLUDED.sha256
        AND combined_segments.line_count IS NOT DISTINCT FROM EXCLUDED.line_count
        AND combined_segments.min_ts IS NOT DISTINCT FROM EXCLUDED.min_ts
        AND combined_segments.max_ts IS NOT DISTINCT FROM EXCLUDED.max_ts
      THEN combined_segments.version
      ELSE combined_segments.version + 1
    END,
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
	page, err := r.RecentSegmentsPage(ctx, limit, 0)
	return page.Segments, err
}

func (r *Repository) RecentSegmentsPage(ctx context.Context, limit int, offset int) (SegmentPage, error) {
	limit = normalizeRecentSegmentsLimit(limit)
	offset = normalizeRecentSegmentsOffset(offset)
	out := SegmentPage{Segments: []SegmentManifest{}, Limit: limit, Offset: offset}
	if !r.Enabled() {
		return out, nil
	}

	pool, err := r.db.Pool()
	if err != nil {
		return out, err
	}

	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM combined_segments`).Scan(&out.Total); err != nil {
		return out, err
	}

	rows, err := pool.Query(ctx, `
SELECT id::text, log_type, bucket_start, bucket_end, path, coalesce(sha256, ''),
       line_count, min_ts, max_ts, status, indexed_at, indexed_at IS NOT NULL
FROM combined_segments
ORDER BY bucket_start DESC, log_type
LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return out, err
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
			return out, err
		}
		segment.Path = normalizeStoredCombinedPath(segment.Path, r.combinedDir)
		segments = append(segments, segment)
	}
	out.Segments = segments
	return out, rows.Err()
}

func normalizeRecentSegmentsLimit(limit int) int {
	if limit <= 0 {
		return 25
	}
	if limit > RecentSegmentsMaxLimit {
		return RecentSegmentsMaxLimit
	}
	return limit
}

func normalizeRecentSegmentsOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
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
		segment.Path = normalizeStoredCombinedPath(segment.Path, r.combinedDir)
		segments = append(segments, segment)
	}
	return segments, rows.Err()
}
