package pantheon

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"originpulse/internal/db"
)

type RawFile struct {
	SiteID      string
	Env         string
	ContainerID string
	LogType     string
	RemotePath  string
	RemoteSize  int64
	RemoteMTime time.Time
	LocalPath   string
	SHA256      string
	Status      string
	Error       string
}

type RawFileSummary struct {
	SiteID       string     `json:"site_id"`
	Env          string     `json:"env"`
	ContainerID  string     `json:"container_id"`
	LogType      string     `json:"log_type"`
	RemotePath   string     `json:"remote_path"`
	RemoteSize   int64      `json:"remote_size"`
	RemoteMTime  *time.Time `json:"remote_mtime,omitempty"`
	LocalPath    string     `json:"local_path"`
	SHA256       string     `json:"sha256,omitempty"`
	Status       string     `json:"status"`
	Error        string     `json:"error,omitempty"`
	LastSeenAt   time.Time  `json:"last_seen_at"`
	DownloadedAt *time.Time `json:"downloaded_at,omitempty"`
}

type RawFileRepository struct {
	db *db.Store
}

const (
	collectionLockKey     int64 = 7720001
	RawFileRecentMaxLimit       = 500
)

func NewRawFileRepository(store *db.Store) *RawFileRepository {
	return &RawFileRepository{db: store}
}

func (r *RawFileRepository) Enabled() bool {
	return r != nil && r.db != nil && r.db.Enabled()
}

func (r *RawFileRepository) WithCollectionLock(ctx context.Context, fn func(context.Context) error) error {
	if !r.Enabled() {
		return fn(ctx)
	}
	return r.db.WithAdvisoryLock(ctx, collectionLockKey, fn)
}

func (r *RawFileRepository) ShouldDownload(ctx context.Context, file RawFile) (bool, error) {
	if !r.Enabled() {
		return true, nil
	}
	file = normalizeRawFile(file)

	pool, err := r.db.Pool()
	if err != nil {
		return false, err
	}

	var remoteSize int64
	var remoteMTime time.Time
	var status string
	err = pool.QueryRow(ctx, `
SELECT remote_size, remote_mtime, status
FROM raw_files
WHERE site_id = $1
  AND env = $2
  AND container_id = $3
  AND remote_path = $4`,
		file.SiteID, file.Env, file.ContainerID, file.RemotePath,
	).Scan(&remoteSize, &remoteMTime, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	remoteMTime = normalizeRemoteMTime(remoteMTime)

	if status != "downloaded" {
		return true, nil
	}
	return remoteSize != file.RemoteSize || !remoteMTime.Equal(file.RemoteMTime), nil
}

func (r *RawFileRepository) MarkDiscovered(ctx context.Context, file RawFile) error {
	if !r.Enabled() {
		return nil
	}
	file.Status = "discovered"
	return r.upsert(ctx, file)
}

func (r *RawFileRepository) MarkDownloaded(ctx context.Context, file RawFile) error {
	if !r.Enabled() {
		return nil
	}
	file.Status = "downloaded"
	return r.upsert(ctx, file)
}

func (r *RawFileRepository) MarkFailed(ctx context.Context, file RawFile, downloadErr error) error {
	if !r.Enabled() {
		return nil
	}
	file.Status = "failed"
	if downloadErr != nil {
		file.Error = downloadErr.Error()
	}
	return r.upsert(ctx, file)
}

func (r *RawFileRepository) Stats(ctx context.Context) (map[string]int64, error) {
	stats := map[string]int64{
		"discovered": 0,
		"downloaded": 0,
		"failed":     0,
	}
	if !r.Enabled() {
		return stats, nil
	}

	pool, err := r.db.Pool()
	if err != nil {
		return nil, err
	}

	rows, err := pool.Query(ctx, `SELECT status, count(*) FROM raw_files GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		stats[status] = count
	}
	return stats, rows.Err()
}

func (r *RawFileRepository) Recent(ctx context.Context, limit int) ([]RawFileSummary, error) {
	if !r.Enabled() {
		return []RawFileSummary{}, nil
	}
	limit = normalizeRawFileRecentLimit(limit)

	pool, err := r.db.Pool()
	if err != nil {
		return nil, err
	}

	rows, err := pool.Query(ctx, `
SELECT site_id, env, container_id, log_type, remote_path, coalesce(remote_size, 0),
       remote_mtime, local_path, coalesce(sha256, ''), status, coalesce(error, ''),
       last_seen_at, downloaded_at
FROM raw_files
ORDER BY last_seen_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	files := make([]RawFileSummary, 0, limit)
	for rows.Next() {
		var file RawFileSummary
		if err := rows.Scan(
			&file.SiteID,
			&file.Env,
			&file.ContainerID,
			&file.LogType,
			&file.RemotePath,
			&file.RemoteSize,
			&file.RemoteMTime,
			&file.LocalPath,
			&file.SHA256,
			&file.Status,
			&file.Error,
			&file.LastSeenAt,
			&file.DownloadedAt,
		); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, rows.Err()
}

func normalizeRawFileRecentLimit(limit int) int {
	if limit <= 0 {
		return 25
	}
	if limit > RawFileRecentMaxLimit {
		return RawFileRecentMaxLimit
	}
	return limit
}

func (r *RawFileRepository) upsert(ctx context.Context, file RawFile) error {
	file = normalizeRawFile(file)

	pool, err := r.db.Pool()
	if err != nil {
		return err
	}

	var downloadedAt any
	if file.Status == "downloaded" {
		downloadedAt = time.Now().UTC()
	}

	_, err = pool.Exec(ctx, `
INSERT INTO raw_files (
  site_id, env, container_id, log_type, remote_path, remote_size, remote_mtime,
  local_path, sha256, status, error, downloaded_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7,
  $8, $9, $10, nullif($11, ''), $12
)
ON CONFLICT (site_id, env, container_id, remote_path) DO UPDATE
SET log_type = EXCLUDED.log_type,
    remote_size = EXCLUDED.remote_size,
    remote_mtime = EXCLUDED.remote_mtime,
    local_path = EXCLUDED.local_path,
    sha256 = CASE
      WHEN EXCLUDED.status = 'discovered'
        AND raw_files.status = 'downloaded'
        AND raw_files.remote_size = EXCLUDED.remote_size
        AND raw_files.remote_mtime = EXCLUDED.remote_mtime
      THEN raw_files.sha256
      ELSE EXCLUDED.sha256
    END,
    status = CASE
      WHEN EXCLUDED.status = 'discovered'
        AND raw_files.status = 'downloaded'
        AND raw_files.remote_size = EXCLUDED.remote_size
        AND raw_files.remote_mtime = EXCLUDED.remote_mtime
      THEN raw_files.status
      ELSE EXCLUDED.status
    END,
    error = CASE
      WHEN EXCLUDED.status = 'discovered'
        AND raw_files.status = 'downloaded'
        AND raw_files.remote_size = EXCLUDED.remote_size
        AND raw_files.remote_mtime = EXCLUDED.remote_mtime
      THEN raw_files.error
      ELSE EXCLUDED.error
    END,
    last_seen_at = now(),
    downloaded_at = CASE
      WHEN EXCLUDED.status = 'downloaded' THEN EXCLUDED.downloaded_at
      WHEN EXCLUDED.status = 'discovered'
        AND raw_files.status = 'downloaded'
        AND raw_files.remote_size = EXCLUDED.remote_size
        AND raw_files.remote_mtime = EXCLUDED.remote_mtime
      THEN raw_files.downloaded_at
      ELSE NULL
    END`,
		file.SiteID, file.Env, file.ContainerID, file.LogType, file.RemotePath, file.RemoteSize, file.RemoteMTime,
		file.LocalPath, file.SHA256, file.Status, file.Error, downloadedAt,
	)
	return err
}

func normalizeRawFile(file RawFile) RawFile {
	file.RemoteMTime = normalizeRemoteMTime(file.RemoteMTime)
	return file
}

func normalizeRemoteMTime(value time.Time) time.Time {
	if value.IsZero() {
		return value
	}
	return value.UTC().Truncate(time.Microsecond)
}
