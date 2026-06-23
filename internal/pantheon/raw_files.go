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

type RawFilePage struct {
	Recent []RawFileSummary `json:"recent"`
	Total  int              `json:"total"`
	Limit  int              `json:"limit"`
	Offset int              `json:"offset"`
	Status string           `json:"status,omitempty"`
}

type ServerCooldown struct {
	SiteID        string    `json:"site_id"`
	Env           string    `json:"env"`
	ServerKind    string    `json:"server_kind"`
	ServerIP      string    `json:"server_ip"`
	CooldownUntil time.Time `json:"cooldown_until"`
	Reason        string    `json:"reason"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type RawFileRepository struct {
	db *db.Store
}

const (
	collectionLockKey          int64 = 7720001
	RawFileRecentMaxLimit            = 500
	rawFileFailureRecentWindow       = time.Hour
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

func (r *RawFileRepository) ServerCooldownUntil(ctx context.Context, siteID string, env string, serverKind string, serverIP string) (time.Time, bool, error) {
	if !r.Enabled() {
		return time.Time{}, false, nil
	}

	pool, err := r.db.Pool()
	if err != nil {
		return time.Time{}, false, err
	}

	var until time.Time
	err = pool.QueryRow(ctx, `
SELECT cooldown_until
FROM pantheon_server_cooldowns
WHERE site_id = $1
  AND env = $2
  AND server_kind = $3
  AND server_ip = $4`,
		siteID, env, serverKind, serverIP,
	).Scan(&until)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	if !time.Now().UTC().Before(until) {
		_, _ = pool.Exec(context.Background(), `
DELETE FROM pantheon_server_cooldowns
WHERE site_id = $1
  AND env = $2
  AND server_kind = $3
  AND server_ip = $4`,
			siteID, env, serverKind, serverIP,
		)
		return time.Time{}, false, nil
	}
	return until.UTC(), true, nil
}

func (r *RawFileRepository) MarkServerCooldown(ctx context.Context, siteID string, env string, serverKind string, serverIP string, until time.Time, reason string) error {
	if !r.Enabled() {
		return nil
	}

	pool, err := r.db.Pool()
	if err != nil {
		return err
	}

	_, err = pool.Exec(ctx, `
INSERT INTO pantheon_server_cooldowns (
  site_id, env, server_kind, server_ip, cooldown_until, reason
) VALUES (
  $1, $2, $3, $4, $5, $6
)
ON CONFLICT (site_id, env, server_kind, server_ip) DO UPDATE
SET cooldown_until = EXCLUDED.cooldown_until,
    reason = EXCLUDED.reason,
    updated_at = now()`,
		siteID, env, serverKind, serverIP, until.UTC(), reason,
	)
	return err
}

func (r *RawFileRepository) ActiveServerCooldowns(ctx context.Context, limit int) ([]ServerCooldown, error) {
	if !r.Enabled() {
		return []ServerCooldown{}, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}

	pool, err := r.db.Pool()
	if err != nil {
		return nil, err
	}

	rows, err := pool.Query(ctx, `
SELECT site_id, env, server_kind, server_ip, cooldown_until, coalesce(reason, ''), updated_at
FROM pantheon_server_cooldowns
WHERE cooldown_until > now()
ORDER BY cooldown_until ASC, updated_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cooldowns := []ServerCooldown{}
	for rows.Next() {
		var item ServerCooldown
		if err := rows.Scan(&item.SiteID, &item.Env, &item.ServerKind, &item.ServerIP, &item.CooldownUntil, &item.Reason, &item.UpdatedAt); err != nil {
			return nil, err
		}
		cooldowns = append(cooldowns, item)
	}
	return cooldowns, rows.Err()
}

func (r *RawFileRepository) Stats(ctx context.Context) (map[string]int64, error) {
	stats := map[string]int64{
		"discovered":                   0,
		"downloaded":                   0,
		"failed":                       0,
		"failed_recent":                0,
		"failed_stale":                 0,
		"failed_recent_window_seconds": int64(rawFileFailureRecentWindow.Seconds()),
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	cutoff := time.Now().UTC().Add(-rawFileFailureRecentWindow)
	var recentFailed int64
	if err := pool.QueryRow(ctx, `
SELECT count(*)::bigint
FROM raw_files
WHERE status = 'failed'
  AND last_seen_at >= $1`, cutoff).Scan(&recentFailed); err != nil {
		return nil, err
	}
	stats["failed_recent"] = recentFailed
	stats["failed_stale"] = maxInt64(0, stats["failed"]-recentFailed)
	return stats, nil
}

func (r *RawFileRepository) LastDownloadAt(ctx context.Context) (*time.Time, error) {
	if !r.Enabled() {
		return nil, nil
	}

	pool, err := r.db.Pool()
	if err != nil {
		return nil, err
	}

	var latest time.Time
	if err := pool.QueryRow(ctx, `
SELECT coalesce(max(downloaded_at), '0001-01-01T00:00:00Z'::timestamptz)
FROM raw_files
WHERE status = 'downloaded'`).Scan(&latest); err != nil {
		return nil, err
	}
	if latest.IsZero() {
		return nil, nil
	}
	return &latest, nil
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (r *RawFileRepository) Recent(ctx context.Context, limit int) ([]RawFileSummary, error) {
	page, err := r.RecentPage(ctx, limit, 0, "")
	return page.Recent, err
}

func (r *RawFileRepository) RecentPage(ctx context.Context, limit int, offset int, status string) (RawFilePage, error) {
	limit = normalizeRawFileRecentLimit(limit)
	offset = normalizeRawFileRecentOffset(offset)
	status = normalizeRawFileStatusFilter(status)
	out := RawFilePage{Recent: []RawFileSummary{}, Limit: limit, Offset: offset, Status: status}
	if !r.Enabled() {
		return out, nil
	}

	pool, err := r.db.Pool()
	if err != nil {
		return out, err
	}

	if err := pool.QueryRow(ctx, `
SELECT count(*)::int
FROM raw_files
WHERE ($1 = '' OR status = $1)`, status).Scan(&out.Total); err != nil {
		return out, err
	}

	rows, err := pool.Query(ctx, `
SELECT site_id, env, container_id, log_type, remote_path, coalesce(remote_size, 0),
       remote_mtime, local_path, coalesce(sha256, ''), status, coalesce(error, ''),
       last_seen_at, downloaded_at
FROM raw_files
WHERE ($3 = '' OR status = $3)
ORDER BY last_seen_at DESC
LIMIT $1 OFFSET $2`, limit, offset, status)
	if err != nil {
		return out, err
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
			return out, err
		}
		files = append(files, file)
	}
	out.Recent = files
	return out, rows.Err()
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

func normalizeRawFileRecentOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

func normalizeRawFileStatusFilter(status string) string {
	switch status {
	case "discovered", "downloaded", "failed":
		return status
	default:
		return ""
	}
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
