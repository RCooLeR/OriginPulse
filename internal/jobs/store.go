package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"originpulse/internal/db"
)

type Status string

const (
	StatusRunning Status = "running"
	StatusSkipped Status = "skipped"
	StatusSuccess Status = "success"
	StatusFailed  Status = "failed"
)

type Job struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Status      Status            `json:"status"`
	Message     string            `json:"message,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
	StartedAt   time.Time         `json:"started_at"`
	FinishedAt  *time.Time        `json:"finished_at,omitempty"`
	DurationMS  int64             `json:"duration_ms,omitempty"`
	LastError   string            `json:"last_error,omitempty"`
	TriggeredBy string            `json:"triggered_by,omitempty"`
}

type Page struct {
	Jobs   []Job `json:"jobs"`
	Total  int   `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}

type Store struct {
	mu     sync.RWMutex
	nextID int64
	limit  int
	jobs   []Job
	db     *db.Store
}

func NewStore(limit int, stores ...*db.Store) *Store {
	if limit <= 0 {
		limit = 100
	}
	var store *db.Store
	if len(stores) > 0 {
		store = stores[0]
	}
	return &Store{limit: limit, db: store}
}

func (s *Store) Start(ctx context.Context, jobType string, triggeredBy string, meta map[string]string) Job {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextID++
	now := time.Now().UTC()
	job := Job{
		ID:          fmt.Sprintf("job-%d-%06d", now.UnixNano(), s.nextID),
		Type:        jobType,
		Status:      StatusRunning,
		Meta:        cloneMeta(meta),
		StartedAt:   now,
		TriggeredBy: triggeredBy,
	}
	s.jobs = append([]Job{job}, s.jobs...)
	if len(s.jobs) > s.limit {
		s.jobs = s.jobs[:s.limit]
	}
	_ = s.insertJob(ctx, job)
	return job
}

func (s *Store) Finish(id string, status Status, message string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for i := range s.jobs {
		if s.jobs[i].ID != id {
			continue
		}
		s.jobs[i].Status = status
		s.jobs[i].Message = message
		s.jobs[i].FinishedAt = &now
		s.jobs[i].DurationMS = now.Sub(s.jobs[i].StartedAt).Milliseconds()
		if err != nil {
			s.jobs[i].LastError = err.Error()
		}
		_ = s.updateJob(context.Background(), s.jobs[i])
		return
	}
}

func (s *Store) Recent(limit int) []Job {
	page := s.RecentPage(limit, 0)
	return page.Jobs
}

func (s *Store) RecentPage(limit int, offset int) Page {
	limit = normalizeLimit(limit, s.limit)
	offset = normalizeOffset(offset)
	if jobs, total, ok := s.recentFromDB(context.Background(), limit, offset); ok {
		return Page{Jobs: jobs, Total: total, Limit: limit, Offset: offset}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.jobs)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	result := make([]Job, end-offset)
	copy(result, s.jobs[offset:end])
	return Page{Jobs: result, Total: total, Limit: limit, Offset: offset}
}

func (s *Store) Stats() map[Status]int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[Status]int{
		StatusRunning: 0,
		StatusSkipped: 0,
		StatusSuccess: 0,
		StatusFailed:  0,
	}
	for _, job := range s.jobs {
		stats[job.Status]++
	}
	return stats
}

func cloneMeta(meta map[string]string) map[string]string {
	if len(meta) == 0 {
		return nil
	}
	out := make(map[string]string, len(meta))
	for key, value := range meta {
		out[key] = value
	}
	return out
}

func normalizeLimit(limit int, max int) int {
	if max <= 0 {
		max = 100
	}
	if limit <= 0 {
		return max
	}
	if limit > max {
		return max
	}
	return limit
}

func normalizeOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

func (s *Store) dbEnabled() bool {
	return s != nil && s.db != nil && s.db.Enabled()
}

func (s *Store) insertJob(ctx context.Context, job Job) error {
	if !s.dbEnabled() {
		return nil
	}
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	meta, err := json.Marshal(emptyMeta(job.Meta))
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
INSERT INTO job_runs (id, type, status, message, meta, started_at, finished_at, duration_ms, last_error, triggered_by)
VALUES ($1, $2, $3, nullif($4, ''), $5::jsonb, $6, $7, $8, nullif($9, ''), nullif($10, ''))
ON CONFLICT (id) DO UPDATE SET
  type = EXCLUDED.type,
  status = EXCLUDED.status,
  message = EXCLUDED.message,
  meta = EXCLUDED.meta,
  started_at = EXCLUDED.started_at,
  finished_at = EXCLUDED.finished_at,
  duration_ms = EXCLUDED.duration_ms,
  last_error = EXCLUDED.last_error,
  triggered_by = EXCLUDED.triggered_by`,
		job.ID, job.Type, string(job.Status), job.Message, string(meta), job.StartedAt, job.FinishedAt, job.DurationMS, job.LastError, job.TriggeredBy)
	return err
}

func (s *Store) updateJob(ctx context.Context, job Job) error {
	if !s.dbEnabled() {
		return nil
	}
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	meta, err := json.Marshal(emptyMeta(job.Meta))
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
INSERT INTO job_runs (id, type, status, message, meta, started_at, finished_at, duration_ms, last_error, triggered_by)
VALUES ($1, $2, $3, nullif($4, ''), $5::jsonb, $6, $7, $8, nullif($9, ''), nullif($10, ''))
ON CONFLICT (id) DO UPDATE SET
  status = EXCLUDED.status,
  message = EXCLUDED.message,
  meta = EXCLUDED.meta,
  finished_at = EXCLUDED.finished_at,
  duration_ms = EXCLUDED.duration_ms,
  last_error = EXCLUDED.last_error`,
		job.ID, job.Type, string(job.Status), job.Message, string(meta), job.StartedAt, job.FinishedAt, job.DurationMS, job.LastError, job.TriggeredBy)
	return err
}

func (s *Store) recentFromDB(ctx context.Context, limit int, offset int) ([]Job, int, bool) {
	if !s.dbEnabled() {
		return nil, 0, false
	}
	pool, err := s.db.Pool()
	if err != nil {
		return nil, 0, false
	}
	var total int
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM job_runs`).Scan(&total); err != nil {
		return nil, 0, false
	}
	rows, err := pool.Query(ctx, `
SELECT id,
       type,
       status,
       coalesce(message, ''),
       meta,
       started_at,
       finished_at,
       coalesce(duration_ms, 0),
       coalesce(last_error, ''),
       coalesce(triggered_by, '')
FROM job_runs
ORDER BY started_at DESC
LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, false
	}
	defer rows.Close()

	jobs := make([]Job, 0, limit)
	for rows.Next() {
		var job Job
		var status string
		var metaRaw []byte
		if err := rows.Scan(&job.ID, &job.Type, &status, &job.Message, &metaRaw, &job.StartedAt, &job.FinishedAt, &job.DurationMS, &job.LastError, &job.TriggeredBy); err != nil {
			return nil, 0, false
		}
		job.Status = Status(status)
		job.Meta = decodeMeta(metaRaw)
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false
	}
	return jobs, total, true
}

func emptyMeta(meta map[string]string) map[string]string {
	if meta == nil {
		return map[string]string{}
	}
	return meta
}

func decodeMeta(raw []byte) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var meta map[string]string
	if err := json.Unmarshal(raw, &meta); err != nil || len(meta) == 0 {
		return nil
	}
	return meta
}
