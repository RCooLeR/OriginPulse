package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
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
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Status      Status         `json:"status"`
	Message     string         `json:"message,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`
	StartedAt   time.Time      `json:"started_at"`
	FinishedAt  *time.Time     `json:"finished_at,omitempty"`
	DurationMS  int64          `json:"duration_ms,omitempty"`
	LastError   string         `json:"last_error,omitempty"`
	TriggeredBy string         `json:"triggered_by,omitempty"`
}

type Step struct {
	ID         int64          `json:"id"`
	JobID      string         `json:"job_id"`
	Name       string         `json:"name"`
	Status     Status         `json:"status"`
	Message    string         `json:"message,omitempty"`
	Meta       map[string]any `json:"meta,omitempty"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	DurationMS int64          `json:"duration_ms,omitempty"`
	LastError  string         `json:"last_error,omitempty"`
}

type StepPhaseSummary struct {
	Name     string    `json:"name"`
	Status   Status    `json:"status"`
	Count    int       `json:"count"`
	TotalMS  int64     `json:"total_ms"`
	MaxMS    int64     `json:"max_ms"`
	AvgMS    int64     `json:"avg_ms"`
	LatestAt time.Time `json:"latest_at"`
}

type Page struct {
	Jobs   []Job `json:"jobs"`
	Total  int   `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}

type StepPage struct {
	Steps      []Step             `json:"steps"`
	Total      int                `json:"total"`
	Limit      int                `json:"limit"`
	Offset     int                `json:"offset"`
	SlowPhases []StepPhaseSummary `json:"slow_phases,omitempty"`
}

type SchedulerSummary struct {
	CollectionIntervalMS   int64     `json:"collection_interval_ms"`
	LastCycleStartedAt     time.Time `json:"last_cycle_started_at,omitempty"`
	LastCycleFinishedAt    time.Time `json:"last_cycle_finished_at,omitempty"`
	LastCycleDurationMS    int64     `json:"last_cycle_duration_ms,omitempty"`
	LastCycleUtilization   float64   `json:"last_cycle_utilization,omitempty"`
	CollectionJobs         int       `json:"collection_jobs,omitempty"`
	PipelineDurationMS     int64     `json:"pipeline_duration_ms,omitempty"`
	PostPipelineDurationMS int64     `json:"post_pipeline_duration_ms,omitempty"`
	LatestPipelineAt       time.Time `json:"latest_pipeline_at,omitempty"`
	RunningSinceStart      int       `json:"running_since_start"`
	FailedSinceStart       int       `json:"failed_since_start"`
	InterruptedSinceStart  int       `json:"interrupted_since_start"`
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

func (s *Store) Start(ctx context.Context, jobType string, triggeredBy string, meta map[string]any) Job {
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
	s.FinishWithMeta(id, status, message, err, nil)
}

func (s *Store) FinishWithMeta(id string, status Status, message string, err error, meta map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for i := range s.jobs {
		if s.jobs[i].ID != id {
			continue
		}
		now = clampFinishTime(s.jobs[i].StartedAt, now)
		s.jobs[i].Status = status
		s.jobs[i].Message = message
		if len(meta) > 0 {
			s.jobs[i].Meta = mergeMeta(s.jobs[i].Meta, meta)
		}
		s.jobs[i].FinishedAt = &now
		s.jobs[i].DurationMS = now.Sub(s.jobs[i].StartedAt).Milliseconds()
		if err != nil {
			s.jobs[i].LastError = err.Error()
		}
		_ = s.updateJob(context.Background(), s.jobs[i])
		return
	}
}

func (s *Store) StartStep(ctx context.Context, jobID string, name string, meta map[string]any) Step {
	if s == nil {
		return Step{}
	}
	now := time.Now().UTC()
	step := Step{
		JobID:     strings.TrimSpace(jobID),
		Name:      strings.TrimSpace(name),
		Status:    StatusRunning,
		Meta:      cloneMeta(meta),
		StartedAt: now,
	}
	if step.Name == "" {
		step.Name = "step"
	}
	if step.JobID == "" {
		return step
	}
	_ = s.insertStep(ctx, &step)
	return step
}

func (s *Store) FinishStep(step Step, status Status, message string, err error, meta map[string]any) {
	if s == nil {
		return
	}
	if step.ID == 0 {
		return
	}
	now := clampFinishTime(step.StartedAt, time.Now().UTC())
	step.Status = status
	step.Message = message
	if len(meta) > 0 {
		step.Meta = mergeMeta(step.Meta, meta)
	}
	step.FinishedAt = &now
	step.DurationMS = now.Sub(step.StartedAt).Milliseconds()
	if err != nil {
		step.LastError = err.Error()
	}
	_ = s.updateStep(context.Background(), step)
}

func (s *Store) StepsPage(ctx context.Context, limit int, offset int, jobID string, summarySince ...time.Time) StepPage {
	if s == nil {
		limit = normalizeLimit(limit, 100)
		offset = normalizeOffset(offset)
		return StepPage{Steps: []Step{}, Total: 0, Limit: limit, Offset: offset}
	}
	limit = normalizeLimit(limit, s.limit)
	offset = normalizeOffset(offset)
	if steps, total, ok := s.stepsFromDB(ctx, limit, offset, jobID); ok {
		return StepPage{Steps: steps, Total: total, Limit: limit, Offset: offset, SlowPhases: s.slowPhasesFromDB(ctx, firstTime(summarySince))}
	}
	return StepPage{Steps: []Step{}, Total: 0, Limit: limit, Offset: offset}
}

func clampFinishTime(startedAt time.Time, finishedAt time.Time) time.Time {
	if !startedAt.IsZero() && finishedAt.Before(startedAt) {
		return startedAt
	}
	return finishedAt
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
	if stats, ok := s.statsFromDB(context.Background()); ok {
		return stats
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return statsFromJobs(s.jobs)
}

func (s *Store) SchedulerSummary(ctx context.Context, appStartedAt time.Time, interval time.Duration) SchedulerSummary {
	summary := SchedulerSummary{CollectionIntervalMS: interval.Milliseconds()}
	if !s.dbEnabled() {
		return summary
	}
	pool, err := s.db.Pool()
	if err != nil {
		return summary
	}
	if appStartedAt.IsZero() {
		appStartedAt = time.Now().UTC().Add(-24 * time.Hour)
	}
	var cycleStart sql.NullTime
	var cycleEnd sql.NullTime
	var latestPipeline sql.NullTime
	var cycleMS sql.NullInt64
	var collectionJobs sql.NullInt64
	var pipelineMS sql.NullInt64
	var postPipelineMS sql.NullInt64
	var runningSinceStart sql.NullInt64
	var failedSinceStart sql.NullInt64
	var interruptedSinceStart sql.NullInt64
	err = pool.QueryRow(ctx, `
WITH params AS (
  SELECT $1::timestamptz AS app_started_at,
         greatest($2::bigint, 1) AS interval_ms
),
latest_pipeline AS (
  SELECT id,
         started_at,
         finished_at,
         CASE
           WHEN status = 'running' THEN greatest(0, floor(extract(epoch FROM (now() - started_at)) * 1000)::bigint)
           ELSE coalesce(duration_ms, 0)
         END AS duration_ms
  FROM job_runs, params
  WHERE type = 'pipeline'
    AND started_at >= params.app_started_at
  ORDER BY started_at DESC
  LIMIT 1
),
previous_pipeline AS (
  SELECT job_runs.started_at,
         job_runs.finished_at
  FROM job_runs, latest_pipeline, params
  WHERE type = 'pipeline'
    AND job_runs.started_at >= params.app_started_at
    AND job_runs.started_at < latest_pipeline.started_at
  ORDER BY job_runs.started_at DESC
  LIMIT 1
),
cycle_jobs AS (
  SELECT j.*
  FROM job_runs j
  JOIN latest_pipeline p ON true
  JOIN params ON true
  LEFT JOIN previous_pipeline previous ON true
  WHERE (
      j.type = 'collect_site_env'
      AND j.started_at >= greatest(
        coalesce(previous.finished_at, p.started_at - (params.interval_ms::double precision * interval '1 millisecond')),
        p.started_at - interval '3 minutes'
      )
      AND j.started_at <= p.started_at
    )
    OR (
      j.type IN ('pipeline', 'evaluate_alerts', 'send_notifications', 'refresh_ip_intel')
      AND j.started_at >= p.started_at
      AND j.started_at <= coalesce(p.finished_at, now()) + interval '2 minutes'
    )
),
cycle AS (
  SELECT min(started_at) AS cycle_started_at,
         max(coalesce(finished_at, now())) AS cycle_finished_at,
         count(*) FILTER (WHERE type = 'collect_site_env')::bigint AS collection_jobs,
         coalesce(max(duration_ms) FILTER (WHERE type = 'pipeline'), 0)::bigint AS pipeline_ms,
         greatest(
           0,
           floor(extract(epoch FROM (max(coalesce(finished_at, now())) - max(finished_at) FILTER (WHERE type = 'pipeline'))) * 1000)::bigint
         ) AS post_pipeline_ms
  FROM cycle_jobs
),
since_start AS (
  SELECT count(*) FILTER (WHERE status = 'running')::bigint AS running_since_start,
         count(*) FILTER (
           WHERE status = 'failed'
             AND coalesce(last_error, '') !~* '(interrupted by application restart|context canceled)'
         )::bigint AS failed_since_start,
         count(*) FILTER (
           WHERE status = 'failed'
             AND coalesce(last_error, '') ~* '(interrupted by application restart|context canceled)'
         )::bigint AS interrupted_since_start
  FROM job_runs, params
  WHERE started_at >= params.app_started_at
)
SELECT cycle.cycle_started_at,
       cycle.cycle_finished_at,
       greatest(0, floor(extract(epoch FROM (cycle.cycle_finished_at - cycle.cycle_started_at)) * 1000)::bigint) AS cycle_ms,
       cycle.collection_jobs,
       cycle.pipeline_ms,
       cycle.post_pipeline_ms,
       latest_pipeline.started_at AS latest_pipeline_at,
       since_start.running_since_start,
       since_start.failed_since_start,
       since_start.interrupted_since_start
FROM cycle
CROSS JOIN latest_pipeline
CROSS JOIN since_start`, appStartedAt, summary.CollectionIntervalMS).Scan(
		&cycleStart,
		&cycleEnd,
		&cycleMS,
		&collectionJobs,
		&pipelineMS,
		&postPipelineMS,
		&latestPipeline,
		&runningSinceStart,
		&failedSinceStart,
		&interruptedSinceStart,
	)
	if err != nil {
		return summary
	}
	if cycleStart.Valid {
		summary.LastCycleStartedAt = cycleStart.Time
	}
	if cycleEnd.Valid {
		summary.LastCycleFinishedAt = cycleEnd.Time
	}
	if latestPipeline.Valid {
		summary.LatestPipelineAt = latestPipeline.Time
	}
	if cycleMS.Valid {
		summary.LastCycleDurationMS = cycleMS.Int64
	}
	if collectionJobs.Valid {
		summary.CollectionJobs = int(collectionJobs.Int64)
	}
	if pipelineMS.Valid {
		summary.PipelineDurationMS = pipelineMS.Int64
	}
	if postPipelineMS.Valid {
		summary.PostPipelineDurationMS = postPipelineMS.Int64
	}
	if runningSinceStart.Valid {
		summary.RunningSinceStart = int(runningSinceStart.Int64)
	}
	if failedSinceStart.Valid {
		summary.FailedSinceStart = int(failedSinceStart.Int64)
	}
	if interruptedSinceStart.Valid {
		summary.InterruptedSinceStart = int(interruptedSinceStart.Int64)
	}
	if summary.CollectionIntervalMS > 0 && summary.LastCycleDurationMS > 0 {
		summary.LastCycleUtilization = float64(summary.LastCycleDurationMS) / float64(summary.CollectionIntervalMS)
	}
	return summary
}

func statsFromJobs(jobs []Job) map[Status]int {
	stats := map[Status]int{
		StatusRunning: 0,
		StatusSkipped: 0,
		StatusSuccess: 0,
		StatusFailed:  0,
	}
	for _, job := range jobs {
		stats[job.Status]++
	}
	return stats
}

func (s *Store) statsFromDB(ctx context.Context) (map[Status]int, bool) {
	if !s.dbEnabled() {
		return nil, false
	}
	pool, err := s.db.Pool()
	if err != nil {
		return nil, false
	}
	rows, err := pool.Query(ctx, `
WITH recent AS (
  SELECT status
  FROM job_runs
  ORDER BY started_at DESC
  LIMIT $1
)
SELECT status, count(*)::int
FROM recent
GROUP BY status`, s.limit)
	if err != nil {
		return nil, false
	}
	defer rows.Close()

	stats := statsFromJobs(nil)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, false
		}
		stats[Status(status)] = count
	}
	if err := rows.Err(); err != nil {
		return nil, false
	}
	return stats, true
}

func (s *Store) MarkRunningInterrupted(ctx context.Context, reason string) error {
	if !s.dbEnabled() {
		return nil
	}
	if strings.TrimSpace(reason) == "" {
		reason = "interrupted by application restart"
	}
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
UPDATE job_runs
SET status = 'failed',
    message = $1,
    finished_at = now(),
    duration_ms = greatest(0, floor(extract(epoch from (now() - started_at)) * 1000)::bigint),
    last_error = $1
WHERE status = 'running'`, reason)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
UPDATE job_steps
SET status = 'failed',
    message = $1,
    finished_at = now(),
    duration_ms = greatest(0, floor(extract(epoch from (now() - started_at)) * 1000)::bigint),
    last_error = $1
WHERE status = 'running'`, reason)
	return err
}

func cloneMeta(meta map[string]any) map[string]any {
	if len(meta) == 0 {
		return nil
	}
	out := make(map[string]any, len(meta))
	for key, value := range meta {
		out[key] = value
	}
	return out
}

func mergeMeta(base map[string]any, updates map[string]any) map[string]any {
	out := cloneMeta(base)
	if out == nil {
		out = map[string]any{}
	}
	for key, value := range updates {
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
       CASE
         WHEN status = 'running' THEN greatest(0, floor(extract(epoch from (now() - started_at)) * 1000)::bigint)
         ELSE coalesce(duration_ms, 0)
       END,
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

func (s *Store) insertStep(ctx context.Context, step *Step) error {
	if !s.dbEnabled() {
		return nil
	}
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	meta, err := json.Marshal(emptyMeta(step.Meta))
	if err != nil {
		return err
	}
	return pool.QueryRow(ctx, `
INSERT INTO job_steps (job_id, name, status, message, meta, started_at, finished_at, duration_ms, last_error)
VALUES ($1, $2, $3, nullif($4, ''), $5::jsonb, $6, $7, $8, nullif($9, ''))
RETURNING id`,
		step.JobID, step.Name, string(step.Status), step.Message, string(meta), step.StartedAt, step.FinishedAt, step.DurationMS, step.LastError).Scan(&step.ID)
}

func (s *Store) updateStep(ctx context.Context, step Step) error {
	if !s.dbEnabled() {
		return nil
	}
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	meta, err := json.Marshal(emptyMeta(step.Meta))
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
UPDATE job_steps
SET status = $2,
    message = nullif($3, ''),
    meta = $4::jsonb,
    finished_at = $5,
    duration_ms = $6,
    last_error = nullif($7, '')
WHERE id = $1`,
		step.ID, string(step.Status), step.Message, string(meta), step.FinishedAt, step.DurationMS, step.LastError)
	return err
}

func (s *Store) stepsFromDB(ctx context.Context, limit int, offset int, jobID string) ([]Step, int, bool) {
	if !s.dbEnabled() {
		return nil, 0, false
	}
	pool, err := s.db.Pool()
	if err != nil {
		return nil, 0, false
	}
	jobID = strings.TrimSpace(jobID)
	var total int
	if err := pool.QueryRow(ctx, `
SELECT count(*)::int
FROM job_steps
WHERE ($1 = '' OR job_id = $1)`, jobID).Scan(&total); err != nil {
		return nil, 0, false
	}
	rows, err := pool.Query(ctx, `
SELECT id,
       job_id,
       name,
       status,
       coalesce(message, ''),
       meta,
       started_at,
       finished_at,
       CASE
         WHEN status = 'running' THEN greatest(0, floor(extract(epoch from (now() - started_at)) * 1000)::bigint)
         ELSE coalesce(duration_ms, 0)
       END,
       coalesce(last_error, '')
FROM job_steps
WHERE ($1 = '' OR job_id = $1)
ORDER BY started_at DESC, id DESC
LIMIT $2 OFFSET $3`, jobID, limit, offset)
	if err != nil {
		return nil, 0, false
	}
	defer rows.Close()

	steps := make([]Step, 0, limit)
	for rows.Next() {
		var step Step
		var status string
		var metaRaw []byte
		if err := rows.Scan(&step.ID, &step.JobID, &step.Name, &status, &step.Message, &metaRaw, &step.StartedAt, &step.FinishedAt, &step.DurationMS, &step.LastError); err != nil {
			return nil, 0, false
		}
		step.Status = Status(status)
		step.Meta = decodeMeta(metaRaw)
		steps = append(steps, step)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false
	}
	return steps, total, true
}

func (s *Store) slowPhasesFromDB(ctx context.Context, since time.Time) []StepPhaseSummary {
	if !s.dbEnabled() || since.IsZero() {
		return []StepPhaseSummary{}
	}
	pool, err := s.db.Pool()
	if err != nil {
		return []StepPhaseSummary{}
	}
	rows, err := pool.Query(ctx, `
WITH measured AS (
  SELECT name,
         status,
         started_at,
         CASE
           WHEN status = 'running' THEN greatest(0, floor(extract(epoch FROM (now() - started_at)) * 1000)::bigint)
           ELSE coalesce(duration_ms, 0)
         END AS duration_ms
  FROM job_steps
  WHERE started_at >= $1
)
SELECT name,
       status,
       count(*)::int,
       sum(duration_ms)::bigint,
       max(duration_ms)::bigint,
       floor(avg(duration_ms))::bigint,
       max(started_at)
FROM measured
GROUP BY name, status
ORDER BY sum(duration_ms) DESC, max(duration_ms) DESC, max(started_at) DESC
LIMIT 8`, since)
	if err != nil {
		return []StepPhaseSummary{}
	}
	defer rows.Close()

	summaries := make([]StepPhaseSummary, 0, 8)
	for rows.Next() {
		var item StepPhaseSummary
		var status string
		if err := rows.Scan(&item.Name, &status, &item.Count, &item.TotalMS, &item.MaxMS, &item.AvgMS, &item.LatestAt); err != nil {
			return []StepPhaseSummary{}
		}
		item.Status = Status(status)
		summaries = append(summaries, item)
	}
	if rows.Err() != nil {
		return []StepPhaseSummary{}
	}
	return summaries
}

func firstTime(values []time.Time) time.Time {
	if len(values) == 0 {
		return time.Time{}
	}
	return values[0]
}

func emptyMeta(meta map[string]any) map[string]any {
	if meta == nil {
		return map[string]any{}
	}
	return meta
}

func decodeMeta(raw []byte) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil || len(meta) == 0 {
		return nil
	}
	return meta
}
