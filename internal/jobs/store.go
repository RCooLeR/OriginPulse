package jobs

import (
	"context"
	"fmt"
	"sync"
	"time"
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

type Store struct {
	mu     sync.RWMutex
	nextID int64
	limit  int
	jobs   []Job
}

func NewStore(limit int) *Store {
	if limit <= 0 {
		limit = 100
	}
	return &Store{limit: limit}
}

func (s *Store) Start(ctx context.Context, jobType string, triggeredBy string, meta map[string]string) Job {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextID++
	job := Job{
		ID:          fmt.Sprintf("job-%06d", s.nextID),
		Type:        jobType,
		Status:      StatusRunning,
		Meta:        cloneMeta(meta),
		StartedAt:   time.Now().UTC(),
		TriggeredBy: triggeredBy,
	}
	s.jobs = append([]Job{job}, s.jobs...)
	if len(s.jobs) > s.limit {
		s.jobs = s.jobs[:s.limit]
	}
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
		return
	}
}

func (s *Store) Recent(limit int) []Job {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.jobs) {
		limit = len(s.jobs)
	}
	result := make([]Job, limit)
	copy(result, s.jobs[:limit])
	return result
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
