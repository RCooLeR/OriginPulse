package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"originpulse/internal/combiner"
	"originpulse/internal/config"
	"originpulse/internal/indexer"
	"originpulse/internal/jobs"
)

type Options struct {
	From        time.Time `json:"from,omitempty"`
	To          time.Time `json:"to,omitempty"`
	Force       bool      `json:"force"`
	SkipCombine bool      `json:"skip_combine"`
	LogTypes    []string  `json:"log_types,omitempty"`
	MaxSegments int       `json:"max_segments,omitempty"`
	TriggeredBy string    `json:"triggered_by,omitempty"`
}

type Result struct {
	From             time.Time         `json:"from,omitempty"`
	To               time.Time         `json:"to,omitempty"`
	LogTypes         []string          `json:"log_types"`
	CombinedSegments int               `json:"combined_segments"`
	LinesCombined    int               `json:"lines_combined"`
	LinesQuarantined int               `json:"lines_quarantined"`
	IndexedSegments  int               `json:"indexed_segments"`
	EventsInserted   int               `json:"events_inserted"`
	EventsStored     int               `json:"events_stored"`
	EventsSkipped    int               `json:"events_skipped"`
	RollupsUpdated   int               `json:"rollups_updated"`
	CombineResults   []combiner.Result `json:"combine_results,omitempty"`
	IndexResults     []indexer.Result  `json:"index_results,omitempty"`
}

type Service struct {
	cfg      config.Config
	jobs     *jobs.Store
	combiner *combiner.Service
	segments *combiner.Repository
	indexer  *indexer.Service
}

func New(cfg config.Config, store *jobs.Store, combinerService *combiner.Service, segmentRepo *combiner.Repository, indexerService *indexer.Service) *Service {
	return &Service{
		cfg:      cfg,
		jobs:     store,
		combiner: combinerService,
		segments: segmentRepo,
		indexer:  indexerService,
	}
}

func (s *Service) Enabled() bool {
	return s != nil && s.combiner != nil && s.segments != nil && s.indexer != nil && s.segments.Enabled()
}

func (s *Service) Run(ctx context.Context, opts Options) (Result, error) {
	if !s.Enabled() {
		return Result{}, indexer.ErrDatabaseRequired
	}
	opts = s.normalizeOptions(opts)
	if !opts.SkipCombine && !opts.From.Before(opts.To) {
		return Result{}, fmt.Errorf("pipeline requires a valid from/to range")
	}

	meta := map[string]string{
		"from": opts.From.Format(time.RFC3339),
		"to":   opts.To.Format(time.RFC3339),
	}
	triggeredBy := opts.TriggeredBy
	if triggeredBy == "" {
		triggeredBy = "manual"
	}

	var job jobs.Job
	if s.jobs != nil {
		job = s.jobs.Start(ctx, "pipeline", triggeredBy, meta)
	}

	var result Result
	err := s.segments.WithPipelineLock(ctx, func(ctx context.Context) error {
		var runErr error
		result, runErr = s.run(ctx, opts)
		return runErr
	})
	if s.jobs != nil {
		if err != nil {
			s.jobs.Finish(job.ID, jobs.StatusFailed, "pipeline failed", err)
		} else {
			s.jobs.Finish(job.ID, jobs.StatusSuccess, "pipeline completed", nil)
		}
	}
	return result, err
}

func (s *Service) RunRecent(ctx context.Context, triggeredBy string) (Result, error) {
	now := time.Now().UTC()
	settlingWindow := s.cfg.Combiner.SettlingWindow
	if settlingWindow <= 0 {
		settlingWindow = 5 * time.Minute
	}
	to := now.Add(-settlingWindow)
	from := to.Add(-45 * time.Minute)
	return s.Run(ctx, Options{
		From:        from,
		To:          to,
		MaxSegments: 100,
		TriggeredBy: triggeredBy,
	})
}

func (s *Service) run(ctx context.Context, opts Options) (Result, error) {
	result := Result{
		From:     opts.From,
		To:       opts.To,
		LogTypes: append([]string(nil), opts.LogTypes...),
	}

	if !opts.SkipCombine {
		for _, logType := range opts.LogTypes {
			combineResult, err := s.combiner.Combine(ctx, combiner.Options{
				LogType: logType,
				From:    opts.From,
				To:      opts.To,
				Force:   opts.Force,
			})
			if err != nil {
				return result, err
			}
			result.CombineResults = append(result.CombineResults, combineResult)
			result.CombinedSegments += combineResult.SegmentsWritten
			result.LinesCombined += combineResult.LinesCombined
			result.LinesQuarantined += combineResult.LinesQuarantined
		}
	}

	pending, err := s.segments.PendingIndexSegments(ctx, opts.MaxSegments)
	if err != nil {
		return result, err
	}
	for _, segment := range pending {
		indexResult, err := s.indexer.IndexSegment(ctx, indexer.Options{SegmentPath: segment.Path})
		if err != nil {
			return result, err
		}
		result.IndexResults = append(result.IndexResults, indexResult)
		result.IndexedSegments++
		result.EventsInserted += indexResult.EventsInserted
		result.EventsStored += indexResult.EventsStored
		result.EventsSkipped += indexResult.EventsSkipped
		result.RollupsUpdated += indexResult.RollupsUpdated
	}

	log.Info().
		Time("from", result.From).
		Time("to", result.To).
		Int("combined_segments", result.CombinedSegments).
		Int("indexed_segments", result.IndexedSegments).
		Int("events_inserted", result.EventsInserted).
		Msg("pipeline completed")

	return result, nil
}

func (s *Service) normalizeOptions(opts Options) Options {
	if opts.MaxSegments <= 0 {
		opts.MaxSegments = 100
	}
	if len(opts.LogTypes) == 0 {
		opts.LogTypes = []string{"nginx-access"}
	}
	for i := range opts.LogTypes {
		if opts.LogTypes[i] == "" {
			opts.LogTypes[i] = "nginx-access"
		}
	}
	return opts
}
