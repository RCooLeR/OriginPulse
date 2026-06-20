package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog/log"

	"originpulse/internal/combiner"
	"originpulse/internal/config"
	"originpulse/internal/indexer"
	"originpulse/internal/jobs"
)

type Options struct {
	From         time.Time `json:"from,omitempty"`
	To           time.Time `json:"to,omitempty"`
	Force        bool      `json:"force"`
	SkipCombine  bool      `json:"skip_combine"`
	LogTypes     []string  `json:"log_types,omitempty"`
	MaxSegments  int       `json:"max_segments,omitempty"`
	IndexWorkers int       `json:"index_workers,omitempty"`
	TriggeredBy  string    `json:"triggered_by,omitempty"`
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
	RollupsRepaired  int               `json:"rollups_repaired"`
	RollupsRecovered int               `json:"rollups_recovered"`
	SecurityProbes   int               `json:"security_probes"`
	ErrorEvents      int               `json:"error_events"`
	SlowRequests     int               `json:"slow_request_events"`
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
	var repairStart time.Time
	var repairEnd time.Time
	repairedSegmentIDs := make([]string, 0, len(pending))
	indexResults, indexErr := s.indexPendingSegments(ctx, pending, opts)
	for _, indexResult := range indexResults {
		result.IndexResults = append(result.IndexResults, indexResult)
		result.IndexedSegments++
		result.EventsInserted += indexResult.EventsInserted
		result.EventsStored += indexResult.EventsStored
		result.EventsSkipped += indexResult.EventsSkipped
		result.RollupsUpdated += indexResult.RollupsUpdated
		result.SecurityProbes += indexResult.SecurityProbes
		result.ErrorEvents += indexResult.ErrorEvents
		result.SlowRequests += indexResult.SlowRequestEvents
		if !indexResult.RangeStart.IsZero() && !indexResult.RangeEnd.IsZero() {
			if repairStart.IsZero() || indexResult.RangeStart.Before(repairStart) {
				repairStart = indexResult.RangeStart
			}
			if repairEnd.IsZero() || indexResult.RangeEnd.After(repairEnd) {
				repairEnd = indexResult.RangeEnd
			}
		}
		if indexResult.SegmentID != "" && !indexResult.AlreadyIndexed {
			repairedSegmentIDs = append(repairedSegmentIDs, indexResult.SegmentID)
		}
	}
	if result.IndexedSegments > 0 && !repairStart.IsZero() && repairEnd.After(repairStart) {
		repaired, err := s.indexer.RebuildRollups(ctx, repairStart, repairEnd)
		if err != nil {
			return result, err
		}
		if err := s.indexer.MarkRollupsBackfilledForSegments(ctx, repairedSegmentIDs); err != nil {
			return result, err
		}
		result.RollupsRepaired = repaired
		result.RollupsUpdated += repaired
	}
	recovered, err := s.indexer.RepairUnbackfilledRollups(ctx)
	if err != nil {
		return result, err
	}
	result.RollupsRecovered = recovered
	result.RollupsUpdated += recovered
	if indexErr != nil {
		return result, indexErr
	}

	log.Info().
		Time("from", result.From).
		Time("to", result.To).
		Int("combined_segments", result.CombinedSegments).
		Int("indexed_segments", result.IndexedSegments).
		Int("index_workers", opts.IndexWorkers).
		Int("events_inserted", result.EventsInserted).
		Int("rollups_repaired", result.RollupsRepaired).
		Int("rollups_recovered", result.RollupsRecovered).
		Int("security_probes", result.SecurityProbes).
		Int("error_events", result.ErrorEvents).
		Int("slow_request_events", result.SlowRequests).
		Msg("pipeline completed")

	return result, nil
}

func (s *Service) normalizeOptions(opts Options) Options {
	if opts.MaxSegments <= 0 {
		opts.MaxSegments = 100
	}
	if opts.IndexWorkers <= 0 {
		opts.IndexWorkers = s.cfg.Pipeline.IndexWorkers
	}
	if opts.IndexWorkers <= 0 {
		opts.IndexWorkers = 1
	}
	if opts.IndexWorkers > opts.MaxSegments {
		opts.IndexWorkers = opts.MaxSegments
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

type indexedSegmentResult struct {
	index  int
	result indexer.Result
	err    error
}

func (s *Service) indexPendingSegments(ctx context.Context, pending []combiner.SegmentManifest, opts Options) ([]indexer.Result, error) {
	if len(pending) == 0 {
		return []indexer.Result{}, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	workers := opts.IndexWorkers
	if workers <= 0 {
		workers = 1
	}
	if workers > len(pending) {
		workers = len(pending)
	}
	jobs := make(chan int)
	results := make(chan indexedSegmentResult, len(pending))
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				segment := pending[idx]
				indexResult, err := s.indexSegmentWithRetry(ctx, segment, opts)
				results <- indexedSegmentResult{index: idx, result: indexResult, err: err}
				if err != nil {
					cancel()
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for idx := range pending {
			select {
			case <-ctx.Done():
				return
			case jobs <- idx:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	ordered := make([]indexer.Result, len(pending))
	seen := 0
	var firstErr error
	collected := make([]indexedSegmentResult, 0, len(pending))
	for item := range results {
		if item.err != nil {
			if firstErr == nil {
				firstErr = item.err
				cancel()
			}
			continue
		}
		collected = append(collected, item)
		seen++
	}
	sort.Slice(collected, func(i int, j int) bool {
		return collected[i].index < collected[j].index
	})
	for i, item := range collected {
		ordered[i] = item.result
	}
	if firstErr != nil {
		return ordered[:seen], firstErr
	}
	if err := ctx.Err(); err != nil {
		return ordered[:seen], err
	}
	return ordered[:seen], nil
}

func (s *Service) indexSegmentWithRetry(ctx context.Context, segment combiner.SegmentManifest, opts Options) (indexer.Result, error) {
	var result indexer.Result
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		result, err = s.indexer.IndexSegment(ctx, indexer.Options{SegmentPath: segment.Path, Force: opts.Force, SkipRollups: true})
		if err == nil || !isRetryableIndexError(err) {
			return result, err
		}
		delay := time.Duration(attempt+1) * 750 * time.Millisecond
		log.Warn().
			Err(err).
			Str("segment_id", segment.ID).
			Time("bucket_start", segment.BucketStart).
			Int("attempt", attempt+1).
			Dur("retry_after", delay).
			Msg("retrying segment index after transient database conflict")
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(delay):
		}
	}
	return result, err
}

func isRetryableIndexError(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "40P01" || pgErr.Code == "40001"
}
