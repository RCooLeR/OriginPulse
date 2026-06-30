package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	From               time.Time `json:"from,omitempty"`
	To                 time.Time `json:"to,omitempty"`
	Force              bool      `json:"force"`
	SkipCombine        bool      `json:"skip_combine"`
	SkipRollupRecovery bool      `json:"skip_rollup_recovery,omitempty"`
	PreferRecent       bool      `json:"prefer_recent,omitempty"`
	SiteID             string    `json:"site_id,omitempty"`
	Env                string    `json:"env,omitempty"`
	AllSourceEvents    bool      `json:"all_source_events,omitempty"`
	LogTypes           []string  `json:"log_types,omitempty"`
	MaxSegments        int       `json:"max_segments,omitempty"`
	IndexWorkers       int       `json:"index_workers,omitempty"`
	TriggeredBy        string    `json:"triggered_by,omitempty"`
}

type Result struct {
	From              time.Time         `json:"from,omitempty"`
	To                time.Time         `json:"to,omitempty"`
	LogTypes          []string          `json:"log_types"`
	CombinedSegments  int               `json:"combined_segments"`
	LinesCombined     int               `json:"lines_combined"`
	LinesQuarantined  int               `json:"lines_quarantined"`
	IndexedSegments   int               `json:"indexed_segments"`
	EventsInserted    int               `json:"events_inserted"`
	LogEventsInserted int               `json:"log_events_inserted"`
	EventsStored      int               `json:"events_stored"`
	EventsSkipped     int               `json:"events_skipped"`
	RollupsUpdated    int               `json:"rollups_updated"`
	RollupsRepaired   int               `json:"rollups_repaired"`
	RollupsRecovered  int               `json:"rollups_recovered"`
	SecurityProbes    int               `json:"security_probes"`
	ErrorEvents       int               `json:"error_events"`
	SlowRequests      int               `json:"slow_request_events"`
	FailedSites       int               `json:"failed_sites,omitempty"`
	FailedSegments    int               `json:"failed_segments,omitempty"`
	FailedSiteIDs     []string          `json:"failed_site_ids,omitempty"`
	CombineResults    []combiner.Result `json:"combine_results,omitempty"`
	IndexResults      []indexer.Result  `json:"index_results,omitempty"`
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

	meta := map[string]any{
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
		result, runErr = s.run(ctx, opts, job.ID)
		return runErr
	})
	if s.jobs != nil {
		if err != nil {
			s.jobs.FinishWithMeta(job.ID, jobs.StatusFailed, "pipeline failed", err, resultJobMeta(result))
		} else {
			s.jobs.FinishWithMeta(job.ID, jobs.StatusSuccess, "pipeline completed", nil, resultJobMeta(result))
		}
	}
	return result, err
}

func resultJobMeta(result Result) map[string]any {
	return map[string]any{
		"combined_segments":   result.CombinedSegments,
		"indexed_segments":    result.IndexedSegments,
		"events_inserted":     result.EventsInserted,
		"log_events_inserted": result.LogEventsInserted,
		"events_stored":       result.EventsStored,
		"events_skipped":      result.EventsSkipped,
		"rollups_updated":     result.RollupsUpdated,
		"rollups_repaired":    result.RollupsRepaired,
		"rollups_recovered":   result.RollupsRecovered,
		"security_probes":     result.SecurityProbes,
		"error_events":        result.ErrorEvents,
		"slow_request_events": result.SlowRequests,
		"failed_sites":        result.FailedSites,
		"failed_segments":     result.FailedSegments,
		"failed_site_ids":     result.FailedSiteIDs,
	}
}

func (s *Service) RunRecent(ctx context.Context, triggeredBy string) (Result, error) {
	return s.RunRecentWithOptions(ctx, triggeredBy, Options{})
}

func (s *Service) RunRecentWithOptions(ctx context.Context, triggeredBy string, opts Options) (Result, error) {
	now := time.Now().UTC()
	settlingWindow := s.cfg.Combiner.SettlingWindow
	if settlingWindow <= 0 {
		settlingWindow = 5 * time.Minute
	}
	to := now.Add(-settlingWindow)
	from := to.Add(-45 * time.Minute)
	opts.From = from
	opts.To = to
	opts.AllSourceEvents = true
	opts.TriggeredBy = triggeredBy
	return s.Run(ctx, opts)
}

func (s *Service) run(ctx context.Context, opts Options, jobID string) (Result, error) {
	result := Result{
		From:     opts.From,
		To:       opts.To,
		LogTypes: append([]string(nil), opts.LogTypes...),
	}

	if !opts.SkipCombine {
		for _, logType := range opts.LogTypes {
			step := s.startStep(ctx, jobID, "combine "+logType, map[string]any{
				"log_type":          logType,
				"site_id":           opts.SiteID,
				"env":               opts.Env,
				"from":              opts.From.Format(time.RFC3339),
				"to":                opts.To.Format(time.RFC3339),
				"force":             opts.Force,
				"all_source_events": opts.AllSourceEvents,
			})
			combineResult, err := s.combiner.Combine(ctx, combiner.Options{
				LogType:         logType,
				From:            opts.From,
				To:              opts.To,
				Force:           opts.Force,
				AllSourceEvents: opts.AllSourceEvents,
				SiteID:          opts.SiteID,
				Env:             opts.Env,
			})
			if err != nil {
				s.finishStep(step, jobs.StatusFailed, "combine failed", err, nil)
				return result, err
			}
			s.finishStep(step, jobs.StatusSuccess, "combine completed", nil, map[string]any{
				"segments_written":  combineResult.SegmentsWritten,
				"lines_combined":    combineResult.LinesCombined,
				"lines_quarantined": combineResult.LinesQuarantined,
			})
			result.CombineResults = append(result.CombineResults, combineResult)
			result.CombinedSegments += combineResult.SegmentsWritten
			result.LinesCombined += combineResult.LinesCombined
			result.LinesQuarantined += combineResult.LinesQuarantined
		}
	}

	pendingStep := s.startStep(ctx, jobID, "load pending segments", map[string]any{
		"from":         opts.From.Format(time.RFC3339),
		"to":           opts.To.Format(time.RFC3339),
		"max_segments": opts.MaxSegments,
	})
	pending, err := s.pendingIndexSegments(ctx, opts)
	if err != nil {
		s.finishStep(pendingStep, jobs.StatusFailed, "pending segment load failed", err, nil)
		return result, err
	}
	s.finishStep(pendingStep, jobs.StatusSuccess, "pending segments loaded", nil, map[string]any{"pending_segments": len(pending)})
	log.Info().
		Time("from", result.From).
		Time("to", result.To).
		Int("pending_segments", len(pending)).
		Int("max_segments", opts.MaxSegments).
		Bool("skip_combine", opts.SkipCombine).
		Bool("skip_rollup_recovery", opts.SkipRollupRecovery).
		Bool("prefer_recent", opts.PreferRecent).
		Msg("pending segments loaded")
	var repairStart time.Time
	var repairEnd time.Time
	repairedSegmentIDs := make([]string, 0, len(pending))
	indexResults, indexErr := s.indexPendingSegmentsBySite(ctx, jobID, pending, opts, &result)
	for _, indexResult := range indexResults {
		result.IndexResults = append(result.IndexResults, indexResult)
		result.IndexedSegments++
		result.EventsInserted += indexResult.EventsInserted
		result.LogEventsInserted += indexResult.LogEventsInserted
		result.EventsStored += indexResult.EventsStored
		result.EventsSkipped += indexResult.EventsSkipped
		result.RollupsUpdated += indexResult.RollupsUpdated
		result.SecurityProbes += indexResult.SecurityProbes
		result.ErrorEvents += indexResult.ErrorEvents
		result.SlowRequests += indexResult.SlowRequestEvents
		if isAccessLogType(indexResult.LogType) && !indexResult.RangeStart.IsZero() && !indexResult.RangeEnd.IsZero() {
			if repairStart.IsZero() || indexResult.RangeStart.Before(repairStart) {
				repairStart = indexResult.RangeStart
			}
			if repairEnd.IsZero() || indexResult.RangeEnd.After(repairEnd) {
				repairEnd = indexResult.RangeEnd
			}
		}
		if isAccessLogType(indexResult.LogType) && indexResult.SegmentID != "" && !indexResult.AlreadyIndexed {
			repairedSegmentIDs = append(repairedSegmentIDs, indexResult.SegmentID)
		}
	}
	if result.IndexedSegments > 0 && !repairStart.IsZero() && repairEnd.After(repairStart) {
		step := s.startStep(ctx, jobID, "rebuild rollups", map[string]any{
			"from": repairStart.Format(time.RFC3339),
			"to":   repairEnd.Format(time.RFC3339),
		})
		repaired, err := s.indexer.RebuildRollups(ctx, repairStart, repairEnd)
		if err != nil {
			s.finishStep(step, jobs.StatusFailed, "rollup rebuild failed", err, nil)
			return result, err
		}
		s.finishStep(step, jobs.StatusSuccess, "rollups rebuilt", nil, map[string]any{"rollups_repaired": repaired})
		markStep := s.startStep(ctx, jobID, "mark rollups backfilled", map[string]any{"segment_count": len(repairedSegmentIDs)})
		if err := s.indexer.MarkRollupsBackfilledForSegments(ctx, repairedSegmentIDs); err != nil {
			s.finishStep(markStep, jobs.StatusFailed, "failed to mark rollups backfilled", err, nil)
			return result, err
		}
		s.finishStep(markStep, jobs.StatusSuccess, "rollups marked backfilled", nil, nil)
		result.RollupsRepaired = repaired
		result.RollupsUpdated += repaired
	}
	if hasAccessLogType(opts.LogTypes) && !opts.SkipRollupRecovery {
		step := s.startStep(ctx, jobID, "recover unbackfilled rollups", nil)
		recovered, err := s.indexer.RepairUnbackfilledRollups(ctx)
		if err != nil {
			s.finishStep(step, jobs.StatusFailed, "rollup recovery failed", err, nil)
			return result, err
		}
		s.finishStep(step, jobs.StatusSuccess, "rollup recovery completed", nil, map[string]any{"rollups_recovered": recovered})
		result.RollupsRecovered = recovered
		result.RollupsUpdated += recovered
	}
	if indexErr != nil {
		log.Warn().
			Time("from", result.From).
			Time("to", result.To).
			Int("combined_segments", result.CombinedSegments).
			Int("indexed_segments", result.IndexedSegments).
			Int("failed_sites", result.FailedSites).
			Int("failed_segments", result.FailedSegments).
			Strs("failed_site_ids", result.FailedSiteIDs).
			Err(indexErr).
			Msg("pipeline completed with site failures")
		return result, indexErr
	}

	log.Info().
		Time("from", result.From).
		Time("to", result.To).
		Int("combined_segments", result.CombinedSegments).
		Int("indexed_segments", result.IndexedSegments).
		Int("index_workers", opts.IndexWorkers).
		Int("events_inserted", result.EventsInserted).
		Int("log_events_inserted", result.LogEventsInserted).
		Int("rollups_repaired", result.RollupsRepaired).
		Int("rollups_recovered", result.RollupsRecovered).
		Int("security_probes", result.SecurityProbes).
		Int("error_events", result.ErrorEvents).
		Int("slow_request_events", result.SlowRequests).
		Int("failed_sites", result.FailedSites).
		Int("failed_segments", result.FailedSegments).
		Strs("failed_site_ids", result.FailedSiteIDs).
		Msg("pipeline completed")

	return result, nil
}

func hasAccessLogType(logTypes []string) bool {
	for _, logType := range logTypes {
		if isAccessLogType(logType) {
			return true
		}
	}
	return false
}

func isAccessLogType(logType string) bool {
	return logType == "nginx-access" || logType == "apache-access"
}

func (s *Service) pendingIndexSegments(ctx context.Context, opts Options) ([]combiner.SegmentManifest, error) {
	if opts.PreferRecent && (opts.From.IsZero() || opts.To.IsZero() || !opts.From.Before(opts.To)) {
		if opts.Force {
			return s.segments.ReindexSegmentsForScope(ctx, opts.MaxSegments, true, opts.SiteID, opts.Env)
		}
		return s.segments.RecentPendingIndexSegmentsForScope(ctx, opts.MaxSegments, opts.SiteID, opts.Env)
	}
	inRange, err := s.segments.IndexSegmentsInRange(ctx, opts.From, opts.To, opts.MaxSegments, opts.Force, opts.SiteID, opts.Env)
	if err != nil {
		return nil, err
	}
	if len(inRange) >= opts.MaxSegments {
		return inRange, nil
	}
	if opts.Force && !opts.From.IsZero() && !opts.To.IsZero() && opts.From.Before(opts.To) {
		return inRange, nil
	}
	backlog, err := s.segments.PendingIndexSegments(ctx, opts.MaxSegments-len(inRange))
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(inRange)+len(backlog))
	pending := make([]combiner.SegmentManifest, 0, len(inRange)+len(backlog))
	for _, segment := range inRange {
		seen[segment.ID] = struct{}{}
		pending = append(pending, segment)
	}
	for _, segment := range backlog {
		if _, ok := seen[segment.ID]; ok {
			continue
		}
		pending = append(pending, segment)
	}
	return pending, nil
}

func (s *Service) normalizeOptions(opts Options) Options {
	if opts.MaxSegments <= 0 {
		opts.MaxSegments = s.cfg.Pipeline.MaxSegments
	}
	if opts.MaxSegments <= 0 {
		opts.MaxSegments = 500
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
		opts.LogTypes = append([]string(nil), s.cfg.Collection.LogTypes...)
		if len(opts.LogTypes) == 0 {
			opts.LogTypes = []string{"nginx-access"}
		}
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

type siteSegmentGroup struct {
	SiteID   string
	Segments []combiner.SegmentManifest
}

func (s *Service) indexPendingSegmentsBySite(ctx context.Context, parentJobID string, pending []combiner.SegmentManifest, opts Options, result *Result) ([]indexer.Result, error) {
	groups := groupSegmentsBySite(pending)
	if len(groups) == 0 {
		return []indexer.Result{}, nil
	}

	allResults := make([]indexer.Result, 0, len(pending))
	failures := make([]string, 0)
	for _, group := range groups {
		siteJobID := parentJobID
		if s.jobs != nil {
			siteJob := s.jobs.Start(ctx, "pipeline_site", opts.TriggeredBy, map[string]any{
				"parent_job_id": parentJobID,
				"site_id":       group.SiteID,
				"segments":      len(group.Segments),
				"force":         opts.Force,
			})
			siteJobID = siteJob.ID
		}

		siteResults, err := s.indexPendingSegments(ctx, siteJobID, group.Segments, opts)
		allResults = append(allResults, siteResults...)
		meta := map[string]any{
			"parent_job_id":     parentJobID,
			"site_id":           group.SiteID,
			"segments":          len(group.Segments),
			"indexed_segments":  len(siteResults),
			"failed_segments":   len(group.Segments) - len(siteResults),
			"events_inserted":   sumIndexResults(siteResults, func(item indexer.Result) int { return item.EventsInserted }),
			"events_stored":     sumIndexResults(siteResults, func(item indexer.Result) int { return item.EventsStored }),
			"events_skipped":    sumIndexResults(siteResults, func(item indexer.Result) int { return item.EventsSkipped }),
			"security_probes":   sumIndexResults(siteResults, func(item indexer.Result) int { return item.SecurityProbes }),
			"error_events":      sumIndexResults(siteResults, func(item indexer.Result) int { return item.ErrorEvents }),
			"slow_request_rows": sumIndexResults(siteResults, func(item indexer.Result) int { return item.SlowRequestEvents }),
		}
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", group.SiteID, err))
			if result != nil {
				result.FailedSites++
				result.FailedSegments += len(group.Segments) - len(siteResults)
				result.FailedSiteIDs = append(result.FailedSiteIDs, group.SiteID)
			}
			if s.jobs != nil {
				s.jobs.FinishWithMeta(siteJobID, jobs.StatusFailed, "site pipeline failed", err, meta)
			}
			log.Error().
				Err(err).
				Str("site_id", group.SiteID).
				Int("indexed_segments", len(siteResults)).
				Int("failed_segments", len(group.Segments)-len(siteResults)).
				Msg("site pipeline failed; continuing with remaining sites")
			continue
		}
		if s.jobs != nil {
			s.jobs.FinishWithMeta(siteJobID, jobs.StatusSuccess, "site pipeline completed", nil, meta)
		}
	}
	if len(failures) > 0 {
		return allResults, fmt.Errorf("%d site pipeline(s) failed: %s", len(failures), strings.Join(failures, "; "))
	}
	return allResults, nil
}

func groupSegmentsBySite(pending []combiner.SegmentManifest) []siteSegmentGroup {
	groups := make([]siteSegmentGroup, 0)
	indexBySite := map[string]int{}
	for _, segment := range pending {
		siteID := strings.TrimSpace(segment.SiteID)
		if siteID == "" {
			siteID = "unknown"
		}
		if idx, ok := indexBySite[siteID]; ok {
			groups[idx].Segments = append(groups[idx].Segments, segment)
			continue
		}
		indexBySite[siteID] = len(groups)
		groups = append(groups, siteSegmentGroup{SiteID: siteID, Segments: []combiner.SegmentManifest{segment}})
	}
	return groups
}

func sumIndexResults(items []indexer.Result, value func(indexer.Result) int) int {
	total := 0
	for _, item := range items {
		total += value(item)
	}
	return total
}

func (s *Service) indexPendingSegments(ctx context.Context, jobID string, pending []combiner.SegmentManifest, opts Options) ([]indexer.Result, error) {
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
	work := make(chan int)
	results := make(chan indexedSegmentResult, len(pending))
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range work {
				segment := pending[idx]
				step := s.startStep(ctx, jobID, "index segment", map[string]any{
					"segment_id":   segment.ID,
					"site_id":      segment.SiteID,
					"env":          segment.Env,
					"log_type":     segment.LogType,
					"bucket_start": segment.BucketStart.Format(time.RFC3339),
					"bucket_end":   segment.BucketEnd.Format(time.RFC3339),
					"path":         segment.Path,
					"force":        opts.Force,
				})
				indexResult, err := s.indexSegmentWithRetry(ctx, segment, opts)
				if err != nil {
					s.finishStep(step, jobs.StatusFailed, "segment index failed", err, nil)
				} else {
					s.finishStep(step, jobs.StatusSuccess, "segment indexed", nil, map[string]any{
						"events_inserted":     indexResult.EventsInserted,
						"log_events_inserted": indexResult.LogEventsInserted,
						"events_stored":       indexResult.EventsStored,
						"events_skipped":      indexResult.EventsSkipped,
						"security_probes":     indexResult.SecurityProbes,
						"error_events":        indexResult.ErrorEvents,
						"slow_request_events": indexResult.SlowRequestEvents,
						"already_indexed":     indexResult.AlreadyIndexed,
					})
				}
				results <- indexedSegmentResult{index: idx, result: indexResult, err: err}
				if err != nil {
					cancel()
					return
				}
			}
		}()
	}
	go func() {
		defer close(work)
		for idx := range pending {
			select {
			case <-ctx.Done():
				return
			case work <- idx:
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

func (s *Service) startStep(ctx context.Context, jobID string, name string, meta map[string]any) jobs.Step {
	if s.jobs == nil {
		return jobs.Step{}
	}
	return s.jobs.StartStep(ctx, jobID, name, meta)
}

func (s *Service) finishStep(step jobs.Step, status jobs.Status, message string, err error, meta map[string]any) {
	if s.jobs == nil {
		return
	}
	s.jobs.FinishStep(step, status, message, err, meta)
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
