package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"originpulse/internal/accessanalysis"
	"originpulse/internal/alerts"
	"originpulse/internal/analytics"
	"originpulse/internal/archive"
	"originpulse/internal/archivecoverage"
	"originpulse/internal/archivefixture"
	"originpulse/internal/archiveimport"
	"originpulse/internal/auth"
	"originpulse/internal/backfill"
	"originpulse/internal/combiner"
	"originpulse/internal/config"
	"originpulse/internal/db"
	"originpulse/internal/geoip"
	"originpulse/internal/httpapi"
	"originpulse/internal/indexer"
	"originpulse/internal/investigation"
	"originpulse/internal/ipintel"
	"originpulse/internal/jobs"
	"originpulse/internal/notifications"
	"originpulse/internal/pantheon"
	"originpulse/internal/pipeline"
	"originpulse/internal/reports"
	"originpulse/internal/retention"
	"originpulse/internal/rollups"
	"originpulse/internal/scheduler"
	"originpulse/internal/sites"
	"originpulse/internal/storageaudit"
)

type Runtime struct {
	cfg             config.Config
	db              *db.Store
	auth            *auth.Service
	sites           *sites.Repository
	rawFiles        *pantheon.RawFileRepository
	combiner        *combiner.Service
	segments        *combiner.Repository
	indexer         *indexer.Service
	analytics       *analytics.Service
	accessAnalysis  *accessanalysis.Service
	investigation   *investigation.Service
	ipIntel         *ipintel.Service
	geoIP           *geoip.Manager
	geoIPUpdater    *geoip.Updater
	alerts          *alerts.Service
	reports         *reports.Service
	notifications   *notifications.Service
	retention       *retention.Service
	archive         *archive.Service
	archiveCoverage *archivecoverage.Service
	archiveImport   *archiveimport.Service
	backfill        *backfill.Service
	storageAudit    *storageaudit.Service
	jobs            *jobs.Store
	collector       *pantheon.Collector
	pipeline        *pipeline.Service
	scheduler       *scheduler.Scheduler
}

type Options struct {
	MarkRunningInterrupted   bool
	InterruptedJobTypes      []string
	InterruptedRestartReason string
}

func New(ctx context.Context, cfg config.Config) (*Runtime, error) {
	return NewWithOptions(ctx, cfg, Options{MarkRunningInterrupted: true})
}

func NewWithOptions(ctx context.Context, cfg config.Config, opts Options) (*Runtime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	storeDB, err := db.Open(ctx, cfg.Database)
	if err != nil {
		return nil, err
	}
	if storeDB.Enabled() && cfg.Database.AutoMigrate {
		if err := storeDB.Migrate(ctx); err != nil {
			storeDB.Close()
			return nil, err
		}
	}

	store := jobs.NewStore(200, storeDB)
	if len(opts.InterruptedJobTypes) > 0 {
		reason := opts.InterruptedRestartReason
		if reason == "" {
			reason = "interrupted by worker restart"
		}
		if err := store.MarkRunningInterruptedTypes(ctx, reason, opts.InterruptedJobTypes...); err != nil {
			storeDB.Close()
			return nil, err
		}
	} else if opts.MarkRunningInterrupted {
		if err := store.MarkRunningInterrupted(ctx, "interrupted by application restart"); err != nil {
			storeDB.Close()
			return nil, err
		}
	}
	rawFiles := pantheon.NewRawFileRepository(storeDB)
	collector := pantheon.NewCollector(cfg, store, rawFiles)
	segmentRepo := combiner.NewRepository(storeDB, cfg.RawDir(), cfg.CombinedDir())
	combinerService := combiner.NewService(cfg, segmentRepo)
	indexerService := indexer.NewService(storeDB)
	pipelineService := pipeline.New(cfg, store, combinerService, segmentRepo, indexerService)
	analyticsService := analytics.NewService(storeDB)
	accessAnalysisService := accessanalysis.NewService(storeDB)
	investigationService := investigation.NewService(storeDB)
	geoIPManager, geoIPUpdater := setupGeoIP(ctx, cfg)
	ipIntelService := ipintel.NewService(storeDB, geoIPManager)
	if cfg.IPAllowlist.Enabled {
		ipIntelService.SetAllowlist(cfg.IPAllowlist.Entries)
	}
	alertService := alerts.NewService(storeDB)
	backfillService := backfill.NewService(storeDB)
	reportService := reports.NewService(cfg, storeDB, analyticsService, accessAnalysisService, investigationService, alertService, backfillService)
	notificationService := notifications.NewService(cfg, storeDB)
	retentionService := retention.NewService(cfg, storeDB)
	archiveService := archive.NewService(cfg, storeDB)
	archiveCoverageService := archivecoverage.NewService(cfg, storeDB)
	archiveImportService := archiveimport.NewService(cfg, storeDB, indexerService)
	storageAuditService := storageaudit.NewService(cfg, storeDB)
	authService := auth.NewService(storeDB, cfg.Auth)
	siteRepo := sites.NewRepository(storeDB, cfg)
	if storeDB.Enabled() && cfg.Database.SeedConfigSites {
		if err := siteRepo.SeedFromConfig(ctx); err != nil {
			storeDB.Close()
			return nil, err
		}
	}
	if storeDB.Enabled() && cfg.IPAllowlist.Enabled {
		if err := ipIntelService.SeedAllowlist(ctx, cfg.IPAllowlist.Entries); err != nil {
			storeDB.Close()
			return nil, err
		}
	}

	return &Runtime{
		cfg:             cfg,
		db:              storeDB,
		auth:            authService,
		sites:           siteRepo,
		rawFiles:        rawFiles,
		combiner:        combinerService,
		segments:        segmentRepo,
		indexer:         indexerService,
		analytics:       analyticsService,
		accessAnalysis:  accessAnalysisService,
		investigation:   investigationService,
		ipIntel:         ipIntelService,
		geoIP:           geoIPManager,
		geoIPUpdater:    geoIPUpdater,
		alerts:          alertService,
		reports:         reportService,
		notifications:   notificationService,
		retention:       retentionService,
		archive:         archiveService,
		archiveCoverage: archiveCoverageService,
		archiveImport:   archiveImportService,
		backfill:        backfillService,
		storageAudit:    storageAuditService,
		jobs:            store,
		collector:       collector,
		pipeline:        pipelineService,
		scheduler:       scheduler.New(cfg, store, collector, pipelineService, alertService, ipIntelService, archiveService, retentionService, notificationService, reportService),
	}, nil
}

func (r *Runtime) RunServer(ctx context.Context) error {
	if r.geoIPUpdater != nil && r.geoIP != nil {
		go r.geoIPUpdater.Run(ctx, r.geoIP)
	}
	r.scheduler.Start(ctx)
	r.startStartupIntelBackfill(ctx)

	handler := httpapi.NewRouter(httpapi.Dependencies{
		Config:          r.cfg,
		DB:              r.db,
		Auth:            r.auth,
		Sites:           r.sites,
		RawFiles:        r.rawFiles,
		Combiner:        r.combiner,
		Segments:        r.segments,
		Indexer:         r.indexer,
		Analytics:       r.analytics,
		AccessAnalysis:  r.accessAnalysis,
		Investigation:   r.investigation,
		IPIntel:         r.ipIntel,
		GeoIP:           r.geoIP,
		GeoIPUpdater:    r.geoIPUpdater,
		Alerts:          r.alerts,
		Reports:         r.reports,
		Notifications:   r.notifications,
		Retention:       r.retention,
		Archive:         r.archive,
		ArchiveCoverage: r.archiveCoverage,
		ArchiveImport:   r.archiveImport,
		Backfill:        r.backfill,
		StorageAudit:    r.storageAudit,
		Jobs:            r.jobs,
		Collector:       r.collector,
		Pipeline:        r.pipeline,
	})

	server := &http.Server{
		Addr:              r.cfg.Server.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info().Str("addr", r.cfg.Server.Addr).Msg("originpulse server listening")
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		r.Close()
		return nil
	case err := <-errCh:
		r.Close()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (r *Runtime) RunAPI(ctx context.Context) error {
	if r.geoIPUpdater != nil && r.geoIP != nil {
		go r.geoIPUpdater.Run(ctx, r.geoIP)
	}
	handler := httpapi.NewRouter(httpapi.Dependencies{
		Config:          r.cfg,
		DB:              r.db,
		Auth:            r.auth,
		Sites:           r.sites,
		RawFiles:        r.rawFiles,
		Combiner:        r.combiner,
		Segments:        r.segments,
		Indexer:         r.indexer,
		Analytics:       r.analytics,
		AccessAnalysis:  r.accessAnalysis,
		Investigation:   r.investigation,
		IPIntel:         r.ipIntel,
		GeoIP:           r.geoIP,
		GeoIPUpdater:    r.geoIPUpdater,
		Alerts:          r.alerts,
		Reports:         r.reports,
		Notifications:   r.notifications,
		Retention:       r.retention,
		Archive:         r.archive,
		ArchiveCoverage: r.archiveCoverage,
		ArchiveImport:   r.archiveImport,
		Backfill:        r.backfill,
		StorageAudit:    r.storageAudit,
		Jobs:            r.jobs,
		Collector:       r.collector,
		Pipeline:        r.pipeline,
	})

	server := &http.Server{
		Addr:              r.cfg.Server.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info().Str("addr", r.cfg.Server.Addr).Msg("originpulse API listening")
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		r.Close()
		return nil
	case err := <-errCh:
		r.Close()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (r *Runtime) RunCollectorWorker(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = r.cfg.Collection.Interval
	}
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	if r.cfg.Retention.Enabled {
		go r.runPeriodic(ctx, "collector maintenance", r.cfg.Retention.Interval, false, func(ctx context.Context) error {
			if _, err := r.RunArchive(ctx, archive.Options{MaxGroups: 25, RemoveSources: true}); err != nil {
				return err
			}
			_, err := r.RunRetention(ctx, retention.Options{})
			return err
		})
	}
	return r.runPeriodic(ctx, "collector", interval, true, func(ctx context.Context) error {
		return r.CollectAndPipelineSitesOnce(ctx)
	})
}

func (r *Runtime) RunIngestWorker(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = time.Minute
	}
	r.startStartupIntelBackfill(ctx)
	go r.runIPIntelWorker(ctx)
	return r.runPeriodic(ctx, "ingest", interval, true, func(ctx context.Context) error {
		if _, err := r.RunPipeline(ctx, pipeline.Options{SkipCombine: true, SkipRollupRecovery: true, PreferRecent: true, TriggeredBy: "ingest-worker"}); err != nil {
			return err
		}
		if err := r.EvaluateAlertsAndNotify(ctx); err != nil {
			return err
		}
		return nil
	})
}

func (r *Runtime) RunReportsWorker(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = r.cfg.Reports.Interval
	}
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return r.runPeriodic(ctx, "reports", interval, false, func(ctx context.Context) error {
		_, err := r.GenerateScheduledReports(ctx)
		return err
	})
}

func (r *Runtime) runPeriodic(ctx context.Context, name string, interval time.Duration, immediate bool, fn func(context.Context) error) error {
	log.Info().Dur("interval", interval).Str("worker", name).Msg("worker started")
	if immediate {
		if err := fn(ctx); err != nil {
			log.Error().Err(err).Str("worker", name).Msg("worker cycle failed")
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Str("worker", name).Msg("worker stopped")
			return nil
		case <-ticker.C:
			if err := fn(ctx); err != nil {
				log.Error().Err(err).Str("worker", name).Msg("worker cycle failed")
			}
		}
	}
}

func (r *Runtime) startStartupIntelBackfill(ctx context.Context) {
	if r == nil || r.db == nil || !r.db.Enabled() || !r.cfg.IPIntel.Enabled || !r.cfg.IPIntel.StartupBackfill {
		return
	}
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
		job := r.jobs.Start(ctx, "startup_backfill_intel", "startup", map[string]any{
			"range":            r.cfg.IPIntel.StartupBackfillRange,
			"ip_limit":         r.cfg.IPIntel.StartupBackfillLimit,
			"user_agent_limit": r.cfg.IPIntel.StartupUserAgentLimit,
		})
		uaUpdated, err := r.backfill.ReclassifyUserAgents(ctx, r.cfg.IPIntel.StartupUserAgentLimit)
		if err != nil {
			r.jobs.Finish(job.ID, jobs.StatusFailed, "startup user-agent backfill failed", err)
			log.Error().Err(err).Msg("startup user-agent backfill failed")
			return
		}
		providers, providerErr := r.ipIntel.RefreshOfficialProviderRanges(ctx)
		providerMatches, err := r.ipIntel.BackfillProviderMatches(ctx, r.cfg.IPIntel.StartupBackfillRange, r.cfg.IPIntel.StartupBackfillLimit)
		if err != nil {
			r.jobs.Finish(job.ID, jobs.StatusFailed, "startup IP intel backfill failed", err)
			log.Error().Err(err).Msg("startup IP intel backfill failed")
			return
		}
		if providerErr != nil {
			log.Warn().
				Err(providerErr).
				Int("provider_ranges", providers.Ranges).
				Int("provider_failed", providers.Failed).
				Msg("startup provider range refresh completed with errors")
		}
		r.jobs.FinishWithMeta(job.ID, jobs.StatusSuccess, "startup intel backfill completed", nil, map[string]any{
			"user_agents_reclassified": uaUpdated,
			"provider_matched_ips":     providerMatches,
			"provider_ranges":          providers.Ranges,
			"provider_failed":          providers.Failed,
		})
		log.Info().
			Int64("user_agents_reclassified", uaUpdated).
			Int64("provider_matched_ips", providerMatches).
			Int("provider_ranges", providers.Ranges).
			Int("provider_failed", providers.Failed).
			Msg("startup intel backfill completed")
	}()
}

func (r *Runtime) CollectOnce(ctx context.Context) error {
	return r.collector.CollectAll(ctx)
}

func (r *Runtime) CollectAndPipelineSitesOnce(ctx context.Context) error {
	if r.collector == nil {
		return nil
	}
	sites := r.cfg.EnabledSites()
	if len(sites) == 0 {
		return r.CollectOnce(ctx)
	}
	workerCount := r.cfg.Collection.MaxParallelSites
	if workerCount <= 0 {
		workerCount = 1
	}
	sem := make(chan struct{}, workerCount)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex

	for _, site := range sites {
		for _, env := range site.Envs {
			site := site
			env := env
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}

				collectErr := r.collector.CollectSiteEnv(ctx, site, env, "collector-worker")
				<-sem
				if collectErr != nil {
					log.Error().Err(collectErr).Str("site_id", site.ID).Str("env", env).Msg("site collection failed")
					errMu.Lock()
					if firstErr == nil {
						firstErr = collectErr
					}
					errMu.Unlock()
				}
				if ctx.Err() != nil || r.pipeline == nil || !r.pipeline.Enabled() {
					return
				}
				pipelineResult, pipelineErr := r.pipeline.RunRecentWithOptions(ctx, "collector-worker", pipeline.Options{
					SiteID:             site.ID,
					Env:                env,
					SkipRollupRecovery: true,
				})
				if pipelineErr != nil {
					log.Error().
						Err(pipelineErr).
						Str("site_id", site.ID).
						Str("env", env).
						Int("combined_segments", pipelineResult.CombinedSegments).
						Int("indexed_segments", pipelineResult.IndexedSegments).
						Msg("site post-collection pipeline failed")
					errMu.Lock()
					if firstErr == nil {
						firstErr = pipelineErr
					}
					errMu.Unlock()
					return
				}
				log.Info().
					Str("site_id", site.ID).
					Str("env", env).
					Int("combined_segments", pipelineResult.CombinedSegments).
					Int("indexed_segments", pipelineResult.IndexedSegments).
					Msg("site post-collection pipeline completed")
			}()
		}
	}

	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

func (r *Runtime) CombineRecent(ctx context.Context, triggeredBy string) (pipeline.Result, error) {
	now := time.Now().UTC()
	settlingWindow := r.cfg.Combiner.SettlingWindow
	if settlingWindow <= 0 {
		settlingWindow = 5 * time.Minute
	}
	to := now.Add(-settlingWindow)
	from := to.Add(-45 * time.Minute)
	logTypes := append([]string(nil), r.cfg.Collection.LogTypes...)
	if len(logTypes) == 0 {
		logTypes = []string{"nginx-access"}
	}
	if strings.TrimSpace(triggeredBy) == "" {
		triggeredBy = "collector-worker"
	}
	job := r.jobs.Start(ctx, "combine_recent", triggeredBy, map[string]any{
		"from":              from.Format(time.RFC3339),
		"to":                to.Format(time.RFC3339),
		"all_source_events": true,
	})
	result := pipeline.Result{From: from, To: to, LogTypes: logTypes}
	for _, logType := range logTypes {
		logType = strings.TrimSpace(logType)
		if logType == "" {
			logType = "nginx-access"
		}
		combineResult, err := r.combiner.Combine(ctx, combiner.Options{
			LogType:         logType,
			From:            from,
			To:              to,
			AllSourceEvents: true,
		})
		if err != nil {
			r.jobs.Finish(job.ID, jobs.StatusFailed, "combine recent failed", err)
			return result, err
		}
		result.CombineResults = append(result.CombineResults, combineResult)
		result.CombinedSegments += combineResult.SegmentsWritten
		result.LinesCombined += combineResult.LinesCombined
		result.LinesQuarantined += combineResult.LinesQuarantined
	}
	r.jobs.FinishWithMeta(job.ID, jobs.StatusSuccess, "combine recent completed", nil, map[string]any{
		"combined_segments": result.CombinedSegments,
		"lines_combined":    result.LinesCombined,
		"lines_quarantined": result.LinesQuarantined,
	})
	return result, nil
}

func (r *Runtime) Combine(ctx context.Context, opts combiner.Options) (combiner.Result, error) {
	return r.combiner.Combine(ctx, opts)
}

func (r *Runtime) IndexSegment(ctx context.Context, opts indexer.Options) (indexer.Result, error) {
	return r.indexer.IndexSegment(ctx, opts)
}

func (r *Runtime) RunPipeline(ctx context.Context, opts pipeline.Options) (pipeline.Result, error) {
	return r.pipeline.Run(ctx, opts)
}

func (r *Runtime) RunRetention(ctx context.Context, opts retention.Options) (retention.Result, error) {
	return r.retention.Run(ctx, opts)
}

func (r *Runtime) RunArchive(ctx context.Context, opts archive.Options) (archive.Result, error) {
	return r.archive.Run(ctx, opts)
}

func (r *Runtime) ArchiveCoverage(ctx context.Context, opts archivecoverage.Options) (archivecoverage.Coverage, error) {
	return r.archiveCoverage.Coverage(ctx, opts)
}

func (r *Runtime) ImportArchive(ctx context.Context, opts archiveimport.Options) (archiveimport.Result, error) {
	return r.archiveImport.Import(ctx, opts)
}

type ArchiveSmokeResult struct {
	Fixture               archivefixture.Result `json:"fixture"`
	Import                archiveimport.Result  `json:"import"`
	Retention             retention.Result      `json:"retention"`
	TemporaryEventsBefore int                   `json:"temporary_events_before"`
	TemporaryEventsAfter  int                   `json:"temporary_events_after"`
	TemporaryImportsAfter int                   `json:"temporary_imports_after"`
}

type ArchiveCompactionSmokeResult struct {
	Fixture              archivefixture.CompactionResult `json:"fixture"`
	Archive              archive.Result                  `json:"archive"`
	WeeklyArchiveID      string                          `json:"weekly_archive_id"`
	WeeklyArchivePath    string                          `json:"weekly_archive_path"`
	WeeklyArchiveMembers int                             `json:"weekly_archive_members"`
	DailyArchivesAfter   int                             `json:"daily_archives_after"`
}

type ArchiveCoverageSmokeResult struct {
	Fixture               archivefixture.CompactionResult `json:"fixture"`
	Archive               archive.Result                  `json:"archive"`
	CoverageBeforeImport  archivecoverage.Coverage        `json:"coverage_before_import"`
	Import                archiveimport.Result            `json:"import"`
	CoverageAfterImport   archivecoverage.Coverage        `json:"coverage_after_import"`
	Retention             retention.Result                `json:"retention"`
	TemporaryEventsAfter  int                             `json:"temporary_events_after"`
	TemporaryImportsAfter int                             `json:"temporary_imports_after"`
}

func (r *Runtime) RunArchiveCoverageSmoke(ctx context.Context) (ArchiveCoverageSmokeResult, error) {
	pool, err := r.db.Pool()
	if err != nil {
		return ArchiveCoverageSmokeResult{}, err
	}
	fixture, err := archivefixture.CreateCompactionSet(ctx, r.cfg, pool)
	if err != nil {
		return ArchiveCoverageSmokeResult{}, err
	}
	result := ArchiveCoverageSmokeResult{Fixture: fixture}
	defer func() {
		_ = archivefixture.CleanupCompactionSet(context.Background(), pool, fixture)
	}()

	archiveResult, err := r.archive.Run(ctx, archive.Options{LogType: fixture.LogType, MaxGroups: 1})
	if err != nil {
		return result, err
	}
	result.Archive = archiveResult
	coverageNow := fixture.WeekEnd.Add(180 * 24 * time.Hour)

	coverageBefore, err := r.archiveCoverage.Coverage(ctx, archivecoverage.Options{
		From: fixture.WeekStart,
		To:   fixture.WeekEnd,
		Now:  coverageNow,
	})
	if err != nil {
		return result, err
	}
	result.CoverageBeforeImport = coverageBefore
	if !coverageBefore.ImportRecommended || coverageBefore.SelectedArchiveCount != 1 || len(coverageBefore.Archives) != 1 || coverageBefore.Archives[0].Granularity != "weekly" {
		selectedGranularity := ""
		if len(coverageBefore.Archives) > 0 {
			selectedGranularity = coverageBefore.Archives[0].Granularity
		}
		return result, fmt.Errorf("archive coverage smoke expected exactly one selected weekly archive: groups=%d written=%d weekly=%d skipped=%d recommended=%t available=%d selected=%d selected_len=%d selected_granularity=%q ratio=%.4f",
			archiveResult.GroupsMatched,
			archiveResult.ArchivesWritten,
			archiveResult.WeeklyArchivesWritten,
			archiveResult.SkippedExisting,
			coverageBefore.ImportRecommended,
			coverageBefore.AvailableArchiveCount,
			coverageBefore.SelectedArchiveCount,
			len(coverageBefore.Archives),
			selectedGranularity,
			coverageBefore.ArchiveCoverageRatio,
		)
	}

	importResult, err := r.archiveImport.Import(ctx, archiveimport.Options{
		ArchiveID: coverageBefore.Archives[0].ID,
		Reason:    "archive coverage smoke verification",
	})
	if err != nil {
		return result, err
	}
	result.Import = importResult

	coverageAfter, err := r.archiveCoverage.Coverage(ctx, archivecoverage.Options{
		From: fixture.WeekStart,
		To:   fixture.WeekEnd,
		Now:  coverageNow,
	})
	if err != nil {
		return result, err
	}
	result.CoverageAfterImport = coverageAfter
	if !coverageAfter.AlreadyImported || coverageAfter.ImportRecommended {
		return result, errors.New("archive coverage smoke expected active temporary import coverage")
	}

	if _, err := pool.Exec(ctx, `UPDATE temporary_imports SET expires_at = now() - interval '1 second' WHERE id = $1::uuid`, importResult.TemporaryImportID); err != nil {
		return result, err
	}
	retentionResult, err := r.retention.Run(ctx, retention.Options{TemporaryImportsOnly: true})
	if err != nil {
		return result, err
	}
	result.Retention = retentionResult
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM access_events WHERE temporary_import_id = $1::uuid`, importResult.TemporaryImportID).Scan(&result.TemporaryEventsAfter); err != nil {
		return result, err
	}
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM temporary_imports WHERE id = $1::uuid`, importResult.TemporaryImportID).Scan(&result.TemporaryImportsAfter); err != nil {
		return result, err
	}
	return result, nil
}

func (r *Runtime) RunArchiveCompactionSmoke(ctx context.Context) (ArchiveCompactionSmokeResult, error) {
	pool, err := r.db.Pool()
	if err != nil {
		return ArchiveCompactionSmokeResult{}, err
	}
	fixture, err := archivefixture.CreateCompactionSet(ctx, r.cfg, pool)
	if err != nil {
		return ArchiveCompactionSmokeResult{}, err
	}
	result := ArchiveCompactionSmokeResult{Fixture: fixture}
	defer func() {
		_ = archivefixture.CleanupCompactionSet(context.Background(), pool, fixture)
	}()
	archiveResult, err := r.archive.Run(ctx, archive.Options{LogType: fixture.LogType, MaxGroups: 1, RemoveSources: true})
	if err != nil {
		return result, err
	}
	result.Archive = archiveResult
	if err := pool.QueryRow(ctx, `
SELECT id::text, path
FROM log_archives
WHERE log_type = $1
  AND granularity = 'weekly'
  AND range_start = $2
  AND status = 'ready'`, fixture.LogType, fixture.WeekStart).Scan(&result.WeeklyArchiveID, &result.WeeklyArchivePath); err != nil {
		return result, err
	}
	members, err := archivefixture.CountArchiveMembers(result.WeeklyArchivePath)
	if err != nil {
		return result, err
	}
	result.WeeklyArchiveMembers = members
	if err := pool.QueryRow(ctx, `
SELECT count(*)::int
FROM log_archives
WHERE id = ANY($1::uuid[])`, fixture.DailyArchiveIDs).Scan(&result.DailyArchivesAfter); err != nil {
		return result, err
	}
	return result, nil
}

func (r *Runtime) RunArchiveSmoke(ctx context.Context, limit int) (ArchiveSmokeResult, error) {
	pool, err := r.db.Pool()
	if err != nil {
		return ArchiveSmokeResult{}, err
	}
	fixture, err := archivefixture.Create(ctx, r.cfg, pool, archivefixture.Options{Limit: limit})
	if err != nil {
		return ArchiveSmokeResult{}, err
	}
	result := ArchiveSmokeResult{Fixture: fixture}
	defer func() {
		_ = archivefixture.Cleanup(context.Background(), pool, fixture)
	}()

	importResult, err := r.archiveImport.Import(ctx, archiveimport.Options{
		ArchiveID: fixture.ArchiveID,
		Reason:    "archive smoke verification",
	})
	if err != nil {
		return result, err
	}
	result.Import = importResult
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM access_events WHERE temporary_import_id = $1::uuid`, importResult.TemporaryImportID).Scan(&result.TemporaryEventsBefore); err != nil {
		return result, err
	}
	if _, err := pool.Exec(ctx, `UPDATE temporary_imports SET expires_at = now() - interval '1 second' WHERE id = $1::uuid`, importResult.TemporaryImportID); err != nil {
		return result, err
	}
	retentionResult, err := r.retention.Run(ctx, retention.Options{TemporaryImportsOnly: true})
	if err != nil {
		return result, err
	}
	result.Retention = retentionResult
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM access_events WHERE temporary_import_id = $1::uuid`, importResult.TemporaryImportID).Scan(&result.TemporaryEventsAfter); err != nil {
		return result, err
	}
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM temporary_imports WHERE id = $1::uuid`, importResult.TemporaryImportID).Scan(&result.TemporaryImportsAfter); err != nil {
		return result, err
	}
	return result, nil
}

func (r *Runtime) RunBackfill(ctx context.Context, opts backfill.Options) (backfill.Result, error) {
	return r.backfill.Run(ctx, opts)
}

func (r *Runtime) RebuildRollups(ctx context.Context, from time.Time, to time.Time) (time.Time, time.Time, int, error) {
	return r.rebuildRollups(ctx, from, to, 6*time.Hour, rollups.Rebuild)
}

func (r *Runtime) RebuildStatusRollups(ctx context.Context, from time.Time, to time.Time) (time.Time, time.Time, int, error) {
	return r.rebuildRollups(ctx, from, to, 0, rollups.RebuildStatus)
}

func (r *Runtime) rebuildRollups(ctx context.Context, from time.Time, to time.Time, chunk time.Duration, rebuild func(context.Context, *pgxpool.Pool, time.Time, time.Time) (int, error)) (time.Time, time.Time, int, error) {
	if r.db == nil || !r.db.Enabled() {
		return time.Time{}, time.Time{}, 0, db.ErrUnavailable
	}
	pool, err := r.db.Pool()
	if err != nil {
		return time.Time{}, time.Time{}, 0, err
	}
	if from.IsZero() || to.IsZero() {
		if err := pool.QueryRow(ctx, `SELECT min(ts), max(ts) FROM access_events`).Scan(&from, &to); err != nil {
			return time.Time{}, time.Time{}, 0, err
		}
	}
	if from.IsZero() || to.IsZero() || !to.After(from) {
		return from, to, 0, nil
	}
	start := from.UTC().Truncate(time.Hour)
	end := to.UTC().Truncate(time.Hour).Add(time.Hour)
	if chunk <= 0 {
		rows, err := rebuild(ctx, pool, start, end)
		return start, end, rows, err
	}
	total := 0
	for chunkStart := start; chunkStart.Before(end); chunkStart = chunkStart.Add(chunk) {
		chunkEnd := chunkStart.Add(chunk)
		if chunkEnd.After(end) {
			chunkEnd = end
		}
		rows, err := rebuild(ctx, pool, chunkStart, chunkEnd)
		if err != nil {
			return start, end, total, err
		}
		total += rows
	}
	return start, end, total, nil
}

func (r *Runtime) StorageAudit(ctx context.Context) (storageaudit.Report, error) {
	return r.storageAudit.Audit(ctx)
}

func (r *Runtime) EvaluateAlerts(ctx context.Context, opts alerts.Options) (alerts.Result, error) {
	return r.alerts.Evaluate(ctx, opts)
}

func (r *Runtime) AlertDetail(ctx context.Context, id string, limit int) (alerts.Detail, error) {
	return r.alerts.Get(ctx, id, limit)
}

func (r *Runtime) AnalyzeAccess(ctx context.Context, opts accessanalysis.Options) (accessanalysis.Report, error) {
	return r.accessAnalysis.Analyze(ctx, opts)
}

func (r *Runtime) InvestigateTraffic(ctx context.Context, opts investigation.Options) (investigation.Traffic, error) {
	return r.investigation.Traffic(ctx, opts)
}

func (r *Runtime) RecentReports(ctx context.Context, limit int, siteID string) ([]reports.Report, error) {
	return r.reports.Recent(ctx, limit, siteID)
}

func (r *Runtime) GenerateReport(ctx context.Context, opts reports.Options) (reports.Report, error) {
	return r.reports.Generate(ctx, opts)
}

func (r *Runtime) GenerateScheduledReports(ctx context.Context) (int, error) {
	if r.reports == nil || !r.cfg.Reports.Enabled {
		return 0, nil
	}
	job := r.jobs.Start(ctx, "generate_llm_reports", "reports-worker", map[string]any{"ranges": strings.Join(r.cfg.Reports.Ranges, ",")})
	generated := 0
	for _, reportRange := range r.cfg.Reports.Ranges {
		reportRange = strings.TrimSpace(reportRange)
		if reportRange == "" {
			continue
		}
		if _, err := r.reports.Generate(ctx, reports.Options{Range: reportRange}); err != nil {
			r.jobs.Finish(job.ID, jobs.StatusFailed, "LLM report generation failed", err)
			return generated, err
		}
		generated++
	}
	r.jobs.FinishWithMeta(job.ID, jobs.StatusSuccess, "LLM reports generated", nil, map[string]any{"generated": generated})
	log.Info().Int("generated", generated).Msg("scheduled LLM reports generated")
	return generated, nil
}

func (r *Runtime) EvaluateAlertsAndNotify(ctx context.Context) error {
	if r.alerts == nil || !r.alerts.Enabled() {
		return nil
	}
	job := r.jobs.Start(ctx, "evaluate_alerts", "ingest-worker", map[string]any{"range": "24h"})
	result, err := r.alerts.Evaluate(ctx, alerts.Options{Range: "24h", Limit: 200})
	if err != nil {
		r.jobs.Finish(job.ID, jobs.StatusFailed, "alert evaluation failed", err)
		return err
	}
	r.jobs.FinishWithMeta(job.ID, jobs.StatusSuccess, "alert evaluation completed", nil, map[string]any{
		"evaluated": result.Evaluated,
		"upserted":  result.Upserted,
	})
	if r.notifications == nil || !r.cfg.Notifications.Enabled {
		return nil
	}
	notifyJob := r.jobs.Start(ctx, "send_notifications", "ingest-worker", map[string]any{"min_severity": r.cfg.Notifications.MinSeverity})
	notifyResult, err := r.notifications.NotifyOpenAlerts(ctx, 100)
	if err != nil {
		r.jobs.Finish(notifyJob.ID, jobs.StatusFailed, "notifications failed", err)
		return err
	}
	r.jobs.FinishWithMeta(notifyJob.ID, jobs.StatusSuccess, "notifications completed", nil, map[string]any{
		"evaluated": notifyResult.Evaluated,
		"sent":      notifyResult.Sent,
		"skipped":   notifyResult.Skipped,
		"failed":    notifyResult.Failed,
	})
	return nil
}

func (r *Runtime) runIPIntelWorker(ctx context.Context) {
	if r.ipIntel == nil || !r.ipIntel.Enabled() || !r.cfg.IPIntel.Enabled {
		return
	}
	interval := r.cfg.IPIntel.Interval
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	_ = r.runPeriodic(ctx, "ip-intel", interval, true, func(ctx context.Context) error {
		limit := r.cfg.IPIntel.Limit
		if limit <= 0 {
			limit = ipintel.ResultMaxLimit
		}
		refreshRange := strings.TrimSpace(r.cfg.IPIntel.Range)
		if refreshRange == "" {
			refreshRange = "24h"
		}
		job := r.jobs.Start(ctx, "refresh_ip_intel", "ingest-worker", map[string]any{"range": refreshRange, "limit": limit})
		providers, providerErr := r.ipIntel.RefreshOfficialProviderRanges(ctx)
		result, err := r.ipIntel.RefreshTop(ctx, ipintel.Options{Range: refreshRange, Limit: limit})
		if err != nil {
			r.jobs.Finish(job.ID, jobs.StatusFailed, "IP intelligence refresh failed", err)
			return err
		}
		if providerErr != nil {
			log.Warn().Err(providerErr).Int("provider_ranges", providers.Ranges).Int("provider_failed", providers.Failed).Msg("provider range refresh completed with errors")
		}
		r.jobs.FinishWithMeta(job.ID, jobs.StatusSuccess, "IP intelligence refresh completed", nil, map[string]any{
			"refreshed":          result.Refreshed,
			"failed":             result.Failed,
			"lookup_failed":      result.LookupFailed,
			"geoip_failed":       result.GeoIPFailed,
			"reverse_dns_failed": result.ReverseDNSFailed,
			"providers":          providers.Providers,
			"provider_ranges":    providers.Ranges,
			"provider_failed":    providers.Failed,
		})
		return nil
	})
}

func (r *Runtime) ReportDetail(ctx context.Context, id string) (reports.Report, error) {
	return r.reports.Get(ctx, id)
}

func (r *Runtime) ReportFastReadAudit(ctx context.Context, opts reports.FastReadAuditOptions) (reports.FastReadAudit, error) {
	return r.reports.FastReadAudit(ctx, opts)
}

func (r *Runtime) IPDetails(ctx context.Context, opts ipintel.DetailOptions) (ipintel.Detail, error) {
	return r.ipIntel.Details(ctx, opts)
}

func (r *Runtime) RefreshIPIntel(ctx context.Context, opts ipintel.Options) (ipintel.Result, error) {
	return r.ipIntel.RefreshTop(ctx, opts)
}

func (r *Runtime) Migrate(ctx context.Context) error {
	if r.db == nil || !r.db.Enabled() {
		return db.ErrUnavailable
	}
	return r.db.Migrate(ctx)
}

func (r *Runtime) CreateUser(ctx context.Context, email string, password string, displayName string) (auth.User, error) {
	return r.auth.CreateUser(ctx, email, password, displayName)
}

func (r *Runtime) Close() {
	if r.geoIP != nil {
		r.geoIP.Close()
	}
	if r.db != nil {
		r.db.Close()
	}
}

func setupGeoIP(ctx context.Context, cfg config.Config) (*geoip.Manager, *geoip.Updater) {
	if !cfg.GeoIP.Enabled {
		return nil, nil
	}

	manager := geoip.NewManager(cfg.GeoIPDBPath())
	updater := geoip.NewUpdater(geoip.UpdaterConfig{
		DBPath:           cfg.GeoIPDBPath(),
		SeedPath:         cfg.GeoIPSeedPath(),
		DownloadURL:      cfg.GeoIPDownloadURL(),
		AccountID:        cfg.GeoIPAccountID(),
		LicenseKey:       cfg.GeoIPLicenseKey(),
		Interval:         cfg.GeoIP.UpdateInterval,
		LastModifiedPath: cfg.GeoIPLastModifiedPath(),
		HTTPTimeout:      cfg.GeoIP.DownloadTimeout,
	})
	if err := updater.EnsureAndLoad(ctx, manager); err != nil {
		log.Warn().Err(err).Str("db_path", cfg.GeoIPDBPath()).Msg("geoip database unavailable")
		return manager, updater
	}
	log.Info().Str("db_path", cfg.GeoIPDBPath()).Msg("geoip database loaded")
	return manager, updater
}
