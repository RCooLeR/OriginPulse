package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

func New(ctx context.Context, cfg config.Config) (*Runtime, error) {
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
	rawFiles := pantheon.NewRawFileRepository(storeDB)
	collector := pantheon.NewCollector(cfg, store, rawFiles)
	segmentRepo := combiner.NewRepository(storeDB)
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

func (r *Runtime) CollectOnce(ctx context.Context) error {
	return r.collector.CollectAll(ctx)
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

func (r *Runtime) RecentReports(ctx context.Context, limit int, siteID string) ([]reports.Report, error) {
	return r.reports.Recent(ctx, limit, siteID)
}

func (r *Runtime) GenerateReport(ctx context.Context, opts reports.Options) (reports.Report, error) {
	return r.reports.Generate(ctx, opts)
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
