package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"originpulse/internal/accessanalysis"
	"originpulse/internal/alerts"
	"originpulse/internal/analytics"
	"originpulse/internal/auth"
	"originpulse/internal/combiner"
	"originpulse/internal/config"
	"originpulse/internal/db"
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
	"originpulse/internal/scheduler"
	"originpulse/internal/sites"
)

type Runtime struct {
	cfg            config.Config
	db             *db.Store
	auth           *auth.Service
	sites          *sites.Repository
	rawFiles       *pantheon.RawFileRepository
	combiner       *combiner.Service
	segments       *combiner.Repository
	indexer        *indexer.Service
	analytics      *analytics.Service
	accessAnalysis *accessanalysis.Service
	investigation  *investigation.Service
	ipIntel        *ipintel.Service
	alerts         *alerts.Service
	reports        *reports.Service
	notifications  *notifications.Service
	retention      *retention.Service
	jobs           *jobs.Store
	collector      *pantheon.Collector
	pipeline       *pipeline.Service
	scheduler      *scheduler.Scheduler
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

	store := jobs.NewStore(200)
	rawFiles := pantheon.NewRawFileRepository(storeDB)
	collector := pantheon.NewCollector(cfg, store, rawFiles)
	segmentRepo := combiner.NewRepository(storeDB)
	combinerService := combiner.NewService(cfg, segmentRepo)
	indexerService := indexer.NewService(storeDB)
	pipelineService := pipeline.New(cfg, store, combinerService, segmentRepo, indexerService)
	analyticsService := analytics.NewService(storeDB)
	accessAnalysisService := accessanalysis.NewService(storeDB)
	investigationService := investigation.NewService(storeDB)
	ipIntelService := ipintel.NewService(storeDB)
	alertService := alerts.NewService(storeDB)
	reportService := reports.NewService(cfg, storeDB, analyticsService, accessAnalysisService, investigationService, alertService)
	notificationService := notifications.NewService(cfg, storeDB)
	retentionService := retention.NewService(cfg, storeDB)
	authService := auth.NewService(storeDB, cfg.Auth)
	siteRepo := sites.NewRepository(storeDB, cfg)
	if storeDB.Enabled() && cfg.Database.SeedConfigSites {
		if err := siteRepo.SeedFromConfig(ctx); err != nil {
			storeDB.Close()
			return nil, err
		}
	}

	return &Runtime{
		cfg:            cfg,
		db:             storeDB,
		auth:           authService,
		sites:          siteRepo,
		rawFiles:       rawFiles,
		combiner:       combinerService,
		segments:       segmentRepo,
		indexer:        indexerService,
		analytics:      analyticsService,
		accessAnalysis: accessAnalysisService,
		investigation:  investigationService,
		ipIntel:        ipIntelService,
		alerts:         alertService,
		reports:        reportService,
		notifications:  notificationService,
		retention:      retentionService,
		jobs:           store,
		collector:      collector,
		pipeline:       pipelineService,
		scheduler:      scheduler.New(cfg, store, collector, pipelineService, alertService, ipIntelService, retentionService, notificationService, reportService),
	}, nil
}

func (r *Runtime) RunServer(ctx context.Context) error {
	r.scheduler.Start(ctx)

	handler := httpapi.NewRouter(httpapi.Dependencies{
		Config:         r.cfg,
		DB:             r.db,
		Auth:           r.auth,
		Sites:          r.sites,
		RawFiles:       r.rawFiles,
		Combiner:       r.combiner,
		Segments:       r.segments,
		Indexer:        r.indexer,
		Analytics:      r.analytics,
		AccessAnalysis: r.accessAnalysis,
		Investigation:  r.investigation,
		IPIntel:        r.ipIntel,
		Alerts:         r.alerts,
		Reports:        r.reports,
		Notifications:  r.notifications,
		Retention:      r.retention,
		Jobs:           r.jobs,
		Collector:      r.collector,
		Pipeline:       r.pipeline,
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
	if r.db != nil {
		r.db.Close()
	}
}
