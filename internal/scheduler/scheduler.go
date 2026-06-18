package scheduler

import (
	"context"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"originpulse/internal/alerts"
	"originpulse/internal/config"
	"originpulse/internal/ipintel"
	"originpulse/internal/jobs"
	"originpulse/internal/notifications"
	"originpulse/internal/pantheon"
	"originpulse/internal/pipeline"
	"originpulse/internal/reports"
	"originpulse/internal/retention"
)

type Scheduler struct {
	cfg           config.Config
	jobs          *jobs.Store
	collector     *pantheon.Collector
	pipeline      *pipeline.Service
	alerts        *alerts.Service
	ipIntel       *ipintel.Service
	retention     *retention.Service
	notifications *notifications.Service
	reports       *reports.Service
}

func New(cfg config.Config, store *jobs.Store, collector *pantheon.Collector, pipelineService *pipeline.Service, alerts *alerts.Service, ipIntel *ipintel.Service, retentionService *retention.Service, notificationService *notifications.Service, reportService *reports.Service) *Scheduler {
	return &Scheduler{cfg: cfg, jobs: store, collector: collector, pipeline: pipelineService, alerts: alerts, ipIntel: ipIntel, retention: retentionService, notifications: notificationService, reports: reportService}
}

func (s *Scheduler) Start(ctx context.Context) {
	go s.loop(ctx)
}

func (s *Scheduler) loop(ctx context.Context) {
	log.Info().
		Dur("collection_interval", s.cfg.Collection.Interval).
		Bool("collection_enabled", s.cfg.Collection.Enabled).
		Dur("retention_interval", s.cfg.Retention.Interval).
		Bool("retention_enabled", s.cfg.Retention.Enabled).
		Dur("reports_interval", s.cfg.Reports.Interval).
		Bool("reports_enabled", s.cfg.Reports.Enabled).
		Msg("background scheduler started")

	ticker := time.NewTicker(s.cfg.Collection.Interval)
	defer ticker.Stop()
	retentionTicker := time.NewTicker(s.cfg.Retention.Interval)
	defer retentionTicker.Stop()
	reportTicker := time.NewTicker(s.cfg.Reports.Interval)
	defer reportTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("background scheduler stopped")
			return
		case <-ticker.C:
			if err := s.collector.CollectAll(ctx); err != nil {
				log.Error().Err(err).Msg("scheduled collection completed with errors")
			}
			s.runPipeline(ctx)
			s.evaluateAlerts(ctx)
			s.refreshIPIntel(ctx)
		case <-retentionTicker.C:
			s.runRetention(ctx)
		case <-reportTicker.C:
			s.runReports(ctx)
		}
	}
}

func (s *Scheduler) runPipeline(ctx context.Context) {
	if s.pipeline == nil || !s.pipeline.Enabled() {
		return
	}
	result, err := s.pipeline.RunRecent(ctx, "scheduler")
	if err != nil {
		log.Error().Err(err).Msg("scheduled pipeline failed")
		return
	}
	log.Info().
		Int("combined_segments", result.CombinedSegments).
		Int("indexed_segments", result.IndexedSegments).
		Int("events_inserted", result.EventsInserted).
		Msg("scheduled pipeline completed")
}

func (s *Scheduler) evaluateAlerts(ctx context.Context) {
	if s.alerts == nil || !s.alerts.Enabled() {
		return
	}
	job := s.jobs.Start(ctx, "evaluate_alerts", "scheduler", map[string]string{"range": "24h"})
	result, err := s.alerts.Evaluate(ctx, alerts.Options{Range: "24h", Limit: 200})
	if err != nil {
		s.jobs.Finish(job.ID, jobs.StatusFailed, "alert evaluation failed", err)
		return
	}
	s.jobs.Finish(job.ID, jobs.StatusSuccess, "alert evaluation completed", nil)
	log.Info().
		Int("evaluated", result.Evaluated).
		Int("upserted", result.Upserted).
		Msg("scheduled alert evaluation completed")
	s.sendNotifications(ctx)
}

func (s *Scheduler) refreshIPIntel(ctx context.Context) {
	if s.ipIntel == nil || !s.ipIntel.Enabled() {
		return
	}
	job := s.jobs.Start(ctx, "refresh_ip_intel", "scheduler", map[string]string{"range": "24h"})
	result, err := s.ipIntel.RefreshTop(ctx, ipintel.Options{Range: "24h", Limit: 50})
	if err != nil {
		s.jobs.Finish(job.ID, jobs.StatusFailed, "IP intelligence refresh failed", err)
		return
	}
	s.jobs.Finish(job.ID, jobs.StatusSuccess, "IP intelligence refresh completed", nil)
	log.Info().
		Int("refreshed", result.Refreshed).
		Int("failed", result.Failed).
		Msg("scheduled IP intelligence refresh completed")
}

func (s *Scheduler) runRetention(ctx context.Context) {
	if s.retention == nil || !s.cfg.Retention.Enabled {
		return
	}
	job := s.jobs.Start(ctx, "retention", "scheduler", map[string]string{"max_age": s.cfg.Retention.MaxAge.String()})
	result, err := s.retention.Run(ctx, retention.Options{})
	if err != nil {
		s.jobs.Finish(job.ID, jobs.StatusFailed, "retention failed", err)
		log.Error().Err(err).Msg("scheduled retention failed")
		return
	}
	s.jobs.Finish(job.ID, jobs.StatusSuccess, "retention completed", nil)
	log.Info().
		Int("access_events_deleted", result.AccessEventsDeleted).
		Int("rollups_deleted", result.RollupsDeleted).
		Int("combined_segments_deleted", result.CombinedSegmentsDeleted).
		Int("raw_files_deleted", result.RawFilesDeleted).
		Msg("scheduled retention completed")
}

func (s *Scheduler) sendNotifications(ctx context.Context) {
	if s.notifications == nil || !s.cfg.Notifications.Enabled {
		return
	}
	job := s.jobs.Start(ctx, "send_notifications", "scheduler", map[string]string{"min_severity": s.cfg.Notifications.MinSeverity})
	result, err := s.notifications.NotifyOpenAlerts(ctx, 100)
	if err != nil {
		s.jobs.Finish(job.ID, jobs.StatusFailed, "notifications failed", err)
		log.Error().Err(err).Msg("scheduled notifications failed")
		return
	}
	s.jobs.Finish(job.ID, jobs.StatusSuccess, "notifications completed", nil)
	log.Info().
		Int("evaluated", result.Evaluated).
		Int("sent", result.Sent).
		Int("skipped", result.Skipped).
		Int("failed", result.Failed).
		Msg("scheduled notifications completed")
}

func (s *Scheduler) runReports(ctx context.Context) {
	if s.reports == nil || !s.cfg.Reports.Enabled {
		return
	}
	job := s.jobs.Start(ctx, "generate_llm_reports", "scheduler", map[string]string{"ranges": strings.Join(s.cfg.Reports.Ranges, ",")})
	generated := 0
	for _, reportRange := range s.cfg.Reports.Ranges {
		reportRange = strings.TrimSpace(reportRange)
		if reportRange == "" {
			continue
		}
		if _, err := s.reports.Generate(ctx, reports.Options{Range: reportRange}); err != nil {
			s.jobs.Finish(job.ID, jobs.StatusFailed, "LLM report generation failed", err)
			log.Error().Err(err).Str("range", reportRange).Msg("scheduled LLM report generation failed")
			return
		}
		generated++
	}
	s.jobs.Finish(job.ID, jobs.StatusSuccess, "LLM reports generated", nil)
	log.Info().Int("generated", generated).Msg("scheduled LLM reports generated")
}
