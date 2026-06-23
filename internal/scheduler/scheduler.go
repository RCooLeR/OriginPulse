package scheduler

import (
	"context"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"originpulse/internal/alerts"
	"originpulse/internal/archive"
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
	archive       *archive.Service
	retention     *retention.Service
	notifications *notifications.Service
	reports       *reports.Service
}

func New(cfg config.Config, store *jobs.Store, collector *pantheon.Collector, pipelineService *pipeline.Service, alerts *alerts.Service, ipIntel *ipintel.Service, archiveService *archive.Service, retentionService *retention.Service, notificationService *notifications.Service, reportService *reports.Service) *Scheduler {
	return &Scheduler{cfg: cfg, jobs: store, collector: collector, pipeline: pipelineService, alerts: alerts, ipIntel: ipIntel, archive: archiveService, retention: retentionService, notifications: notificationService, reports: reportService}
}

func (s *Scheduler) Start(ctx context.Context) {
	go s.loop(ctx)
	go s.ipIntelLoop(ctx)
}

func (s *Scheduler) loop(ctx context.Context) {
	log.Info().
		Dur("collection_interval", s.cfg.Collection.Interval).
		Bool("collection_enabled", s.cfg.Collection.Enabled).
		Dur("retention_interval", s.cfg.Retention.Interval).
		Bool("retention_enabled", s.cfg.Retention.Enabled).
		Dur("reports_interval", s.cfg.Reports.Interval).
		Bool("reports_enabled", s.cfg.Reports.Enabled).
		Dur("ip_intel_interval", s.cfg.IPIntel.Interval).
		Bool("ip_intel_enabled", s.cfg.IPIntel.Enabled).
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
		case <-retentionTicker.C:
			s.runArchive(ctx)
			s.runRetention(ctx)
		case <-reportTicker.C:
			s.runReports(ctx)
		}
	}
}

func (s *Scheduler) ipIntelLoop(ctx context.Context) {
	if s.ipIntel == nil || !s.ipIntel.Enabled() || !s.cfg.IPIntel.Enabled {
		return
	}
	log.Info().
		Dur("interval", s.cfg.IPIntel.Interval).
		Str("range", s.ipIntelRange()).
		Int("limit", s.ipIntelLimit()).
		Msg("IP intelligence background refresh started")

	s.refreshIPIntel(ctx)

	ticker := time.NewTicker(s.cfg.IPIntel.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("IP intelligence background refresh stopped")
			return
		case <-ticker.C:
			s.refreshIPIntel(ctx)
		}
	}
}

func (s *Scheduler) runArchive(ctx context.Context) {
	if s.archive == nil || !s.archive.Enabled() || !s.cfg.Retention.Enabled {
		return
	}
	job := s.jobs.Start(ctx, "archive_logs", "scheduler", map[string]any{"daily_after": s.cfg.Retention.DailyArchiveAfter.String(), "weekly_after": s.cfg.Retention.WeeklyArchiveAfter.String()})
	result, err := s.archive.Run(ctx, archive.Options{MaxGroups: 25, RemoveSources: true})
	if err != nil {
		s.jobs.Finish(job.ID, jobs.StatusFailed, "archive failed", err)
		log.Error().Err(err).Msg("scheduled archive failed")
		return
	}
	s.jobs.FinishWithMeta(job.ID, jobs.StatusSuccess, "archive completed", nil, map[string]any{
		"archives_written":     result.ArchivesWritten,
		"files_archived":       result.FilesArchived,
		"source_files_deleted": result.SourceFilesDeleted,
		"source_bytes":         result.SourceBytes,
		"compressed_bytes":     result.CompressedBytes,
	})
	log.Info().
		Int("archives_written", result.ArchivesWritten).
		Int("files_archived", result.FilesArchived).
		Int("source_files_deleted", result.SourceFilesDeleted).
		Int64("source_bytes", result.SourceBytes).
		Int64("compressed_bytes", result.CompressedBytes).
		Msg("scheduled archive completed")
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
		Int("log_events_inserted", result.LogEventsInserted).
		Int("rollups_repaired", result.RollupsRepaired).
		Int("security_probes", result.SecurityProbes).
		Int("error_events", result.ErrorEvents).
		Int("slow_request_events", result.SlowRequests).
		Msg("scheduled pipeline completed")
}

func (s *Scheduler) evaluateAlerts(ctx context.Context) {
	if s.alerts == nil || !s.alerts.Enabled() {
		return
	}
	job := s.jobs.Start(ctx, "evaluate_alerts", "scheduler", map[string]any{"range": "24h"})
	result, err := s.alerts.Evaluate(ctx, alerts.Options{Range: "24h", Limit: 200})
	if err != nil {
		s.jobs.Finish(job.ID, jobs.StatusFailed, "alert evaluation failed", err)
		return
	}
	s.jobs.FinishWithMeta(job.ID, jobs.StatusSuccess, "alert evaluation completed", nil, map[string]any{
		"evaluated": result.Evaluated,
		"upserted":  result.Upserted,
	})
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
	refreshRange := s.ipIntelRange()
	limit := s.ipIntelLimit()
	job := s.jobs.Start(ctx, "refresh_ip_intel", "scheduler", map[string]any{"range": refreshRange, "limit": limit})
	providers, providerErr := s.ipIntel.RefreshOfficialProviderRanges(ctx)
	result, err := s.ipIntel.RefreshTop(ctx, ipintel.Options{Range: refreshRange, Limit: limit})
	result.ProviderRanges = providers.Ranges
	result.ProviderFailed = providers.Failed
	if err != nil || (providerErr != nil && providers.Providers == 0) {
		if err == nil && providers.Providers == 0 {
			err = providerErr
		}
		s.jobs.Finish(job.ID, jobs.StatusFailed, "IP intelligence refresh failed", err)
		return
	}
	s.jobs.FinishWithMeta(job.ID, jobs.StatusSuccess, "IP intelligence refresh completed", nil, map[string]any{
		"refreshed":          result.Refreshed,
		"failed":             result.Failed,
		"lookup_failed":      result.LookupFailed,
		"geoip_failed":       result.GeoIPFailed,
		"reverse_dns_failed": result.ReverseDNSFailed,
		"providers":          providers.Providers,
		"provider_ranges":    providers.Ranges,
		"provider_failed":    providers.Failed,
	})
	log.Info().
		Int("refreshed", result.Refreshed).
		Int("hard_failures", result.Failed).
		Int("dns_geoip_misses", result.LookupFailed).
		Int("geoip_misses", result.GeoIPFailed).
		Int("reverse_dns_misses", result.ReverseDNSFailed).
		Int("providers", providers.Providers).
		Int("provider_ranges", providers.Ranges).
		Int("provider_failed", providers.Failed).
		Msg("scheduled IP intelligence refresh completed")
}

func (s *Scheduler) ipIntelRange() string {
	value := strings.TrimSpace(s.cfg.IPIntel.Range)
	if value == "" {
		return "24h"
	}
	return value
}

func (s *Scheduler) ipIntelLimit() int {
	if s.cfg.IPIntel.Limit > 0 {
		return s.cfg.IPIntel.Limit
	}
	return ipintel.ResultMaxLimit
}

func (s *Scheduler) runRetention(ctx context.Context) {
	if s.retention == nil || !s.cfg.Retention.Enabled {
		return
	}
	job := s.jobs.Start(ctx, "retention", "scheduler", map[string]any{"max_age": s.cfg.Retention.MaxAge.String()})
	result, err := s.retention.Run(ctx, retention.Options{})
	if err != nil {
		s.jobs.Finish(job.ID, jobs.StatusFailed, "retention failed", err)
		log.Error().Err(err).Msg("scheduled retention failed")
		return
	}
	s.jobs.FinishWithMeta(job.ID, jobs.StatusSuccess, "retention completed", nil, map[string]any{
		"access_events_deleted":     result.AccessEventsDeleted,
		"rollups_deleted":           result.RollupsDeleted,
		"combined_segments_deleted": result.CombinedSegmentsDeleted,
		"raw_files_deleted":         result.RawFilesDeleted,
	})
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
	job := s.jobs.Start(ctx, "send_notifications", "scheduler", map[string]any{"min_severity": s.cfg.Notifications.MinSeverity})
	result, err := s.notifications.NotifyOpenAlerts(ctx, 100)
	if err != nil {
		s.jobs.Finish(job.ID, jobs.StatusFailed, "notifications failed", err)
		log.Error().Err(err).Msg("scheduled notifications failed")
		return
	}
	s.jobs.FinishWithMeta(job.ID, jobs.StatusSuccess, "notifications completed", nil, map[string]any{
		"evaluated": result.Evaluated,
		"sent":      result.Sent,
		"skipped":   result.Skipped,
		"failed":    result.Failed,
	})
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
	job := s.jobs.Start(ctx, "generate_llm_reports", "scheduler", map[string]any{"ranges": strings.Join(s.cfg.Reports.Ranges, ",")})
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
	s.jobs.FinishWithMeta(job.ID, jobs.StatusSuccess, "LLM reports generated", nil, map[string]any{"generated": generated})
	log.Info().Int("generated", generated).Msg("scheduled LLM reports generated")
}
