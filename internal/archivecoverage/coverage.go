package archivecoverage

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"originpulse/internal/config"
	"originpulse/internal/db"
)

type Options struct {
	Range string
	From  time.Time
	To    time.Time
	Now   time.Time
}

type Archive struct {
	ID               string     `json:"id"`
	LogType          string     `json:"log_type"`
	Granularity      string     `json:"granularity"`
	RangeStart       time.Time  `json:"range_start"`
	RangeEnd         time.Time  `json:"range_end"`
	Path             string     `json:"path"`
	SourceFileCount  int        `json:"source_file_count"`
	SourceBytes      int64      `json:"source_bytes"`
	CompressedBytes  int64      `json:"compressed_bytes"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	CoveredSeconds   int64      `json:"covered_seconds"`
	CoverageFraction float64    `json:"coverage_fraction"`
}

type TemporaryImport struct {
	ID                 string    `json:"id"`
	Reason             string    `json:"reason"`
	RangeStart         time.Time `json:"range_start"`
	RangeEnd           time.Time `json:"range_end"`
	Status             string    `json:"status"`
	ExpiresAt          time.Time `json:"expires_at"`
	ImportedEventCount int64     `json:"imported_event_count"`
}

type Coverage struct {
	Range                   string            `json:"range"`
	Since                   time.Time         `json:"since"`
	Until                   time.Time         `json:"until"`
	HotEventCutoff          time.Time         `json:"hot_event_cutoff"`
	HotEventMaxAge          string            `json:"hot_event_max_age"`
	HotDataMin              *time.Time        `json:"hot_data_min,omitempty"`
	HotDataMax              *time.Time        `json:"hot_data_max,omitempty"`
	RequiresArchiveImport   bool              `json:"requires_archive_import"`
	AlreadyImported         bool              `json:"already_imported"`
	ImportRecommended       bool              `json:"import_recommended"`
	ImportWindowStart       *time.Time        `json:"import_window_start,omitempty"`
	ImportWindowEnd         *time.Time        `json:"import_window_end,omitempty"`
	RequestedOldSeconds     int64             `json:"requested_old_seconds"`
	ArchiveCoveredSeconds   int64             `json:"archive_covered_seconds"`
	ArchiveCoverageRatio    float64           `json:"archive_coverage_ratio"`
	TemporaryCoveredSeconds int64             `json:"temporary_covered_seconds"`
	TemporaryCoverageRatio  float64           `json:"temporary_coverage_ratio"`
	AvailableArchiveCount   int               `json:"available_archive_count"`
	SelectedArchiveCount    int               `json:"selected_archive_count"`
	SelectedCompressedBytes int64             `json:"selected_compressed_bytes"`
	SelectedSourceBytes     int64             `json:"selected_source_bytes"`
	Archives                []Archive         `json:"archives"`
	ActiveTemporaryImports  []TemporaryImport `json:"active_temporary_imports"`
	TemporaryImportMaxAge   string            `json:"temporary_import_max_age"`
}

type Service struct {
	cfg config.Config
	db  *db.Store
}

type interval struct {
	start time.Time
	end   time.Time
}

func NewService(cfg config.Config, store *db.Store) *Service {
	return &Service{cfg: cfg, db: store}
}

func (s *Service) Enabled() bool {
	return s != nil && s.db != nil && s.db.Enabled()
}

func (s *Service) Coverage(ctx context.Context, opts Options) (Coverage, error) {
	if !s.Enabled() {
		return Coverage{}, db.ErrUnavailable
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	since, until, rangeLabel, err := resolveWindow(opts, now)
	if err != nil {
		return Coverage{}, err
	}
	hotCutoff := now.Add(-s.cfg.Retention.HotEventMaxAge)
	oldStart, oldEnd, requiresImport := oldWindow(since, until, hotCutoff)
	report := Coverage{
		Range:                  rangeLabel,
		Since:                  since,
		Until:                  until,
		HotEventCutoff:         hotCutoff,
		HotEventMaxAge:         s.cfg.Retention.HotEventMaxAge.String(),
		RequiresArchiveImport:  requiresImport,
		TemporaryImportMaxAge:  s.cfg.Retention.TemporaryImportMaxAge.String(),
		Archives:               []Archive{},
		ActiveTemporaryImports: []TemporaryImport{},
	}
	if requiresImport {
		report.ImportWindowStart = &oldStart
		report.ImportWindowEnd = &oldEnd
		report.RequestedOldSeconds = secondsBetween(oldStart, oldEnd)
	}

	pool, err := s.db.Pool()
	if err != nil {
		return report, err
	}
	if err := pool.QueryRow(ctx, `SELECT min(ts), max(ts) FROM access_events`).Scan(&report.HotDataMin, &report.HotDataMax); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return report, err
	}
	if !requiresImport {
		return report, nil
	}

	archives, err := s.overlappingArchives(ctx, oldStart, oldEnd, now)
	if err != nil {
		return report, err
	}
	report.AvailableArchiveCount = len(archives)
	selected := selectArchives(archives, oldStart, oldEnd)
	report.Archives = selected
	report.SelectedArchiveCount = len(selected)
	archiveIntervals := make([]interval, 0, len(selected))
	for i := range selected {
		report.SelectedCompressedBytes += selected[i].CompressedBytes
		report.SelectedSourceBytes += selected[i].SourceBytes
		archiveIntervals = append(archiveIntervals, interval{start: selected[i].RangeStart, end: selected[i].RangeEnd})
	}
	report.ArchiveCoveredSeconds = coveredSeconds(archiveIntervals, oldStart, oldEnd)
	report.ArchiveCoverageRatio = ratio(report.ArchiveCoveredSeconds, report.RequestedOldSeconds)

	imports, err := s.activeImports(ctx, oldStart, oldEnd, now)
	if err != nil {
		return report, err
	}
	report.ActiveTemporaryImports = imports
	importIntervals := make([]interval, 0, len(imports))
	for _, item := range imports {
		importIntervals = append(importIntervals, interval{start: item.RangeStart, end: item.RangeEnd})
	}
	report.TemporaryCoveredSeconds = coveredSeconds(importIntervals, oldStart, oldEnd)
	report.TemporaryCoverageRatio = ratio(report.TemporaryCoveredSeconds, report.RequestedOldSeconds)
	report.AlreadyImported = report.RequestedOldSeconds > 0 && report.TemporaryCoveredSeconds >= report.RequestedOldSeconds
	report.ImportRecommended = report.RequiresArchiveImport && !report.AlreadyImported && report.SelectedArchiveCount > 0
	return report, nil
}

func (s *Service) overlappingArchives(ctx context.Context, start time.Time, end time.Time, now time.Time) ([]Archive, error) {
	pool, err := s.db.Pool()
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(ctx, `
SELECT id::text,
       log_type,
       granularity,
       range_start,
       range_end,
       path,
       source_file_count,
       source_bytes,
       compressed_bytes,
       expires_at
FROM log_archives
WHERE status = 'ready'
  AND range_end > $1
  AND range_start < $2
  AND (expires_at IS NULL OR expires_at > $3)
ORDER BY range_start ASC, range_end DESC`, start, end, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	archives := []Archive{}
	for rows.Next() {
		var item Archive
		if err := rows.Scan(&item.ID, &item.LogType, &item.Granularity, &item.RangeStart, &item.RangeEnd, &item.Path, &item.SourceFileCount, &item.SourceBytes, &item.CompressedBytes, &item.ExpiresAt); err != nil {
			return nil, err
		}
		item.CoveredSeconds = overlapSeconds(interval{start: item.RangeStart, end: item.RangeEnd}, start, end)
		item.CoverageFraction = ratio(item.CoveredSeconds, secondsBetween(start, end))
		archives = append(archives, item)
	}
	return archives, rows.Err()
}

func (s *Service) activeImports(ctx context.Context, start time.Time, end time.Time, now time.Time) ([]TemporaryImport, error) {
	pool, err := s.db.Pool()
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(ctx, `
SELECT id::text,
       coalesce(reason, ''),
       range_start,
       range_end,
       status,
       expires_at,
       imported_event_count
FROM temporary_imports
WHERE status = 'imported'
  AND expires_at > $1
  AND range_end > $2
  AND range_start < $3
ORDER BY range_start ASC, imported_at DESC`, now, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	imports := []TemporaryImport{}
	for rows.Next() {
		var item TemporaryImport
		if err := rows.Scan(&item.ID, &item.Reason, &item.RangeStart, &item.RangeEnd, &item.Status, &item.ExpiresAt, &item.ImportedEventCount); err != nil {
			return nil, err
		}
		imports = append(imports, item)
	}
	return imports, rows.Err()
}

func resolveWindow(opts Options, now time.Time) (time.Time, time.Time, string, error) {
	from := opts.From.UTC()
	to := opts.To.UTC()
	if !from.IsZero() && !to.IsZero() {
		if !to.After(from) {
			return time.Time{}, time.Time{}, "", errors.New("to must be after from")
		}
		return from, to, "custom", nil
	}
	rangeValue := strings.TrimSpace(opts.Range)
	if rangeValue == "" {
		rangeValue = "24h"
	}
	duration, err := parseRangeDuration(rangeValue)
	if err != nil {
		return time.Time{}, time.Time{}, "", err
	}
	if !to.IsZero() {
		return to.Add(-duration), to, rangeValue, nil
	}
	if !from.IsZero() {
		return from, from.Add(duration), rangeValue, nil
	}
	return now.Add(-duration), now, rangeValue, nil
}

func parseRangeDuration(value string) (time.Duration, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "15m":
		return 15 * time.Minute, nil
	case "1h":
		return time.Hour, nil
	case "6h":
		return 6 * time.Hour, nil
	case "24h", "1d":
		return 24 * time.Hour, nil
	case "7d":
		return 7 * 24 * time.Hour, nil
	case "30d":
		return 30 * 24 * time.Hour, nil
	case "90d":
		return 90 * 24 * time.Hour, nil
	case "365d", "1y":
		return 365 * 24 * time.Hour, nil
	default:
		return time.ParseDuration(value)
	}
}

func oldWindow(since time.Time, until time.Time, hotCutoff time.Time) (time.Time, time.Time, bool) {
	if !since.Before(hotCutoff) {
		return time.Time{}, time.Time{}, false
	}
	end := until
	if hotCutoff.Before(end) {
		end = hotCutoff
	}
	if !end.After(since) {
		return time.Time{}, time.Time{}, false
	}
	return since, end, true
}

func selectArchives(archives []Archive, start time.Time, end time.Time) []Archive {
	sort.SliceStable(archives, func(i, j int) bool {
		pi, pj := granularityPriority(archives[i].Granularity), granularityPriority(archives[j].Granularity)
		if pi != pj {
			return pi > pj
		}
		di, dj := archives[i].RangeEnd.Sub(archives[i].RangeStart), archives[j].RangeEnd.Sub(archives[j].RangeStart)
		if di != dj {
			return di > dj
		}
		return archives[i].RangeStart.Before(archives[j].RangeStart)
	})
	selected := []Archive{}
	covered := []interval{}
	for _, item := range archives {
		next := interval{start: item.RangeStart, end: item.RangeEnd}
		if overlapSeconds(next, start, end) <= 0 || intervalCovered(next, covered, start, end) {
			continue
		}
		selected = append(selected, item)
		covered = mergeIntervals(append(covered, next), start, end)
	}
	sort.SliceStable(selected, func(i, j int) bool {
		return selected[i].RangeStart.Before(selected[j].RangeStart)
	})
	return selected
}

func granularityPriority(value string) int {
	switch strings.ToLower(value) {
	case "monthly":
		return 3
	case "weekly":
		return 2
	case "daily":
		return 1
	default:
		return 0
	}
}

func intervalCovered(candidate interval, covered []interval, start time.Time, end time.Time) bool {
	clipped := clipInterval(candidate, start, end)
	if !clipped.end.After(clipped.start) {
		return true
	}
	return coveredSeconds(append([]interval{}, covered...), clipped.start, clipped.end) >= secondsBetween(clipped.start, clipped.end)
}

func coveredSeconds(items []interval, start time.Time, end time.Time) int64 {
	total := int64(0)
	for _, item := range mergeIntervals(items, start, end) {
		total += secondsBetween(item.start, item.end)
	}
	return total
}

func mergeIntervals(items []interval, start time.Time, end time.Time) []interval {
	clipped := make([]interval, 0, len(items))
	for _, item := range items {
		next := clipInterval(item, start, end)
		if next.end.After(next.start) {
			clipped = append(clipped, next)
		}
	}
	sort.Slice(clipped, func(i, j int) bool {
		return clipped[i].start.Before(clipped[j].start)
	})
	merged := []interval{}
	for _, item := range clipped {
		if len(merged) == 0 || item.start.After(merged[len(merged)-1].end) {
			merged = append(merged, item)
			continue
		}
		if item.end.After(merged[len(merged)-1].end) {
			merged[len(merged)-1].end = item.end
		}
	}
	return merged
}

func clipInterval(item interval, start time.Time, end time.Time) interval {
	if item.start.Before(start) {
		item.start = start
	}
	if item.end.After(end) {
		item.end = end
	}
	return item
}

func overlapSeconds(item interval, start time.Time, end time.Time) int64 {
	return secondsBetween(clipInterval(item, start, end).start, clipInterval(item, start, end).end)
}

func secondsBetween(start time.Time, end time.Time) int64 {
	if !end.After(start) {
		return 0
	}
	return int64(end.Sub(start).Seconds())
}

func ratio(numerator int64, denominator int64) float64 {
	if denominator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}
