package reports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"originpulse/internal/accessanalysis"
	"originpulse/internal/alerts"
	"originpulse/internal/analytics"
	"originpulse/internal/backfill"
	"originpulse/internal/config"
	"originpulse/internal/db"
	"originpulse/internal/investigation"
)

var ErrNotFound = errors.New("report not found")

const RecentMaxLimit = 500

type CatalogOptions struct {
	Limit      int
	Offset     int
	SiteID     string
	ReportType string
}

type CatalogResult struct {
	Reports          []Report       `json:"reports"`
	Total            int            `json:"total"`
	Limit            int            `json:"limit"`
	Offset           int            `json:"offset"`
	ReportTypes      []string       `json:"report_types"`
	ReportTypeCounts map[string]int `json:"report_type_counts"`
}

type Options struct {
	Range      string `json:"range"`
	ReportType string `json:"report_type"`
	SiteID     string `json:"site_id"`
}

type Report struct {
	ID               string         `json:"id,omitempty"`
	ReportType       string         `json:"report_type"`
	Range            string         `json:"range"`
	SiteID           string         `json:"site_id,omitempty"`
	RangeStart       time.Time      `json:"range_start"`
	RangeEnd         time.Time      `json:"range_end"`
	Model            string         `json:"model"`
	OllamaConfigured bool           `json:"ollama_configured"`
	Stored           bool           `json:"stored"`
	Summary          *ReportSummary `json:"summary,omitempty"`
	Charts           []ReportChart  `json:"charts,omitempty"`
	Drilldowns       []Drilldown    `json:"drilldowns,omitempty"`
	Input            map[string]any `json:"input,omitempty"`
	Output           string         `json:"output,omitempty"`
	OutputPreview    string         `json:"output_preview,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
}

type Service struct {
	cfg            config.Config
	db             *db.Store
	analytics      *analytics.Service
	accessAnalysis *accessanalysis.Service
	investigation  *investigation.Service
	alerts         *alerts.Service
	backfill       *backfill.Service
	client         *http.Client
}

func NewService(
	cfg config.Config,
	store *db.Store,
	analytics *analytics.Service,
	accessAnalysis *accessanalysis.Service,
	investigation *investigation.Service,
	alerts *alerts.Service,
	backfillService *backfill.Service,
) *Service {
	return &Service{
		cfg:            cfg,
		db:             store,
		analytics:      analytics,
		accessAnalysis: accessAnalysis,
		investigation:  investigation,
		alerts:         alerts,
		backfill:       backfillService,
		client:         &http.Client{Timeout: 180 * time.Second},
	}
}

func (s *Service) Enabled() bool {
	return s != nil && s.db != nil && s.db.Enabled()
}

func (s *Service) Daily(ctx context.Context, opts Options) (Report, error) {
	return s.Generate(ctx, opts)
}

func (s *Service) Generate(ctx context.Context, opts Options) (Report, error) {
	duration, label := parseRange(opts.Range)
	now := time.Now().UTC()
	reportType := strings.TrimSpace(opts.ReportType)
	if reportType == "" {
		reportType = reportTypeForRange(label)
	}
	siteID := strings.TrimSpace(opts.SiteID)
	report := Report{
		ReportType:       reportType,
		Range:            label,
		SiteID:           siteID,
		RangeStart:       now.Add(-duration),
		RangeEnd:         now,
		Model:            s.cfg.OllamaModel(),
		OllamaConfigured: s.cfg.OllamaBaseURL() != "",
		CreatedAt:        now,
	}

	input, err := s.reportInput(ctx, label, siteID, now)
	if err != nil {
		return report, err
	}
	summary, charts, drilldowns := buildReportViews(input)
	report.Summary = summary
	report.Charts = charts
	report.Drilldowns = drilldowns
	input["report_summary"] = summary
	input["report_charts"] = charts
	input["report_drilldowns"] = drilldowns
	report.Input = input

	promptEvidence := buildPromptEvidence(input, summary, charts, drilldowns)
	promptBytes, err := json.MarshalIndent(promptEvidence, "", "  ")
	if err != nil {
		return report, err
	}
	prompt := summaryPrompt(report.ReportType, string(promptBytes))
	if report.OllamaConfigured {
		log.Info().
			Str("model", report.Model).
			Str("report_type", report.ReportType).
			Str("range", report.Range).
			Int("prompt_bytes", len(prompt)).
			Msg("LLM report generation started")
		output, err := s.callOllama(ctx, prompt)
		if err != nil {
			log.Warn().
				Err(err).
				Str("model", report.Model).
				Str("report_type", report.ReportType).
				Str("range", report.Range).
				Msg("LLM report generation failed; using deterministic fallback")
			report.Output = fmt.Sprintf("Ollama request failed for %s: %v\n\n%s", report.Model, err, deterministicSummary(input))
		} else {
			report.Output = cleanText(output)
			if isMetaResponse(report.Output) || tooShortResponse(report.Output) {
				report.Output = deterministicSummary(input)
			}
		}
	} else {
		report.Output = "Ollama is not configured. " + deterministicSummary(input)
	}
	report.Output = cleanText(report.Output)
	if report.Output == "" {
		report.Output = "Ollama returned an empty response. " + deterministicSummary(input)
	}

	if err := s.store(ctx, &report, prompt); err != nil {
		return report, err
	}
	log.Info().
		Str("model", report.Model).
		Str("report_type", report.ReportType).
		Str("range", report.Range).
		Bool("stored", report.Stored).
		Int("output_bytes", len(report.Output)).
		Msg("LLM report generated")
	return report, nil
}

func (s *Service) Recent(ctx context.Context, limit int, siteID string) ([]Report, error) {
	catalog, err := s.Catalog(ctx, CatalogOptions{Limit: limit, SiteID: siteID})
	return catalog.Reports, err
}

func (s *Service) Catalog(ctx context.Context, opts CatalogOptions) (CatalogResult, error) {
	result := CatalogResult{
		Reports:          []Report{},
		Limit:            normalizeRecentLimit(opts.Limit),
		Offset:           normalizeOffset(opts.Offset),
		ReportTypes:      []string{},
		ReportTypeCounts: map[string]int{},
	}
	if s.db == nil || !s.db.Enabled() {
		return result, nil
	}
	siteID := strings.TrimSpace(opts.SiteID)
	reportType := strings.TrimSpace(opts.ReportType)
	pool, err := s.db.Pool()
	if err != nil {
		return result, err
	}

	typeRows, err := pool.Query(ctx, `
SELECT report_type, count(*)::int
FROM llm_reports
WHERE ($1 = '' OR site_id = $1 OR site_id IS NULL)
GROUP BY report_type
ORDER BY report_type`, siteID)
	if err != nil {
		return result, err
	}
	defer typeRows.Close()
	for typeRows.Next() {
		var value string
		var count int
		if err := typeRows.Scan(&value, &count); err != nil {
			return result, err
		}
		result.ReportTypes = append(result.ReportTypes, value)
		result.ReportTypeCounts[value] = count
	}
	if err := typeRows.Err(); err != nil {
		return result, err
	}

	if err := pool.QueryRow(ctx, `
SELECT count(*)::int
FROM llm_reports
WHERE ($1 = '' OR site_id = $1 OR site_id IS NULL)
  AND ($2 = '' OR report_type = $2)`, siteID, reportType).Scan(&result.Total); err != nil {
		return result, err
	}

	rows, err := pool.Query(ctx, `
SELECT id::text,
       report_type,
       range_start,
       range_end,
       coalesce(site_id, ''),
       model,
       coalesce(input->'report_summary', '{}'::jsonb)::text,
       left(output, 1200),
       created_at
FROM llm_reports
WHERE ($2 = '' OR site_id = $2 OR site_id IS NULL)
  AND ($3 = '' OR report_type = $3)
ORDER BY created_at DESC
LIMIT $1 OFFSET $4`, result.Limit, siteID, reportType, result.Offset)
	if err != nil {
		return result, err
	}
	defer rows.Close()

	reports := make([]Report, 0, result.Limit)
	for rows.Next() {
		var item Report
		var summaryRaw string
		if err := rows.Scan(
			&item.ID,
			&item.ReportType,
			&item.RangeStart,
			&item.RangeEnd,
			&item.SiteID,
			&item.Model,
			&summaryRaw,
			&item.OutputPreview,
			&item.CreatedAt,
		); err != nil {
			return result, err
		}
		item.Stored = true
		item.OllamaConfigured = true
		item.Range = rangeLabel(item.RangeStart, item.RangeEnd)
		var summary ReportSummary
		if err := json.Unmarshal([]byte(summaryRaw), &summary); err == nil {
			item.Summary = &summary
		}
		reports = append(reports, item)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	result.Reports = reports
	return result, nil
}

func normalizeRecentLimit(limit int) int {
	if limit <= 0 {
		return 25
	}
	if limit > RecentMaxLimit {
		return RecentMaxLimit
	}
	return limit
}

func normalizeOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

func (s *Service) Get(ctx context.Context, id string) (Report, error) {
	if s.db == nil || !s.db.Enabled() {
		return Report{}, ErrNotFound
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return Report{}, ErrNotFound
	}
	pool, err := s.db.Pool()
	if err != nil {
		return Report{}, err
	}

	var item Report
	var inputRaw string
	err = pool.QueryRow(ctx, `
SELECT id::text,
       report_type,
       range_start,
       range_end,
       coalesce(site_id, ''),
       model,
       input::text,
       output,
       created_at
FROM llm_reports
WHERE id = $1::uuid`, id).Scan(
		&item.ID,
		&item.ReportType,
		&item.RangeStart,
		&item.RangeEnd,
		&item.SiteID,
		&item.Model,
		&inputRaw,
		&item.Output,
		&item.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Report{}, ErrNotFound
	}
	if err != nil {
		return Report{}, err
	}
	item.Stored = true
	item.OllamaConfigured = true
	item.Range = rangeLabel(item.RangeStart, item.RangeEnd)
	_ = json.Unmarshal([]byte(inputRaw), &item.Input)
	populateReportViewsFromInput(&item)
	return item, nil
}

func (s *Service) reportInput(ctx context.Context, rangeLabel string, siteID string, now time.Time) (map[string]any, error) {
	input := map[string]any{
		"range":        rangeLabel,
		"site_id":      siteID,
		"generated_at": now.UTC(),
	}
	if s.Enabled() {
		audit, err := s.fastReadAuditWithCatchup(ctx, FastReadAuditOptions{Range: rangeLabel, SiteID: siteID, Now: now})
		if err != nil {
			return nil, err
		}
		input["fast_read_audit"] = audit
	}

	if s.analytics != nil {
		overview, err := s.analytics.DashboardOverviewFor(ctx, analytics.Options{Range: rangeLabel, SiteID: siteID})
		if err != nil {
			return nil, err
		}
		input["overview"] = overview
	}
	if s.accessAnalysis != nil {
		analysis, err := s.accessAnalysis.Analyze(ctx, accessanalysis.Options{Range: rangeLabel, SiteID: siteID, Limit: accessanalysis.ResultMaxLimit})
		if err != nil {
			return nil, err
		}
		input["access_analysis"] = analysis
	}
	if s.investigation != nil {
		traffic, err := s.investigation.Traffic(ctx, investigation.Options{Range: rangeLabel, SiteID: siteID, Limit: investigation.DetailMaxLimit})
		if err != nil {
			return nil, err
		}
		input["traffic"] = traffic
	}
	if s.alerts != nil {
		openAlerts, err := s.alerts.Open(ctx, alerts.RecentMaxLimit)
		if err != nil {
			return nil, err
		}
		input["open_alerts"] = openAlerts
	}

	return input, nil
}

func (s *Service) fastReadAuditWithCatchup(ctx context.Context, opts FastReadAuditOptions) (FastReadAudit, error) {
	audit, err := s.FastReadAudit(ctx, opts)
	if err != nil {
		return audit, err
	}
	if !audit.ExpectedRawRangeAggregations || s.backfill == nil || !s.backfill.Enabled() {
		return audit, nil
	}
	lastUnbackfilled := audit.UnbackfilledFullHourEvents
	for attempt := 0; attempt < 3 && audit.ExpectedRawRangeAggregations; attempt++ {
		if _, err := s.backfill.Run(ctx, backfill.Options{BatchSize: 10000, MaxBatches: 20, Rollups: true}); err != nil {
			return audit, err
		}
		next, err := s.FastReadAudit(ctx, opts)
		if err != nil {
			return audit, err
		}
		audit = next
		if !audit.ExpectedRawRangeAggregations {
			break
		}
		if audit.UnbackfilledFullHourEvents >= lastUnbackfilled {
			break
		}
		lastUnbackfilled = audit.UnbackfilledFullHourEvents
	}
	return audit, nil
}

func (s *Service) callOllama(ctx context.Context, prompt string) (string, error) {
	body, err := json.Marshal(map[string]any{
		"model":  s.cfg.OllamaModel(),
		"prompt": prompt,
		"stream": false,
		"think":  false,
		"options": map[string]any{
			"num_predict": 1500,
			"num_ctx":     32768,
			"temperature": 0.2,
		},
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.OllamaBaseURL()+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("ollama returned %s", resp.Status)
	}

	var decoded struct {
		Response string `json:"response"`
		Thinking string `json:"thinking"`
		Error    string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return "", err
	}
	if decoded.Error != "" {
		return "", fmt.Errorf("ollama error: %s", decoded.Error)
	}
	if strings.TrimSpace(decoded.Response) == "" && strings.TrimSpace(decoded.Thinking) != "" {
		return "", fmt.Errorf("ollama returned thinking text but no final response")
	}
	return decoded.Response, nil
}

func (s *Service) store(ctx context.Context, report *Report, prompt string) error {
	if s.db == nil || !s.db.Enabled() {
		return nil
	}
	pool, err := s.db.Pool()
	if err != nil {
		return err
	}
	inputJSON, err := json.Marshal(report.Input)
	if err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(prompt))

	if err := pool.QueryRow(ctx, `
INSERT INTO llm_reports (
  report_type, range_start, range_end, site_id, prompt_hash, model, input, output
) VALUES (
  $1, $2, $3, $4, $5, $6, $7::jsonb, $8
)
RETURNING id::text, created_at`,
		report.ReportType,
		report.RangeStart,
		report.RangeEnd,
		nullableSiteID(report.SiteID),
		hex.EncodeToString(hash[:]),
		report.Model,
		string(inputJSON),
		report.Output,
	).Scan(&report.ID, &report.CreatedAt); err != nil {
		return err
	}
	report.Stored = true
	return nil
}

func summaryPrompt(reportType string, inputJSON string) string {
	return `You are a web traffic incident analyst.
You are reading OriginPulse telemetry, not describing a JSON file.
Write a rich operator report about the observed origin traffic.
Make it concrete, action-oriented, and useful for a human who will drill into charts and source IP evidence.
Include an executive summary, reliability notes, security signals, source IP and user-agent observations, likely causes, open alerts, and immediate next checks.
Use the report_summary, report_charts, and report_drilldowns facts as evidence.
Clearly distinguish observed facts from hypotheses.
Report type: ` + reportType + `
Return only the report. Do not mention prompts, JSON, schemas, or hidden reasoning.
/no_think

Evidence:
` + inputJSON
}

func deterministicSummary(input map[string]any) string {
	overview, _ := input["overview"].(analytics.Overview)
	traffic, _ := input["traffic"].(investigation.Traffic)
	openAlerts, _ := input["open_alerts"].([]alerts.Alert)
	analysis, _ := input["access_analysis"].(accessanalysis.Report)

	return fmt.Sprintf(
		"Deterministic summary: %d requests, %d unique IPs, %.2f%% 5xx rate, %d detected issues, %d open alerts, %d top IP rows, %d top user-agent rows, %d recent error rows.",
		overview.Requests,
		overview.UniqueIPs,
		overview.Status5xxRate*100,
		len(analysis.Issues),
		len(openAlerts),
		len(traffic.TopIPs),
		len(analysis.UserAgents),
		len(traffic.RecentErrors),
	)
}

func cleanText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	var cleaned strings.Builder
	cleaned.Grow(len(value))
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			value = value[size:]
			continue
		}
		if r != 0 {
			cleaned.WriteRune(r)
		}
		value = value[size:]
	}
	return strings.TrimSpace(cleaned.String())
}

func isMetaResponse(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	metaPhrases := []string{
		"you've provided",
		"you have provided",
		"json structure",
		"json object",
		"appears to be",
		"looks like",
		"this appears",
	}
	for _, phrase := range metaPhrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

func tooShortResponse(value string) bool {
	return utf8.RuneCountInString(strings.TrimSpace(value)) < 80
}

func parseRange(value string) (time.Duration, string) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "15m":
		return 15 * time.Minute, "15m"
	case "6h":
		return 6 * time.Hour, "6h"
	case "24h", "daily", "day":
		return 24 * time.Hour, "24h"
	case "7d", "weekly", "week":
		return 7 * 24 * time.Hour, "7d"
	case "30d", "monthly", "month":
		return 30 * 24 * time.Hour, "30d"
	case "90d", "quarterly", "quarter":
		return 90 * 24 * time.Hour, "90d"
	case "365d", "annual", "yearly", "year", "1y":
		return 365 * 24 * time.Hour, "365d"
	case "1h", "":
		return time.Hour, "1h"
	default:
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed, value
		}
		return time.Hour, "1h"
	}
}

func reportTypeForRange(label string) string {
	switch label {
	case "24h":
		return "daily"
	case "7d":
		return "weekly"
	case "30d":
		return "monthly"
	case "90d":
		return "quarterly"
	case "365d":
		return "annual"
	default:
		return "period"
	}
}

func rangeLabel(start time.Time, end time.Time) string {
	duration := end.Sub(start)
	switch {
	case duration >= 360*24*time.Hour && duration <= 370*24*time.Hour:
		return "365d"
	case duration >= 85*24*time.Hour && duration <= 95*24*time.Hour:
		return "90d"
	case duration >= 29*24*time.Hour && duration <= 31*24*time.Hour:
		return "30d"
	case duration >= 6*24*time.Hour && duration <= 8*24*time.Hour:
		return "7d"
	case duration >= 23*time.Hour && duration <= 25*time.Hour:
		return "24h"
	case duration >= 50*time.Minute && duration <= 70*time.Minute:
		return "1h"
	default:
		return duration.Round(time.Minute).String()
	}
}

func nullableSiteID(siteID string) any {
	siteID = strings.TrimSpace(siteID)
	if siteID == "" {
		return nil
	}
	return siteID
}
